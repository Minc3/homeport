package sysx

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/quinlan102/homeport/internal/model"
)

// fakeRunner records commands and replays canned output for queries.
type fakeRunner struct {
	calls   []string
	replies map[string]string
	fail    map[string]string
}

// Run answers from the canned table, longest matching prefix first.
//
// Longest rather than first, because Go's map iteration order is random and the
// keys a test needs are routinely prefixes of one another: "ip rule show" is a
// prefix of "ip rule show table 220", and a readback that reads both listings
// would otherwise get whichever the runtime picked that second. The specific
// key is always the one the test meant.
func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	line := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, line)
	if prefix, ok := longestPrefix(f.fail, line); ok {
		return f.fail[prefix], fmt.Errorf("%s: %s", line, f.fail[prefix])
	}
	if prefix, ok := longestPrefix(f.replies, line); ok {
		return f.replies[prefix], nil
	}
	return "", nil
}

func longestPrefix(m map[string]string, line string) (string, bool) {
	best, found := "", false
	for prefix := range m {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		if !found || len(prefix) > len(best) {
			best, found = prefix, true
		}
	}
	return best, found
}

func (f *fakeRunner) Applying() bool { return true }

func (f *fakeRunner) ran(substr string) bool {
	for _, c := range f.calls {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

func TestEnsureOverlayAddressCreatesWhenMissing(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"ip -o addr show": "1: lo    inet 127.0.0.1/8 scope host lo\n",
	}}
	if err := EnsureOverlayAddress(context.Background(), f, "10.99.0.1", "dummy0"); err != nil {
		t.Fatalf("EnsureOverlayAddress: %v", err)
	}
	for _, want := range []string{
		"ip link add dummy0 type dummy",
		"ip addr add 10.99.0.1/32 dev dummy0",
		"ip link set dummy0 up",
	} {
		if !f.ran(want) {
			t.Errorf("missing command %q; calls were %v", want, f.calls)
		}
	}
}

func TestEnsureOverlayAddressIsIdempotent(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"ip -o addr show": "5: dummy0    inet 10.99.0.1/32 scope global dummy0\n",
	}}
	if err := EnsureOverlayAddress(context.Background(), f, "10.99.0.1", "dummy0"); err != nil {
		t.Fatalf("EnsureOverlayAddress: %v", err)
	}
	if f.ran("ip link add") || f.ran("ip addr add") {
		t.Errorf("an existing address must be left alone; calls were %v", f.calls)
	}
}

func TestEnsureOverlayAddressToleratesExistingDevice(t *testing.T) {
	// The device exists but carries no address yet - a partial previous run.
	f := &fakeRunner{
		replies: map[string]string{"ip -o addr show": "5: dummy0    <BROADCAST>\n"},
		fail:    map[string]string{"ip link add": "RTNETLINK answers: File exists"},
	}
	if err := EnsureOverlayAddress(context.Background(), f, "10.99.0.1", "dummy0"); err != nil {
		t.Fatalf("an existing dummy device must not be an error: %v", err)
	}
	if !f.ran("ip addr add 10.99.0.1/32 dev dummy0") {
		t.Errorf("should still have added the address; calls were %v", f.calls)
	}
}

func TestEnsureOverlayAddressRejectsEmpty(t *testing.T) {
	f := &fakeRunner{}
	if err := EnsureOverlayAddress(context.Background(), f, "", "dummy0"); err == nil {
		t.Error("an empty overlay address is a configuration error, not a no-op")
	}
}

func TestDryRunnerSuppressesMutationsButRunsQueries(t *testing.T) {
	// Observe mode must not change anything, but it has to be able to read the
	// system or it could not report what it would do.
	mutations := [][]string{
		{"ip", "route", "replace", "10.99.0.2/32", "dev", "wg-main"},
		{"ip", "rule", "add", "fwmark", "0x101", "lookup", "101"},
		{"ip", "link", "add", "dummy0", "type", "dummy"},
		{"nft", "-f", "/var/lib/failover/ruleset.nft"},
		// The blocklist's two loads. The second is a flush-and-add of set
		// elements rather than a table, which is still a mutation and still
		// reaches nft the same way: it must not run in observe mode, where
		// no blocklist table exists to hold them.
		{"nft", "-f", "/var/lib/failover/blocklist.nft"},
		{"nft", "-f", "/var/lib/failover/blocklist-feed.nft"},
		{"nft", "delete", "table", "ip", "failover_blocklist"},
		{"sysctl", "-w", "net.ipv4.ip_forward=1"},
		// Nothing issues `wg set` today; this pins that the day something
		// does, observe mode suppresses it rather than running it for real
		// because "every wg is a read" happened to be true at the time.
		{"wg", "set", "wg-main", "peer", "abc", "endpoint", "1.2.3.4:51820"},
	}
	for _, m := range mutations {
		if isReadOnly(m[0], m[1:]) {
			t.Errorf("%v was treated as read-only and would be executed in observe mode", m)
		}
	}

	// A read wrongly classified as a mutation is the more dangerous direction,
	// because of what it returns: not an error, but ("", nil) - success with no
	// output - which every caller here reads as "the thing is not installed".
	// The agent then acts on the opposite of the truth. All three of the last
	// entries were getting this wrong.
	queries := [][]string{
		{"ip", "route", "show", "10.99.0.2/32"},
		{"ip", "rule", "show"},
		{"ip", "rule", "show", "table", "101"},
		{"ip", "-o", "addr", "show"},
		{"nft", "list", "ruleset"},
		{"wg", "show", "all", "latest-handshakes"},

		// EnsureQdisc runs through the mode-gated runner, so this one was live:
		// in observe mode the readback always answered "no shaper installed",
		// and every reconcile tick proposed replacing a correct one.
		{"tc", "qdisc", "show", "dev", "wg-main"},
		// Latent, and only because every caller passes the real runner today:
		// the option comes before the verb, so testing args[0] read the flag.
		{"nft", "-a", "list", "chain", "ip", "filter", "DOCKER-USER"},
		{"nft", "-j", "list", "table", "ip", "failover_protect"},
		// The protection readback: the terse table listing carries two flags
		// before the verb, and the per-set listings one - each is a shape
		// `args[0] == "list"` would have misread.
		{"nft", "-j", "-t", "list", "table", "ip", "failover_protect"},
		{"nft", "-j", "list", "set", "ip", "failover_protect", "blocked"},
		// The blocklist counter readback, the same terse shape.
		{"nft", "-j", "-t", "list", "table", "ip", "failover_blocklist"},
	}
	for _, q := range queries {
		if !isReadOnly(q[0], q[1:]) {
			t.Errorf("%v was treated as a mutation and would be suppressed in observe mode", q)
		}
	}

	// And the tools that gained a branch must not have gained a hole with it.
	moreMutations := [][]string{
		{"tc", "qdisc", "replace", "dev", "wg-main", "root", "cake", "bandwidth", "18mbit"},
		{"tc", "qdisc", "del", "dev", "wg-main", "root"},
		{"nft", "delete", "table", "ip", "failover"},
		{"nft", "-a", "delete", "rule", "ip", "filter", "DOCKER-USER", "handle", "12"},
		// The word "list" appearing as data must not make a write look like a
		// read, which is why the verb is taken positionally.
		{"nft", "insert", "rule", "ip", "filter", "DOCKER-USER", "accept", "comment", "list"},
	}
	for _, m := range moreMutations {
		if isReadOnly(m[0], m[1:]) {
			t.Errorf("%v was treated as read-only and would be executed in observe mode", m)
		}
	}
}

// The control-channel rule must select on fwmark, never on the source and
// destination addresses. Probe packets carry those same two addresses, so an
// address-matched rule outranks the per-path fwmark rules and sends all three
// paths down one tunnel - the exact failure the marks exist to prevent. This
// shipped once and cost an evening: every standby path read as 100% loss while
// its tunnel was perfectly healthy.
func TestControlRouteSelectsOnMarkNotAddresses(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"ip rule show": "0:\tfrom all lookup local\n32766:\tfrom all lookup main\n",
	}}
	if err := EnsureControlRoute(context.Background(), f, "10.99.0.2/32", "10.99.0.2", "10.99.0.1", "wg-main"); err != nil {
		t.Fatalf("EnsureControlRoute: %v", err)
	}
	if !f.ran("ip rule add fwmark 0x100 lookup 100") {
		t.Errorf("expected a fwmark rule, got calls: %v", f.calls)
	}
	for _, c := range f.calls {
		if strings.HasPrefix(c, "ip rule add") && strings.Contains(c, "to 10.99.0.2") {
			t.Errorf("control rule matches probe traffic by address: %s", c)
		}
	}
	if !f.ran("ip route replace 10.99.0.2/32 dev wg-main src 10.99.0.1 table 100") {
		t.Errorf("expected the control route in table 100, got calls: %v", f.calls)
	}
}

// The control table must carry the whole overlay range once a subnet is set.
//
// The frontend's control listener is marked, and an accepted connection
// inherits the mark, so every reply on a control channel is steered into this
// table - a linker's included. With only the backend's /32 here, a linker's
// SYN-ACK matched nothing, fell through to main, and in observe mode main has
// no overlay route at all: the reply left by the public interface and the
// linker retried forever against a frontend that was answering.
func TestControlRouteCoversTheOverlayRange(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"ip rule show":                         "0:\tfrom all lookup local\n",
		"ip route show 10.99.0.2/32 table 100": "10.99.0.2 dev wg-main scope link src 10.99.0.1\n",
	}}
	if err := EnsureControlRoute(context.Background(), f, "10.99.0.0/24", "10.99.0.2", "10.99.0.1", "wg-main"); err != nil {
		t.Fatalf("EnsureControlRoute: %v", err)
	}
	if !f.ran("ip route replace 10.99.0.0/24 dev wg-main src 10.99.0.1 table 100") {
		t.Errorf("the overlay range is not in the control table: %v", f.calls)
	}
	// And the host route it supersedes, which is more specific and would keep
	// the backend's own channel pinned to whichever tunnel was active when the
	// subnet was set.
	if !f.ran("ip route del 10.99.0.2/32 table 100") {
		t.Errorf("the superseded host route was left in the control table: %v", f.calls)
	}
}

// A site with no subnet must issue exactly what it always did - invariant 19.
func TestControlRouteWithoutSubnetIsUnchanged(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{"ip rule show": "0:\tfrom all lookup local\n"}}
	if err := EnsureControlRoute(context.Background(), f, "10.99.0.2/32", "10.99.0.2", "10.99.0.1", "wg-main"); err != nil {
		t.Fatalf("EnsureControlRoute: %v", err)
	}
	if !f.ran("ip route replace 10.99.0.2/32 dev wg-main src 10.99.0.1 table 100") {
		t.Errorf("expected the host route in table 100, got: %v", f.calls)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "ip route del") {
			t.Errorf("a site with no subnet has nothing to supersede, but ran: %s", c)
		}
	}
}

// Revert takes its own routes out of the control table by name. Flushing it
// would take an operator's own entries with it: 100 is a number, not this
// system's property. Invariant 8.
func TestRemoveControlRouteNeverFlushes(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"ip rule show table 100": "29999:\tfrom all fwmark 0x100 lookup 100\n",
	}}
	RemoveControlRoute(context.Background(), f, "10.99.0.0/24", "10.99.0.2", "10.99.0.1")
	for _, c := range f.calls {
		if strings.Contains(c, "route flush") {
			t.Errorf("revert flushed a table it does not own: %s", c)
		}
	}
	if !f.ran("ip route del 10.99.0.0/24 table 100") || !f.ran("ip route del 10.99.0.2/32 table 100") {
		t.Errorf("both control routes should be removed by name, got: %v", f.calls)
	}
	if !f.ran("ip rule del fwmark 0x100 lookup 100 pref 29999") {
		t.Errorf("the control rule should be removed at the priority it was found at, got: %v", f.calls)
	}
}

// A path may not claim the control channel's mark or table: both would then
// carry two different flows to the same destination and fight over routing.
func TestControlMarkIsOutsideThePathRange(t *testing.T) {
	if ControlMark != 0x100 {
		t.Fatalf("ControlMark moved to %#x; the shipped path marks start at 0x101", ControlMark)
	}
	if ControlTable != 100 {
		t.Fatalf("ControlTable moved to %d; the shipped path tables start at 101", ControlTable)
	}
}

// rp_filter must be disabled, not set to loose.
//
// The tunnels carry no IPv4 address of their own, and on such an interface the
// kernel's "loose" mode still drops a packet whose reverse lookup resolves to a
// different device (__fib_validate_source takes the no_addr branch straight to
// last_resort). Since each path's forward route lives in its own fwmark table
// and arriving packets carry no mark, that lookup can only ever name one
// tunnel - so two of the three paths get their replies dropped below the
// socket, with no log anywhere. Setting this back to 2 reintroduces a failure
// that looks exactly like two dead links.
func TestSysctlsDisableReversePathFilter(t *testing.T) {
	f := &fakeRunner{}
	EnsureSysctls(context.Background(), f, []string{"wg-main", "wg-lte1"})

	for _, want := range []string{
		"sysctl -w net.ipv4.conf.all.rp_filter=0",
		"sysctl -w net.ipv4.conf.wg-main.rp_filter=0",
		"sysctl -w net.ipv4.conf.wg-lte1.rp_filter=0",
		"sysctl -w net.ipv4.ip_forward=1",
	} {
		if !f.ran(want) {
			t.Errorf("missing %q, got calls: %v", want, f.calls)
		}
	}
	for _, c := range f.calls {
		if strings.Contains(c, "rp_filter=1") || strings.Contains(c, "rp_filter=2") {
			t.Errorf("reverse-path filtering must be off on address-less tunnels, got: %s", c)
		}
	}
}

// An interface being deleted takes every route that used it with it, and the
// kernel says so by returning nothing at all. Reading that back is how the
// reconcilers tell "this tunnel was restarted" from "this tunnel is fine", so
// the empty case must not be confused with an error.
func TestRouteViaReportsAnEmptyTableAsNoInterface(t *testing.T) {
	// One reply per runner: fakeRunner matches on prefix, and
	// "ip route show 10.99.0.2/32" is a prefix of the per-table form.
	via := func(reply string, table int) string {
		t.Helper()
		f := &fakeRunner{replies: map[string]string{"ip route show": reply}}
		out, err := RouteVia(context.Background(), f, "10.99.0.2", table)
		if err != nil {
			t.Fatalf("RouteVia: %v", err)
		}
		return out
	}

	if got := via("10.99.0.2 dev wg-main scope link src 10.99.0.1", 101); got != "wg-main" {
		t.Errorf("RouteVia(table 101) = %q, want wg-main", got)
	}
	// The purged case is the one that matters: no route, but not an error.
	if got := via("", 102); got != "" {
		t.Errorf("RouteVia(purged table) = %q, want an empty interface", got)
	}
	// Table 0 means the main table, which takes no `table` argument at all.
	if got := via("10.99.0.2 dev wg-lte1 scope link src 10.99.0.1", 0); got != "wg-lte1" {
		t.Errorf("RouteVia(main) = %q, want wg-lte1", got)
	}

	f := &fakeRunner{replies: map[string]string{"ip route show default": "default dev wg-lte2 scope link"}}
	if got, err := DefaultVia(context.Background(), f, 100); err != nil || got != "wg-lte2" {
		t.Errorf("DefaultVia(100) = %q, %v; want wg-lte2", got, err)
	}
}

// A table that has never held a route does not exist to the kernel, and
// `ip route show` reports that as an error rather than an empty listing. To
// every reconciler that is the same answer as an empty table - no route - and
// reading it as an error was the boot failure: a frontend started before
// wg-quick had no interface to install a route on, so the probe table was
// never created, and the reconciler skipped that path on the error every tick
// from then on. The path whose tunnel happened to exist at startup measured
// perfectly; the other two never sent a probe until the service was restarted
// with every interface present. A tunnel restart, by contrast, empties a table
// that still exists, which is why that case was always repaired.
func TestRouteViaReportsATableThatNeverExistedAsNoRoute(t *testing.T) {
	// Exactly what iproute2 prints, with ExecRunner's framing around it.
	kernel := "Error: ipv4: FIB table does not exist.\nDump terminated"
	f := &fakeRunner{fail: map[string]string{"ip route show": kernel}}

	via, err := RouteVia(context.Background(), f, "10.99.0.2/32", 101)
	if err != nil || via != "" {
		t.Errorf("RouteVia(never-created table) = %q, %v; want no route and no error", via, err)
	}
	via, err = DefaultVia(context.Background(), f, 100)
	if err != nil || via != "" {
		t.Errorf("DefaultVia(never-created table) = %q, %v; want no route and no error", via, err)
	}

	// Any other failure is still a failure: a reconciler must not install a
	// route on the strength of `ip` having crashed.
	g := &fakeRunner{fail: map[string]string{"ip route show": "RTNETLINK answers: Operation not permitted"}}
	if _, err := RouteVia(context.Background(), g, "10.99.0.2/32", 101); err == nil {
		t.Error("an unrelated ip failure was read as an empty table")
	}
}

// The per-path fwmark rules must outrank the backend's `from <overlay> lookup
// 100` rule, which is a broader match on the same packets. `ip rule add` with
// no preference puts each new rule ahead of the last, and the backend installs
// the path rules first - so the source rule won, and every probe reply left by
// the active tunnel rather than the one its request arrived on. Both paths
// still got replies, so nothing looked wrong; what they measured was a mix of
// two tunnels, and a tunnel dead in the return direction tested as healthy.
func TestProbeRulesArePinnedAheadOfTheReturnRule(t *testing.T) {
	if ProbeRulePrefBase >= 32762 {
		t.Fatalf("ProbeRulePrefBase %d does not outrank the auto-assigned rules it has to beat",
			ProbeRulePrefBase)
	}
	f := &fakeRunner{replies: map[string]string{
		"ip rule show": "0:\tfrom all lookup local\n" +
			"32762:\tfrom all fwmark 0x200 lookup 100\n" +
			"32763:\tfrom 10.99.0.2 lookup 100\n" +
			"32765:\tfrom all fwmark 0x101 lookup 101\n" +
			"32766:\tfrom all lookup main\n",
	}}
	p := model.PathConfig{ID: 1, Name: "main", Iface: "lo", Table: 101, Mark: 0x101}

	if err := EnsureProbeRoute(context.Background(), f, p, "10.99.0.1", "10.99.0.2"); err != nil {
		t.Fatalf("EnsureProbeRoute: %v", err)
	}
	if !f.ran("ip rule add fwmark 0x101 lookup 101 pref 30001") {
		t.Errorf("rule not installed at an explicit priority; calls were %v", f.calls)
	}
	// The old one has to go, or the upgrade keeps the ordering that caused it.
	if !f.ran("ip rule del fwmark 0x101 lookup 101 pref 32765") {
		t.Errorf("stale rule from an older build left in place; calls were %v", f.calls)
	}
}

// A rule already at the right priority must be left alone, or every reconcile
// tick churns the rule set.
func TestProbeRuleIsNotReinstalledWhenAlreadyCorrect(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"ip rule show": "30001:\tfrom all fwmark 0x101 lookup 101\n" +
			"31001:\tfrom all fwmark 0x101 unreachable\n" +
			"32766:\tfrom all lookup main\n",
	}}
	p := model.PathConfig{ID: 1, Name: "main", Iface: "lo", Table: 101, Mark: 0x101}

	if err := EnsureProbeRoute(context.Background(), f, p, "10.99.0.1", "10.99.0.2"); err != nil {
		t.Fatalf("EnsureProbeRoute: %v", err)
	}
	for _, c := range f.calls {
		if strings.HasPrefix(c, "ip rule") && !strings.HasPrefix(c, "ip rule show") {
			t.Errorf("touched a correct rule set: %s", c)
		}
	}
}

// A rule whose table has no route for the destination is skipped, and the
// lookup carries on to main. On the frontend main always has a default route
// out the public uplink, so a probe for a tunnel that did not exist yet was
// not refused: it left the datacentre addressed to a private address, and on
// a site with backend egress on it picked up a source NAT binding on the way.
// That binding belongs to the conntrack entry, and the prober keeps one socket
// for as long as sends succeed, so every probe it ever sent afterwards carried
// the public address down the tunnel and no reply ever came back. A frontend
// rebooted before wg-quick measured three dead paths until the service was
// restarted. The unreachable rule behind the lookup is what makes the probe
// fail instead, which is the behaviour the prober's hold path was written for.
func TestProbeMarkIsRefusedRatherThanFallingThroughToMain(t *testing.T) {
	if ProbeDenyRulePrefBase <= EgressRulePref {
		t.Fatalf("deny band %d is not behind the lookup band at %d and the egress rule at %d",
			ProbeDenyRulePrefBase, ProbeRulePrefBase, EgressRulePref)
	}
	if ProbeDenyRulePrefBase >= OverlayLocalRulePref || ProbeDenyRulePrefBase >= ReturnRulePrefBase {
		t.Fatalf("deny band %d sits behind the source rules, which would route a marked packet first",
			ProbeDenyRulePrefBase)
	}
	f := &fakeRunner{replies: map[string]string{
		"ip rule show": "0:\tfrom all lookup local\n32766:\tfrom all lookup main\n",
	}}
	paths := []model.PathConfig{
		// An interface that cannot exist, which is the case this guards: the
		// rules go in now, and the route waits for the reconciler.
		{ID: 1, Name: "main", Iface: "wg-does-not-exist-here", Table: 101, Mark: 0x101},
	}
	err := EnsureProbeRoutes(context.Background(), f, paths, "10.99.0.2", "10.99.0.1")
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("a missing tunnel must still be reported, got %v", err)
	}
	add := f.index("ip rule add fwmark 0x101 lookup 101 pref 30001")
	deny := f.index("ip rule add fwmark 0x101 unreachable pref 31001")
	if add < 0 || deny < 0 {
		t.Fatalf("rules not installed without the interface; calls were %v", f.calls)
	}
	if add > deny {
		t.Errorf("the lookup must be in place before the refusal behind it; calls were %v", f.calls)
	}
	if f.ran("ip route replace") {
		t.Errorf("a route was installed on an interface that does not exist: %v", f.calls)
	}
}

// A refusal at the wrong priority inside the band - a path renumbered from id
// 3 to id 1 - is swept like every other pinned rule here. The pinned one goes
// in before the stray comes out, so there is no moment with no refusal.
func TestProbeUnreachableRuleIsMovedToItsPinnedPriority(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"ip rule show": "30001:\tfrom all fwmark 0x101 lookup 101\n" +
			"31003:\tfrom all fwmark 0x101 unreachable\n" +
			"32766:\tfrom all lookup main\n",
	}}
	p := model.PathConfig{ID: 1, Name: "main", Iface: "lo", Table: 101, Mark: 0x101}
	if err := EnsureProbeRoute(context.Background(), f, p, "10.99.0.1", "10.99.0.2"); err != nil {
		t.Fatalf("EnsureProbeRoute: %v", err)
	}
	add := f.index("ip rule add fwmark 0x101 unreachable pref 31001")
	del := f.index("ip rule del fwmark 0x101 unreachable pref 31003")
	if add < 0 || del < 0 {
		t.Fatalf("stray refusal not moved; calls were %v", f.calls)
	}
	if add > del {
		t.Errorf("the stray was removed before its replacement existed; calls were %v", f.calls)
	}
	if f.ran("ip rule del fwmark 0x101 lookup 101") {
		t.Errorf("the lookup rule was correct and must not be touched: %v", f.calls)
	}
}

// A refusal is keyed to a mark, and a mark can change: edited in the portal,
// or the shipped defaults a backend runs on until its first push. Unlike an
// orphaned lookup rule, which selects an empty table and does nothing, an
// orphaned refusal blackholes that mark for good - so anything in the band
// whose mark no path carries is swept on every apply.
func TestProbeRefusalForAMarkNoPathCarriesIsSwept(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"ip rule show": "30001:\tfrom all fwmark 0x111 lookup 101\n" +
			"31001:\tfrom all fwmark 0x101 unreachable\n" + // the mark before the edit
			"31001:\tfrom all fwmark 0x111 unreachable\n" +
			"32766:\tfrom all lookup main\n",
	}}
	paths := []model.PathConfig{{ID: 1, Name: "main", Iface: "wg-none-such", Table: 101, Mark: 0x111}}
	_ = EnsureProbeRoutes(context.Background(), f, paths, "10.99.0.2", "10.99.0.1")
	if !f.ran("ip rule del fwmark 0x101 unreachable pref 31001") {
		t.Errorf("the refusal for the old mark was left behind: %v", f.calls)
	}
	if f.ran("ip rule del fwmark 0x111") || f.ran("ip rule add fwmark 0x111 unreachable") {
		t.Errorf("the current mark's refusal was correct and must not be touched: %v", f.calls)
	}
}

// The band is the ownership line. A fwmark is only a number, and a host that
// already policy-routes may refuse on the same value for its own reasons, so a
// `fwmark ... unreachable` outside the band is neither "already installed" nor
// a stray: ensure still installs its own, and revert leaves the host's alone.
func TestAHostsOwnRefusalOutsideTheBandIsNeverTouched(t *testing.T) {
	listing := "5000:\tfrom all fwmark 0x101 unreachable\n" + // the host's
		"30001:\tfrom all fwmark 0x101 lookup 101\n" +
		"32766:\tfrom all lookup main\n"
	f := &fakeRunner{replies: map[string]string{"ip rule show": listing}}
	p := model.PathConfig{ID: 1, Name: "main", Iface: "lo", Table: 101, Mark: 0x101}
	if err := EnsureProbeRoute(context.Background(), f, p, "10.99.0.1", "10.99.0.2"); err != nil {
		t.Fatalf("EnsureProbeRoute: %v", err)
	}
	if !f.ran("ip rule add fwmark 0x101 unreachable pref 31001") {
		t.Errorf("the host's rule was mistaken for ours; calls were %v", f.calls)
	}
	if f.ran("pref 5000") {
		t.Errorf("a rule outside the band was touched: %v", f.calls)
	}

	g := &fakeRunner{replies: map[string]string{"ip rule show": listing +
		"31001:\tfrom all fwmark 0x101 unreachable\n"}}
	RemoveProbeRoutes(context.Background(), g, []model.PathConfig{p}, "10.99.0.2/32", "10.99.0.0/24")
	if !g.ran("ip rule del fwmark 0x101 unreachable pref 31001") {
		t.Errorf("revert left our refusal behind: %v", g.calls)
	}
	if g.ran("pref 5000") {
		t.Errorf("revert removed a rule the agent never installed: %v", g.calls)
	}
}

// And the revert clears the whole band, not only the configured marks: a mark
// changed while the agent was stopped has had no apply to sweep it, and every
// rule in the band is this system's. Left behind, a refusal blackholes every
// packet carrying its mark on a host that has just uninstalled this system.
func TestRemoveProbeRoutesClearsTheDenyBand(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"ip rule show": "30001:\tfrom all fwmark 0x101 lookup 101\n" +
			"31001:\tfrom all fwmark 0x101 unreachable\n" +
			"31002:\tfrom all fwmark 0x102 unreachable\n", // a path no longer configured
	}}
	RemoveProbeRoutes(context.Background(), f,
		[]model.PathConfig{{ID: 1, Name: "main", Iface: "wg-main", Table: 101, Mark: 0x101}},
		"10.99.0.2/32", "10.99.0.0/24")
	for _, want := range []string{
		"ip rule del fwmark 0x101 unreachable pref 31001",
		"ip rule del fwmark 0x102 unreachable pref 31002",
	} {
		if !f.ran(want) {
			t.Errorf("revert left %q behind: %v", want, f.calls)
		}
	}
}

// rp_filter belongs to the interface, not to its name. `wg-quick down` deletes
// the device and `up` creates a new one, which inherits
// net.ipv4.conf.default.rp_filter - systemd ships that as 2 - rather than the
// zero the agent set on the device it replaced. Every probe arriving on the
// recreated tunnel is then dropped below the socket, so the interface counters
// show packets arriving and no replies leaving and the path reads as 100% loss
// with a perfectly healthy WireGuard handshake.
func TestRPFilterIsDisabledAgainAfterATunnelIsRecreated(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"sysctl -n net.ipv4.conf.wg-main.rp_filter": "2\n",
	}}
	changed, err := RPFilterOff(context.Background(), f, "wg-main")
	if err != nil || !changed {
		t.Fatalf("RPFilterOff = %v, %v; want it to report a change", changed, err)
	}
	if !f.ran("sysctl -w net.ipv4.conf.wg-main.rp_filter=0") {
		t.Errorf("filtering not disabled; calls were %v", f.calls)
	}

	// Already off: it must not write, or it does so on every tick forever.
	g := &fakeRunner{replies: map[string]string{
		"sysctl -n net.ipv4.conf.wg-main.rp_filter": "0\n",
	}}
	if changed, err := RPFilterOff(context.Background(), g, "wg-main"); err != nil || changed {
		t.Errorf("RPFilterOff = %v, %v; want no change when it is already off", changed, err)
	}
	if g.ran("sysctl -w") {
		t.Errorf("wrote to an already-correct sysctl: %v", g.calls)
	}
}

// index reports where a command first appears, or -1. Used where the *order*
// of two commands is the thing being asserted.
func (f *fakeRunner) index(substr string) int {
	for i, c := range f.calls {
		if strings.Contains(c, substr) {
			return i
		}
	}
	return -1
}

// A routing table's number is what selects it; its name is only how it prints.
// Wherever /etc/iproute2/rt_tables gives a table a name - `isp2` on an entirely
// ordinary dual-ISP box - `ip rule show` prints that name, and every readback
// that grepped for "lookup 101" went blind. The agent could then not recognise
// the rule it installed seconds earlier: it re-added it on every tick, logged
// "File exists" forever, and because a failed add is fatal for the whole batch
// the paths after it never got rules at all.
func TestProbeRuleIsFoundWhenTheTableHasAName(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		// What the kernel prints once the operator has named table 101.
		"ip rule show table 101": "30001:\tfrom all fwmark 0x101 lookup isp2\n",
		"ip rule show": "30001:\tfrom all fwmark 0x101 lookup isp2\n" +
			"31001:\tfrom all fwmark 0x101 unreachable\n",
	}}
	p := model.PathConfig{ID: 1, Name: "main", Iface: "lo", Table: 101, Mark: 0x101}

	if err := EnsureProbeRoute(context.Background(), f, p, "10.99.0.1", "10.99.0.2"); err != nil {
		t.Fatalf("EnsureProbeRoute: %v", err)
	}
	for _, c := range f.calls {
		if strings.HasPrefix(c, "ip rule add") || strings.HasPrefix(c, "ip rule del") {
			t.Errorf("an aliased table name hid the agent's own rule: %s (calls %v)", c, f.calls)
		}
	}
	// And it must have asked the kernel by number, which is the only form the
	// alias cannot affect.
	if !f.ran("ip rule show table 101") {
		t.Errorf("rules were not read back by table number; calls were %v", f.calls)
	}
}

// The same for the two rules that select table 100.
func TestTableOneHundredRulesAreFoundWhenTheTableHasAName(t *testing.T) {
	named := "29999:\tfrom all fwmark 0x100 lookup uplink\n"
	f := &fakeRunner{replies: map[string]string{"ip rule show table 100": named}}
	if err := EnsureControlRoute(context.Background(), f, "10.99.0.2/32", "10.99.0.2", "10.99.0.1", "wg-main"); err != nil {
		t.Fatalf("EnsureControlRoute: %v", err)
	}
	if f.ran("ip rule add") {
		t.Errorf("control rule re-added because the table has a name; calls were %v", f.calls)
	}

	g := &fakeRunner{replies: map[string]string{
		"ip rule show table 100": "29998:\tfrom all fwmark 0x200 lookup uplink\n",
	}}
	if err := EnsureReturnMarkRule(context.Background(), g); err != nil {
		t.Fatalf("EnsureReturnMarkRule: %v", err)
	}
	if g.ran("ip rule add") {
		t.Errorf("return mark rule re-added because the table has a name; calls were %v", g.calls)
	}
}

// Every rule this system installs carries an explicit priority. `ip rule add`
// without one takes the first existing rule's priority minus one, so each rule
// added lands ahead of the last and the ordering depends on installation
// sequence rather than on anything anybody decided. That has already caused
// this bug twice - once for the path rules, once for the source return rule -
// and these two were still being added without one.
//
// The values keep both rules exactly where the kernel had been putting them,
// immediately ahead of the probe band: nothing sits between them and 30001, so
// pinning changes no ordering on a running host. It only stops the ordering
// being an accident.
func TestControlAndReturnMarkRulesCarryAnExplicitPriority(t *testing.T) {
	if ControlRulePref >= ProbeRulePrefBase || ReturnMarkRulePref >= ProbeRulePrefBase {
		t.Fatalf("control %d and return-mark %d must stay ahead of the probe band at %d, "+
			"which is where the kernel was placing them",
			ControlRulePref, ReturnMarkRulePref, ProbeRulePrefBase)
	}
	if ControlRulePref == ReturnMarkRulePref {
		t.Errorf("two rules pinned to the same priority %d", ControlRulePref)
	}

	f := &fakeRunner{replies: map[string]string{"ip rule show table 100": ""}}
	if err := EnsureControlRoute(context.Background(), f, "10.99.0.2/32", "10.99.0.2", "10.99.0.1", "wg-main"); err != nil {
		t.Fatalf("EnsureControlRoute: %v", err)
	}
	want := "ip rule add fwmark 0x100 lookup 100 pref " + strconv.Itoa(ControlRulePref)
	if !f.ran(want) {
		t.Errorf("control rule added without a priority; calls were %v", f.calls)
	}

	g := &fakeRunner{replies: map[string]string{"ip rule show table 100": ""}}
	if err := EnsureReturnMarkRule(context.Background(), g); err != nil {
		t.Fatalf("EnsureReturnMarkRule: %v", err)
	}
	want = "ip rule add fwmark 0x200 lookup 100 pref " + strconv.Itoa(ReturnMarkRulePref)
	if !g.ran(want) {
		t.Errorf("return mark rule added without a priority; calls were %v", g.calls)
	}
}

// Moving a rule to its pinned priority must add before it deletes.
//
// The gap matters on an upgrade, which is the only time this runs: with no rule
// at all, a marked packet matches nothing and falls through to main - and in
// observe mode main has no route to the backend, so the control channel drops
// for as long as the two commands take. The same window on a probe rule is
// worse than a missing measurement: the probe follows the single active route
// and silently measures a different tunnel.
func TestMovingARuleAddsBeforeItDeletes(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"ip rule show table 100": "30000:\tfrom all fwmark 0x100 lookup 100\n",
	}}
	if err := EnsureControlRoute(context.Background(), f, "10.99.0.2/32", "10.99.0.2", "10.99.0.1", "wg-main"); err != nil {
		t.Fatalf("EnsureControlRoute: %v", err)
	}
	add := f.index("ip rule add fwmark 0x100 lookup 100 pref " + strconv.Itoa(ControlRulePref))
	del := f.index("ip rule del fwmark 0x100 lookup 100 pref 30000")
	if add < 0 || del < 0 {
		t.Fatalf("expected the rule to be moved; calls were %v", f.calls)
	}
	if add > del {
		t.Errorf("the old rule was removed before the new one existed; calls were %v", f.calls)
	}

	g := &fakeRunner{replies: map[string]string{
		"ip rule show table 101": "32765:\tfrom all fwmark 0x101 lookup 101\n",
	}}
	p := model.PathConfig{ID: 1, Name: "main", Iface: "lo", Table: 101, Mark: 0x101}
	if err := EnsureProbeRoute(context.Background(), g, p, "10.99.0.1", "10.99.0.2"); err != nil {
		t.Fatalf("EnsureProbeRoute: %v", err)
	}
	add = g.index("ip rule add fwmark 0x101 lookup 101 pref 30001")
	del = g.index("ip rule del fwmark 0x101 lookup 101 pref 32765")
	if add < 0 || del < 0 {
		t.Fatalf("expected the probe rule to be moved; calls were %v", g.calls)
	}
	if add > del {
		t.Errorf("the old probe rule was removed before the new one existed; calls were %v", g.calls)
	}

	// The source-based return rule moves the same way. Its gap is worse than a
	// wrong measurement: with no rule at all, a reply sourced from the overlay
	// address falls through to main and leaves by the LAN to pfSense, which is
	// a dropped reply to a real client for as long as the two commands take.
	h := &fakeRunner{replies: map[string]string{
		"ip rule show table 100": "30000:\tfrom 10.99.0.2 lookup 100\n",
	}}
	if err := EnsureReturnRule(context.Background(), h, "10.99.0.2"); err != nil {
		t.Fatalf("EnsureReturnRule: %v", err)
	}
	add = h.index("ip rule add from 10.99.0.2 lookup 100 pref " + strconv.Itoa(ReturnRulePrefBase))
	del = h.index("ip rule del from 10.99.0.2 lookup 100 pref 30000")
	if add < 0 || del < 0 {
		t.Fatalf("expected the return rule to be moved; calls were %v", h.calls)
	}
	if add > del {
		t.Errorf("the old return rule was removed before the new one existed; calls were %v", h.calls)
	}
}

// The probe tables go the same way the control table does: by name.
//
// 101 to 103 are numbers this system picked, not property it owns. A host that
// already policy-routes may keep its own entries in them, and `ip route flush`
// would take those with it while the revert reported success. Invariant 8, and
// what uninstall.sh promises in as many words.
func TestRemoveProbeRoutesNeverFlushesATable(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"ip rule show table 101": "30001:\tfrom all fwmark 0x101 lookup 101\n",
		"ip rule show table 102": "30002:\tfrom all fwmark 0x102 lookup 102\n",
	}}
	paths := []model.PathConfig{
		{ID: 1, Name: "main", Iface: "wg-main", Table: 101, Mark: 0x101},
		{ID: 2, Name: "lte1", Iface: "wg-lte1", Table: 102, Mark: 0x102},
	}
	RemoveProbeRoutes(context.Background(), f, paths, "10.99.0.2/32", "10.99.0.0/24")

	for _, c := range f.calls {
		if strings.Contains(c, "route flush") {
			t.Errorf("revert flushed a table it does not own: %s", c)
		}
	}
	for _, want := range []string{
		"ip route del 10.99.0.2/32 table 101",
		"ip route del 10.99.0.2/32 table 102",
		"ip rule del fwmark 0x101 lookup 101 pref 30001",
		"ip rule del fwmark 0x102 lookup 102 pref 30002",
		// The main-table route, at whatever width it was installed.
		"ip route del 10.99.0.0/24",
	} {
		if !f.ran(want) {
			t.Errorf("revert left %q behind, calls were %v", want, f.calls)
		}
	}
}

// The two prefixes are not interchangeable. A probe table always holds the far
// end's /32 however wide the main-table route has become, so a revert that
// passed the data prefix to both would ask the kernel to delete a range from a
// table that holds a host route, and leave the host route there. Invariant 20.
func TestRemoveProbeRoutesUsesTheProbePrefixInTheProbeTable(t *testing.T) {
	f := &fakeRunner{}
	RemoveProbeRoutes(context.Background(), f,
		[]model.PathConfig{{ID: 1, Name: "main", Iface: "wg-main", Table: 101, Mark: 0x101}},
		"10.99.0.2/32", "10.99.0.0/24")

	if f.ran("ip route del 10.99.0.0/24 table 101") {
		t.Errorf("the overlay range was never installed in a probe table: %v", f.calls)
	}
	if !f.ran("ip route del 10.99.0.2/32 table 101") {
		t.Errorf("the probe route was not removed by name: %v", f.calls)
	}
}

// The egress lookup fails open exactly as the probe lookups did, with a worse
// consequence: with the active tunnel deleted, table 100 has no default and a
// marked container packet goes out the LAN to pfSense, where Docker's
// masquerade gives it the house's address - and that binding follows the flow
// down the tunnel once it is back, where the frontend's NAT does not match it.
// A heartbeat sent in the gap also lists the server at the house's address,
// the one thing the feature exists to prevent. So the lookup carries a refusal
// behind it, pinned, owned by its priority alone, and removed with the lookup.
func TestEgressRuleFailsClosed(t *testing.T) {
	if EgressDenyRulePref <= EgressRulePref || EgressDenyRulePref >= OverlayLocalRulePref {
		t.Fatalf("egress refusal at %d is not between its lookup at %d and the source rules at %d",
			EgressDenyRulePref, EgressRulePref, OverlayLocalRulePref)
	}
	if inProbeDenyBand(EgressDenyRulePref) {
		t.Fatalf("egress refusal at %d sits inside the per-path band and would be swept as an orphan",
			EgressDenyRulePref)
	}
	f := &fakeRunner{replies: map[string]string{
		"ip rule show": "30100:\tfrom all fwmark 0x300 lookup 100\n" +
			"5000:\tfrom all fwmark 0x300 unreachable\n", // the host's own
	}}
	if err := EnsureEgressRule(context.Background(), f); err != nil {
		t.Fatalf("EnsureEgressRule: %v", err)
	}
	if !f.ran("ip rule add fwmark 0x300 unreachable pref " + strconv.Itoa(EgressDenyRulePref)) {
		t.Errorf("no refusal behind the egress lookup; calls were %v", f.calls)
	}
	if f.ran("pref 5000") {
		t.Errorf("a refusal the host installed was touched: %v", f.calls)
	}

	intact := "30100:\tfrom all fwmark 0x300 lookup 100\n" +
		strconv.Itoa(EgressDenyRulePref) + ":\tfrom all fwmark 0x300 unreachable\n"
	g := &fakeRunner{replies: map[string]string{"ip rule show": intact}}
	if err := EnsureEgressRule(context.Background(), g); err != nil {
		t.Fatalf("EnsureEgressRule: %v", err)
	}
	for _, c := range g.calls {
		if strings.Contains(c, " add ") || strings.Contains(c, " del ") {
			t.Errorf("an intact rule set was rewritten: %s", c)
		}
	}

	h := &fakeRunner{replies: map[string]string{"ip rule show": intact}}
	RemoveEgressRule(context.Background(), h)
	for _, want := range []string{
		"ip rule del fwmark 0x300 lookup 100 pref 30100",
		"ip rule del fwmark 0x300 unreachable pref " + strconv.Itoa(EgressDenyRulePref),
	} {
		if !h.ran(want) {
			t.Errorf("%q left behind: %v", want, h.calls)
		}
	}
}
