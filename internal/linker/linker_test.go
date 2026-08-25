package linker

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/sysx"
)

// fakeRunner records every command and answers reads from a canned table.
//
// fails makes a matching command return an error, which is how a load the
// kernel refused is staged: the retry paths exist for exactly that and cannot
// be reached by leaving a reply out.
type fakeRunner struct {
	replies map[string]string
	fails   []string
	calls   []string
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	cmd := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, cmd)
	for _, bad := range f.fails {
		if strings.Contains(cmd, bad) {
			return "", errors.New("refused: " + bad)
		}
	}
	if out, ok := f.replies[cmd]; ok {
		return out, nil
	}
	return "", nil
}

func (f *fakeRunner) Applying() bool { return true }

// index reports the position of the first call containing substr, or -1.
func (f *fakeRunner) index(substr string) int {
	for i, c := range f.calls {
		if strings.Contains(c, substr) {
			return i
		}
	}
	return -1
}

func (f *fakeRunner) ran(substr string) bool {
	for _, c := range f.calls {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

func (f *fakeRunner) writes() []string {
	var w []string
	for _, c := range f.calls {
		if strings.Contains(c, " add ") || strings.Contains(c, " replace ") ||
			strings.Contains(c, " del ") || strings.Contains(c, " flush ") ||
			strings.Contains(c, "sysctl -w") {
			w = append(w, c)
		}
	}
	return w
}

func testLinker(t *testing.T, f *fakeRunner) *Linker {
	t.Helper()
	boot := model.Bootstrap{
		Role: model.RoleLinker,
		Overlay: model.OverlayConfig{
			FrontendIP: "10.99.0.1", BackendIP: "10.99.0.2",
			Subnet: "10.99.0.0/24", Device: "dummy0",
		},
		Linker: model.LinkerInfo{OverlayIP: "10.99.0.3", BackendLAN: "192.168.1.2"},

		// A real bootstrap gets /var/lib/failover from LoadBootstrap; this one
		// is built by hand and skips that, and the ruleset writer joins the
		// state dir with a file name. Left empty it writes the generated
		// linker-return.nft into the package directory on every `go test`,
		// which is how a copy of it ended up committed to the repo.
		StateDir: t.TempDir(),
	}
	return &Linker{
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		boot:   boot,
		runner: f,
	}
}

// An intact linker must be left completely alone. A reconciler that rewrites
// working state every ten seconds hides the one log line that matters when
// something has actually gone.
func TestReconcileChangesNothingWhenTheKernelAgrees(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"ip -o addr show": "5: dummy0    inet 10.99.0.3/32 scope global dummy0",
		"ip rule show table 200": "32400: from 10.99.0.3 lookup 200\n" +
			"32401: from all fwmark 0x201 lookup 200",
		"ip rule show": "0: from all lookup local\n" +
			"32400: from 10.99.0.3 lookup 200\n" +
			"32401: from all fwmark 0x201 lookup 200\n" +
			"32766: from all lookup main",
		"ip route show default table 200":       "default via 192.168.1.2 dev eth0",
		"sysctl -n net.ipv4.conf.all.rp_filter": "0",
	}}
	l := testLinker(t, f)
	l.reconcile(context.Background())

	if w := f.writes(); len(w) != 0 {
		t.Fatalf("reconcile touched an intact system: %v", w)
	}
}

// The route points at a neighbour rather than a device, so the kernel drops it
// when the LAN interface bounces and nothing else would ever put it back. This
// is the case the reconciler exists for.
func TestReconcileRestoresTheRouteLostWithTheInterface(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"ip -o addr show":                 "5: dummy0    inet 10.99.0.3/32 scope global dummy0",
		"ip rule show table 200":          "32764: from 10.99.0.3 lookup 200",
		"ip route show default table 200": "", // gone with the interface
	}}
	l := testLinker(t, f)
	l.reconcile(context.Background())

	want := "ip route replace default via 192.168.1.2 table 200"
	var found bool
	for _, c := range f.writes() {
		if c == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("reconcile should reinstall the overlay route, writes were %v", f.writes())
	}
}

// A route pointing somewhere else is worse than a missing one: traffic leaves,
// and goes to a host that will not put it on a tunnel.
func TestReconcileCorrectsARouteToTheWrongNeighbour(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"ip -o addr show":                 "5: dummy0    inet 10.99.0.3/32 scope global dummy0",
		"ip rule show table 200":          "32764: from 10.99.0.3 lookup 200",
		"ip route show default table 200": "default via 192.168.1.99 dev eth0",
	}}
	l := testLinker(t, f)
	l.reconcile(context.Background())

	if len(f.writes()) == 0 {
		t.Fatal("reconcile should correct a route pointing at the wrong neighbour")
	}
}

// The rule is what makes the address useful. Without it everything the host
// sends from the overlay address leaves by the LAN default route, which reaches
// the internet perfectly well and from an address no client is expecting.
func TestReconcileRestoresAMissingPolicyRule(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"ip -o addr show":                 "5: dummy0    inet 10.99.0.3/32 scope global dummy0",
		"ip rule show table 200":          "",
		"ip route show default table 200": "default via 192.168.1.2 dev eth0",
	}}
	l := testLinker(t, f)
	l.reconcile(context.Background())

	// With its priority, which is part of the contract rather than incidental:
	// an unpinned rule lands wherever the kernel puts it relative to whatever
	// was added last, and the mark rule beside it is the second rule that makes
	// that matter.
	want := "ip rule add from 10.99.0.3 lookup 200 pref 32400"
	var found bool
	for _, c := range f.writes() {
		if c == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("reconcile should reinstall the policy rule, writes were %v", f.writes())
	}
}

// Revert takes down the routing and leaves the address. A service may still be
// bound to it, and removing an address out from under a listening process turns
// a routing change into a crash.
func TestRevertLeavesTheOverlayAddressAlone(t *testing.T) {
	f := &fakeRunner{}
	testLinker(t, f).Revert(context.Background())

	joined := strings.Join(f.calls, " | ")
	if !strings.Contains(joined, "ip rule del from 10.99.0.3 lookup 200") {
		t.Errorf("revert should remove the policy rule, calls were %v", f.calls)
	}
	// By name, never a flush. The table number belongs to the host and not to
	// this system: the first real deployment landed on a machine already using
	// 200 for a second ISP, and a flush would have deleted that machine's own
	// routing while reporting a clean revert.
	// Qualified by the gateway: on a host that had its own default in this
	// table, an unqualified delete would take that one instead.
	if !strings.Contains(joined, "ip route del default via 192.168.1.2 table 200") {
		t.Errorf("revert should remove the default route it installed, calls were %v", f.calls)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "route flush") {
			t.Errorf("revert flushed a table it does not own: %s", c)
		}
	}
	if strings.Contains(joined, "addr del") || strings.Contains(joined, "link delete") {
		t.Errorf("revert must not remove the overlay address: %v", f.calls)
	}
}

// Reverse-path filtering is reported, never changed. The other two agents turn
// it off because their tunnels carry no address and it is broken there by
// construction; a linker has an ordinary interface, and silently changing a
// system-wide sysctl on somebody's server is not this agent's call.
func TestApplyNeverWritesRPFilter(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"sysctl -n net.ipv4.conf.all.rp_filter": "2",
	}}
	l := testLinker(t, f)
	l.apply(context.Background())

	for _, c := range f.calls {
		if strings.Contains(c, "sysctl -w") {
			t.Fatalf("the linker must not change sysctls, got %q", c)
		}
	}
}

// A linker loads exactly one nftables table, its own, and it contains no NAT.
//
// It used to load none at all, which was true while only host services could be
// published here. A container cannot bind the overlay address, so its replies
// have to be found by connection mark instead - but the marking table must stay
// the linker's own and stay free of address translation, because a source
// rewrite here would destroy the real client addresses that surviving two hops
// of DNAT was the whole point of.
func TestLinkerLoadsOnlyItsOwnMarkingTable(t *testing.T) {
	f := &fakeRunner{}
	l := testLinker(t, f)
	l.apply(context.Background())
	l.reconcile(context.Background())

	for _, c := range f.calls {
		if !strings.HasPrefix(c, "nft ") {
			continue
		}
		if !strings.Contains(c, "linker-return.nft") {
			t.Fatalf("the linker touched an nftables table that is not its own: %q", c)
		}
	}
	ruleset := sysx.BuildLinkerReturnRuleset("10.99.0.3")
	for _, banned := range []string{"masquerade", "snat", "dnat"} {
		if strings.Contains(ruleset, banned) {
			t.Fatalf("the linker's table must never translate addresses, found %q in:\n%s", banned, ruleset)
		}
	}
}

// The mark has to be matched while the overlay address is still on the packet.
// nftables runs prerouting hooks in priority order and dstnat sits at -100, so
// marking at mangle (-150) sees the destination before Docker rewrites it.
// Marking any later would match the container's address instead, which is the
// thing being worked around.
func TestLinkerMarksBeforeDestinationNAT(t *testing.T) {
	ruleset := sysx.BuildLinkerReturnRuleset("10.99.0.3")
	if !strings.Contains(ruleset, "hook prerouting priority mangle") {
		t.Fatalf("marking must happen at mangle priority, got:\n%s", ruleset)
	}
	if !strings.Contains(ruleset, "ip daddr 10.99.0.3 ct direction original") {
		t.Fatalf("only connections addressed here, and only in the original direction:\n%s", ruleset)
	}
}

// Without `ct direction original` this also stamps the replies to connections
// the host started from its own overlay address - which arrive addressed to it -
// and those would be routed to the backend instead of delivered to the process
// waiting here.
func TestLinkerMarksOnlyTheOriginalDirection(t *testing.T) {
	ruleset := sysx.BuildLinkerReturnRuleset("10.99.0.3")
	for _, line := range strings.Split(ruleset, "\n") {
		if strings.Contains(line, "ct mark set") && !strings.Contains(line, "ct direction original") {
			t.Fatalf("a mark is set without restricting to the original direction: %q", line)
		}
	}
}

// The table has to stay clear of the ones the other agents use, or a host that
// is both would have two agents writing the same table.
func TestLinkerTableDoesNotCollide(t *testing.T) {
	if sysx.LinkerTable == sysx.ReturnTable || sysx.LinkerTable == sysx.ControlTable {
		t.Fatalf("linker table %d collides with an existing table", sysx.LinkerTable)
	}
	for _, p := range model.Defaults().Paths {
		if p.Table == sysx.LinkerTable {
			t.Fatalf("linker table %d collides with path %s", sysx.LinkerTable, p.Name)
		}
	}
}

// `ip rule show` prints a routing table's *name* wherever /etc/iproute2/rt_tables
// gives it one. A host that called table 200 "isp2" - an ordinary dual-ISP
// setup - made every `lookup 200` comparison in the agent fail, so it could not
// recognise rules it had installed seconds earlier and re-added them on every
// tick forever, logging "File exists" each time. The listing is now filtered by
// the kernel, which cannot be fooled by the name.
func TestRulesAreRecognisedWhenTheTableHasAName(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"ip -o addr show": "5: dummy0    inet 10.99.0.3/32 scope global dummy0",
		// exactly what the kernel prints on such a host
		"ip rule show table 200": "32400:\tfrom 10.99.0.3 lookup isp2\n" +
			"32401:\tfrom all fwmark 0x201 lookup isp2",
		"ip rule show": "0:\tfrom all lookup local\n" +
			"32400:\tfrom 10.99.0.3 lookup isp2\n" +
			"32401:\tfrom all fwmark 0x201 lookup isp2\n" +
			"32766:\tfrom all lookup main",
		"ip route show default table 200":       "default via 192.168.1.2 dev eth0",
		"sysctl -n net.ipv4.conf.all.rp_filter": "0",
	}}
	l := testLinker(t, f)
	l.reconcile(context.Background())

	for _, c := range f.writes() {
		if strings.Contains(c, "ip rule add") {
			t.Errorf("re-added a rule that was already installed under a table alias: %q", c)
		}
	}
}

// A rule left behind by an older build, or by the table being changed in the
// portal, points at a table this agent no longer uses - and because it is
// matched on source exactly like the current one, a lower priority makes it win
// silently. On the host this was found on it sat at priority 0, ahead of
// everything, sending the control channel out a second ISP instead of to the
// backend. Published traffic kept working the whole time, because that is
// inbound and never matches a source rule.
func TestStaleSourceRulesInOtherTablesAreRemoved(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"ip -o addr show":        "5: dummy0    inet 10.99.0.3/32 scope global dummy0",
		"ip rule show table 200": "32400:\tfrom 10.99.0.3 lookup 200",
		// the old build's unpinned rule landed at 0, ahead of everything
		"ip rule show": "0:\tfrom all lookup local\n" +
			"0:\tfrom 10.99.0.3 lookup isp2\n" +
			"1:\tfrom 10.100.1.4 lookup isp2\n" +
			"32400:\tfrom 10.99.0.3 lookup 200\n" +
			"32766:\tfrom all lookup main",
		"ip route show default table 200":       "default via 192.168.1.2 dev eth0",
		"sysctl -n net.ipv4.conf.all.rp_filter": "0",
	}}
	l := testLinker(t, f)
	l.reconcile(context.Background())

	// Deleted with the table token as the kernel printed it, and with the full
	// selector: `ip rule del pref 0` alone would match the local table's rule,
	// which shares that priority, and take the host's address resolution away.
	want := "ip rule del from 10.99.0.3 lookup isp2 pref 0"
	var found bool
	for _, c := range f.writes() {
		if c == want {
			found = true
		}
		if strings.Contains(c, "10.100.1.4") {
			t.Errorf("touched a rule belonging to the operator: %q", c)
		}
		if c == "ip rule del pref 0" {
			t.Errorf("deleted by priority alone, which would take the local table's rule: %q", c)
		}
	}
	if !found {
		t.Errorf("the stale rule was not removed; writes were %v", f.writes())
	}
	// The correct rule is already in place and must not be re-added.
	for _, c := range f.writes() {
		if strings.Contains(c, "ip rule add from 10.99.0.3") {
			t.Errorf("re-added a rule that was already correct: %q", c)
		}
	}
}

// An egress install the kernel refused must not be remembered as a success.
//
// The list used to be recorded as applied before `nft -f` had even run, so a
// failure left the agent believing the networks were on the overlay when they
// were not - and because the frontend pushes once per configuration version,
// nothing ever tried again. The ordinary way in is a boot where the LAN
// interface is not up yet, so there is no route to the backend and no interface
// to scope the source NAT to.
func TestAFailedEgressInstallIsRetriedRatherThanRemembered(t *testing.T) {
	// No route to the backend: `ip route get` answers nothing.
	f := &fakeRunner{replies: map[string]string{}}
	l := testLinker(t, f)

	l.applyEgress(context.Background(), []string{"172.18.0.0/16"})
	if f.ran("linker-egress.nft") {
		t.Errorf("a ruleset was loaded with no interface to scope it to; calls were %v", f.calls)
	}
	if l.egressOK {
		t.Error("a failed install was recorded as applied, so nothing would ever retry it")
	}

	// The LAN comes up. The next reconcile tick has to put this right on its
	// own: the frontend has nothing more to say.
	f.replies["ip route get 192.168.1.2"] = "192.168.1.2 dev eth0 src 192.168.1.50 uid 0"
	f.calls = nil
	l.reconcile(context.Background())

	if !f.ran("linker-egress.nft") {
		t.Errorf("reconcile did not retry the failed egress install; calls were %v", f.calls)
	}
	if !f.ran("ip rule add fwmark 0x301") {
		t.Errorf("the egress mark rule was not installed on retry; calls were %v", f.calls)
	}
	if !l.egressOK {
		t.Error("a successful retry was not recorded, so it will run again every tick")
	}

	// Rules before the ruleset, as on the backend. The ruleset is what starts
	// marking packets, and a marked packet with no lookup rule and no refusal
	// behind it leaves by this host's own internet, where Docker's masquerade
	// binds the flow to that address for good. Loading the ruleset first
	// reopened that window on every boot and every retry.
	lookup, refusal, ruleset := f.index("ip rule add fwmark 0x301 lookup"), f.index("ip rule add fwmark 0x301 unreachable"), f.index("linker-egress.nft")
	if lookup < 0 || refusal < 0 || ruleset < 0 || lookup > ruleset || refusal > ruleset {
		t.Errorf("the ruleset was loaded before the rules that route what it marks; calls were %v", f.calls)
	}
}

// ...and once it has worked, it must stop. The frontend re-sends on every
// configuration version bump, including ones with nothing to do with this host,
// and reloading an nftables table drops the conntrack-independent state in it
// for no reason.
func TestAnUnchangedEgressPushCostsNothing(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"ip route get 192.168.1.2": "192.168.1.2 dev eth0 src 192.168.1.50 uid 0",
	}}
	l := testLinker(t, f)

	l.applyEgress(context.Background(), []string{"172.18.0.0/16"})
	if !f.ran("linker-egress.nft") {
		t.Fatalf("first push did not install anything; calls were %v", f.calls)
	}

	f.calls = nil
	l.applyEgress(context.Background(), []string{"172.18.0.0/16"})
	if len(f.calls) != 0 {
		t.Errorf("an identical push reinstalled the ruleset; calls were %v", f.calls)
	}

	f.calls = nil
	l.reconcile(context.Background())
	if f.ran("linker-egress.nft") {
		t.Errorf("reconcile reinstalled egress that was already applied; calls were %v", f.calls)
	}
}

// A host the frontend has never sent an egress list to must not have its egress
// rules touched at all - not even to remove them. Empty is the state every
// linker starts in, and "nothing configured" is a different instruction from
// "configured as nothing".
func TestReconcileLeavesEgressAloneUntilTheFrontendHasSpoken(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"ip route get 192.168.1.2": "192.168.1.2 dev eth0 src 192.168.1.50 uid 0",
	}}
	l := testLinker(t, f)

	l.reconcile(context.Background())
	for _, c := range f.calls {
		if strings.Contains(c, "failover_linker_egress") || strings.Contains(c, "0x301") {
			t.Errorf("touched egress before being told anything about it: %s", c)
		}
	}
}

// A push whose networks are all unusable is a fault, not an instruction, and
// leaves the working rules alone.
//
// The networks arrive over the wire, so this agent re-parses them rather than
// trusting that the far end validated anything - see sysx.EgressNetworks. What
// that leaves is a list which is not empty as sent and is empty as rendered,
// and the two cases mean different things: an empty list as sent is the
// feature turned off, while a list that parses to nothing is corruption. The
// backend's applyEgress already refuses the second (see
// TestAPushWithNoUsableNetworkDoesNotTearDownEgress in internal/agent), and
// for a while this agent read it as the first and took a working ruleset down
// - containers lost their tunnel egress and the server browser started
// advertising the house's address, silently, on the word of a push nothing
// honest produces. The refusal still must not half-install: no ruleset built,
// no mark rule in front of it, and no teardown either. And it is remembered
// as handled rather than retried, because the parse of a fixed list is
// deterministic and a retry every reconcile tick could only repeat the error
// line forever.
func TestAnUnusableEgressPushLeavesTheRulesAlone(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"ip route get 192.168.1.2": "192.168.1.2 dev eth0 src 192.168.1.50 uid 0",
	}}
	l := testLinker(t, f)

	l.applyEgress(context.Background(), []string{"172.18.0.0/16"})
	if !f.ran("linker-egress.nft") {
		t.Fatalf("first push did not install anything; calls were %v", f.calls)
	}

	f.calls = nil
	l.applyEgress(context.Background(), []string{"nonsense", "10.0.0.0/8 accept\n\tchain evil {"})

	if f.ran("linker-egress.nft") {
		t.Errorf("a ruleset was built from networks none of which parse; calls were %v", f.calls)
	}
	if f.ran("ip rule add fwmark 0x301") {
		t.Errorf("the mark rule went in with no ruleset behind it; calls were %v", f.calls)
	}
	if f.ran("delete table ip failover_linker_egress") {
		t.Errorf("a working egress ruleset was torn down on the word of an unusable push; calls were %v", f.calls)
	}

	f.calls = nil
	l.retryEgress(context.Background())
	if len(f.calls) != 0 {
		t.Errorf("an unusable push is deterministic and must not be retried; calls were %v", f.calls)
	}
}

// An empty push is the instruction the unusable one is not: the feature is
// off, and the rules come down.
func TestAnEmptyEgressPushRemovesTheRules(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"ip route get 192.168.1.2": "192.168.1.2 dev eth0 src 192.168.1.50 uid 0",
	}}
	l := testLinker(t, f)

	l.applyEgress(context.Background(), []string{"172.18.0.0/16"})
	if !f.ran("linker-egress.nft") {
		t.Fatalf("first push did not install anything; calls were %v", f.calls)
	}

	f.calls = nil
	l.applyEgress(context.Background(), nil)
	if !f.ran("delete table ip failover_linker_egress") {
		t.Errorf("an empty push must take the source NAT down; calls were %v", f.calls)
	}
}

// An egress install that would render no ruleset is a failure, not a success.
//
// The generators answer an address they cannot use by rendering nothing, and an
// empty file is one `nft -f` accepts. Passed on, it latches egressOK against a
// table that was never created, so retryEgress never looks again and the
// journal reports networks installed that are not. LoadBootstrap refuses the
// address that gets here, and this is the second lock on that door.
func TestAnEgressInstallThatRendersNothingIsNotRecordedAsApplied(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"ip route get 192.168.1.2": "192.168.1.2 dev eth0 src 192.168.1.50 uid 0",
	}}
	l := testLinker(t, f)
	l.boot.Linker.OverlayIP = "not-an-address"

	l.applyEgress(context.Background(), []string{"172.18.0.0/16"})

	if f.ran("linker-egress.nft") {
		t.Errorf("an empty ruleset was loaded; calls were %v", f.calls)
	}
	if l.egressOK {
		t.Error("an install that rendered nothing was recorded as applied, so nothing will retry it")
	}
}

// The marking table and the mark rule are a pair. Nothing sets that mark unless
// the table is loaded, so the rule on its own selects a table for traffic that
// can never carry it - plumbing that reads as correct in `ip rule` while the
// thing it serves was never built. apply guarded this and reconcile installed
// the rule unconditionally ten seconds later, so the guard lasted exactly one
// tick.
func TestReconcileWithholdsTheMarkRuleUntilItsTableIsLoaded(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"ip route get 192.168.1.2": "192.168.1.2 dev eth0 src 192.168.1.50 uid 0",
	}}
	l := testLinker(t, f)
	// An address no generator can render, which is what makes the ruleset empty.
	l.boot.Linker.OverlayIP = "2001:db8::3"

	l.reconcile(context.Background())

	if f.ran("linker-return.nft") {
		t.Errorf("an empty ruleset was written and loaded; calls were %v", f.calls)
	}
	if f.ran("ip rule add fwmark 0x201") {
		t.Errorf("the mark rule went in without the table it selects; calls were %v", f.calls)
	}
}

// The inverse of the same pairing, and the worse half: a table that failed to
// load at startup was never reinstalled, while its rule was kept perpetually
// fresh by every tick. Recording the success only after `nft -f` has taken it
// is what lets reconcile come back for it, exactly as retryEgress does.
func TestReconcileRetriesAReturnRulesetThatFailedToLoad(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"ip route get 192.168.1.2": "192.168.1.2 dev eth0 src 192.168.1.50 uid 0",
	}}
	l := testLinker(t, f)

	f.fails = []string{"linker-return.nft"}
	l.ensureReturnPath(context.Background())
	if l.returnPathOK() {
		t.Fatal("a load the kernel refused was recorded as applied")
	}
	if f.ran("ip rule add fwmark 0x201") {
		t.Errorf("the mark rule went in after the table failed to load; calls were %v", f.calls)
	}

	f.fails = nil
	f.calls = nil
	l.reconcile(context.Background())

	if !f.ran("linker-return.nft") {
		t.Errorf("reconcile did not retry the failed load; calls were %v", f.calls)
	}
	if !f.ran("ip rule add fwmark 0x201") {
		t.Errorf("the mark rule was not installed on retry; calls were %v", f.calls)
	}
	if !l.returnPathOK() {
		t.Error("a successful retry was not recorded, so it will reload every tick")
	}
}

// ...and once it has loaded, it must stop reloading. An nftables table is not
// lost with an interface the way a rule or a route is, so there is nothing for
// reconcile to repair in the ordinary case.
func TestReconcileDoesNotReloadAnIntactReturnRuleset(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"ip route get 192.168.1.2": "192.168.1.2 dev eth0 src 192.168.1.50 uid 0",
	}}
	l := testLinker(t, f)

	l.ensureReturnPath(context.Background())
	if !l.returnPathOK() {
		t.Fatalf("the first install did not take; calls were %v", f.calls)
	}

	f.calls = nil
	l.reconcile(context.Background())
	if f.ran("linker-return.nft") {
		t.Errorf("reconcile reloaded a table that was already loaded; calls were %v", f.calls)
	}
}
