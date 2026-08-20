package linker

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/sysx"
)

// fakeRunner records every command and answers reads from a canned table.
type fakeRunner struct {
	replies map[string]string
	calls   []string
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	cmd := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, cmd)
	if out, ok := f.replies[cmd]; ok {
		return out, nil
	}
	return "", nil
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
	if !strings.Contains(joined, "ip route flush table 200") {
		t.Errorf("revert should empty the overlay table, calls were %v", f.calls)
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
	if f.ran("nft -f") {
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

	if !f.ran("nft -f") {
		t.Errorf("reconcile did not retry the failed egress install; calls were %v", f.calls)
	}
	if !f.ran("ip rule add fwmark 0x301") {
		t.Errorf("the egress mark rule was not installed on retry; calls were %v", f.calls)
	}
	if !l.egressOK {
		t.Error("a successful retry was not recorded, so it will run again every tick")
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
	if !f.ran("nft -f") {
		t.Fatalf("first push did not install anything; calls were %v", f.calls)
	}

	f.calls = nil
	l.applyEgress(context.Background(), []string{"172.18.0.0/16"})
	if len(f.calls) != 0 {
		t.Errorf("an identical push reinstalled the ruleset; calls were %v", f.calls)
	}

	f.calls = nil
	l.reconcile(context.Background())
	if f.ran("nft -f") {
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
