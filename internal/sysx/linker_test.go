package sysx

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/quinlan102/homeport/internal/model"
)

// linkerless is the configuration every site starts in and most stay in: one
// backend at the far end, no overlay subnet, no service targets, no egress
// owners. Everything generated from it must be identical to what was generated
// before linker support existed.
func linkerless() model.Config {
	cfg := defaultsPublishing()
	cfg.Frontend.PublicIface = "eth0"
	cfg.Frontend.PublicIP = "203.0.113.10"
	return cfg
}

// The whole feature is an addon. A deployment that never configures a linker
// must not see a single character change in the rules it loads, because a diff
// in ruleset.nft is how an operator decides something moved - and there are
// several sites where nothing is meant to.
func TestNoSubnetLeavesThePublishedRulesetUnchanged(t *testing.T) {
	cfg := linkerless()
	got := BuildRuleset(cfg)

	if !strings.Contains(got, "dnat to "+cfg.Overlay.BackendIP+" ") {
		t.Fatalf("services must still DNAT to the backend's bare address:\n%s", got)
	}
	// A /32 here would be equivalent to the kernel and still a diff on every
	// existing host.
	if strings.Contains(got, cfg.Overlay.BackendIP+"/32") {
		t.Errorf("published ruleset gained a /32 where it used a bare address:\n%s", got)
	}
	// The invariant that outranks all of this.
	if strings.Contains(got, "masquerade") || strings.Contains(got, "snat") {
		t.Errorf("published ruleset must never rewrite a source address:\n%s", got)
	}
}

func TestNoSubnetLeavesTheEgressRulesetUnchanged(t *testing.T) {
	cfg := linkerless()
	cfg.Frontend.BackendEgress = true

	got := BuildEgressRuleset(cfg)
	want := "ip saddr " + cfg.Overlay.BackendIP + " oifname \"eth0\""
	if !strings.Contains(got, want) {
		t.Fatalf("egress ruleset should match the backend's bare address, want %q:\n%s", want, got)
	}
	if strings.Contains(got, cfg.Overlay.BackendIP+"/32") {
		t.Errorf("egress ruleset gained a /32 where it used a bare address:\n%s", got)
	}
}

// MatchPrefix and RoutePrefix differ only where no subnet is set, and only
// because each has to keep producing what it already produced. Once a subnet
// exists they are the same string, and anything else would mean the frontend
// routed one range and translated another.
func TestPrefixHelpersAgreeOnceASubnetIsSet(t *testing.T) {
	ov := model.OverlayConfig{BackendIP: "10.99.0.2"}
	if ov.MatchPrefix() != "10.99.0.2" {
		t.Errorf("MatchPrefix without a subnet = %q, want the bare address", ov.MatchPrefix())
	}
	if ov.RoutePrefix() != "10.99.0.2/32" {
		t.Errorf("RoutePrefix without a subnet = %q, want an explicit /32", ov.RoutePrefix())
	}

	ov.Subnet = "10.99.0.0/24"
	if ov.MatchPrefix() != ov.RoutePrefix() {
		t.Errorf("with a subnet the two must agree: match %q, route %q",
			ov.MatchPrefix(), ov.RoutePrefix())
	}
	if ov.MatchPrefix() != "10.99.0.0/24" {
		t.Errorf("with a subnet both should be the subnet, got %q", ov.MatchPrefix())
	}
}

// A service published to a linker is the same DNAT rule pointed one address
// further along. There is deliberately no second mechanism.
func TestServiceTargetRedirectsTheDNATWithoutChangingAnythingElse(t *testing.T) {
	cfg := linkerless()
	cfg.Overlay.Subnet = "10.99.0.0/24"
	cfg.Services = []model.Service{
		{Name: "gmod", Proto: "udp", Port: 27015, Enabled: true},
		{Name: "web", Proto: "tcp", Port: 443, Enabled: true, Target: "10.99.0.4"},
	}

	got := BuildRuleset(cfg)
	if !strings.Contains(got, "udp dport 27015 dnat to 10.99.0.2") {
		t.Errorf("an untargeted service must still go to the backend:\n%s", got)
	}
	if !strings.Contains(got, "tcp dport 443 dnat to 10.99.0.4") {
		t.Errorf("a targeted service must go to its linker:\n%s", got)
	}
	if strings.Contains(got, "masquerade") || strings.Contains(got, "snat") {
		t.Errorf("publishing to a linker must not introduce source NAT:\n%s", got)
	}
}

// The frontend translates and forwards the whole overlay range once linkers
// exist, or a linker's traffic reaches the public interface untranslated and is
// answered to an address that means nothing on the internet.
func TestSubnetWidensTheFrontendDataPlaneOnly(t *testing.T) {
	cfg := linkerless()
	cfg.Overlay.Subnet = "10.99.0.0/24"
	cfg.Frontend.BackendEgress = true

	egress := BuildEgressRuleset(cfg)
	if !strings.Contains(egress, "ip saddr 10.99.0.0/24 oifname \"eth0\"") {
		t.Errorf("egress SNAT should cover the overlay range:\n%s", egress)
	}
	// Still scoped to the public interface: unscoped it would rewrite the
	// source of a reply on its way back down a tunnel to a player.
	if !strings.Contains(egress, "oifname \"eth0\"") {
		t.Errorf("egress SNAT must stay scoped to the public interface:\n%s", egress)
	}
}

// The second time the same default has caused the same bug. `ip rule add` with
// no preference takes the lowest existing priority minus one, so a source rule
// added after the per-path rules lands in front of them - and a probe reply is
// sourced from the overlay address, so it matches there first and leaves by the
// active tunnel instead of its own. Standby paths keep answering and keep
// reading healthy while measuring a round trip over two different tunnels.
func TestReturnRulesSitBehindTheProbeRules(t *testing.T) {
	if ReturnRulePrefBase <= ProbeRulePrefBase {
		t.Fatalf("return rules at %d must be behind the probe band at %d",
			ReturnRulePrefBase, ProbeRulePrefBase)
	}
	// Behind every per-path rule, not merely behind the base.
	for _, p := range model.Defaults().Paths {
		if ReturnRulePrefBase <= ProbeRulePrefBase+p.ID {
			t.Fatalf("return rules at %d must be behind path %s at %d",
				ReturnRulePrefBase, p.Name, ProbeRulePrefBase+p.ID)
		}
	}
	// And ahead of main, or they never run at all.
	if ReturnRulePrefBase >= 32766 {
		t.Fatalf("return rules at %d must be ahead of the main table rule at 32766",
			ReturnRulePrefBase)
	}
}

// A rule the kernel priced itself has to be moved, not left beside the correct
// one: the whole problem is that it sits in front of the probe rules.
func TestReturnRuleAtAKernelChosenPriorityIsMoved(t *testing.T) {
	r := &recordRunner{out: "" +
		"30000:\tfrom 10.99.0.0/24 lookup 100\n" +
		"30001:\tfrom all fwmark 0x101 lookup 101\n" +
		"32766:\tfrom all lookup main\n"}

	if err := EnsureReturnRule(context.Background(), r, "10.99.0.0/24"); err != nil {
		t.Fatal(err)
	}

	joined := strings.Join(r.calls, " | ")
	if !strings.Contains(joined, "ip rule del from 10.99.0.0/24 lookup 100 pref 30000") {
		t.Errorf("the misplaced rule should be removed, calls were %v", r.calls)
	}
	want := "ip rule add from 10.99.0.0/24 lookup 100 pref " + strconv.Itoa(ReturnRulePrefBase)
	if !strings.Contains(joined, want) {
		t.Errorf("the rule should be reinstalled behind the probe rules, calls were %v", r.calls)
	}
}

// Already correct means nothing to do. This runs on every backend start and on
// every reconcile, so a rule rewritten each time is reply routing dropped and
// restored several times a minute.
func TestReturnRuleAtTheRightPriorityIsLeftAlone(t *testing.T) {
	r := &recordRunner{out: "" +
		"30001:\tfrom all fwmark 0x101 lookup 101\n" +
		strconv.Itoa(ReturnRulePrefBase) + ":\tfrom 10.99.0.2 lookup 100\n" +
		"32766:\tfrom all lookup main\n"}

	if err := EnsureReturnRule(context.Background(), r, "10.99.0.2"); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.calls {
		if strings.Contains(c, "rule add") || strings.Contains(c, "rule del") {
			t.Fatalf("an already-correct rule must be left alone, got %q", c)
		}
	}
}

// Two sources get two priorities. Both at one priority is legal to the kernel
// and unreadable to anyone looking at `ip rule show` afterwards.
func TestTwoReturnSourcesGetDistinctPriorities(t *testing.T) {
	r := &recordRunner{out: "32766:\tfrom all lookup main\n"}

	if err := EnsureReturnRule(context.Background(), r, "10.99.0.2", "10.99.0.0/24"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.calls, " | ")
	first := "pref " + strconv.Itoa(ReturnRulePrefBase)
	second := "pref " + strconv.Itoa(ReturnRulePrefBase+1)
	if !strings.Contains(joined, first) || !strings.Contains(joined, second) {
		t.Fatalf("expected distinct priorities %s and %s, calls were %v", first, second, r.calls)
	}
}

// recordRunner answers every `ip rule show` with one canned listing and records
// what was asked of it.
type recordRunner struct {
	out   string
	calls []string
}

func (r *recordRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	if name == "ip" && len(args) >= 2 && args[0] == "rule" && args[1] == "show" {
		return r.out, nil
	}
	return "", nil
}

func (r *recordRunner) Applying() bool { return true }

// The mark rules are pinned like every other rule this package installs.
//
// Both of these used to accept a rule at any priority: if one was there at all,
// the agent was satisfied. That is invariant 3 with one side pinned and the
// other left wherever the kernel happened to put it, next to a source rule that
// selects the same packets.
func TestLinkerMarkRuleIsMovedToItsPinnedPriority(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"ip rule show table 200": "31000:\tfrom all fwmark 0x201 lookup 200\n",
		"ip rule show":           "31000:\tfrom all fwmark 0x201 lookup 200\n",
	}}
	if err := EnsureLinkerMarkRule(context.Background(), f, "192.168.1.2", 200); err != nil {
		t.Fatalf("EnsureLinkerMarkRule: %v", err)
	}
	want := "ip rule add fwmark 0x201 lookup 200 pref " + strconv.Itoa(LinkerRulePrefBase+1)
	if !f.ran(want) {
		t.Errorf("the rule was not installed at its pinned priority: %v", f.calls)
	}
	if !f.ran("ip rule del fwmark 0x201 lookup 200 pref 31000") {
		t.Errorf("the rule at the old priority was left behind: %v", f.calls)
	}
	// Added before the stray goes: in the gap a marked reply falls through to
	// main and leaves by the LAN instead of going to the backend.
	if f.index(want) > f.index("ip rule del fwmark 0x201 lookup 200 pref 31000") {
		t.Errorf("the stray was removed before the replacement went in: %v", f.calls)
	}
}

// Changing linker.table leaves the old table's rule behind, and it is not
// inert: it still claims the marked packets and sends them to a table whose
// route nothing maintains any more.
func TestLinkerMarkRuleClearsARuleLeftInAnotherTable(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"ip rule show table 220": "",
		"ip rule show":           "32401:\tfrom all fwmark 0x201 lookup 200\n",
	}}
	if err := EnsureLinkerMarkRule(context.Background(), f, "192.168.1.2", 220); err != nil {
		t.Fatalf("EnsureLinkerMarkRule: %v", err)
	}
	if !f.ran("ip rule add fwmark 0x201 lookup 220 pref " + strconv.Itoa(LinkerRulePrefBase+1)) {
		t.Errorf("the rule was not installed in the new table: %v", f.calls)
	}
	if !f.ran("ip rule del fwmark 0x201 lookup 200 pref 32401") {
		t.Errorf("the rule in the old table was left behind: %v", f.calls)
	}
}

// An intact rule is left completely alone, so a reconcile tick on a healthy
// host issues nothing but the two listings.
func TestLinkerMarkRuleLeavesAnIntactRuleAlone(t *testing.T) {
	pinned := strconv.Itoa(LinkerRulePrefBase + 2)
	listing := pinned + ":\tfrom all fwmark 0x301 lookup 200\n"
	f := &fakeRunner{replies: map[string]string{
		"ip rule show table 200": listing,
		"ip rule show":           listing,
	}}
	if err := EnsureLinkerEgressRule(context.Background(), f, "192.168.1.2", 200); err != nil {
		t.Fatalf("EnsureLinkerEgressRule: %v", err)
	}
	for _, c := range f.calls {
		if strings.Contains(c, " add ") || strings.Contains(c, " del ") {
			t.Errorf("an intact rule was rewritten: %s", c)
		}
	}
}

// Revert removes it at the priority it was found at. Deleting by selector alone
// takes one arbitrary match, so a duplicate from an older build would survive.
//
// And in whatever table it is found in, not only the configured one: a change
// of linker.table leaves the old rule holding the mark, and a revert blind to
// it would leave that behind steering marked packets into a table nothing
// maintains. A rule in another table is only swept when it sits at the pinned
// priority, which is what ties it to this system - see the host-owned test
// below for the other side of that line.
func TestRemoveLinkerRulesetsDeleteByPriority(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"ip rule show": "32401:\tfrom all fwmark 0x201 lookup 200\n" +
			"31000:\tfrom all fwmark 0x201 lookup 200\n" +
			"32401:\tfrom all fwmark 0x201 lookup isp2\n",
	}}
	RemoveLinkerReturnRuleset(context.Background(), f, "192.168.1.2", 200)
	for _, want := range []string{
		"ip rule del fwmark 0x201 lookup 200 pref 32401",
		"ip rule del fwmark 0x201 lookup 200 pref 31000",
		// By the table token the kernel printed, name and all.
		"ip rule del fwmark 0x201 lookup isp2 pref 32401",
		"nft delete table ip failover_linker_return",
	} {
		if !f.ran(want) {
			t.Errorf("revert left %q behind: %v", want, f.calls)
		}
	}
}

// With no listing to read, the selector alone is still tried: it removes one
// arbitrary match, which is worth more than leaving the rule in place.
func TestRemoveLinkerRulesetsFallBackToTheSelector(t *testing.T) {
	f := &fakeRunner{}
	RemoveLinkerEgressRuleset(context.Background(), f, "192.168.1.2", 200)
	if !f.ran("ip rule del fwmark 0x301 lookup 200") {
		t.Errorf("nothing was withdrawn when the listing came back empty: %v", f.calls)
	}
}

// The default route goes by its gateway, not by being the table's default.
//
// The two are the same thing only until the collision this whole change exists
// for actually happens. On a host that uses this table for a second ISP the
// agent overwrote `default via <isp2 gateway>` when it installed; if the
// operator has since put theirs back, an unqualified delete removes the route
// they repaired, on the command they ran to undo us.
func TestRemoveLinkerRoutingDeletesOnlyItsOwnDefaultRoute(t *testing.T) {
	f := &fakeRunner{}
	RemoveLinkerRouting(context.Background(), f, "10.99.0.3", "192.168.1.2", 200)

	if !f.ran("ip route del default via 192.168.1.2 table 200") {
		t.Errorf("the default route was not removed by its gateway: %v", f.calls)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "route flush") {
			t.Errorf("revert flushed a table it does not own: %s", c)
		}
		if c == "ip route del default table 200" {
			t.Errorf("an unqualified delete takes whatever default the table holds: %s", c)
		}
	}
}

// A stray at the *same* priority in another table is still a stray.
//
// Two rules may share a priority, and the one this is most likely to meet was
// pinned there by an earlier run of this same code: change linker.table and the
// old table's rule sits at exactly the priority the new one wants. Deciding
// which rule is ours by priority alone calls that stray correct and leaves it
// claiming the marked packets forever.
func TestLinkerMarkRuleClearsAStrayAtTheSamePriority(t *testing.T) {
	pinned := strconv.Itoa(LinkerRulePrefBase + 1)
	f := &fakeRunner{replies: map[string]string{
		"ip rule show table 220": pinned + ":\tfrom all fwmark 0x201 lookup 220\n",
		"ip rule show": pinned + ":\tfrom all fwmark 0x201 lookup 220\n" +
			pinned + ":\tfrom all fwmark 0x201 lookup 200\n",
	}}
	if err := EnsureLinkerMarkRule(context.Background(), f, "192.168.1.2", 220); err != nil {
		t.Fatalf("EnsureLinkerMarkRule: %v", err)
	}
	if !f.ran("ip rule del fwmark 0x201 lookup 200 pref " + pinned) {
		t.Errorf("the stray in the old table was left behind: %v", f.calls)
	}
	if f.ran("ip rule add") {
		t.Errorf("the rule in this table was already correct and should not have been re-added: %v", f.calls)
	}
}

// The same, for the source rule beside it, and with the same reasoning: it was
// written before tableTokens existed and matched on priority alone.
func TestLinkerRuleClearsAStrayAtTheSamePriority(t *testing.T) {
	pinned := strconv.Itoa(LinkerRulePrefBase)
	f := &fakeRunner{replies: map[string]string{
		"ip rule show table 220": pinned + ":\tfrom 10.99.0.3 lookup 220\n",
		"ip rule show": pinned + ":\tfrom 10.99.0.3 lookup 220\n" +
			pinned + ":\tfrom 10.99.0.3 lookup 200\n",
		"ip route show default table 200": "default via 192.168.1.2 dev eth0",
	}}
	if err := EnsureLinkerRule(context.Background(), f, "10.99.0.3", "192.168.1.2", 220); err != nil {
		t.Fatalf("EnsureLinkerRule: %v", err)
	}
	if !f.ran("ip rule del from 10.99.0.3 lookup 200 pref " + pinned) {
		t.Errorf("the stray in the old table was left behind: %v", f.calls)
	}
	// The table the stray pointed at is one this system stopped using, and it
	// still holds our `default via <backend>`: on the host the configurable
	// table exists for, that table is the host's own, with the host's own
	// rules still pointing at it, so leaving the route sends that host's
	// second-ISP traffic to the backend forever. Qualified by the gateway, so
	// a default the operator has since put back is never the one removed.
	if !f.ran("ip route del default via 192.168.1.2 table 200") {
		t.Errorf("the abandoned table kept this system's default route: %v", f.calls)
	}
	// And the route goes before the rule: the rule is the only evidence the
	// table was ever ours, so it must be the last thing standing.
	if f.index("ip route del default via 192.168.1.2 table 200") >
		f.index("ip rule del from 10.99.0.3 lookup 200 pref "+pinned) {
		t.Errorf("the marker rule was deleted before its table was cleaned: %v", f.calls)
	}
}

// A stray whose table could not be cleaned is deliberately kept. It is the only
// evidence the table was ever this system's: with the rule gone, nothing can
// tell our leftover default from the host's own routing, so a failure here -
// the agent killed between the two deletes, a transient `ip route del` error -
// would otherwise turn into the permanent misroute the cleanup exists to fix.
// The kept rule is what the next reconcile tick retries from.
func TestAStrayIsKeptWhileItsTableStillHoldsOurRoute(t *testing.T) {
	pinned := strconv.Itoa(LinkerRulePrefBase)
	f := &fakeRunner{
		replies: map[string]string{
			"ip rule show table 220": pinned + ":\tfrom 10.99.0.3 lookup 220\n",
			"ip rule show": pinned + ":\tfrom 10.99.0.3 lookup 220\n" +
				pinned + ":\tfrom 10.99.0.3 lookup 200\n",
			"ip route show default table 200": "default via 192.168.1.2 dev eth0",
		},
		fail: map[string]string{
			"ip route del default via 192.168.1.2 table 200": "RTNETLINK answers: Operation not permitted",
		},
	}
	if err := EnsureLinkerRule(context.Background(), f, "10.99.0.3", "192.168.1.2", 220); err != nil {
		t.Fatalf("EnsureLinkerRule: %v", err)
	}
	if f.ran("ip rule del from 10.99.0.3 lookup 200") {
		t.Errorf("the marker rule was deleted although its table still holds our route: %v", f.calls)
	}
}

// The same when the table cannot even be read: not knowing whether our route is
// still there is a reason to keep the marker, not to discard it.
func TestAStrayIsKeptWhileItsTableCannotBeRead(t *testing.T) {
	pinned := strconv.Itoa(LinkerRulePrefBase)
	f := &fakeRunner{
		replies: map[string]string{
			"ip rule show table 220": pinned + ":\tfrom 10.99.0.3 lookup 220\n",
			"ip rule show": pinned + ":\tfrom 10.99.0.3 lookup 220\n" +
				pinned + ":\tfrom 10.99.0.3 lookup 200\n",
		},
		fail: map[string]string{
			"ip route show default table 200": "Error: ipv4: FIB table does not exist.",
		},
	}
	if err := EnsureLinkerRule(context.Background(), f, "10.99.0.3", "192.168.1.2", 220); err != nil {
		t.Fatalf("EnsureLinkerRule: %v", err)
	}
	if f.ran("ip rule del from 10.99.0.3 lookup 200") {
		t.Errorf("the marker rule was deleted although its table could not be read: %v", f.calls)
	}
}

// An abandoned table holding somebody else's default - the operator noticed and
// put theirs back - has nothing of ours left in it: the rule goes, the route
// stays.
func TestAStrayGoesWhenItsTableHoldsTheOperatorsDefault(t *testing.T) {
	pinned := strconv.Itoa(LinkerRulePrefBase)
	f := &fakeRunner{replies: map[string]string{
		"ip rule show table 220": pinned + ":\tfrom 10.99.0.3 lookup 220\n",
		"ip rule show": pinned + ":\tfrom 10.99.0.3 lookup 220\n" +
			pinned + ":\tfrom 10.99.0.3 lookup 200\n",
		"ip route show default table 200": "default via 10.0.0.1 dev eth1",
	}}
	if err := EnsureLinkerRule(context.Background(), f, "10.99.0.3", "192.168.1.2", 220); err != nil {
		t.Fatalf("EnsureLinkerRule: %v", err)
	}
	if !f.ran("ip rule del from 10.99.0.3 lookup 200 pref " + pinned) {
		t.Errorf("the stray was kept although its table holds nothing of ours: %v", f.calls)
	}
	if f.ran("ip route del") {
		t.Errorf("a default this system did not install was deleted: %v", f.calls)
	}
}

// A named table is still recognised as this host's own. `ip rule show` prints
// `lookup isp2` wherever rt_tables names 200, and a readback that only knew the
// number would treat this agent's own rule as a stray, delete it, and add it
// again on every tick.
func TestLinkerRuleRecognisesItsOwnRuleInANamedTable(t *testing.T) {
	pinned := strconv.Itoa(LinkerRulePrefBase)
	listing := pinned + ":\tfrom 10.99.0.3 lookup isp2\n"
	f := &fakeRunner{replies: map[string]string{
		"ip rule show table 200": listing,
		"ip rule show":           listing,
	}}
	if err := EnsureLinkerRule(context.Background(), f, "10.99.0.3", "192.168.1.2", 200); err != nil {
		t.Fatalf("EnsureLinkerRule: %v", err)
	}
	for _, c := range f.calls {
		if strings.Contains(c, " add ") || strings.Contains(c, " del ") {
			t.Errorf("a correct rule in a named table was rewritten: %s", c)
		}
	}
}

// A mark rule the host owns is never swept. The mark constants are this
// system's, but a fwmark is only a number and the linker's host archetype is a
// machine that already policy-routes - web.validate constrains this system's
// configuration, not the host's. A rule at the host's own priority pointing at
// the host's own table is indistinguishable from one, and invariant 8 says the
// tie goes to leaving it: deleting it here would fight whatever maintains it,
// on every reconcile tick.
func TestLinkerMarkRuleLeavesTheHostsOwnRuleAlone(t *testing.T) {
	pinned := strconv.Itoa(LinkerRulePrefBase + 1)
	f := &fakeRunner{replies: map[string]string{
		"ip rule show table 200": pinned + ":\tfrom all fwmark 0x201 lookup 200\n",
		"ip rule show": pinned + ":\tfrom all fwmark 0x201 lookup 200\n" +
			"1000:\tfrom all fwmark 0x201 lookup vpn\n",
	}}
	if err := EnsureLinkerMarkRule(context.Background(), f, "192.168.1.2", 200); err != nil {
		t.Fatalf("EnsureLinkerMarkRule: %v", err)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "lookup vpn") {
			t.Errorf("touched a rule belonging to the host: %q", c)
		}
	}
}

// The same boundary on revert: the rules this system can prove are its own go,
// and the host's survive the command run to undo us.
func TestRemoveLinkerRulesetsLeaveTheHostsOwnRuleAlone(t *testing.T) {
	pinned := strconv.Itoa(LinkerRulePrefBase + 1)
	f := &fakeRunner{replies: map[string]string{
		"ip rule show table 200": pinned + ":\tfrom all fwmark 0x201 lookup 200\n",
		"ip rule show": pinned + ":\tfrom all fwmark 0x201 lookup 200\n" +
			"1000:\tfrom all fwmark 0x201 lookup vpn\n",
	}}
	RemoveLinkerReturnRuleset(context.Background(), f, "192.168.1.2", 200)
	if !f.ran("ip rule del fwmark 0x201 lookup 200 pref " + pinned) {
		t.Errorf("this system's own rule was left behind: %v", f.calls)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "lookup vpn") {
			t.Errorf("revert touched a rule belonging to the host: %q", c)
		}
	}
}

// Revert is as blind to the configured table as the ensure path: a change of
// linker.table followed by a revert has to take this system's rule *and* its
// default route out of the table it stopped using, or the host's own traffic
// keeps going to the backend after the command that was run to undo us.
func TestRemoveLinkerRoutingSweepsTheAbandonedTable(t *testing.T) {
	pinned := strconv.Itoa(LinkerRulePrefBase)
	f := &fakeRunner{replies: map[string]string{
		"ip rule show table 220": pinned + ":\tfrom 10.99.0.3 lookup 220\n",
		"ip rule show": pinned + ":\tfrom 10.99.0.3 lookup 220\n" +
			pinned + ":\tfrom 10.99.0.3 lookup isp2\n",
		"ip route show default table isp2": "default via 192.168.1.2 dev eth0",
	}}
	RemoveLinkerRouting(context.Background(), f, "10.99.0.3", "192.168.1.2", 220)
	if !f.ran("ip rule del from 10.99.0.3 lookup isp2 pref " + pinned) {
		t.Errorf("the rule in the abandoned table was left behind: %v", f.calls)
	}
	// By the token the kernel printed, and qualified by our gateway, so the
	// delete fails harmlessly if the operator already put their default back.
	if !f.ran("ip route del default via 192.168.1.2 table isp2") {
		t.Errorf("the abandoned table kept this system's default route: %v", f.calls)
	}
	if !f.ran("ip route del default via 192.168.1.2 table 220") {
		t.Errorf("the configured table kept this system's default route: %v", f.calls)
	}
}
