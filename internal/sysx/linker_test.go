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
