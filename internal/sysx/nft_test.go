package sysx

import (
	"context"
	"strings"
	"testing"

	"github.com/quinlan102/homeport/internal/model"
)

// defaultsPublishing is Defaults() with the shipped example services ticked on.
//
// They ship disabled, because a fresh install must not publish ports on the
// strength of nobody having deleted a row. These tests are about what a
// published service generates, so they turn the examples on rather than
// inventing a parallel list that could drift from the real one.
func defaultsPublishing() model.Config {
	cfg := model.Defaults()
	for i := range cfg.Services {
		cfg.Services[i].Enabled = true
	}
	return cfg
}

func TestRulesetNeverMasquerades(t *testing.T) {
	rs := BuildRuleset(defaultsPublishing())
	// Leaving the source address alone is the entire reason the game server
	// and the web server see real client IPs. A masquerade rule sneaking in
	// would silently replace every client address with the frontend's.
	for _, banned := range []string{"masquerade", "snat", "postrouting"} {
		if strings.Contains(strings.ToLower(rs), banned) {
			t.Errorf("ruleset contains %q; source addresses must never be rewritten:\n%s", banned, rs)
		}
	}
}

func TestRulesetPublishesEnabledServices(t *testing.T) {
	cfg := defaultsPublishing()
	cfg.Frontend.PublicIface = "eth0"
	rs := BuildRuleset(cfg)

	for _, want := range []string{
		`udp dport 27015 dnat to 10.99.0.2`,
		`udp dport 27020 dnat to 10.99.0.2`,
		`tcp dport 80 dnat to 10.99.0.2`,
		`tcp dport 443 dnat to 10.99.0.2`,
		`iifname "eth0"`,
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset missing %q:\n%s", want, rs)
		}
	}
}

func TestRulesetSkipsDisabledServices(t *testing.T) {
	cfg := defaultsPublishing()
	cfg.Services[0].Enabled = false // gmod
	rs := BuildRuleset(cfg)
	if strings.Contains(rs, "dport 27015") {
		t.Errorf("disabled service was published:\n%s", rs)
	}
}

func TestRulesetPortRange(t *testing.T) {
	cfg := defaultsPublishing()
	cfg.Services = []model.Service{{Name: "gmod", Proto: "udp", Port: 27015, PortEnd: 27020, Enabled: true}}
	rs := BuildRuleset(cfg)
	if !strings.Contains(rs, "udp dport 27015-27020") {
		t.Errorf("port range not rendered:\n%s", rs)
	}
}

func TestRulesetIsAtomicReplace(t *testing.T) {
	rs := BuildRuleset(defaultsPublishing())
	// create-then-delete-then-define, so loading it is atomic and never leaves
	// the box with half a ruleset.
	create := strings.Index(rs, "table ip failover\n")
	del := strings.Index(rs, "delete table ip failover")
	if create < 0 || del < 0 || del < create {
		t.Errorf("ruleset is not an atomic replace:\n%s", rs)
	}
}

func TestRulesetScopesToPublicIP(t *testing.T) {
	cfg := defaultsPublishing()
	cfg.Frontend.PublicIP = "203.0.113.10"
	rs := BuildRuleset(cfg)
	if !strings.Contains(rs, "ip daddr 203.0.113.10") {
		t.Errorf("public IP not used to scope rules:\n%s", rs)
	}
}

// Only reply traffic may restore the connection mark.
//
// Restoring it for every packet looks equivalent and is not. A request arriving
// from a tunnel would keep the mark through the container DNAT, so the packet
// destined for the container would be routed by the return table and sent
// straight back out the tunnel it came from - the service appears completely
// dead while every component of it is healthy. This was observed in production.
func TestReturnRulesetMarksOnlyReplies(t *testing.T) {
	rs := BuildReturnRuleset([]string{"wg-nbn", "wg-lte1"})

	if !strings.Contains(rs, "ct direction reply meta mark set ct mark") {
		t.Errorf("mark restore must be limited to the reply direction:\n%s", rs)
	}
	if strings.Contains(rs, "\n\t\tmeta mark set ct mark") {
		t.Errorf("unconditional mark restore would send requests back out their own tunnel:\n%s", rs)
	}
	if !strings.Contains(rs, `iifname { "wg-nbn", "wg-lte1" } ct direction original ct mark set 0x200`) {
		t.Errorf("connections arriving from a tunnel must be marked:\n%s", rs)
	}
	// The direction qualifier is not decoration. A connection the backend
	// started down the tunnel - what the egress feature creates - has its
	// replies arrive on a tunnel too. Stamping those would give them the return
	// mark, route them by table 100, and send them straight back out the tunnel
	// instead of to the container waiting for them.
	if strings.Contains(rs, `} ct mark set 0x200`) {
		t.Errorf("marking must be limited to connections that originated from a tunnel:\n%s", rs)
	}
	// Same atomic create-delete-define dance as the DNAT ruleset.
	if !strings.Contains(rs, "delete table ip "+NFTReturnTable) {
		t.Errorf("ruleset must replace itself atomically:\n%s", rs)
	}
}

// The frontend must never match forward exceptions on the source address: a
// reply has its source rewritten back to the public address before the forward
// hook runs, so such a rule never fires and every published service hangs
// after the request reaches the backend.
func TestForwardExceptionsMatchStateNotSource(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"nft -a list chain ip filter DOCKER-USER": "table ip filter {\n chain DOCKER-USER {\n }\n}\n",
	}}
	if err := EnsureForwardExceptions(context.Background(), f, "10.99.0.2"); err != nil {
		t.Fatalf("EnsureForwardExceptions: %v", err)
	}
	if !f.ran("ct state established,related accept") {
		t.Errorf("replies must be accepted by connection state, got: %v", f.calls)
	}
	if !f.ran("ip daddr 10.99.0.2 accept") {
		t.Errorf("inbound published traffic must be accepted, got: %v", f.calls)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "ip saddr") {
			t.Errorf("a source match never fires for replies: %s", c)
		}
	}
}

// Without Docker there is no drop-policy forward chain to work around, and the
// agent must not create rules in tables it does not own.
func TestForwardExceptionsSkippedWithoutDocker(t *testing.T) {
	f := &fakeRunner{fail: map[string]string{
		"nft -a list chain ip filter DOCKER-USER": "No such file or directory",
	}}
	if err := EnsureForwardExceptions(context.Background(), f, "10.99.0.2"); err != nil {
		t.Fatalf("a missing chain is not an error: %v", err)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "insert rule") {
			t.Errorf("nothing should be inserted when the chain is absent: %s", c)
		}
	}
}

// The published ruleset and the egress ruleset must stay separate tables. The
// first must never rewrite a source address, because that is what gives srcds
// and the web server real client IPs; the second exists precisely to rewrite
// one, for traffic going the other way. Merging them would make the assertion
// above unenforceable.
func TestEgressRulesetIsASeparateTableFromThePublishedOne(t *testing.T) {
	cfg := defaultsPublishing()
	cfg.Frontend.BackendEgress = true

	if NFTEgressTable == NFTTable {
		t.Fatal("the egress table must not be the published table")
	}
	if strings.Contains(BuildRuleset(cfg), NFTEgressTable) {
		t.Error("the published ruleset must not contain the egress table")
	}
	if strings.Contains(BuildEgressRuleset(cfg), "dnat") {
		t.Error("the egress ruleset must not publish anything")
	}
}

// A game server is listed in the server browser at the address Steam sees its
// heartbeat arrive from, and there is no way to declare a different one. Without
// this rule the heartbeat leaves the house's own service and the server is
// advertised at an address with no port forward behind it - and none at all
// while a CGNAT'd LTE path is carrying traffic.
func TestEgressRulesetRewritesOnlyBackendOriginatedTraffic(t *testing.T) {
	cfg := defaultsPublishing()
	cfg.Frontend.BackendEgress = true
	cfg.Frontend.PublicIface = "eth0"
	cfg.Frontend.PublicIP = "51.161.196.207"

	rs := BuildEgressRuleset(cfg)
	want := `ip saddr 10.99.0.2 oifname "eth0" snat to 51.161.196.207`
	if !strings.Contains(rs, want) {
		t.Errorf("egress ruleset missing %q:\n%s", want, rs)
	}
	// Scoping to the public interface is not tidiness. Without it the rule also
	// matches traffic leaving down a tunnel, which is a reply on its way to a
	// player - and rewriting that source is the one thing the design forbids.
	if !strings.Contains(rs, `oifname "eth0"`) {
		t.Errorf("egress rule is not scoped to the public interface:\n%s", rs)
	}
}

// With no public IP configured there is no address to snat to, so it has to
// masquerade instead of silently rewriting to nothing.
func TestEgressRulesetMasqueradesWhenNoPublicIPIsKnown(t *testing.T) {
	cfg := defaultsPublishing()
	cfg.Frontend.BackendEgress = true
	cfg.Frontend.PublicIface = "eth0"
	cfg.Frontend.PublicIP = ""

	if rs := BuildEgressRuleset(cfg); !strings.Contains(rs, "masquerade") {
		t.Errorf("expected a masquerade when no public IP is set:\n%s", rs)
	}
}

// Disabled must render nothing at all, so the caller can tell "off" from "on
// but empty" and actually remove the table. Rendering an empty table instead
// would leave it loaded and translating with nothing in the config to explain it.
func TestEgressRulesetIsEmptyWhenDisabled(t *testing.T) {
	cfg := defaultsPublishing()
	if rs := BuildEgressRuleset(cfg); rs != "" {
		t.Errorf("egress ruleset should be empty when disabled, got:\n%s", rs)
	}
	// Enabled but unusable is also empty: without an output interface the rule
	// would match every way out, tunnels included.
	cfg.Frontend.BackendEgress = true
	cfg.Frontend.PublicIface = ""
	if rs := BuildEgressRuleset(cfg); rs != "" {
		t.Errorf("egress ruleset should be empty with no public interface, got:\n%s", rs)
	}
}

// The two forward exceptions are found by comment, and one comment is a prefix
// of the other. Matching loosely would make each delete the other's rules, so
// turning egress off would tear down the published services' exceptions with it.
func TestForwardCommentsCannotMatchEachOther(t *testing.T) {
	if !strings.HasPrefix(egressForwardComment, forwardComment) {
		t.Skip("comments no longer share a prefix; the hazard this guards is gone")
	}
	if strings.Contains(commentNeedle(egressForwardComment), commentNeedle(forwardComment)) {
		t.Errorf("%q matches inside %q; the two exceptions would delete each other",
			commentNeedle(forwardComment), commentNeedle(egressForwardComment))
	}
}

// The exception has to match on source, unlike the published ones. A connection
// the backend starts is not covered by `ip daddr backend` - it is going to the
// internet - nor by `ct state established` - it is the first packet. Without it
// the source NAT is installed correctly and nothing ever reaches it.
func TestEgressForwardExceptionMatchesSource(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"nft -a list chain ip filter DOCKER-USER": "chain DOCKER-USER {\n\t\tct state established,related accept\n\t}",
	}}
	if err := EnsureEgressForwardException(context.Background(), f, "10.99.0.2"); err != nil {
		t.Fatalf("EnsureEgressForwardException: %v", err)
	}
	if !f.ran("ip saddr 10.99.0.2 accept") {
		t.Errorf("expected a source match; calls were %v", f.calls)
	}
	if !f.ran(egressForwardComment) {
		t.Errorf("rule must carry its own comment so it can be removed alone; calls were %v", f.calls)
	}
}

// A containerised game server cannot bind the overlay address - it does not
// exist in the container's namespace - and its packets are forwarded through
// the host rather than originated on it, so there is no local socket to match
// either. What is left is where they came from.
func TestBackendEgressRulesetPullsANetworkOntoTheTunnel(t *testing.T) {
	rs := BuildBackendEgressRuleset(
		[]string{"172.18.0.0/16"},
		[]string{"wg-nbn", "wg-lte1"},
		"10.99.0.2")

	// The mark is set in prerouting because a forwarded packet's routing
	// decision happens after that hook; this is what diverts it to the return
	// table instead of out to pfSense.
	if !strings.Contains(rs, "type filter hook prerouting priority mangle") {
		t.Errorf("marking must happen in prerouting for forwarded traffic:\n%s", rs)
	}
	if !strings.Contains(rs, "ip saddr 172.18.0.0/16 meta mark set 0x300") {
		t.Errorf("network not marked:\n%s", rs)
	}
	// The source has to become the overlay address: that is what the frontend's
	// egress rule matches, and the only address it can route a reply back to.
	if !strings.Contains(rs, `ip saddr 172.18.0.0/16 oifname { "wg-nbn", "wg-lte1" } snat to 10.99.0.2`) {
		t.Errorf("source not rewritten to the overlay address:\n%s", rs)
	}
}

// Docker installs its masquerade at srcnat (100). Left to run first it would
// rewrite the source to an address on the output interface - and the tunnels
// have none, because wg-quick runs with Table = off and no Address. The
// translation has to be settled before Docker gets a look.
func TestBackendEgressSNATRunsBeforeDockersMasquerade(t *testing.T) {
	rs := BuildBackendEgressRuleset([]string{"172.18.0.0/16"}, []string{"wg-nbn"}, "10.99.0.2")
	if !strings.Contains(rs, "type nat hook postrouting priority -10") {
		t.Errorf("egress SNAT must be ahead of srcnat priority 100:\n%s", rs)
	}
}

// The SNAT is scoped to the tunnels on purpose. In observe mode the return
// table is empty, so the traffic falls through to the ordinary default route -
// and rewriting its source to an overlay address on the way out of the LAN
// would break it rather than merely leave it alone.
func TestBackendEgressSNATOnlyAppliesOnTheTunnels(t *testing.T) {
	rs := BuildBackendEgressRuleset([]string{"172.18.0.0/16"}, []string{"wg-nbn"}, "10.99.0.2")
	for _, line := range strings.Split(rs, "\n") {
		if strings.Contains(line, "snat to") && !strings.Contains(line, "oifname") {
			t.Errorf("unscoped SNAT would fire on the local network too: %q", line)
		}
	}
}

// Nothing configured must render nothing, so the caller removes the table
// rather than loading an empty one that looks deliberate.
func TestBackendEgressRulesetIsEmptyWithoutSources(t *testing.T) {
	if rs := BuildBackendEgressRuleset(nil, []string{"wg-nbn"}, "10.99.0.2"); rs != "" {
		t.Errorf("expected nothing with no sources:\n%s", rs)
	}
	if rs := BuildBackendEgressRuleset([]string{"172.18.0.0/16"}, nil, "10.99.0.2"); rs != "" {
		t.Errorf("expected nothing with no tunnels to send it down:\n%s", rs)
	}
}

// The marks must not collide: two features sharing one would route each
// other's traffic.
func TestEgressMarkIsClearOfEveryOtherMark(t *testing.T) {
	marks := []struct {
		name  string
		value int
	}{
		{"control", ControlMark},
		{"return", ReturnMark},
		{"egress", EgressMark},
	}
	for _, p := range model.Defaults().Paths {
		marks = append(marks, struct {
			name  string
			value int
		}{"path " + p.Name, p.Mark})
	}
	seen := map[int]string{}
	for _, m := range marks {
		if other, dup := seen[m.value]; dup {
			t.Errorf("%s and %s both use mark %#x; each would route the other's traffic",
				other, m.name, m.value)
		}
		seen[m.value] = m.name
	}
}
