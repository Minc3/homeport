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
		`tcp dport 80 dnat to 10.99.0.2`,
		`tcp dport 443 dnat to 10.99.0.2`,
		`tcp dport 2022 dnat to 10.99.0.2`,
		`tcp dport 8080 dnat to 10.99.0.2`,
		`udp dport 27015-27030 dnat to 10.99.0.2`,
		`tcp dport 25565 dnat to 10.99.0.2`,
		`iifname "eth0"`,
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset missing %q:\n%s", want, rs)
		}
	}
}

func TestRulesetSkipsDisabledServices(t *testing.T) {
	cfg := defaultsPublishing()
	for i := range cfg.Services {
		if cfg.Services[i].Name == "source" {
			cfg.Services[i].Enabled = false
		}
	}
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
	rs := BuildReturnRuleset([]string{"wg-main", "wg-lte1"})

	if !strings.Contains(rs, "ct direction reply meta mark set ct mark") {
		t.Errorf("mark restore must be limited to the reply direction:\n%s", rs)
	}
	if strings.Contains(rs, "\n\t\tmeta mark set ct mark") {
		t.Errorf("unconditional mark restore would send requests back out their own tunnel:\n%s", rs)
	}
	if !strings.Contains(rs, `iifname { "wg-main", "wg-lte1" } ct direction original ct mark set 0x200`) {
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
		[]string{"wg-main", "wg-lte1"},
		"10.99.0.2")

	// The mark is set in prerouting because a forwarded packet's routing
	// decision happens after that hook; this is what diverts it to the return
	// table instead of out to pfSense.
	if !strings.Contains(rs, "type filter hook prerouting priority mangle") {
		t.Errorf("marking must happen in prerouting for forwarded traffic:\n%s", rs)
	}
	if !strings.Contains(rs, "ip saddr 172.18.0.0/16 ip daddr != {") ||
		!strings.Contains(rs, "} meta mark set 0x300") {
		t.Errorf("network not marked:\n%s", rs)
	}
	// The source has to become the overlay address: that is what the frontend's
	// egress rule matches, and the only address it can route a reply back to.
	if !strings.Contains(rs, `ip saddr 172.18.0.0/16 oifname { "wg-main", "wg-lte1" } snat to 10.99.0.2`) {
		t.Errorf("source not rewritten to the overlay address:\n%s", rs)
	}
}

// The mark is limited to internet destinations, and that limit is the feature
// working at all on a real host. Matched on source alone, the rule stamped
// everything a container sent: its DNS queries to the LAN resolver, its
// traffic to the host's own LAN address, to a database on the next bridge, to
// the panel that manages it. All of it went down the tunnel to a frontend
// that can do nothing with a private destination, and the symptom was the
// containers "going offline" the moment their network was ticked - unable to
// resolve a name or reach their panel, while their internet traffic was fine.
func TestBackendEgressLeavesPrivateDestinationsOnTheirNormalRoute(t *testing.T) {
	rs := BuildBackendEgressRuleset([]string{"172.25.50.0/24"}, []string{"wg-main"}, "10.99.0.2")
	var markLine string
	for _, line := range strings.Split(rs, "\n") {
		if strings.Contains(line, "meta mark set") {
			markLine = line
		}
	}
	if markLine == "" {
		t.Fatalf("no mark rule:\n%s", rs)
	}
	assertInternetOnly(t, "mark", markLine)
}

// assertInternetOnly checks that a rule carries the whole exclusion, negated,
// as rendered - not a hand-typed subset of it, which a rule rendering the
// inverse set (private destinations only) would also satisfy.
func assertInternetOnly(t *testing.T, name, line string) {
	t.Helper()
	if !strings.Contains(line, internetOnly) {
		t.Errorf("the %s rule does not carry the exact exclusion %q: %q", name, internetOnly, line)
	}
	for _, want := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"169.254.0.0/16", "127.0.0.0/8", "100.64.0.0/10", "0.0.0.0/8", "224.0.0.0/3"} {
		found := false
		for _, have := range nonInternetDestinations {
			if have == want {
				found = true
			}
		}
		if !found {
			t.Errorf("nonInternetDestinations no longer excludes %s", want)
		}
	}
}

// Docker installs its masquerade at srcnat (100). Left to run first it would
// rewrite the source to an address on the output interface - and the tunnels
// have none, because wg-quick runs with Table = off and no Address. The
// translation has to be settled before Docker gets a look.
func TestBackendEgressSNATRunsBeforeDockersMasquerade(t *testing.T) {
	rs := BuildBackendEgressRuleset([]string{"172.18.0.0/16"}, []string{"wg-main"}, "10.99.0.2")
	if !strings.Contains(rs, "type nat hook postrouting priority -10") {
		t.Errorf("egress SNAT must be ahead of srcnat priority 100:\n%s", rs)
	}
}

// The SNAT is scoped to the tunnels on purpose. In observe mode the return
// table is empty, so the traffic falls through to the ordinary default route -
// and rewriting its source to an overlay address on the way out of the LAN
// would break it rather than merely leave it alone.
func TestBackendEgressSNATOnlyAppliesOnTheTunnels(t *testing.T) {
	rs := BuildBackendEgressRuleset([]string{"172.18.0.0/16"}, []string{"wg-main"}, "10.99.0.2")
	for _, line := range strings.Split(rs, "\n") {
		if strings.Contains(line, "snat to") && !strings.Contains(line, "oifname") {
			t.Errorf("unscoped SNAT would fire on the local network too: %q", line)
		}
	}
}

// Nothing configured must render nothing, so the caller removes the table
// rather than loading an empty one that looks deliberate.
func TestBackendEgressRulesetIsEmptyWithoutSources(t *testing.T) {
	if rs := BuildBackendEgressRuleset(nil, []string{"wg-main"}, "10.99.0.2"); rs != "" {
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

// A host that forwards overlay traffic needs an exception in both directions,
// and the backend is such a host the moment a linker exists behind it. Docker
// leaves the FORWARD policy at drop, and a drop in another chain cannot be
// rescued from ours, so the accepts go where Docker leaves room for them.
func TestOverlayForwardExceptionsCoverBothDirections(t *testing.T) {
	f := &fakeRunner{replies: map[string]string{
		"nft -a list chain ip filter DOCKER-USER": "table ip filter {\n chain DOCKER-USER {\n }\n}\n",
	}}
	if err := EnsureOverlayForwardExceptions(context.Background(), f, "10.99.0.0/24"); err != nil {
		t.Fatalf("EnsureOverlayForwardExceptions: %v", err)
	}
	// Published traffic arrives addressed to the linker; everything the linker
	// sends carries its overlay address as the source. Matching one direction
	// only lets the request through and drops the answer.
	if !f.ran(`nft insert rule ip filter DOCKER-USER ip daddr 10.99.0.0/24 accept comment "failover_overlay"`) {
		t.Errorf("no accept for traffic to the overlay range: %v", f.calls)
	}
	if !f.ran(`nft insert rule ip filter DOCKER-USER ip saddr 10.99.0.0/24 accept comment "failover_overlay"`) {
		t.Errorf("no accept for traffic from the overlay range: %v", f.calls)
	}
}

// Its own comment, or removing one feature's rules would take another's with
// them - and each of the three is removable on its own by design.
func TestOverlayForwardCommentIsDistinct(t *testing.T) {
	for _, other := range []string{forwardComment, egressForwardComment} {
		if strings.Contains(commentNeedle(overlayForwardComment), commentNeedle(other)) ||
			strings.Contains(commentNeedle(other), commentNeedle(overlayForwardComment)) {
			t.Errorf("comment %q collides with %q", overlayForwardComment, other)
		}
	}
}

// No chain, no rules, no error: a host without Docker has nothing to work
// around and must issue nothing at all.
func TestOverlayForwardExceptionsSkipWhenNoDockerChain(t *testing.T) {
	f := &fakeRunner{fail: map[string]string{
		"nft -a list chain ip filter DOCKER-USER": "No such file or directory",
	}}
	if err := EnsureOverlayForwardExceptions(context.Background(), f, "10.99.0.0/24"); err != nil {
		t.Fatalf("a host with no DOCKER-USER chain must not error: %v", err)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "insert rule") {
			t.Errorf("inserted a rule into a chain that does not exist: %s", c)
		}
	}
}

// The tunnels run at 1420 and everything either side of them at 1500, so a
// forwarded TCP connection depended on path MTU discovery - on the far end
// acting on an ICMP it frequently never sees. Valve's servers are the
// canonical case: steamcmd from a container routed out through the frontend
// completed its handshake and then sat at "Retrying..." forever, because the
// first full-size segment from Steam was dropped at the tunnel and nothing
// told Steam to send smaller ones. Clamping the MSS on every SYN that leaves by
// a tunnel tells the far end the size up front, on both hosts, and needs no
// cooperation from anybody.
func TestBothRulesetsClampTCPMSSIntoTheTunnels(t *testing.T) {
	cfg := defaultsPublishing()
	front := BuildRuleset(cfg)
	back := BuildReturnRuleset([]string{"wg-main", "wg-lte1", "wg-lte2"})
	want := `oifname { "wg-main", "wg-lte1", "wg-lte2" } tcp flags syn tcp option maxseg size set rt mtu`
	for name, rs := range map[string]string{"frontend": front, "backend": back} {
		if !strings.Contains(rs, want) {
			t.Errorf("%s ruleset does not clamp the MSS into the tunnels:\n%s", name, rs)
		}
		if !strings.Contains(rs, "type filter hook forward priority mangle") {
			t.Errorf("%s clamp is not on the forward hook, where the tunnel-bound SYNs are:\n%s", name, rs)
		}
	}
	// Scoped to the tunnels: a SYN leaving by the public interface or the
	// LAN carries a full-size MSS as it always did.
	for _, line := range strings.Split(front+back, "\n") {
		if strings.Contains(line, "maxseg") && !strings.Contains(line, "oifname {") {
			t.Errorf("an MSS clamp is not scoped to the tunnels: %q", line)
		}
	}
	// And nowhere to leave by means nothing to clamp.
	if rs := BuildReturnRuleset(nil); strings.Contains(rs, "maxseg") {
		t.Errorf("a clamp was rendered with no tunnels:\n%s", rs)
	}
}

// The networks an agent is told to pull onto the overlay are re-parsed before
// anything is written, and what is written is what came back from the parse.
//
// They arrive over the control channel, and until this existed they were
// interpolated into the generated file unquoted and unchecked, straight into
// `nft -f` as root. web.validate does check them, but that runs on a different
// host at save time, so it cannot be the only check: what reaches this function
// is whatever the peer at the far end of a socket said. A value carrying a
// newline is not one bad rule, it is a free hand with the whole ruleset.
func TestEgressNetworksAreReparsedBeforeTheyReachTheRuleset(t *testing.T) {
	injected := "10.0.0.0/8 accept\n\t}\n\tchain evil {\n" +
		"\t\ttype nat hook prerouting priority -100; policy accept;\n" +
		"\t\ttcp dport 443 dnat to 203.0.113.9\n"

	for _, tc := range []struct {
		what string
		rs   string
	}{
		{"backend", BuildBackendEgressRuleset(
			[]string{injected, "172.18.0.0/16"}, []string{"wg-main"}, "10.99.0.2")},
		{"linker", BuildLinkerEgressRuleset(
			[]string{injected, "172.18.0.0/16"}, "eth0", "10.99.0.3", "")},
	} {
		if strings.Contains(tc.rs, "chain evil") || strings.Contains(tc.rs, "dnat to") {
			t.Errorf("%s: injected rules reached the ruleset:\n%s", tc.what, tc.rs)
		}
		// The good row alongside it still goes in: nft rejects a whole table
		// over one bad element, so refusing the batch would let one unusable
		// network take a working ruleset down with it.
		if !strings.Contains(tc.rs, "ip saddr 172.18.0.0/16") {
			t.Errorf("%s: the usable network was dropped with the bad one:\n%s", tc.what, tc.rs)
		}
	}
}

// A network the parse cannot use is dropped, and a batch with nothing usable in
// it renders nothing at all - which is what makes the callers take the rules
// down rather than load an empty file over a table that is already there.
func TestEgressNetworksDropsWhatNftCouldNotLoad(t *testing.T) {
	for _, bad := range []string{
		"", "  ", "not-a-network", "172.18.0.0", "2001:db8::/32", "::ffff:172.18.0.0/120",
	} {
		if got := EgressNetworks([]string{bad}); len(got) != 0 {
			t.Errorf("%q should not have survived, got %v", bad, got)
		}
		if rs := BuildBackendEgressRuleset([]string{bad}, []string{"wg-main"}, "10.99.0.2"); rs != "" {
			t.Errorf("%q rendered a ruleset:\n%s", bad, rs)
		}
		if rs := BuildLinkerEgressRuleset([]string{bad}, "eth0", "10.99.0.3", ""); rs != "" {
			t.Errorf("%q rendered a linker ruleset:\n%s", bad, rs)
		}
	}
}

// Re-rendering must not move a single byte for a network the portal accepted,
// or every existing deployment gets a diff in a file where nothing was meant to
// change. web.parseIPv4Network already normalises to exactly this form.
func TestEgressNetworksLeavesAnAcceptedNetworkAlone(t *testing.T) {
	in := []string{"172.18.0.0/16", "10.0.0.0/8", "192.168.1.0/24", "203.0.113.5/32"}
	got := EgressNetworks(in)
	if len(got) != len(in) {
		t.Fatalf("dropped a valid network: %v", got)
	}
	for i := range in {
		if got[i] != in[i] {
			t.Errorf("network %d was rewritten: %q -> %q", i, in[i], got[i])
		}
	}
	// A host part, which the portal masks off on save, is masked here too
	// rather than passed through as typed.
	if got := EgressNetworks([]string{"172.18.0.5/16"}); len(got) != 1 || got[0] != "172.18.0.0/16" {
		t.Errorf("a host-part network should render as its network address, got %v", got)
	}
}

// The overlay address in a generated ruleset gets the same treatment the
// networks do, because on the backend it comes from the same place: the pushed
// configuration. It was the quiet half of the same problem, rendered with %s
// beside the loud one.
func TestTheOverlayAddressIsReparsedToo(t *testing.T) {
	for _, bad := range []string{
		"", "10.99.0.2 counter\n\tchain evil {", "not-an-address", "10.99.0.0/24", "2001:db8::1",
	} {
		if got := AddressLiteral(bad); got != "" {
			t.Errorf("AddressLiteral(%q) = %q, want nothing usable", bad, got)
		}
		if rs := BuildBackendEgressRuleset([]string{"172.18.0.0/16"}, []string{"wg-main"}, bad); rs != "" {
			t.Errorf("overlay %q rendered a ruleset:\n%s", bad, rs)
		}
		if rs := BuildLinkerEgressRuleset([]string{"172.18.0.0/16"}, "eth0", bad, ""); rs != "" {
			t.Errorf("overlay %q rendered a linker ruleset:\n%s", bad, rs)
		}
		if rs := BuildLinkerReturnRuleset(bad); rs != "" {
			t.Errorf("overlay %q rendered a linker return ruleset:\n%s", bad, rs)
		}
	}
	// And an address that is fine is not moved by a byte.
	if got := AddressLiteral("10.99.0.2"); got != "10.99.0.2" {
		t.Errorf("a good address was rewritten to %q", got)
	}
}

// qcacheConfig is a published Source service with the cache switched on.
func qcacheConfig() model.Config {
	cfg := model.Defaults()
	cfg.Frontend.PublicIface = "eth0"
	cfg.QueryCache.Enabled = true
	cfg.Services = []model.Service{
		{Name: "gmod", Proto: "udp", Port: 27015, PortEnd: 27030, Enabled: true, SourceEngine: true},
	}
	return cfg
}

// With the cache off the ruleset is byte-identical to a build that never
// heard of it - invariant 19's discipline, applied here because every site
// that does not opt in must see exactly the rules it always had.
func TestRulesetIsUntouchedWithTheQueryCacheOff(t *testing.T) {
	cfg := qcacheConfig()
	cfg.QueryCache.Enabled = false
	rs := BuildRuleset(cfg)
	if strings.Contains(rs, "redirect") || strings.Contains(rs, "qcache") {
		t.Errorf("cache off still generated redirect rules:\n%s", rs)
	}
}

// The redirects take only what the cache answers: the connectionless marker
// and then the three query type bytes. A flow whose first packet is not a
// query - game traffic, a join handshake - still reaches the dnat rule below
// them, which is why the redirects also have to come first: rules run in
// order, and a query that reaches the dnat is already on its way down a
// tunnel.
func TestQueryCacheRedirectsAreNarrowAndPrecedeTheDNAT(t *testing.T) {
	rs := BuildRuleset(qcacheConfig())
	// All three query types, and RULES is not optional: the redirect verdict
	// binds to the conntrack flow, so a tuple that queried INFO first has its
	// RULES packets delivered to the cache whatever this match says - a type
	// missing here is not passed through, it is silently dropped on every
	// socket that ever sent another query first.
	for _, want := range []string{
		`iifname "eth0" udp dport 27015-27030 @th,64,32 0xffffffff @th,96,8 0x54 redirect comment "qcache info: gmod"`,
		`iifname "eth0" udp dport 27015-27030 @th,64,32 0xffffffff @th,96,8 0x55 redirect comment "qcache players: gmod"`,
		`iifname "eth0" udp dport 27015-27030 @th,64,32 0xffffffff @th,96,8 0x56 redirect comment "qcache rules: gmod"`,
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset lacks %q:\n%s", want, rs)
		}
	}
	dnat := strings.Index(rs, "dnat to")
	redirect := strings.Index(rs, "redirect")
	if dnat < 0 || redirect < 0 || redirect > dnat {
		t.Errorf("redirects must precede the dnat rule:\n%s", rs)
	}
	// A bare redirect keeps the destination port, which is what lets the
	// responder bind the service port itself. A `redirect to` would be a
	// port mapping that has to agree with the engine's sockets by hand.
	if strings.Contains(rs, "redirect to") {
		t.Errorf("redirect maps ports; the responder binds the service port:\n%s", rs)
	}
}

// Only the opted-in service is redirected: a UDP service without the Source
// tick, and any TCP service, keep their queries going to the real server.
func TestQueryCacheRedirectsOnlyOptedInServices(t *testing.T) {
	cfg := qcacheConfig()
	cfg.Services = append(cfg.Services,
		model.Service{Name: "other-udp", Proto: "udp", Port: 30000, Enabled: true},
		model.Service{Name: "web", Proto: "tcp", Port: 443, Enabled: true, SourceEngine: true},
	)
	rs := BuildRuleset(cfg)
	if strings.Contains(rs, "qcache info: other-udp") || strings.Contains(rs, "qcache info: web") {
		t.Errorf("a service that did not opt in was redirected:\n%s", rs)
	}
	if !strings.Contains(rs, "qcache info: gmod") {
		t.Errorf("the opted-in service lost its redirect:\n%s", rs)
	}
}
