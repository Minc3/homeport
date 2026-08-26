package sysx

import (
	"strings"
	"testing"

	"github.com/quinlan102/homeport/internal/model"
)

func protectCfg() model.Config {
	cfg := defaultsPublishing()
	cfg.Frontend.PublicIface = "eth0"
	cfg.Protect.Enabled = true
	return cfg
}

// The state every site is in. A feature that generates rules for somebody who
// never asked for it is a feature that drops their traffic for reasons they
// cannot see, so "off" has to mean no table at all - not an empty one.
func TestProtectionOffGeneratesNothing(t *testing.T) {
	if got := BuildProtectRuleset(ProtectSpecFrom(defaultsPublishing())); got != "" {
		t.Fatalf("a site with protection off generated a ruleset:\n%s", got)
	}
}

// The master switch on with every threshold at zero is somebody who has opened
// the section and not filled anything in yet. Loading an empty table then would
// claim protection is running when nothing is being checked.
func TestProtectionWithNoThresholdsGeneratesNothing(t *testing.T) {
	if got := BuildProtectRuleset(ProtectSpecFrom(protectCfg())); got != "" {
		t.Fatalf("no thresholds set but a ruleset was generated:\n%s", got)
	}
}

// The rule that keeps this feature from being able to break failover. Every
// chain must exclude anything that did not arrive from the internet: a limiter
// that could drop a probe would have the frontend condemn a healthy tunnel
// because of its own firewall, and move traffic to a metered link over it.
func TestEveryChainIsScopedToThePublicInterface(t *testing.T) {
	cfg := protectCfg()
	cfg.Protect.PacketsPerSec = 400
	cfg.Protect.DropInvalid = true
	ruleset := BuildProtectRuleset(ProtectSpecFrom(cfg))

	chains := 0
	for _, block := range strings.Split(ruleset, "chain ")[1:] {
		chains++
		first := ""
		for _, line := range strings.Split(block, "\n") {
			line = strings.TrimSpace(line)
			// The chain's own opening line, its type declaration and comments
			// carry no match of their own.
			if line == "" || strings.HasSuffix(line, "{") ||
				strings.HasPrefix(line, "type ") || strings.HasPrefix(line, "#") {
				continue
			}
			first = line
			break
		}
		if !strings.HasPrefix(first, `iifname != "eth0" accept`) {
			t.Errorf("a chain does not exclude non-public traffic first; its first rule is %q", first)
		}
	}
	if chains == 0 {
		t.Fatal("no chains were generated at all")
	}
}

// Probes and the control channel travel between overlay addresses inside the
// tunnels. Their ports must never appear here - if one ever does, the rule
// matching it is a rule that can silently break path measurement.
func TestProtectionNeverMentionsTheSystemsOwnPorts(t *testing.T) {
	cfg := protectCfg()
	cfg.Protect.PacketsPerSec = 400
	cfg.Protect.NewConnsPerSec = 20
	cfg.Protect.DropInvalid = true
	cfg.Protect.DropBogusTCP = true
	cfg.Protect.DropSpoofed = true
	// The legacy-query drop has to be in the ruleset this scans, or a future
	// edit widening it could mention the system's own traffic with nothing
	// here to notice.
	cfg.Protect.DropLegacyQueries = true
	for i := range cfg.Services {
		if cfg.Services[i].Proto == "udp" {
			cfg.Services[i].SourceEngine = true
		}
	}
	ruleset := BuildProtectRuleset(ProtectSpecFrom(cfg))

	for _, banned := range []string{"51999", "51998", "10.99.0.1", "10.99.0.2"} {
		if strings.Contains(ruleset, banned) {
			t.Errorf("the protection ruleset mentions %s, which belongs to the system's own traffic:\n%s", banned, ruleset)
		}
	}
}

// This table drops and counts. It must never translate an address: that is the
// published table's job, and a source rewrite here would destroy the real
// client addresses the whole design exists to preserve.
func TestProtectionNeverTranslatesAnAddress(t *testing.T) {
	cfg := protectCfg()
	cfg.Protect.PacketsPerSec = 400
	cfg.Protect.NewConnsPerSec = 20
	ruleset := BuildProtectRuleset(ProtectSpecFrom(cfg))

	for _, banned := range []string{"masquerade", "snat", "dnat"} {
		if strings.Contains(ruleset, banned) {
			t.Errorf("found %q in the protection ruleset:\n%s", banned, ruleset)
		}
	}
}

// The drops have to happen before the traffic is translated and forwarded, or
// the attack has already been sent down the tunnel and paid for. dstnat is
// -100, conntrack is -200: a chain needing connection state has exactly one
// window, between them.
func TestProtectionRunsBeforeDestinationNAT(t *testing.T) {
	cfg := protectCfg()
	cfg.Protect.DropInvalid = true
	cfg.Protect.DropBogusTCP = true
	ruleset := BuildProtectRuleset(ProtectSpecFrom(cfg))

	if !strings.Contains(ruleset, "hook prerouting priority raw") {
		t.Error("the cheap drops must run at raw priority, before conntrack")
	}
	if !strings.Contains(ruleset, "hook prerouting priority mangle") {
		t.Error("stateful checks must run at mangle priority: after conntrack, before dstnat")
	}
	if strings.Contains(ruleset, "priority dstnat") || strings.Contains(ruleset, "priority filter") {
		t.Errorf("a chain runs at or after translation, too late to protect the tunnel:\n%s", ruleset)
	}
}

// A limit with no parking configured drops the excess and nothing else. Parking
// is a much bigger hammer - it blocks a source outright for minutes, including
// the traffic that was within the limit - so it has to be asked for.
func TestSourcesAreOnlyParkedWhenBlockingIsConfigured(t *testing.T) {
	cfg := protectCfg()
	cfg.Protect.PacketsPerSec = 400

	if got := BuildProtectRuleset(ProtectSpecFrom(cfg)); strings.Contains(got, "@blocked") {
		t.Errorf("sources are parked without a block time configured:\n%s", got)
	}

	cfg.Protect.BlockSeconds = 600
	got := BuildProtectRuleset(ProtectSpecFrom(cfg))
	if !strings.Contains(got, "add @blocked { ip saddr }") {
		t.Errorf("a block time is set but nothing is ever added to the blocklist:\n%s", got)
	}
	if !strings.Contains(got, "ip saddr @blocked counter drop") {
		t.Errorf("the blocklist is populated but never consulted:\n%s", got)
	}
}

// The blocklist check has to come first, or a parked source still costs a
// conntrack entry and a walk through every limiter on every packet - which is
// the whole cost the parking was meant to avoid.
func TestTheBlocklistIsCheckedFirst(t *testing.T) {
	cfg := protectCfg()
	cfg.Protect.PacketsPerSec = 400
	cfg.Protect.BlockSeconds = 600
	cfg.Protect.DropBogusTCP = true
	ruleset := BuildProtectRuleset(ProtectSpecFrom(cfg))

	blocked := strings.Index(ruleset, "ip saddr @blocked")
	bogus := strings.Index(ruleset, "tcp flags")
	if blocked < 0 || bogus < 0 {
		t.Fatalf("expected both rules to be present:\n%s", ruleset)
	}
	if blocked > bogus {
		t.Error("the blocklist is consulted after other work has already been done")
	}
}

// Source-engine limiting must only ever match connectionless packets. A player
// already in the game sends sequence-numbered ones, and a limit that caught
// those would throttle gameplay itself - at a rate chosen for queries, which is
// orders of magnitude too low.
func TestQueryLimitingOnlyMatchesConnectionlessPackets(t *testing.T) {
	cfg := protectCfg()
	cfg.Protect.QueriesPerSec = 3
	for i := range cfg.Services {
		if cfg.Services[i].Proto == "udp" {
			cfg.Services[i].SourceEngine = true
		}
	}
	ruleset := BuildProtectRuleset(ProtectSpecFrom(cfg))

	for _, line := range strings.Split(ruleset, "\n") {
		if !strings.Contains(line, "@query_rate") {
			continue
		}
		if !strings.Contains(line, "@th,64,32 0xffffffff") {
			t.Errorf("query limiting matches more than the connectionless packets: %q", line)
		}
		return
	}
	t.Fatalf("no query limiting rule was generated:\n%s", ruleset)
}

// A service nobody marked as Source-engine must not have its game traffic rate
// limited as if it were queries.
func TestQueryLimitingNeedsAServiceToOptIn(t *testing.T) {
	cfg := protectCfg()
	cfg.Protect.QueriesPerSec = 3 // and no service marked
	if got := BuildProtectRuleset(ProtectSpecFrom(cfg)); got != "" {
		t.Errorf("query limiting was generated with no service opted in:\n%s", got)
	}
}

// The legacy-query drop takes only the two deprecated type bytes, before
// conntrack, on the Source-engine ports. It must not touch the three live
// query types (0x54-0x56) or in-game traffic, and it must match the
// connectionless header first, exactly as the query-rate limiter does.
func TestLegacyQueryDropIsNarrowAndStateless(t *testing.T) {
	cfg := protectCfg()
	cfg.Protect.DropLegacyQueries = true
	for i := range cfg.Services {
		if cfg.Services[i].Proto == "udp" {
			cfg.Services[i].SourceEngine = true
		}
	}
	ruleset := BuildProtectRuleset(ProtectSpecFrom(cfg))

	var rule string
	for _, line := range strings.Split(ruleset, "\n") {
		if strings.Contains(line, CounterLegacyQ) {
			rule = line
			break
		}
	}
	if rule == "" {
		t.Fatalf("no legacy-query drop was generated:\n%s", ruleset)
	}
	if !strings.Contains(rule, "@th,64,32 0xffffffff") {
		t.Errorf("the drop matches more than connectionless packets: %q", rule)
	}
	if !strings.Contains(rule, "{ 0x57, 0x69 }") {
		t.Errorf("the drop is not scoped to the two legacy type bytes: %q", rule)
	}
	if !strings.Contains(rule, "drop") {
		t.Errorf("the legacy-query rule does not drop: %q", rule)
	}
	// It belongs in the raw chain, before conntrack: these are junk, and a
	// junk packet must not cost a conntrack entry.
	rawEnd := strings.Index(ruleset, "chain filter")
	if rawEnd < 0 || strings.Index(ruleset, CounterLegacyQ) > rawEnd {
		t.Errorf("the legacy-query drop is not in the raw chain:\n%s", ruleset)
	}
	// The live queries must survive: no rule may match their type bytes.
	for _, live := range []string{"0x54", "0x55", "0x56"} {
		if strings.Contains(rule, live) {
			t.Errorf("the drop mentions a live query type %s: %q", live, rule)
		}
	}
}

// Like the query-rate limiter, the drop needs a Source-engine port to scope
// to: with none it activates nothing rather than dropping on every UDP port.
func TestLegacyQueryDropNeedsASourceEnginePort(t *testing.T) {
	cfg := protectCfg()
	cfg.Protect.DropLegacyQueries = true // and no service marked Source engine
	if got := BuildProtectRuleset(ProtectSpecFrom(cfg)); got != "" {
		t.Errorf("the legacy-query drop generated a ruleset with nothing opted in:\n%s", got)
	}
}

// Every limiter is counted, because a limit whose effect cannot be seen turns a
// tuning mistake into an unexplained outage: "players cannot connect" looks
// exactly like the service being down.
func TestEveryDropIsCounted(t *testing.T) {
	cfg := protectCfg()
	cfg.Protect.NewConnsPerSec = 20
	cfg.Protect.PacketsPerSec = 400
	cfg.Protect.MaxConnsPerSource = 50
	cfg.Protect.BlockSeconds = 600
	cfg.Protect.DropInvalid = true
	cfg.Protect.DropBogusTCP = true
	cfg.Protect.DropSpoofed = true
	// Every drop means every drop: the legacy-query rule must be rendered
	// here too, so it needs its toggle and a Source-engine port to scope to.
	cfg.Protect.DropLegacyQueries = true
	for i := range cfg.Services {
		if cfg.Services[i].Proto == "udp" {
			cfg.Services[i].SourceEngine = true
		}
	}
	ruleset := BuildProtectRuleset(ProtectSpecFrom(cfg))

	for _, line := range strings.Split(ruleset, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasSuffix(trimmed, `"`) || !strings.Contains(trimmed, " drop ") {
			continue
		}
		if !strings.Contains(trimmed, "counter drop") {
			t.Errorf("a drop with no counter in front of it: %q", trimmed)
		}
	}
}

// The counters and the blocklist are read back out of the kernel, because the
// kernel is the only thing that knows: reloading the table resets them.
func TestProtectStateIsReadFromTheKernel(t *testing.T) {
	const out = `{"nftables": [
		{"metainfo": {"version": "1.0.6"}},
		{"set": {"name": "blocked", "table": "failover_protect",
			"elem": [{"elem": {"val": "198.51.100.7", "expires": 421}}, "203.0.113.9"]}},
		{"set": {"name": "geo_lockdown_udp", "table": "failover_protect",
			"elem": [{"elem": {"val": 27015, "expires": 42}}]}},
		{"set": {"name": "geo_lockdown_eu", "table": "failover_protect",
			"elem": [25565]}},
		{"rule": {"chain": "filter", "comment": "packet-rate",
			"expr": [{"match": {}}, {"counter": {"packets": 1200, "bytes": 96000}}, {"drop": null}]}},
		{"rule": {"chain": "raw", "comment": "bogus-tcp",
			"expr": [{"counter": {"packets": 3, "bytes": 180}}, {"drop": null}]}},
		{"rule": {"chain": "raw", "comment": "bogus-tcp",
			"expr": [{"counter": {"packets": 5, "bytes": 300}}, {"drop": null}]}},
		{"rule": {"chain": "raw", "comment": "geo-trip:minecraft",
			"expr": [{"counter": {"packets": 7, "bytes": 420}}]}},
		{"rule": {"chain": "raw", "comment": "blocked",
			"expr": [{"counter": {"packets": 4, "bytes": 240}}, {"drop": null}]}}
	]}`

	counters, blocked, locked, err := parseProtectState(out)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// An engaged region lock looks exactly like the service being down to
	// everyone outside the region, so it has to read back out of the kernel
	// with the counters - the set is where the truth lives. Matched on the
	// two exact names the generator emits: geo_lockdown_eu above is what a
	// region named "lockdown_eu" renders to, an operator's set in the same
	// namespace, and reading it as lock state would surface phantom locks for
	// a protocol called "eu".
	if len(locked) != 1 || locked[0].Proto != "udp" || locked[0].Port != 27015 || locked[0].ExpiresSec != 42 {
		t.Errorf("engaged locks read as %+v, want udp/27015 releasing in 42s", locked)
	}
	// One limit is often several rules - the bogus-TCP filter alone is seven -
	// and they must come back as one figure per limit, not a card per rule:
	// seven identical zero tiles is what this looked like before.
	if len(counters) != 4 {
		t.Fatalf("read %d counters, want 4 (one per distinct comment): %+v", len(counters), counters)
	}
	byName := map[string]model.ProtectCounter{}
	for _, c := range counters {
		byName[c.Name] = c
	}
	if byName["packet-rate"].Packets != 1200 {
		t.Errorf("packet-rate counter read as %d", byName["packet-rate"].Packets)
	}
	if byName["bogus-tcp"].Packets != 8 {
		t.Errorf("two bogus-tcp rules summed to %d packets, want 8", byName["bogus-tcp"].Packets)
	}
	// The trip counter observes the auto-lock threshold and drops nothing;
	// the portal's "packets dropped" total reads this flag rather than
	// sniffing the counter's name, so it has to be right here.
	if byName["geo-trip:minecraft"].Drops {
		t.Errorf("the auto-lock trip counter reads as a drop counter")
	}
	if !byName["packet-rate"].Drops || !byName["bogus-tcp"].Drops || !byName["blocked"].Drops {
		t.Errorf("a drop counter reads as observing only: %+v", counters)
	}
	if len(blocked) != 2 {
		t.Fatalf("read %d blocked sources, want 2: %+v", len(blocked), blocked)
	}
	// An element with time left sorts ahead of one with none, so the portal
	// lists the freshest block first.
	if blocked[0].Address != "198.51.100.7" || blocked[0].ExpiresSec != 421 {
		t.Errorf("first blocked source read as %+v", blocked[0])
	}
}

// nftables refuses a set with a repeated element, and refuses one with
// overlapping intervals - and it refuses the whole table, so a second service
// row on a port another one already uses would take every limit down with it.
// Two rows on port 80 is an ordinary thing to configure, not an error worth
// refusing a save over.
func TestServicesSharingPortsStillProduceALoadableSet(t *testing.T) {
	cfg := protectCfg()
	cfg.Protect.NewConnsPerSec = 20
	cfg.Services = []model.Service{
		{Name: "http", Proto: "tcp", Port: 80, Enabled: true},
		{Name: "http-alt", Proto: "tcp", Port: 80, Enabled: true},
		{Name: "https", Proto: "tcp", Port: 443, Enabled: true},
	}
	ruleset := BuildProtectRuleset(ProtectSpecFrom(cfg))

	if !strings.Contains(ruleset, "tcp dport { 80, 443 }") {
		t.Errorf("ports were not deduplicated:\n%s", ruleset)
	}
}

// The same for overlapping ranges: a service on 27015 beside one on
// 27015-27020 is one interval to the kernel, and listing both is rejected.
func TestOverlappingPortRangesAreMerged(t *testing.T) {
	cfg := protectCfg()
	cfg.Protect.PacketsPerSec = 400
	cfg.Services = []model.Service{
		{Name: "gmod", Proto: "udp", Port: 27015, Enabled: true},
		{Name: "gmod-range", Proto: "udp", Port: 27015, PortEnd: 27020, Enabled: true},
		{Name: "hltv", Proto: "udp", Port: 27021, Enabled: true}, // adjacent, so it joins them
	}
	ruleset := BuildProtectRuleset(ProtectSpecFrom(cfg))

	if !strings.Contains(ruleset, "udp dport 27015-27021") {
		t.Errorf("overlapping and adjacent ranges were not merged:\n%s", ruleset)
	}
}

// Parking a source needs the set to be dynamic. Without that flag the kernel
// refuses every add from the packet path and rejects the whole table - so the
// rate limits would be gone as well, not merely the parking.
func TestTheBlocklistSetIsDynamic(t *testing.T) {
	cfg := protectCfg()
	cfg.Protect.PacketsPerSec = 400
	cfg.Protect.BlockSeconds = 600
	ruleset := BuildProtectRuleset(ProtectSpecFrom(cfg))

	block := strings.Index(ruleset, "set blocked {")
	if block < 0 {
		t.Fatalf("no blocklist set was generated:\n%s", ruleset)
	}
	decl := ruleset[block:]
	if end := strings.Index(decl, "}"); end >= 0 {
		decl = decl[:end]
	}
	if !strings.Contains(decl, "flags dynamic") {
		t.Errorf("the blocklist set is not dynamic, so nothing can be added to it:\n%s", decl)
	}
	if !strings.Contains(decl, "size ") {
		t.Errorf("the blocklist set has no size bound:\n%s", decl)
	}
}

// ---------------------------------------------------------------------------
// Region locks
// ---------------------------------------------------------------------------

// geoCfg is protectCfg with one region and the minecraft service locked to it,
// and nothing else switched on - so anything the ruleset contains is the lock.
func geoCfg() model.Config {
	cfg := protectCfg()
	cfg.Protect.Regions = []model.GeoRegion{
		{Name: "oceania", CIDRs: []string{"1.128.0.0/11", "101.160.0.0/11"}},
	}
	for i := range cfg.Services {
		if cfg.Services[i].Name == "minecraft" {
			cfg.Services[i].GeoRegions = []string{"oceania"}
		}
	}
	return cfg
}

// A site whose only protection is a region lock still needs the table loaded,
// so the lock has to make the spec active on its own.
func TestARegionLockActivatesTheTableOnItsOwn(t *testing.T) {
	ruleset := BuildProtectRuleset(ProtectSpecFrom(geoCfg()))
	if ruleset == "" {
		t.Fatal("a region lock alone generated no ruleset")
	}
	if !strings.Contains(ruleset, "set geo_oceania {") {
		t.Errorf("no region set was generated:\n%s", ruleset)
	}
	// interval, because the elements are networks: without the flag the
	// kernel refuses the first CIDR element and the whole table with it.
	if !strings.Contains(ruleset, "flags interval") {
		t.Errorf("the region set is not an interval set:\n%s", ruleset)
	}
	want := `tcp dport 25565 ip saddr != @geo_oceania counter drop comment "geo:minecraft"`
	if !strings.Contains(ruleset, want) {
		t.Errorf("the lock rule is missing or malformed; want %q in:\n%s", want, ruleset)
	}
}

// The lock matches every packet, statelessly, before conntrack. The set answer
// is fixed per address so an allowed player can never be newly caught by it,
// an out-of-region flood must not cost conntrack entries, and engaging a lock
// mid-attack has to end flows already in progress rather than grandfather them.
func TestRegionLocksMatchEveryPacketBeforeConntrack(t *testing.T) {
	ruleset := BuildProtectRuleset(ProtectSpecFrom(geoCfg()))
	rawChain := ruleset[:strings.Index(ruleset, "chain filter")]
	if !strings.Contains(rawChain, "@geo_oceania") {
		t.Errorf("the lock rule is not in the raw chain:\n%s", ruleset)
	}
	for _, line := range strings.Split(ruleset, "\n") {
		if strings.Contains(line, "@geo_oceania") && strings.Contains(line, "ct state") {
			t.Errorf("a region lock depends on connection state: %q", line)
		}
	}
}

// A region nothing references is a draft in the portal, not a rule. It must
// render no set - a set nothing consults is dead weight the kernel holds - and
// with nothing else configured, no table at all.
func TestARegionNobodyReferencesRendersNothing(t *testing.T) {
	cfg := geoCfg()
	for i := range cfg.Services {
		cfg.Services[i].GeoRegions = nil
	}
	if got := BuildProtectRuleset(ProtectSpecFrom(cfg)); got != "" {
		t.Errorf("an unreferenced region generated a ruleset:\n%s", got)
	}

	cfg.Protect.PacketsPerSec = 400
	if got := BuildProtectRuleset(ProtectSpecFrom(cfg)); strings.Contains(got, "geo_") {
		t.Errorf("an unreferenced region generated a set beside the other limits:\n%s", got)
	}
}

// nftables rejects a whole table over one overlapping set element, and a
// pasted country list being generous - a duplicate line, a /24 inside a /8 -
// is ordinary, not an error worth taking every limit down over. CIDR blocks
// either nest or are disjoint, so dropping the contained ones is a full merge.
func TestOverlappingRegionNetworksAreMerged(t *testing.T) {
	cfg := geoCfg()
	cfg.Protect.Regions = []model.GeoRegion{
		{Name: "oceania", CIDRs: []string{"1.0.0.0/8", "1.2.3.0/24", "1.0.0.0/8", "2.0.0.0/16"}},
	}
	ruleset := BuildProtectRuleset(ProtectSpecFrom(cfg))

	if strings.Contains(ruleset, "1.2.3.0/24") {
		t.Errorf("a network contained in another was kept, which nft refuses to load:\n%s", ruleset)
	}
	if strings.Count(ruleset, "1.0.0.0/8") != 1 {
		t.Errorf("a duplicate network was kept:\n%s", ruleset)
	}
	if !strings.Contains(ruleset, "2.0.0.0/16") {
		t.Errorf("a disjoint network was lost in the merge:\n%s", ruleset)
	}
}

// Several regions on one service are a union allowlist: negated lookups AND
// together in one rule, so a packet is dropped only when it is inside none of
// them. Two rules would drop everything outside the intersection instead.
func TestALockOnSeveralRegionsAdmitsAnyOfThem(t *testing.T) {
	cfg := geoCfg()
	cfg.Protect.Regions = append(cfg.Protect.Regions,
		model.GeoRegion{Name: "aotearoa", CIDRs: []string{"49.224.0.0/14"}})
	for i := range cfg.Services {
		if cfg.Services[i].Name == "minecraft" {
			cfg.Services[i].GeoRegions = []string{"oceania", "aotearoa"}
		}
	}
	ruleset := BuildProtectRuleset(ProtectSpecFrom(cfg))

	want := `ip saddr != @geo_oceania ip saddr != @geo_aotearoa counter drop`
	if !strings.Contains(ruleset, want) {
		t.Errorf("want the negations ANDed in one rule (%q) in:\n%s", want, ruleset)
	}
}

// A reference that resolves to nothing - a region no list defines, or one
// whose networks are empty - must lock nothing rather than invent a
// drop-everything rule. web.validate refuses both states at save time, so
// meeting one here means an older or hand-edited blob, and taking a published
// service off the air in silence is the worse of the two silent answers.
func TestADanglingRegionReferenceLocksNothing(t *testing.T) {
	cfg := geoCfg()
	for i := range cfg.Services {
		if cfg.Services[i].Name == "minecraft" {
			cfg.Services[i].GeoRegions = []string{"atlantis"}
		}
	}
	if got := BuildProtectRuleset(ProtectSpecFrom(cfg)); got != "" {
		t.Errorf("a dangling region reference generated rules:\n%s", got)
	}
}

// The fail-open rule holds per reference, not per service. An allow lock is
// one rule ANDing negated lookups, so emitting it for just the references
// that resolve would silently narrow the allowlist - fail closed for exactly
// the players the missing region was meant to admit. Any dangling reference
// on an allow lock therefore means no rule for that service. The block
// direction is the opposite shape, a rule per region, so dropping only what
// resolves is the fail-open answer there: the resolved regions keep their
// rules and the dangling one simply drops nothing.
func TestAPartlyDanglingAllowLockLocksNothing(t *testing.T) {
	cfg := geoCfg()
	for i := range cfg.Services {
		if cfg.Services[i].Name == "minecraft" {
			cfg.Services[i].GeoRegions = []string{"oceania", "atlantis"}
		}
	}
	if got := BuildProtectRuleset(ProtectSpecFrom(cfg)); got != "" {
		t.Errorf("a partly dangling allow lock generated rules, which can only be stricter than what was configured:\n%s", got)
	}

	for i := range cfg.Services {
		if cfg.Services[i].Name == "minecraft" {
			cfg.Services[i].GeoBlock = true
		}
	}
	got := BuildProtectRuleset(ProtectSpecFrom(cfg))
	want := `tcp dport 25565 ip saddr @geo_oceania counter drop comment "geo:minecraft"`
	if !strings.Contains(got, want) {
		t.Errorf("a partly dangling block lock lost its resolved region; want %q in:\n%s", want, got)
	}
}

// Region sets share the geo_ namespace with the per-protocol lockdown sets,
// so a region named "lockdown-tcp" folds onto the set the automatic lock
// writes to - two definitions of one name with two different types, and nft
// rejects the whole table over it, every other limit included. web.validate
// refuses the name at save; an older blob carrying one has its region set
// shifted out of the way instead, so both the lock and the region still work.
func TestARegionNamedLikeTheLockdownSetCannotCollide(t *testing.T) {
	cfg := geoCfg()
	cfg.Protect.Regions[0].Name = "lockdown-tcp"
	for i := range cfg.Services {
		if cfg.Services[i].Name == "minecraft" {
			cfg.Services[i].GeoRegions = []string{"lockdown-tcp"}
			cfg.Services[i].GeoAutoPPS = 50000
		}
	}
	ruleset := BuildProtectRuleset(ProtectSpecFrom(cfg))

	if n := strings.Count(ruleset, "set geo_lockdown_tcp {"); n != 1 {
		t.Errorf("the lockdown set is defined %d times, which nft refuses to load:\n%s", n, ruleset)
	}
	if !strings.Contains(ruleset, "set geo_lockdown_tcp_ {") {
		t.Errorf("the colliding region's set was not shifted aside:\n%s", ruleset)
	}
	if !strings.Contains(ruleset, "ip saddr != @geo_lockdown_tcp_ ") {
		t.Errorf("the lock rule does not reference the shifted set:\n%s", ruleset)
	}
}

// The automatic lock: with a threshold set, the port stays open to the world
// until its traffic exceeds it, and only then does the region drop apply. Both
// halves live in the kernel - the trigger writes the port into a dynamic set
// exactly the way the blocklist parks a source, and the agent decides nothing.
func TestAnAutoLockOnlyDropsWhileEngaged(t *testing.T) {
	cfg := geoCfg()
	for i := range cfg.Services {
		if cfg.Services[i].Name == "minecraft" {
			cfg.Services[i].GeoAutoPPS = 50000
		}
	}
	ruleset := BuildProtectRuleset(ProtectSpecFrom(cfg))

	trigger := `tcp dport 25565 limit rate over 50000/second update @geo_lockdown_tcp { th dport timeout 60s } counter comment "geo-trip:minecraft"`
	if !strings.Contains(ruleset, trigger) {
		t.Errorf("want the trigger rule %q in:\n%s", trigger, ruleset)
	}
	drop := `tcp dport 25565 th dport @geo_lockdown_tcp ip saddr != @geo_oceania counter drop comment "geo:minecraft"`
	if !strings.Contains(ruleset, drop) {
		t.Errorf("want the conditional drop %q in:\n%s", drop, ruleset)
	}
	// The trigger must come first: it has to see the whole flood, including
	// the packets the drop discards, or the lock would release mid-attack -
	// the surviving in-region traffic alone falls under the threshold, the
	// entry expires, and a burst gets through every timeout.
	if strings.Index(ruleset, trigger) > strings.Index(ruleset, drop) {
		t.Errorf("the trigger runs after the drop, so a locked flood cannot refresh the lock:\n%s", ruleset)
	}
	// dynamic, for the same reason the blocklist is: without the flag the
	// kernel refuses every update from the packet path and the whole table
	// fails to load.
	lock := ruleset[strings.Index(ruleset, "set geo_lockdown_tcp {"):]
	lock = lock[:strings.Index(lock, "}")]
	if !strings.Contains(lock, "flags dynamic,timeout") {
		t.Errorf("the lockdown set cannot be written from the packet path:\n%s", lock)
	}
	// No udp lockdown set: nothing udp is auto-locked, and a set per protocol
	// exists precisely so a tcp flood cannot lock a udp service on the same
	// port number.
	if strings.Contains(ruleset, "geo_lockdown_udp") {
		t.Errorf("a udp lockdown set was generated with no udp auto lock:\n%s", ruleset)
	}
}

// A lock with no threshold is unconditional, and must not gain the lockdown
// machinery: the plain drop needs no dynamic set and no trigger.
func TestAnUnconditionalLockHasNoLockdownMachinery(t *testing.T) {
	ruleset := BuildProtectRuleset(ProtectSpecFrom(geoCfg()))
	for _, banned := range []string{"geo_lockdown", "limit rate", "geo-trip"} {
		if strings.Contains(ruleset, banned) {
			t.Errorf("an unconditional lock generated %q:\n%s", banned, ruleset)
		}
	}
}

// The release lag is configurable, and zero means the shipped minute - an
// older blob predating the field must behave, not lock forever or not at all.
func TestTheLockReleaseLagIsConfigurable(t *testing.T) {
	cfg := geoCfg()
	for i := range cfg.Services {
		if cfg.Services[i].Name == "minecraft" {
			cfg.Services[i].GeoAutoPPS = 50000
		}
	}
	cfg.Protect.GeoLockSeconds = 120
	ruleset := BuildProtectRuleset(ProtectSpecFrom(cfg))
	if !strings.Contains(ruleset, "timeout 120s") {
		t.Errorf("the configured release lag did not reach the ruleset:\n%s", ruleset)
	}
	if strings.Contains(ruleset, "timeout 60s") {
		t.Errorf("the default lag appears beside the configured one:\n%s", ruleset)
	}
}

// Region names become nftables identifiers. Validation refuses anything
// outside the slug, but the ruleset must stay loadable whatever an older or
// hand-edited blob carries - folded into shape, never handed to nft to refuse,
// because nft refuses the whole table and every other limit with it.
func TestRegionNamesAreFoldedToLoadableSetNames(t *testing.T) {
	cfg := geoCfg()
	cfg.Protect.Regions[0].Name = "South Pacific!"
	for i := range cfg.Services {
		if cfg.Services[i].Name == "minecraft" {
			cfg.Services[i].GeoRegions = []string{"South Pacific!"}
		}
	}
	ruleset := BuildProtectRuleset(ProtectSpecFrom(cfg))
	if !strings.Contains(ruleset, "@geo_south_pacific_") {
		t.Errorf("the name was not folded to an identifier:\n%s", ruleset)
	}
	if strings.Contains(ruleset, "South Pacific!") {
		t.Errorf("the raw name reached the file:\n%s", ruleset)
	}
}

// Two names the folding makes identical are one set to nft, and defining it
// twice rejects the whole table - the exact failure the folding exists to
// prevent, so the deduplication has to happen on the folded name. validate
// refuses the collision at save; this is for the blob that predates it.
func TestCollidingFoldedRegionNamesEmitOneSet(t *testing.T) {
	cfg := geoCfg()
	cfg.Protect.Regions = []model.GeoRegion{
		{Name: "south pacific", CIDRs: []string{"1.128.0.0/11"}},
		{Name: "south-pacific", CIDRs: []string{"49.224.0.0/14"}},
	}
	for i := range cfg.Services {
		if cfg.Services[i].Name == "minecraft" {
			cfg.Services[i].GeoRegions = []string{"south pacific", "south-pacific"}
		}
	}
	ruleset := BuildProtectRuleset(ProtectSpecFrom(cfg))

	if got := strings.Count(ruleset, "set geo_south_pacific {"); got != 1 {
		t.Errorf("the folded set is defined %d times; nft loads it once or not at all:\n%s", got, ruleset)
	}
}

// The inverted lock: block the named region, admit everywhere else. A positive
// set match rather than a negated one, and never both on one rule.
func TestABlockLockDropsOnlyTheRegion(t *testing.T) {
	cfg := geoCfg()
	for i := range cfg.Services {
		if cfg.Services[i].Name == "minecraft" {
			cfg.Services[i].GeoBlock = true
		}
	}
	ruleset := BuildProtectRuleset(ProtectSpecFrom(cfg))

	want := `tcp dport 25565 ip saddr @geo_oceania counter drop comment "geo:minecraft"`
	if !strings.Contains(ruleset, want) {
		t.Errorf("want the block rule %q in:\n%s", want, ruleset)
	}
	for _, line := range strings.Split(ruleset, "\n") {
		if strings.Contains(line, "@geo_") && strings.Contains(line, "!=") {
			t.Errorf("a block lock generated a negated match, which is the allow direction: %q", line)
		}
	}
}

// Several blocked regions are an OR - drop a source inside any of them - and
// one rule ANDs its matches, so it has to be one rule per region. A single
// rule with two positive matches would drop only their intersection, which is
// usually nothing, and the lock would silently admit both regions.
func TestABlockOnSeveralRegionsDropsAnyOfThem(t *testing.T) {
	cfg := geoCfg()
	cfg.Protect.Regions = append(cfg.Protect.Regions,
		model.GeoRegion{Name: "aotearoa", CIDRs: []string{"49.224.0.0/14"}})
	for i := range cfg.Services {
		if cfg.Services[i].Name == "minecraft" {
			cfg.Services[i].GeoRegions = []string{"oceania", "aotearoa"}
			cfg.Services[i].GeoBlock = true
		}
	}
	ruleset := BuildProtectRuleset(ProtectSpecFrom(cfg))

	for _, want := range []string{
		`tcp dport 25565 ip saddr @geo_oceania counter drop comment "geo:minecraft"`,
		`tcp dport 25565 ip saddr @geo_aotearoa counter drop comment "geo:minecraft"`,
	} {
		if !strings.Contains(ruleset, want) {
			t.Errorf("want %q in:\n%s", want, ruleset)
		}
	}
	for _, line := range strings.Split(ruleset, "\n") {
		if strings.Contains(line, "@geo_oceania") && strings.Contains(line, "@geo_aotearoa") {
			t.Errorf("two blocked regions share one rule, which drops their intersection instead of their union: %q", line)
		}
	}
}

// The automatic variant of the block direction: the same trigger and lockdown
// set as the allow direction, with each block rule conditional on the port
// being locked.
func TestAnAutoBlockOnlyDropsWhileEngaged(t *testing.T) {
	cfg := geoCfg()
	for i := range cfg.Services {
		if cfg.Services[i].Name == "minecraft" {
			cfg.Services[i].GeoBlock = true
			cfg.Services[i].GeoAutoPPS = 50000
		}
	}
	ruleset := BuildProtectRuleset(ProtectSpecFrom(cfg))

	if !strings.Contains(ruleset, `update @geo_lockdown_tcp { th dport timeout 60s }`) {
		t.Errorf("no trigger rule was generated:\n%s", ruleset)
	}
	want := `tcp dport 25565 th dport @geo_lockdown_tcp ip saddr @geo_oceania counter drop comment "geo:minecraft"`
	if !strings.Contains(ruleset, want) {
		t.Errorf("want the conditional block %q in:\n%s", want, ruleset)
	}
}

// The Drops flag is the rule's own verdict, read back beside the counter, not
// an inference from the comment. A counter that observes without dropping
// must read as observing whatever it is called, and a rule that drops must
// read as dropping under a name the parser has never seen - the alternative
// was an exception list keyed on comment kinds, stale the day the generator
// gains its next observe-only counter.
func TestCounterDropsIsTheRuleVerdictNotTheName(t *testing.T) {
	const out = `{"nftables": [
		{"rule": {"chain": "raw", "comment": "geo:watch-only",
			"expr": [{"counter": {"packets": 1, "bytes": 60}}]}},
		{"rule": {"chain": "raw", "comment": "brand-new-limit",
			"expr": [{"counter": {"packets": 2, "bytes": 120}}, {"drop": null}]}}
	]}`

	counters, _, _, err := parseProtectState(out)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	byName := map[string]model.ProtectCounter{}
	for _, c := range counters {
		byName[c.Name] = c
	}
	if byName["geo:watch-only"].Drops {
		t.Error("a rule with no drop verdict reads as dropping")
	}
	if !byName["brand-new-limit"].Drops {
		t.Error("a dropping rule under an unknown name reads as observing only")
	}
}
