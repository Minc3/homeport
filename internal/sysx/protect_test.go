package sysx

import (
	"strings"
	"testing"

	"github.com/quinlan102/homeport/internal/model"
)

func protectCfg() model.Config {
	cfg := model.Defaults()
	cfg.Frontend.PublicIface = "eth0"
	cfg.Protect.Enabled = true
	return cfg
}

// The state every site is in. A feature that generates rules for somebody who
// never asked for it is a feature that drops their traffic for reasons they
// cannot see, so "off" has to mean no table at all - not an empty one.
func TestProtectionOffGeneratesNothing(t *testing.T) {
	if got := BuildProtectRuleset(ProtectSpecFrom(model.Defaults())); got != "" {
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
		{"rule": {"chain": "filter", "comment": "packet-rate",
			"expr": [{"match": {}}, {"counter": {"packets": 1200, "bytes": 96000}}, {"drop": null}]}},
		{"rule": {"chain": "raw", "comment": "blocked",
			"expr": [{"counter": {"packets": 4, "bytes": 240}}, {"drop": null}]}}
	]}`

	counters, blocked, err := parseProtectState(out)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(counters) != 2 {
		t.Fatalf("read %d counters, want 2: %+v", len(counters), counters)
	}
	byName := map[string]int64{}
	for _, c := range counters {
		byName[c.Name] = c.Packets
	}
	if byName["packet-rate"] != 1200 {
		t.Errorf("packet-rate counter read as %d", byName["packet-rate"])
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
