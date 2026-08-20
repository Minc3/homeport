package sysx

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/quinlan102/homeport/internal/model"
)

// Edge protection
// ---------------
// Rate limiting and hygiene for traffic arriving from the internet, in a table
// of its own for the same reason the egress source NAT has one: NFTTable
// carries the published services and is asserted to contain no translation,
// this can be added and removed on its own, and a reader can tell at a glance
// which rules publish and which rules drop.
//
// Two chains, because they need different information:
//
//	raw    (priority -300) runs before conntrack. Cheapest drops go here - the
//	                       blocklist and the malformed packets - so a flood
//	                       costs no conntrack entries.
//	filter (priority -150) runs after conntrack and before dstnat (-100), which
//	                       is the only window where a rule can both know a
//	                       packet's connection state and still stop it before it
//	                       is translated and forwarded down a tunnel.
//
// Every rule is scoped to the public interface. Nothing here can match a probe,
// the control channel, or anything else on the overlay - a limiter that could
// drop the system's own health checks would make the frontend conclude a link
// had failed and move traffic because of its own firewall.

// NFTProtectTable is the frontend's edge filtering table.
const NFTProtectTable = "failover_protect"

// ProtectService is one published service as the filter needs to see it.
type ProtectService struct {
	Name         string
	Proto        string
	Port         int
	PortEnd      int
	SourceEngine bool
	CeilingPPS   int
}

// ProtectSpec is everything the ruleset is rendered from.
type ProtectSpec struct {
	PublicIface string

	NewConnsPerSec    int
	MaxConnsPerSource int
	PacketsPerSec     int
	QueriesPerSec     int
	BlockSeconds      int

	DropInvalid  bool
	DropBogusTCP bool
	DropSpoofed  bool

	Services []ProtectService
}

// active reports whether anything at all would be generated. A spec with the
// switch on but every threshold at zero is a table with no rules in it, and
// loading that is a worse answer than loading nothing.
func (s ProtectSpec) active() bool {
	if s.PublicIface == "" {
		return false
	}
	if s.DropInvalid || s.DropBogusTCP || s.DropSpoofed {
		return true
	}
	if s.NewConnsPerSec > 0 || s.MaxConnsPerSource > 0 || s.PacketsPerSec > 0 {
		return true
	}
	if s.QueriesPerSec > 0 && len(s.sourceEnginePorts()) > 0 {
		return true
	}
	for _, sv := range s.Services {
		if sv.CeilingPPS > 0 {
			return true
		}
	}
	return false
}

func (s ProtectSpec) ports(proto string) []string {
	var out []portRange
	for _, sv := range s.Services {
		if !strings.EqualFold(sv.Proto, proto) {
			continue
		}
		out = append(out, portRange{sv.Port, max(sv.Port, sv.PortEnd)})
	}
	return mergePorts(out)
}

func (s ProtectSpec) sourceEnginePorts() []string {
	var out []portRange
	for _, sv := range s.Services {
		if sv.SourceEngine && strings.EqualFold(sv.Proto, "udp") {
			out = append(out, portRange{sv.Port, max(sv.Port, sv.PortEnd)})
		}
	}
	return mergePorts(out)
}

// portRange is one service's ports, inclusive.
type portRange struct{ lo, hi int }

// mergePorts turns the services' ports into set elements nftables will accept.
//
// It has to merge rather than just list, because an nftables set rejects both a
// repeated element and two intervals that overlap - and the whole table fails
// to load, taking every other limit with it. Two service rows on port 80, or
// one on 27015 beside another on 27015-27020, are both ordinary things for an
// operator to configure and neither is an error worth refusing a save over.
func mergePorts(in []portRange) []string {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(i, j int) bool {
		if in[i].lo != in[j].lo {
			return in[i].lo < in[j].lo
		}
		return in[i].hi < in[j].hi
	})
	merged := []portRange{in[0]}
	for _, r := range in[1:] {
		last := &merged[len(merged)-1]
		// Adjacent as well as overlapping: 80 beside 81-90 is one interval to
		// the kernel, and listing them separately is a rejected duplicate at
		// the boundary rather than a tidiness question.
		if r.lo <= last.hi+1 {
			if r.hi > last.hi {
				last.hi = r.hi
			}
			continue
		}
		merged = append(merged, r)
	}
	out := make([]string, 0, len(merged))
	for _, r := range merged {
		out = append(out, portSpec(r.lo, r.hi))
	}
	return out
}

func portSpec(port, end int) string {
	if end > port {
		return fmt.Sprintf("%d-%d", port, end)
	}
	return fmt.Sprintf("%d", port)
}

func portSet(ports []string) string {
	if len(ports) == 1 {
		return ports[0]
	}
	return "{ " + strings.Join(ports, ", ") + " }"
}

// ProtectSpecFrom reduces the configuration to what the ruleset needs. Returns
// a spec that renders nothing when the feature is off, so the caller has one
// code path either way.
func ProtectSpecFrom(cfg model.Config) ProtectSpec {
	if !cfg.Protect.Enabled {
		return ProtectSpec{}
	}
	p := cfg.Protect
	spec := ProtectSpec{
		PublicIface:       cfg.Frontend.PublicIface,
		NewConnsPerSec:    p.NewConnsPerSec,
		MaxConnsPerSource: p.MaxConnsPerSource,
		PacketsPerSec:     p.PacketsPerSec,
		QueriesPerSec:     p.QueriesPerSec,
		BlockSeconds:      p.BlockSeconds,
		DropInvalid:       p.DropInvalid,
		DropBogusTCP:      p.DropBogusTCP,
		DropSpoofed:       p.DropSpoofed,
	}
	for _, s := range cfg.Services {
		if !s.Enabled {
			continue
		}
		proto := strings.ToLower(s.Proto)
		if proto != "tcp" && proto != "udp" {
			continue
		}
		spec.Services = append(spec.Services, ProtectService{
			Name: s.Name, Proto: proto, Port: s.Port, PortEnd: s.PortEnd,
			SourceEngine: s.SourceEngine, CeilingPPS: s.CeilingPPS,
		})
	}
	return spec
}

// Counter names, which are also the rule comments. The portal reads the
// counters back by these, so an operator can see which limit is doing the
// dropping instead of guessing at why somebody cannot connect.
const (
	CounterBlocked    = "blocked"
	CounterInvalid    = "invalid"
	CounterBogusTCP   = "bogus-tcp"
	CounterSpoofed    = "spoofed"
	CounterConnRate   = "conn-rate"
	CounterConnCount  = "conn-count"
	CounterPacketRate = "packet-rate"
	CounterQueryRate  = "query-rate"
	CounterCeiling    = "ceiling"
)

// BuildProtectRuleset renders the edge filtering table, or "" when there is
// nothing switched on.
func BuildProtectRuleset(spec ProtectSpec) string {
	if !spec.active() {
		return ""
	}
	iface := spec.PublicIface
	park := spec.BlockSeconds > 0

	var b strings.Builder
	b.WriteString("# generated by failover-frontend - do not edit by hand\n")
	b.WriteString("# rate limiting and edge filtering for traffic arriving from the\n")
	b.WriteString("# internet, before it is translated and sent down a tunnel.\n")
	b.WriteString("# every rule is scoped to the public interface, so probes, the\n")
	b.WriteString("# control channel and overlay traffic are out of reach of it.\n\n")

	fmt.Fprintf(&b, "table ip %s\n", NFTProtectTable)
	fmt.Fprintf(&b, "delete table ip %s\n\n", NFTProtectTable)
	fmt.Fprintf(&b, "table ip %s {\n", NFTProtectTable)

	if park {
		b.WriteString("\tset blocked {\n")
		b.WriteString("\t\ttype ipv4_addr\n")
		b.WriteString("\t\tsize 65535\n")
		// `dynamic` is not optional, and its absence is not a small mistake:
		// without it the kernel refuses every `add @blocked` from the packet
		// path and the whole table fails to load - so the rate limits would be
		// gone too, not just the parking.
		b.WriteString("\t\tflags dynamic,timeout\n")
		fmt.Fprintf(&b, "\t\ttimeout %ds\n", spec.BlockSeconds)
		b.WriteString("\t\tcomment \"sources parked by a rate limit; entries expire on their own\"\n")
		b.WriteString("\t}\n\n")
	}
	// One dynamic set per limit rather than one shared: they age at different
	// rates and a shared set would have the busiest limit evicting the others'
	// state.
	dynSet := func(name string, timeout int) {
		fmt.Fprintf(&b, "\tset %s {\n", name)
		b.WriteString("\t\ttype ipv4_addr\n")
		b.WriteString("\t\tsize 65535\n")
		b.WriteString("\t\tflags dynamic,timeout\n")
		fmt.Fprintf(&b, "\t\ttimeout %ds\n", timeout)
		b.WriteString("\t}\n\n")
	}
	if spec.NewConnsPerSec > 0 {
		dynSet("conn_rate", 60)
	}
	if spec.MaxConnsPerSource > 0 {
		dynSet("conn_count", 60)
	}
	if spec.PacketsPerSec > 0 {
		dynSet("packet_rate", 60)
	}
	if spec.QueriesPerSec > 0 && len(spec.sourceEnginePorts()) > 0 {
		dynSet("query_rate", 60)
	}

	// The parking statement, appended to whichever limit tripped. Written the
	// same way everywhere so the blocklist cannot end up populated by one limit
	// and not another.
	blockStmt := ""
	if park {
		blockStmt = "add @blocked { ip saddr } "
	}

	// --- raw: before conntrack -------------------------------------------
	b.WriteString("\tchain raw {\n")
	b.WriteString("\t\ttype filter hook prerouting priority raw; policy accept;\n")
	fmt.Fprintf(&b, "\t\tiifname != %q accept\n", iface)
	if park {
		b.WriteString("\t\t# Parked sources cost one set lookup and nothing else.\n")
		fmt.Fprintf(&b, "\t\tip saddr @blocked counter drop comment %q\n", CounterBlocked)
	}
	if spec.DropBogusTCP {
		b.WriteString("\t\t# Flag combinations no stack produces: scans and crafted floods.\n")
		for _, m := range bogusTCPMatches() {
			fmt.Fprintf(&b, "\t\t%s counter drop comment %q\n", m, CounterBogusTCP)
		}
	}
	if spec.DropSpoofed {
		b.WriteString("\t\t# Source addresses that cannot legitimately arrive from the internet.\n")
		fmt.Fprintf(&b, "\t\tip saddr %s counter drop comment %q\n", martianSet(), CounterSpoofed)
	}
	b.WriteString("\t}\n\n")

	// --- filter: after conntrack, before dstnat ---------------------------
	b.WriteString("\tchain filter {\n")
	b.WriteString("\t\ttype filter hook prerouting priority mangle; policy accept;\n")
	fmt.Fprintf(&b, "\t\tiifname != %q accept\n", iface)

	if spec.DropInvalid {
		b.WriteString("\t\t# Packets conntrack cannot place in any connection.\n")
		fmt.Fprintf(&b, "\t\tct state invalid counter drop comment %q\n", CounterInvalid)
	}

	if tcp := spec.ports("tcp"); len(tcp) > 0 {
		if spec.NewConnsPerSec > 0 {
			b.WriteString("\t\t# Connection attempts per source. Established connections are untouched.\n")
			fmt.Fprintf(&b, "\t\tct state new tcp dport %s add @conn_rate { ip saddr limit rate over %d/second burst %d packets } %scounter drop comment %q\n",
				portSet(tcp), spec.NewConnsPerSec, spec.NewConnsPerSec*2, blockStmt, CounterConnRate)
		}
		if spec.MaxConnsPerSource > 0 {
			b.WriteString("\t\t# Concurrent connections held by one source.\n")
			fmt.Fprintf(&b, "\t\tct state new tcp dport %s add @conn_count { ip saddr ct count over %d } %scounter drop comment %q\n",
				portSet(tcp), spec.MaxConnsPerSource, blockStmt, CounterConnCount)
		}
	}

	if udp := spec.ports("udp"); len(udp) > 0 && spec.PacketsPerSec > 0 {
		b.WriteString("\t\t# Packets per second from one source. A player in a game sends\n")
		b.WriteString("\t\t# tens of packets a second, so this wants to be generous.\n")
		fmt.Fprintf(&b, "\t\tudp dport %s add @packet_rate { ip saddr limit rate over %d/second burst %d packets } %scounter drop comment %q\n",
			portSet(udp), spec.PacketsPerSec, spec.PacketsPerSec*2, blockStmt, CounterPacketRate)
	}

	if se := spec.sourceEnginePorts(); len(se) > 0 && spec.QueriesPerSec > 0 {
		b.WriteString("\t\t# Source-engine connectionless packets: the queries and connection\n")
		b.WriteString("\t\t# attempts, which start 0xFFFFFFFF. A player already in the game\n")
		b.WriteString("\t\t# sends sequence-numbered packets and never matches this, which is\n")
		b.WriteString("\t\t# what makes a tight limit safe here. @th,64,32 is the first four\n")
		b.WriteString("\t\t# bytes after the 8-byte UDP header.\n")
		fmt.Fprintf(&b, "\t\tudp dport %s @th,64,32 0xffffffff add @query_rate { ip saddr limit rate over %d/second burst %d packets } %scounter drop comment %q\n",
			portSet(se), spec.QueriesPerSec, spec.QueriesPerSec*2, blockStmt, CounterQueryRate)
	}

	// Aggregate ceilings last: a packet that survived every per-source limit
	// can still be one of a million from a million sources, and the tunnel is
	// what has to be protected from that.
	for _, sv := range spec.Services {
		if sv.CeilingPPS <= 0 {
			continue
		}
		fmt.Fprintf(&b, "\t\t%s dport %s limit rate over %d/second burst %d packets counter drop comment %q\n",
			sv.Proto, portSpec(sv.Port, sv.PortEnd), sv.CeilingPPS, sv.CeilingPPS,
			CounterCeiling+":"+sv.Name)
	}

	b.WriteString("\t}\n")
	b.WriteString("}\n")
	return b.String()
}

// bogusTCPMatches lists flag combinations that no real stack sends: scans,
// crafted floods and the occasional broken middlebox.
func bogusTCPMatches() []string {
	return []string{
		"tcp flags & (fin|syn) == (fin|syn)",
		"tcp flags & (syn|rst) == (syn|rst)",
		"tcp flags & (fin|rst) == (fin|rst)",
		"tcp flags & (fin|ack) == fin",
		"tcp flags & (ack|urg) == urg",
		"tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0",
		"tcp flags == (fin|syn|rst|psh|ack|urg)",
	}
}

// martianSet is the source addresses that cannot legitimately reach a public
// interface from the internet. Loopback, the private ranges, link-local,
// multicast and the reserved space.
func martianSet() string {
	return "{ 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, " +
		"192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }"
}

// ApplyProtectRuleset loads the edge filtering table.
func ApplyProtectRuleset(ctx context.Context, r Runner, stateDir, ruleset string) (string, error) {
	return applyRuleset(ctx, r, filepath.Join(stateDir, "protect.nft"), ruleset)
}

// RemoveProtectRuleset deletes it.
func RemoveProtectRuleset(ctx context.Context, r Runner) {
	_, _ = r.Run(ctx, "nft", "delete", "table", "ip", NFTProtectTable)
}

// ProtectState reads the counters and the blocklist back out of the kernel.
//
// Read rather than accumulated in the agent, because the kernel is the only
// thing that knows: the counters live in the rules, and reloading the table
// resets them. A limiter nobody can see the effect of is worse than none at
// all - "some players cannot connect" and "this threshold is too tight" look
// identical from the outside, and only these numbers separate them.
func ProtectState(ctx context.Context, r Runner) ([]model.ProtectCounter, []model.BlockedSource, error) {
	out, err := r.Run(ctx, "nft", "-j", "list", "table", "ip", NFTProtectTable)
	if err != nil {
		return nil, nil, err
	}
	return parseProtectState(out)
}

func parseProtectState(jsonText string) ([]model.ProtectCounter, []model.BlockedSource, error) {
	var doc struct {
		Nftables []struct {
			Rule *struct {
				Comment string                       `json:"comment"`
				Expr    []map[string]json.RawMessage `json:"expr"`
			} `json:"rule"`
			Set *struct {
				Name string            `json:"name"`
				Elem []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(jsonText), &doc); err != nil {
		return nil, nil, fmt.Errorf("read protection state: %w", err)
	}

	var counters []model.ProtectCounter
	var blocked []model.BlockedSource
	for _, item := range doc.Nftables {
		if rule := item.Rule; rule != nil && rule.Comment != "" {
			for _, expr := range rule.Expr {
				raw, ok := expr["counter"]
				if !ok {
					continue
				}
				var c struct {
					Packets int64 `json:"packets"`
					Bytes   int64 `json:"bytes"`
				}
				if json.Unmarshal(raw, &c) == nil {
					counters = append(counters, model.ProtectCounter{Name: rule.Comment, Packets: c.Packets, Bytes: c.Bytes})
				}
			}
		}
		if set := item.Set; set != nil && set.Name == "blocked" {
			for _, raw := range set.Elem {
				if b, ok := parseBlockedElem(raw); ok {
					blocked = append(blocked, b)
				}
			}
		}
	}
	sort.Slice(blocked, func(i, j int) bool { return blocked[i].ExpiresSec > blocked[j].ExpiresSec })
	return counters, blocked, nil
}

// parseBlockedElem handles both shapes nft emits: a bare address for an element
// with no timeout left to report, and an object carrying the remaining seconds.
func parseBlockedElem(raw json.RawMessage) (model.BlockedSource, bool) {
	var plain string
	if json.Unmarshal(raw, &plain) == nil {
		return model.BlockedSource{Address: plain}, true
	}
	var wrapped struct {
		Elem struct {
			Val     string `json:"val"`
			Expires int    `json:"expires"`
		} `json:"elem"`
	}
	if json.Unmarshal(raw, &wrapped) == nil && wrapped.Elem.Val != "" {
		return model.BlockedSource{Address: wrapped.Elem.Val, ExpiresSec: wrapped.Elem.Expires}, true
	}
	return model.BlockedSource{}, false
}
