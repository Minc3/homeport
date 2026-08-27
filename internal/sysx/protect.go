package sysx

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
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
	GeoRegions   []string
	GeoBlock     bool
	GeoAutoPPS   int

	// The per-service overrides of the two shared per-source connection
	// limits. Zero means the shared figure; see model.Service for why they
	// exist. TCP only - the generator ignores them on any other protocol, so
	// a hand-edited blob cannot make a udp row emit a connection-state rule.
	NewConnsPerSec    int
	MaxConnsPerSource int
}

// ProtectSpec is everything the ruleset is rendered from.
type ProtectSpec struct {
	PublicIface string

	NewConnsPerSec    int
	MaxConnsPerSource int
	PacketsPerSec     int
	QueriesPerSec     int
	BlockSeconds      int

	DropInvalid       bool
	DropBogusTCP      bool
	DropSpoofed       bool
	DropLegacyQueries bool

	GeoLockSeconds int
	Regions        []model.GeoRegion
	Services       []ProtectService
}

// DefaultGeoLockSeconds is how long an automatic region lock outlives the
// flood that engaged it when the configuration does not say. See
// model.ProtectConfig.GeoLockSeconds for the reasoning behind a minute.
const DefaultGeoLockSeconds = 60

// geoLockSeconds resolves the configured release lag, defaulting here rather
// than in Normalise so an older blob and a zero left in the portal both mean
// the same thing without a repair pass.
func (s ProtectSpec) geoLockSeconds() int {
	if s.GeoLockSeconds > 0 {
		return s.GeoLockSeconds
	}
	return DefaultGeoLockSeconds
}

// active reports whether anything at all would be generated. A spec with the
// switch on but every threshold at zero is a table with no rules in it, and
// loading that is a worse answer than loading nothing.
//
// It takes the resolved geo services rather than computing them, because its
// one caller needs them again to render the rules: merging every region's
// list is the expensive part of a build (a fetched country is tens of
// thousands of networks, parsed and sorted), it runs under the engine's apply
// lock, and two independent computations of "a live geo service" would be two
// definitions a future edit can move apart. The Source-engine ports come the
// same way for the second reason alone: the emission gates below must agree
// with the answers given here, and a gate written out twice is two
// definitions.
func (s ProtectSpec) active(sePorts []string, geoSvcs []ProtectService, overrides []connOverride) bool {
	if s.PublicIface == "" {
		return false
	}
	if s.DropInvalid || s.DropBogusTCP || s.DropSpoofed {
		return true
	}
	if s.NewConnsPerSec > 0 || s.MaxConnsPerSource > 0 || s.PacketsPerSec > 0 {
		return true
	}
	// A per-service connection override is a limit of its own: it must
	// activate the table with the shared figures at zero, or setting only the
	// row's number would save cleanly and protect nothing.
	if len(overrides) > 0 {
		return true
	}
	// The query-rate limiter and the legacy-query drop both scope to the
	// Source-engine ports, so with none configured neither has anything to
	// match and neither activates anything.
	if (s.QueriesPerSec > 0 || s.DropLegacyQueries) && len(sePorts) > 0 {
		return true
	}
	for _, sv := range s.Services {
		if sv.CeilingPPS > 0 {
			return true
		}
	}
	return len(geoSvcs) > 0
}

// geoRegionElems merges each region's networks into the elements its set will
// hold, keyed by region name. A region that resolves to nothing - every entry
// unparsable, or none at all - is absent from the map, so nothing downstream
// can reference an empty set.
//
// Only regions some service references are merged at all. An unreferenced
// region is a draft in the portal and never reaches the ruleset, but a
// fetched country list is tens of thousands of networks, and this runs under
// the engine's apply lock on every settings save - the same lock a failover
// needs to install a route. Every lookup downstream is through a service's
// GeoRegions, so the narrower map answers exactly the same questions.
func (s ProtectSpec) geoRegionElems() map[string][]string {
	referenced := map[string]bool{}
	for _, sv := range s.Services {
		for _, name := range sv.GeoRegions {
			referenced[name] = true
		}
	}
	out := map[string][]string{}
	for _, r := range s.Regions {
		if !referenced[r.Name] {
			continue
		}
		if els := mergeCIDRs(r.CIDRs); len(els) > 0 {
			out[r.Name] = els
		}
	}
	return out
}

// geoServices lists the services whose lock resolves to real sets. A dangling
// reference - a name no region carries, or one whose list is empty - means an
// older or hand-edited blob, because web.validate refuses both states at save
// time, and the fail-open answer differs by direction. An allow lock is one
// rule ANDing negated lookups, so dropping just the dangling reference would
// silently narrow the allowlist and bar every player the missing region was
// meant to admit: any dangling reference therefore takes the whole lock with
// it, no rule rather than a stricter one. A block lock is a rule per region,
// so a dangling reference simply drops less: the resolved regions keep their
// rules. Either way no drop is invented that the operator did not configure.
func (s ProtectSpec) geoServices(elems map[string][]string) []ProtectService {
	var out []ProtectService
	for _, sv := range s.Services {
		if len(sv.GeoRegions) == 0 {
			continue
		}
		resolved := 0
		for _, name := range sv.GeoRegions {
			if len(elems[name]) > 0 {
				resolved++
			}
		}
		if sv.GeoBlock && resolved > 0 {
			out = append(out, sv)
		} else if !sv.GeoBlock && resolved == len(sv.GeoRegions) {
			out = append(out, sv)
		}
	}
	return out
}

// GeoSetName is the nftables set a region renders to. Validation holds region
// names to characters nft accepts in an identifier, but the ruleset must stay
// loadable whatever an older or hand-edited blob carries, so anything else is
// folded to an underscore here rather than handed to nft to refuse - which
// would reject the whole table, every other limit included.
//
// Exported because web.validate keys its collision check on it: two names are
// one set exactly when this says so, and a second copy of the fold in another
// package is the two definitions drifting apart waiting to happen.
//
// The lockdown sets live in the same geo_ namespace, so a region that folds
// onto one of their names ("lockdown-tcp", "lockdown_udp") would define the
// set twice with two different types, and nft rejects the whole table over
// it. GeoNameReserved lets validate refuse the name at save; here, where the
// blob may predate that check, the region's set is shifted out of the way
// instead, so the lock sets stay theirs and the region still renders.
func GeoSetName(name string) string {
	folded := foldGeoName(name)
	if geoNameFoldsToLockSet(folded) {
		return folded + "_"
	}
	return folded
}

// GeoNameReserved reports whether a region name folds onto a set name the
// generator writes for itself, which validate refuses with a message rather
// than letting GeoSetName silently shift it.
func GeoNameReserved(name string) bool {
	return geoNameFoldsToLockSet(foldGeoName(name))
}

func foldGeoName(name string) string {
	return foldSetName("geo_", name)
}

// foldSetName folds a user-chosen name into characters nft accepts in a set
// identifier, under the given prefix. One fold shared by every set a name
// reaches - the region sets and the per-service connection-limit sets - so
// two callers cannot drift apart about which names are one identifier.
func foldSetName(prefix, name string) string {
	var sb strings.Builder
	sb.WriteString(prefix)
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
		} else {
			sb.WriteByte('_')
		}
	}
	return sb.String()
}

func geoNameFoldsToLockSet(folded string) bool {
	return folded == geoLockSetName("tcp") || folded == geoLockSetName("udp")
}

// geoLockSetName is the dynamic set holding the ports whose automatic region
// lock is currently engaged, one per protocol.
func geoLockSetName(proto string) string {
	return "geo_lockdown_" + strings.ToLower(proto)
}

// mergeCIDRs normalises a region's networks into elements one nftables set
// will accept: parsed, masked to their network address, duplicates and
// contained networks dropped. Two CIDR blocks either nest or are disjoint, so
// containment is the only overlap there is - and it must be handled here for
// the same reason mergePorts exists: nft rejects the whole table over one
// overlapping element, and a pasted country list being generous is not an
// error worth taking every limit down over.
//
// An entry that does not parse as an IPv4 network is skipped rather than
// carried, on the same reasoning as geoServices: validation refuses it at
// save, and one bad string in an old blob must not cost the table.
func mergeCIDRs(cidrs []string) []string {
	type block struct {
		start, end uint32
		text       string
	}
	var blocks []block
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(strings.TrimSpace(c))
		if err != nil || n.IP.To4() == nil {
			continue
		}
		ones, bits := n.Mask.Size()
		if bits != 32 {
			continue
		}
		start := binary.BigEndian.Uint32(n.IP.To4())
		blocks = append(blocks, block{start, start | (0xffffffff >> ones), n.String()})
	}
	sort.Slice(blocks, func(i, j int) bool {
		if blocks[i].start != blocks[j].start {
			return blocks[i].start < blocks[j].start
		}
		return blocks[i].end > blocks[j].end // the containing network first
	})
	out := make([]string, 0, len(blocks))
	lastEnd := int64(-1)
	for _, bl := range blocks {
		// Blocks nest or are disjoint, so ending inside the previous kept
		// network means being contained in it (a duplicate included).
		if int64(bl.end) <= lastEnd {
			continue
		}
		out = append(out, bl.text)
		lastEnd = int64(bl.end)
	}
	return out
}

// geoElements renders a set's elements a few to a line. The file is left on
// disk as a readable record, and a region is routinely hundreds of networks
// long; one line that long is a record nobody can read.
func geoElements(elems []string) string {
	var sb strings.Builder
	for i, e := range elems {
		if i > 0 {
			sb.WriteString(",")
			if i%6 == 0 {
				sb.WriteString("\n\t\t\t")
			} else {
				sb.WriteString(" ")
			}
		}
		sb.WriteString(e)
	}
	return sb.String()
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

// overridesConnRate and overridesConnCount are the one definition of "this
// row replaces a shared connection limit", consulted by connOverrides, the
// shared rules' port subtraction and the rule emission alike. A gate written
// out twice is two definitions (see active), and here the failure of a drift
// is the silent kind: a port excluded from the shared rule by one definition
// with no override rule emitted by the other is a published port with no
// connection limit at all, loading clean. TCP only, because the rules these
// select are connection-state rules.
func (sv ProtectService) overridesConnRate() bool {
	return strings.EqualFold(sv.Proto, "tcp") && sv.NewConnsPerSec > 0
}

func (sv ProtectService) overridesConnCount() bool {
	return strings.EqualFold(sv.Proto, "tcp") && sv.MaxConnsPerSource > 0
}

// sharedConnPorts is the port set one shared connection rule covers: every
// TCP row's ports, minus the port intervals of the rows overriding that
// limit. Subtracted as intervals rather than by skipping the overriding rows:
// skipped by row, any other row covering the same port put it straight back
// into the shared rule, and a port in both rules faces whichever limit is
// tighter rather than the one chosen for it - a loosening override was
// silently dead. web.validate now refuses enabled same-protocol rows from
// overlapping at all, so through the portal this only ever subtracts a row's
// own ports; the interval arithmetic stays because a blob saved before that
// refusal can carry an overlap and must keep generating the rules the
// operator meant, not a rejected table.
func (s ProtectSpec) sharedConnPorts(overridden func(ProtectService) bool) []string {
	var base, cut []portRange
	for _, sv := range s.Services {
		if !strings.EqualFold(sv.Proto, "tcp") {
			continue
		}
		r := portRange{sv.Port, max(sv.Port, sv.PortEnd)}
		if overridden(sv) {
			cut = append(cut, r)
		} else {
			base = append(base, r)
		}
	}
	return mergePorts(subtractRanges(base, cut))
}

// subtractRanges removes every interval in cut from every interval in base.
// The result is not merged or ordered; callers hand it to mergePorts, which
// already does both.
func subtractRanges(base, cut []portRange) []portRange {
	var out []portRange
	for _, b := range base {
		segs := []portRange{b}
		for _, c := range cut {
			var next []portRange
			for _, s := range segs {
				if c.hi < s.lo || c.lo > s.hi {
					next = append(next, s)
					continue
				}
				if c.lo > s.lo {
					next = append(next, portRange{s.lo, c.lo - 1})
				}
				if c.hi < s.hi {
					next = append(next, portRange{c.hi + 1, s.hi})
				}
			}
			segs = next
		}
		out = append(out, segs...)
	}
	return out
}

// connOverride pairs a service that overrides a per-source connection limit
// with the set names its rules feed. Each override needs a set of its own
// rather than the shared one, because the threshold lives in the set's
// elements, not in the rule: an element is created with the limiter of the
// rule that first added it, so one source touching two services through a
// shared set would keep whichever threshold its first packet happened to
// create. A blank name means that limit is not overridden.
type connOverride struct {
	svc      ProtectService
	rateSet  string
	countSet string
}

// connOverrides lists the enabled TCP services overriding either per-source
// connection limit, each with its set names. Names fold exactly as region
// names do; two that fold to one identifier get a numeric suffix, because to
// nft they would otherwise be one set declared twice - which rejects the
// whole table, every other limit included.
func (s ProtectSpec) connOverrides() []connOverride {
	var out []connOverride
	taken := map[string]bool{}
	uniq := func(base string) string {
		name := base
		for n := 2; taken[name]; n++ {
			name = fmt.Sprintf("%s_%d", base, n)
		}
		taken[name] = true
		return name
	}
	for _, sv := range s.Services {
		if !sv.overridesConnRate() && !sv.overridesConnCount() {
			continue
		}
		o := connOverride{svc: sv}
		if sv.overridesConnRate() {
			o.rateSet = uniq(foldSetName("conn_rate_", sv.Name))
		}
		if sv.overridesConnCount() {
			o.countSet = uniq(foldSetName("conn_count_", sv.Name))
		}
		out = append(out, o)
	}
	return out
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
// to load, taking every other limit with it. web.validate now refuses enabled
// same-protocol rows from overlapping, but this must keep merging regardless:
// a blob saved before that refusal can still carry an overlap, and adjacent
// ranges (80 beside 81-90) are legal to save while still being one interval
// to the kernel - listed separately they are a rejected duplicate at the
// boundary.
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
		GeoLockSeconds:    p.GeoLockSeconds,
		DropInvalid:       p.DropInvalid,
		DropBogusTCP:      p.DropBogusTCP,
		DropSpoofed:       p.DropSpoofed,
		DropLegacyQueries: p.DropLegacyQueries,
		Regions:           p.Regions,
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
			GeoRegions: s.GeoRegions, GeoBlock: s.GeoBlock, GeoAutoPPS: s.GeoAutoPPS,
			NewConnsPerSec: s.NewConnsPerSec, MaxConnsPerSource: s.MaxConnsPerSource,
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
	CounterLegacyQ    = "legacy-query"
	CounterConnRate   = "conn-rate"
	CounterConnCount  = "conn-count"
	CounterPacketRate = "packet-rate"
	CounterQueryRate  = "query-rate"
	CounterCeiling    = "ceiling"
	CounterGeo        = "geo"
	CounterGeoTrip    = "geo-trip"
)

// connRateRule and connCountRule are the one spelling of the two connection
// rules, written by the shared rules and the per-service overrides alike. One
// spelling because everything load-bearing is in it: the `ct state new`
// qualifier, the burst-is-twice-the-rate convention, and blockStmt's position
// ahead of the counter. Written out twice, a change to any of those lands in
// the copy an operator tunes and silently not in the copy a row overrides
// with, and "the override behaves differently from the shared limit at the
// same number" is exactly what nobody would suspect.
func connRateRule(b *strings.Builder, ports, set string, rate int, blockStmt, comment string) {
	fmt.Fprintf(b, "\t\tct state new tcp dport %s add @%s { ip saddr limit rate over %d/second burst %d packets } %scounter drop comment %q\n",
		ports, set, rate, rate*2, blockStmt, comment)
}

func connCountRule(b *strings.Builder, ports, set string, most int, blockStmt, comment string) {
	fmt.Fprintf(b, "\t\tct state new tcp dport %s add @%s { ip saddr ct count over %d } %scounter drop comment %q\n",
		ports, set, most, blockStmt, comment)
}

// connectionlessMatch is the Source engine's connectionless header: every
// query and connection attempt starts 0xFFFFFFFF in the first four bytes
// after the 8-byte UDP header, and an in-game client's sequence-numbered
// packets never do. Three rules read it - the query rate limiter, the
// legacy-query drop, and the query cache redirects in nft.go - and a packet
// they disagreed about would be dropped by one and answered by another, so
// there is exactly one spelling.
const connectionlessMatch = "@th,64,32 0xffffffff"

// BuildProtectRuleset renders the edge filtering table, or "" when there is
// nothing switched on.
func BuildProtectRuleset(spec ProtectSpec) string {
	// Resolved once, shared by the emptiness check and the rule emission
	// below; see active for why neither is computed twice.
	geoElems := spec.geoRegionElems()
	geoSvcs := spec.geoServices(geoElems)
	sePorts := spec.sourceEnginePorts()
	overrides := spec.connOverrides()
	sharedRatePorts := spec.sharedConnPorts(ProtectService.overridesConnRate)
	sharedCountPorts := spec.sharedConnPorts(ProtectService.overridesConnCount)
	if !spec.active(sePorts, geoSvcs, overrides) {
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
	// state. A timeout of 0 emits a set with no element timeout at all, and
	// that is not a variant nothing uses: the kernel refuses a connlimit
	// expression (`ct count`) in a timeout-flagged set with "Operation not
	// supported", and refuses the whole table with it - the conntrack table's
	// own timers are what age a live connection count, so an element timeout
	// there is meaningless as well as fatal. Found live: every per-source
	// limit stayed out of the kernel while the journal named this line.
	dynSet := func(name string, timeout int) {
		fmt.Fprintf(&b, "\tset %s {\n", name)
		b.WriteString("\t\ttype ipv4_addr\n")
		b.WriteString("\t\tsize 65535\n")
		if timeout > 0 {
			b.WriteString("\t\tflags dynamic,timeout\n")
			fmt.Fprintf(&b, "\t\ttimeout %ds\n", timeout)
		} else {
			b.WriteString("\t\tflags dynamic\n")
		}
		b.WriteString("\t}\n\n")
	}
	// Gated on the rule surviving, not on the figure alone: with every TCP
	// row overriding a shared limit (or none existing at all) the shared rule
	// is omitted, and a set nothing consults is dead weight the kernel still
	// has to hold - and a reader of `nft list ruleset` cannot trust the set
	// list to mean the rule list.
	if spec.NewConnsPerSec > 0 && len(sharedRatePorts) > 0 {
		dynSet("conn_rate", 60)
	}
	if spec.MaxConnsPerSource > 0 && len(sharedCountPorts) > 0 {
		dynSet("conn_count", 0)
	}
	if spec.PacketsPerSec > 0 {
		dynSet("packet_rate", 60)
	}
	if spec.QueriesPerSec > 0 && len(sePorts) > 0 {
		dynSet("query_rate", 60)
	}
	// The per-service override sets, one per overridden limit rather than the
	// shared set beside them: see connOverride for why the threshold cannot
	// share a set. Rate sets age like conn_rate; count sets carry no timeout,
	// for the reason conn_count does not.
	for _, o := range overrides {
		if o.rateSet != "" {
			dynSet(o.rateSet, 60)
		}
		if o.countSet != "" {
			dynSet(o.countSet, 0)
		}
	}

	// Region sets. Only the regions a locked service actually references
	// become sets: an unreferenced region is a draft in the portal, not a
	// rule, and a set nothing consults is dead weight the kernel still has to
	// hold. Order follows the services so the output is stable across saves.
	var geoOrder []string
	seenGeo := map[string]bool{}
	for _, sv := range geoSvcs {
		for _, name := range sv.GeoRegions {
			if len(geoElems[name]) == 0 {
				continue
			}
			// Deduplicated on the folded set name, not the raw one: two names
			// the folding makes identical are one set to nft, and emitting it
			// twice rejects the whole table - the exact failure the folding
			// exists to prevent. validate refuses the collision at save; an
			// older blob carrying one gets the first region's list.
			if set := GeoSetName(name); !seenGeo[set] {
				seenGeo[set] = true
				geoOrder = append(geoOrder, name)
			}
		}
	}
	for _, name := range geoOrder {
		fmt.Fprintf(&b, "\tset %s {\n", GeoSetName(name))
		b.WriteString("\t\ttype ipv4_addr\n")
		// interval, because the elements are networks; without the flag a
		// CIDR element is refused and the whole table with it.
		b.WriteString("\t\tflags interval\n")
		// Fixed text rather than the region's name: the set name already
		// carries it, and a comment is the one place a hand-edited blob could
		// smuggle a quote past the identifier folding above.
		b.WriteString("\t\tcomment \"sources allowed to reach the services locked to this region\"\n")
		fmt.Fprintf(&b, "\t\telements = { %s }\n", geoElements(geoElems[name]))
		b.WriteString("\t}\n\n")
	}

	// The lockdown sets hold the ports whose automatic lock is currently
	// engaged, written from the packet path exactly like the blocklist. One
	// per protocol rather than one keyed on protocol and port together,
	// because a plain inet_service key works on every kernel this deploys to
	// and a tcp service on a port must not be locked by a udp flood to the
	// same number.
	lockSets := map[string]bool{}
	for _, sv := range geoSvcs {
		if sv.GeoAutoPPS > 0 && !lockSets[sv.Proto] {
			lockSets[sv.Proto] = true
			fmt.Fprintf(&b, "\tset %s {\n", geoLockSetName(sv.Proto))
			b.WriteString("\t\ttype inet_service\n")
			b.WriteString("\t\tsize 65535\n")
			b.WriteString("\t\tflags dynamic,timeout\n")
			fmt.Fprintf(&b, "\t\ttimeout %ds\n", spec.geoLockSeconds())
			b.WriteString("\t\tcomment \"ports whose region lock is engaged; entries release on their own\"\n")
			b.WriteString("\t}\n\n")
		}
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
	if spec.DropLegacyQueries && len(sePorts) > 0 {
		b.WriteString("\t\t# The two deprecated Source connectionless queries, dropped before\n")
		b.WriteString("\t\t# conntrack: GETCHALLENGE (0x57) and A2A_PING (0x69). No client has\n")
		b.WriteString("\t\t# sent either in over a decade, and both are reflector shapes. The\n")
		b.WriteString("\t\t# match is the connectionless header then the type byte, exactly as\n")
		b.WriteString("\t\t# the query rate limiter reads it, so the live queries (0x54-0x56)\n")
		b.WriteString("\t\t# and in-game traffic are untouched.\n")
		fmt.Fprintf(&b, "\t\tudp dport %s %s @th,96,8 { 0x57, 0x69 } counter drop comment %q\n",
			portSet(sePorts), connectionlessMatch, CounterLegacyQ)
	}
	if len(geoSvcs) > 0 {
		b.WriteString("\t\t# Region locks: an allow lock drops everything outside its regions,\n")
		b.WriteString("\t\t# a block lock drops exactly what is inside them. Before conntrack\n")
		b.WriteString("\t\t# and on every packet, not just new connections: the set answer is\n")
		b.WriteString("\t\t# fixed per address, so a player the lock admits can never be newly\n")
		b.WriteString("\t\t# caught by it, while matching statelessly means a barred flood costs\n")
		b.WriteString("\t\t# no conntrack entry and a lock engaging also ends flows already in\n")
		b.WriteString("\t\t# progress.\n")
		for _, sv := range geoSvcs {
			// The conditional lock, engaged and released entirely in the
			// kernel. The trigger runs first and takes no verdict, so it sees
			// the whole flood - including the packets the drop beneath it is
			// discarding - and keeps refreshing the lock for as long as the
			// flood lasts; put after the drop it would only see surviving
			// traffic, release mid-attack, and let a burst through every
			// timeout. The drops then apply only while the port is in the
			// lockdown set.
			lockCond := ""
			if sv.GeoAutoPPS > 0 {
				fmt.Fprintf(&b, "\t\t%s dport %s limit rate over %d/second update @%s { th dport timeout %ds } counter comment %q\n",
					sv.Proto, portSpec(sv.Port, sv.PortEnd), sv.GeoAutoPPS,
					geoLockSetName(sv.Proto), spec.geoLockSeconds(),
					CounterGeoTrip+":"+sv.Name)
				lockCond = fmt.Sprintf("th dport @%s ", geoLockSetName(sv.Proto))
			}
			if sv.GeoBlock {
				// Inverted: drop a source inside any named region. That is an
				// OR, and one rule ANDs its matches, so it is one rule per
				// region rather than one rule per service.
				for _, name := range sv.GeoRegions {
					if len(geoElems[name]) == 0 {
						continue
					}
					fmt.Fprintf(&b, "\t\t%s dport %s %sip saddr @%s counter drop comment %q\n",
						sv.Proto, portSpec(sv.Port, sv.PortEnd), lockCond,
						GeoSetName(name), CounterGeo+":"+sv.Name)
				}
				continue
			}
			// Several regions AND together as negations: dropped only when the
			// source is inside none of them, which is the union as an allowlist.
			var matches strings.Builder
			for _, name := range sv.GeoRegions {
				if len(geoElems[name]) > 0 {
					fmt.Fprintf(&matches, "ip saddr != @%s ", GeoSetName(name))
				}
			}
			fmt.Fprintf(&b, "\t\t%s dport %s %s%scounter drop comment %q\n",
				sv.Proto, portSpec(sv.Port, sv.PortEnd), lockCond, matches.String(),
				CounterGeo+":"+sv.Name)
		}
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

	// The shared connection rules cover every TCP port no override claims;
	// an overriding row's ports are subtracted per limit (sharedConnPorts
	// explains why per limit, and why by interval rather than by row). The
	// length guards also carry the case where every port is claimed: portSet
	// of nothing renders "{  }", which nft refuses along with the whole
	// table. Their sets above are gated on the same condition.
	if spec.NewConnsPerSec > 0 && len(sharedRatePorts) > 0 {
		b.WriteString("\t\t# Connection attempts per source. Established connections are untouched.\n")
		connRateRule(&b, portSet(sharedRatePorts), "conn_rate", spec.NewConnsPerSec, blockStmt, CounterConnRate)
	}
	if spec.MaxConnsPerSource > 0 && len(sharedCountPorts) > 0 {
		b.WriteString("\t\t# Concurrent connections held by one source.\n")
		connCountRule(&b, portSet(sharedCountPorts), "conn_count", spec.MaxConnsPerSource, blockStmt, CounterConnCount)
	}

	if udp := spec.ports("udp"); len(udp) > 0 && spec.PacketsPerSec > 0 {
		b.WriteString("\t\t# Packets per second from one source. A player in a game sends\n")
		b.WriteString("\t\t# tens of packets a second, so this wants to be generous.\n")
		fmt.Fprintf(&b, "\t\tudp dport %s add @packet_rate { ip saddr limit rate over %d/second burst %d packets } %scounter drop comment %q\n",
			portSet(udp), spec.PacketsPerSec, spec.PacketsPerSec*2, blockStmt, CounterPacketRate)
	}

	if len(sePorts) > 0 && spec.QueriesPerSec > 0 {
		b.WriteString("\t\t# Source-engine connectionless packets: the queries and connection\n")
		b.WriteString("\t\t# attempts, which start 0xFFFFFFFF. A player already in the game\n")
		b.WriteString("\t\t# sends sequence-numbered packets and never matches this, which is\n")
		b.WriteString("\t\t# what makes a tight limit safe here. @th,64,32 is the first four\n")
		b.WriteString("\t\t# bytes after the 8-byte UDP header.\n")
		fmt.Fprintf(&b, "\t\tudp dport %s %s add @query_rate { ip saddr limit rate over %d/second burst %d packets } %scounter drop comment %q\n",
			portSet(sePorts), connectionlessMatch, spec.QueriesPerSec, spec.QueriesPerSec*2, blockStmt, CounterQueryRate)
	}

	// The per-service overrides, one rule per overridden limit with the row's
	// own figure and set. The shared figures being zero changes nothing here:
	// a row's limit stands on its own, which is what lets a site hold one
	// game port tight without limiting its web ports at all. The counter
	// carries the service's name the way the ceilings do, so the portal shows
	// which row is dropping without further work. Below the UDP rules rather
	// than beside the shared connection rules they replace, deliberately:
	// order changes nothing (their ports are subtracted from the shared rules
	// and a tcp match cannot take a udp packet), and the highest-pps path
	// through this chain is a UDP flood, which should not walk one TCP-only
	// rule per override before reaching its own limiter.
	if len(overrides) > 0 {
		b.WriteString("\t\t# Per-service overrides of the connection limits; these rows' ports\n")
		b.WriteString("\t\t# are excluded from the shared rules above.\n")
	}
	for _, o := range overrides {
		sv := o.svc
		if o.rateSet != "" {
			connRateRule(&b, portSpec(sv.Port, sv.PortEnd), o.rateSet, sv.NewConnsPerSec, blockStmt, CounterConnRate+":"+sv.Name)
		}
		if o.countSet != "" {
			connCountRule(&b, portSpec(sv.Port, sv.PortEnd), o.countSet, sv.MaxConnsPerSource, blockStmt, CounterConnCount+":"+sv.Name)
		}
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
func ProtectState(ctx context.Context, r Runner) ([]model.ProtectCounter, []model.BlockedSource, []model.GeoLockedPort, error) {
	out, err := r.Run(ctx, "nft", "-j", "list", "table", "ip", NFTProtectTable)
	if err != nil {
		return nil, nil, nil, err
	}
	return parseProtectState(out)
}

func parseProtectState(jsonText string) ([]model.ProtectCounter, []model.BlockedSource, []model.GeoLockedPort, error) {
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
		return nil, nil, nil, fmt.Errorf("read protection state: %w", err)
	}

	var counters []model.ProtectCounter
	// Summed by comment, not listed by rule. One limit is often several
	// rules: the bogus-TCP filter is seven flag combinations, and a block
	// direction lock is a rule per region - and a tile per rule made the
	// portal show seven identical "bogus-tcp" cards, which read as a bug.
	// The comment is the limit's identity; the split into rules is a kernel
	// detail nothing upstream should see.
	counterIdx := map[string]int{}
	var blocked []model.BlockedSource
	var locked []model.GeoLockedPort
	for _, item := range doc.Nftables {
		if rule := item.Rule; rule != nil && rule.Comment != "" {
			var c struct {
				Packets int64 `json:"packets"`
				Bytes   int64 `json:"bytes"`
			}
			counted := false
			drops := false
			for _, expr := range rule.Expr {
				if raw, ok := expr["counter"]; ok && json.Unmarshal(raw, &c) == nil {
					counted = true
				}
				// Whether the counted packets were dropped is the rule's own
				// verdict, sitting beside the counter in the same expression
				// list - the kernel's answer, not an inference from the
				// comment. The auto-lock trip counter is the one that
				// observes without dropping, and a future observe-only
				// counter is covered without anyone remembering to extend an
				// exception here.
				if _, ok := expr["drop"]; ok {
					drops = true
				}
			}
			if !counted {
				continue
			}
			if i, ok := counterIdx[rule.Comment]; ok {
				counters[i].Packets += c.Packets
				counters[i].Bytes += c.Bytes
				counters[i].Drops = counters[i].Drops || drops
				continue
			}
			counterIdx[rule.Comment] = len(counters)
			counters = append(counters, model.ProtectCounter{
				Name: rule.Comment, Packets: c.Packets, Bytes: c.Bytes,
				Drops: drops,
			})
		}
		if set := item.Set; set != nil {
			if set.Name == "blocked" {
				for _, raw := range set.Elem {
					if b, ok := parseBlockedElem(raw); ok {
						blocked = append(blocked, b)
					}
				}
			}
			// Matched on the two exact names the generator emits, never on the
			// prefix: region sets share the geo_ namespace, so a region named
			// "lockdown_eu" would otherwise be scanned as lock state for a
			// protocol called "eu".
			for _, proto := range []string{"tcp", "udp"} {
				if set.Name != geoLockSetName(proto) {
					continue
				}
				for _, raw := range set.Elem {
					if p, ok := parseLockedElem(raw); ok {
						p.Proto = proto
						locked = append(locked, p)
					}
				}
			}
		}
	}
	sort.Slice(blocked, func(i, j int) bool { return blocked[i].ExpiresSec > blocked[j].ExpiresSec })
	sort.Slice(locked, func(i, j int) bool { return locked[i].Port < locked[j].Port })
	return counters, blocked, locked, nil
}

// parseSetElem reads one dynamic-set element in either shape nft -j emits: a
// bare value for an element with no timeout left to report, or an object
// carrying the remaining seconds. One function rather than a copy per set,
// because this is the knowledge of how nft renders elements - an nft version
// shifting the shape must be absorbed once, not remembered at every readback.
func parseSetElem[T comparable](raw json.RawMessage) (val T, expires int, ok bool) {
	var zero T
	var plain T
	if json.Unmarshal(raw, &plain) == nil && plain != zero {
		return plain, 0, true
	}
	var wrapped struct {
		Elem struct {
			Val     T   `json:"val"`
			Expires int `json:"expires"`
		} `json:"elem"`
	}
	if json.Unmarshal(raw, &wrapped) == nil && wrapped.Elem.Val != zero {
		return wrapped.Elem.Val, wrapped.Elem.Expires, true
	}
	return zero, 0, false
}

// parseLockedElem reads one lockdown set element: a port and the seconds until
// the lock releases.
func parseLockedElem(raw json.RawMessage) (model.GeoLockedPort, bool) {
	port, expires, ok := parseSetElem[int](raw)
	return model.GeoLockedPort{Port: port, ExpiresSec: expires}, ok
}

// parseBlockedElem reads one blocklist element: an address and the seconds
// until the parking expires.
func parseBlockedElem(raw json.RawMessage) (model.BlockedSource, bool) {
	addr, expires, ok := parseSetElem[string](raw)
	return model.BlockedSource{Address: addr, ExpiresSec: expires}, ok
}
