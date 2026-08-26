// Package model holds the configuration and runtime types shared by the
// frontend and backend agents.
package model

import (
	"strings"
	"time"
)

// Mode controls whether the frontend is allowed to touch the system.
const (
	ModeObserve = "observe" // compute decisions, never apply them
	ModeArmed   = "armed"   // apply routing and nftables changes
)

// DefaultTimezone is the zone a quota's reset day is counted in when the
// portal is left to choose. A billing period turns over where the carrier
// draws it, not at UTC midnight, so the shipped value is the deployment's
// own zone rather than UTC.
const DefaultTimezone = "Australia/Melbourne"

// Health is what the probes say about a path. It is deliberately separate
// from policy blocks: a path can be perfectly healthy and still unusable
// because it blew its quota.
type Health string

const (
	HealthUnknown Health = "unknown" // no probe result yet
	HealthUp      Health = "up"
	HealthSuspect Health = "suspect" // losing probes, not yet condemned
	HealthDown    Health = "down"
)

// Block is a policy reason a path may not be selected. Empty means no block.
type Block string

const (
	BlockNone       Block = ""
	BlockQuota      Block = "quota"      // over the monthly cap
	BlockQuarantine Block = "quarantine" // circuit breaker tripped on flapping
	BlockDisabled   Block = "disabled"   // switched off in the portal
	BlockDegraded   Block = "degraded"   // reachable but loss/latency over threshold
)

// Config is the full user-editable configuration. It lives in SQLite on the
// frontend; the backend receives the parts it needs over the control channel.
type Config struct {
	Mode     string         `json:"mode"`
	Frontend FrontendConfig `json:"frontend"`
	Overlay  OverlayConfig  `json:"overlay"`
	Paths    []PathConfig   `json:"paths"`
	Probe    ProbeConfig    `json:"probe"`
	Failover FailoverConfig `json:"failover"`
	Services []Service      `json:"services"`
	Linkers  []Linker       `json:"linkers,omitempty"`

	// BackendLAN is the backend's own address on the network its linkers sit
	// on. The frontend never uses it to route anything - it is the one fact a
	// linker's config needs that cannot be derived from anything else here, so
	// holding it lets the portal generate that config instead of the operator
	// assembling it. Empty on a site with no linkers.
	BackendLAN string       `json:"backend_lan,omitempty"`
	Egress     EgressConfig `json:"egress"`
	Notify     NotifyConfig `json:"notify"`

	// Protect is edge filtering and rate limiting on the frontend. Off, with
	// every threshold zero, on every site until somebody turns it on.
	Protect ProtectConfig `json:"protect,omitempty"`

	// QueryCache answers Source-engine A2S_INFO and A2S_PLAYER queries from
	// the frontend itself. Off on every site until somebody turns it on, and
	// an older config unmarshals to exactly this.
	QueryCache QueryCacheConfig `json:"query_cache,omitempty"`
}

// QueryCacheConfig is the frontend's Source query cache: one switch, off by
// default.
//
// With it on, every published UDP service ticked as Source engine has its
// A2S_INFO, A2S_PLAYER and A2S_RULES queries answered at the frontend from a
// cache that is refreshed from the real server every few seconds, instead of
// being forwarded down a tunnel. The cache challenges every source before
// serving a payload, exactly as a modern Source server does, and a challenge
// reply is never larger than the query that provoked it - strictly smaller
// for INFO, byte-for-byte equal for the 9-byte PLAYER and RULES queries - so
// the cache amplifies nothing, and a spoofed-source query flood gets nothing
// but challenges no spoofed sender can answer. Reflection at ratio 1.0 for
// the equal-sized queries is the floor any UDP responder has. That is the hole it exists to
// close: the per-source limits key on source addresses being real, so a flood
// that randomises them never trips a limit and lands on the service ceiling,
// which drops legitimate browser queries along with the flood. The cache
// keeps answering the legitimate clients through it, on a frontend whose
// datacentre may only filter volumetric attacks.
//
// It is independent of ProtectConfig on purpose. A site can run the cache
// with every per-source limit at zero and let it absorb floods, or run both,
// in which case the limits drop first: the protect chains run before
// destination NAT, where the cache's redirect lives. Armed mode only, like
// the DNAT beside it - the redirect rules ride the same table, which observe
// mode never loads, and the cache's refresh traffic rides the active tunnel,
// which observe mode must not send anything down.
type QueryCacheConfig struct {
	Enabled bool `json:"enabled,omitempty"`

	// RefreshMs is how often a queried port is re-fetched from the real
	// server, and therefore the staleness a browser normally sees. Zero
	// takes the shipped 3000: an older config unmarshals to exactly the
	// behaviour it had. Bounded by validate on both sides: below 500 the
	// refresher is a continuous poll of the operator's own server over the
	// billed tunnel, and above 30000 the cache cannot stay inside its 90
	// second staleness bound with room for a failed fetch to be retried.
	RefreshMs int `json:"refresh_ms,omitempty"`
}

// MaxQueryCachePorts bounds how many ports the cache will serve. Each port is
// a bound socket and a refresh stream on the frontend, so the bound has to
// exist, but it is far above any real deployment: the shipped Source row is
// sixteen ports. Ports past the cap are neither cached nor redirected, so
// their queries still reach the real server - the enumeration is the single
// source of truth for both halves, which is what keeps a redirect from ever
// pointing at a port no socket answers.
const MaxQueryCachePorts = 128

// QueryCacheSpan is a contiguous run of ports the cache serves for one
// service, with the overlay address the cache refreshes from.
type QueryCacheSpan struct {
	From, To int
	Target   string // overlay address of the host really answering
	Service  string // the service row's name, for rule comments and the portal
}

// QueryCachePorts enumerates what the cache serves: every port of every
// enabled UDP service ticked as Source engine, deduplicated, capped at
// MaxQueryCachePorts. It is the one definition shared by the nftables
// generator (which redirects exactly these ports) and the engine (which binds
// a responder for exactly these ports); deriving either side separately is
// how a query gets redirected to a port nothing answers. Mode is deliberately
// not consulted here: the engine gates on it, and the generated ruleset is
// only ever loaded when armed.
func QueryCachePorts(cfg Config) []QueryCacheSpan {
	if !cfg.QueryCache.Enabled {
		return nil
	}
	budget := MaxQueryCachePorts
	claimed := map[int]bool{}
	var out []QueryCacheSpan
	for _, s := range cfg.Services {
		if !s.Enabled || !s.SourceEngine || !strings.EqualFold(s.Proto, "udp") {
			continue
		}
		end := s.Port
		if s.PortEnd > s.Port {
			end = s.PortEnd
		}
		target := s.TargetOr(cfg.Overlay.BackendIP)
		var span *QueryCacheSpan
		for p := s.Port; p <= end && budget > 0; p++ {
			if claimed[p] {
				span = nil
				continue
			}
			claimed[p] = true
			budget--
			if span != nil && span.To == p-1 {
				span.To = p
				continue
			}
			out = append(out, QueryCacheSpan{From: p, To: p, Target: target, Service: s.Name})
			span = &out[len(out)-1]
		}
	}
	return out
}

// ProtectConfig is the frontend's filtering of published traffic.
//
// One master switch and a set of thresholds, all off by default and each doing
// nothing at zero. That is not timidity: every one of these can drop a packet a
// real player sent, and a limit set from a guess produces "some people cannot
// connect", which is indistinguishable from the service being down. They are
// meant to be turned on one at a time against the counters the portal shows.
//
// The whole table matches only traffic arriving on the public interface, before
// destination NAT. Nothing here can see a probe, the control channel or any
// overlay traffic, which is deliberate - the system must never be able to drop
// its own health checks and conclude a link has failed.
type ProtectConfig struct {
	Enabled bool `json:"enabled,omitempty"`

	// Per-source limits. Zero disables each one individually.
	NewConnsPerSec    int `json:"new_conns_per_sec,omitempty"`    // TCP connection attempts per second
	MaxConnsPerSource int `json:"max_conns_per_source,omitempty"` // concurrent tracked TCP connections
	PacketsPerSec     int `json:"packets_per_sec,omitempty"`      // UDP packets per second
	QueriesPerSec     int `json:"queries_per_sec,omitempty"`      // Source-engine connectionless packets

	// BlockSeconds parks a source that trips one of the above in a set with
	// this timeout, dropped on sight until it expires. Zero drops only the
	// excess and never parks anybody, which is the gentler and less effective
	// setting.
	BlockSeconds int `json:"block_seconds,omitempty"`

	// Edge hygiene. Cheap, no thresholds, and no legitimate client sends any
	// of what they drop.
	DropInvalid  bool `json:"drop_invalid,omitempty"`   // packets conntrack cannot place
	DropBogusTCP bool `json:"drop_bogus_tcp,omitempty"` // flag combinations no stack sends
	DropSpoofed  bool `json:"drop_spoofed,omitempty"`   // private and reserved sources from the internet

	// DropLegacyQueries drops the two deprecated Source connectionless
	// queries at the edge: A2S_SERVERQUERY_GETCHALLENGE (0x57) and A2A_PING
	// (0x69). No client has sent either in over a decade - the challenge was
	// folded into the queries themselves, and Valve removed ping responses
	// engine-wide - and both are small-request, larger-reply shapes, so a
	// server that still answers them (GETCHALLENGE returns a 9-byte
	// challenge to a 5-byte request, a 1.8x amplifier) is a reflector.
	// Scoped to the Source-engine ports, dropped before conntrack.
	DropLegacyQueries bool `json:"drop_legacy_queries,omitempty"`

	// Regions are the named network lists that Service.GeoRegions locks ports
	// to. Empty, like every other field here, means the feature does not
	// exist: no set is generated, no rule mentions one, and an older config
	// unmarshals to exactly this.
	Regions []GeoRegion `json:"regions,omitempty"`

	// GeoLockSeconds is how long an automatic region lock lingers once the
	// flood that engaged it stops. While the traffic stays over a service's
	// threshold the lock is refreshed continuously, so this is release lag,
	// not a rearm interval. Zero takes the default of a minute: long enough
	// that a flood pulsing on and off does not let a burst through between
	// pulses, short enough that out-of-region players are not locked out for
	// long after a false trip.
	GeoLockSeconds int `json:"geo_lock_seconds,omitempty"`
}

// GeoRegion is a named list of source networks - "oceania" as the address
// space allocated to AU, NZ and the Pacific islands, say - that a published
// service can be locked to.
//
// The list is operator-declared data, deliberately. There is no GeoIP
// database here: an address-to-country mapping would be a second external
// dependency with a licence and an update cadence, and a stale copy fails in
// silence, in whichever direction it happens to fail. The portal's Fetch
// button (see web.handleGeoFetch) fills the list for a set of country codes
// and deploy/geo-zones.sh prints the same data for pasting by hand; either
// way it lands here through a reviewed save, nothing refreshes on a
// schedule, and validation refuses anything nftables would choke on, so a
// typo is a rejected save rather than a rejected table.
//
// A region is direction-neutral: it is only a list. Each service chooses how
// to use one - admit only these sources (the default) or drop exactly these
// sources (Service.GeoBlock) - so the list can serve both jobs unchanged.
type GeoRegion struct {
	// Name is how services refer to the region. It becomes an nftables set
	// name (geo_<name>), so validation holds it to lowercase letters, digits,
	// hyphens and underscores.
	Name string `json:"name"`

	// CIDRs are the source networks the region admits. Overlapping and
	// duplicate entries are merged at generation - nftables rejects a whole
	// table over one overlapping set element, and a pasted list being
	// generous must not take every limit down with it.
	CIDRs []string `json:"cidrs"`

	// Countries is the remembered recipe for the portal's fetch button: the
	// ISO codes this list was last fetched for, so refreshing it is a click
	// rather than a thing to reconstruct. It routes nothing and generates
	// nothing - only CIDRs reaches the ruleset - and a hand-maintained
	// region simply leaves it empty.
	Countries []string `json:"countries,omitempty"`
}

// Linker is an extra host behind the backend that holds an overlay address.
//
// It is declared here rather than discovered because nothing in the system
// knows the mapping from an overlay address to the machine holding it: the
// linker agent has no control channel, and the frontend only ever sees the
// address as a DNAT target. Declaring it in one place is what lets the backend
// be told, rather than the operator installing a route by hand on a box the
// whole point of the agents is to stop logging into.
//
// Empty list is the state every site starts in and most stay in, and it must
// generate exactly what a build with no linker support generated - see the
// multi-host invariant.
type Linker struct {
	Name string `json:"name"`

	// OverlayIP is the address the frontend publishes services to, e.g.
	// 10.99.0.3. It must sit inside Overlay.Subnet.
	OverlayIP string `json:"overlay_ip"`

	// LanIP is the linker's address on the backend's network - the next hop
	// the backend forwards to. It is not the overlay address, and the two
	// names invite exactly that mistake.
	LanIP string `json:"lan_ip"`

	// Table is the routing table that host uses for its overlay traffic. Zero
	// means the default.
	//
	// Configurable because the number belongs to that machine's own namespace,
	// not to this system. A linker is somebody's server first, and a box that
	// already policy-routes - a second ISP, a VPN - may well be using the
	// default already. Two systems writing one table fight over its default
	// route, and the loser's traffic goes somewhere nobody intended.
	Table int `json:"table,omitempty"`

	Enabled bool `json:"enabled"`
}

// TableOr resolves which routing table a linker uses.
func (l Linker) TableOr(def int) int {
	if l.Table != 0 {
		return l.Table
	}
	return def
}

// Normalise fills in settings that a stored configuration predates.
//
// A config written by an older build unmarshals with any newer field at its
// zero value, and Defaults() only ever applies to a first run - so adding a
// field silently gives every existing deployment a zero for it. For the quality
// weights that means every path scoring identically and the portal showing a
// form full of zeros, which is how this was found.
//
// It is deliberately conservative: it fills in a group of settings only when
// *all* of them are zero, which cannot be a deliberate choice, and leaves an
// individual zero alone because that is a legitimate value for a margin or a
// dwell. Call it on load and on save, so a config from an older portal is
// treated the same as one from an older binary.
func Normalise(cfg *Config) {
	if cfg.Failover.Selection == "" {
		cfg.Failover.Selection = SelectionPriority
	}
	q := &cfg.Failover.Quality
	if q.LossWeight == 0 && q.RTTWeight == 0 && q.JitterWeight == 0 &&
		q.MarginPct == 0 && q.MinDwellSec == 0 {
		*q = Defaults().Failover.Quality
	}
}

// EgressConfig lists backend-side networks whose outbound traffic should leave
// through the frontend rather than out the house's own internet service.
//
// This is the second half of Frontend.BackendEgress, and it exists because a
// containerised service cannot use the first half. Binding to the overlay
// address is enough for anything running on the backend host, but the overlay
// address does not exist inside a container's network namespace - and the
// container's packets are forwarded through the host rather than originated on
// it, so there is no local socket to identify them by either. What is left to
// match on is where they came from: the bridge network's address range.
type EgressConfig struct {
	Sources []EgressSource `json:"sources"`
}

// EgressSource is one network whose traffic is pulled onto the tunnel.
type EgressSource struct {
	Name string `json:"name"` // free text, e.g. "gmod bridge"

	// Host is the overlay address of the agent that owns this network. Empty
	// means the backend, which is what every row meant before linkers existed.
	//
	// Without it the list is global and every agent installs every row. That is
	// not merely untidy: 172.17.0.0/16 is Docker's default bridge on *every*
	// machine, and the allocator hands out 172.18, 172.19 and so on in the same
	// order on each one - so several hosts routinely end up with the identical
	// subnet. One row would then pull containers onto the tunnel on hosts it
	// was never meant to touch, silently, and through a metered link.
	//
	// The matching rule is that a repeated CIDR *within* one host is an error
	// while the same CIDR on two different hosts is perfectly normal. See
	// web.validate.
	Host string `json:"host"`

	CIDR    string `json:"cidr"` // e.g. 172.18.0.0/16
	Enabled bool   `json:"enabled"`
}

// HostOr resolves which agent owns this network, defaulting to the backend.
func (s EgressSource) HostOr(backendIP string) string {
	if s.Host != "" {
		return s.Host
	}
	return backendIP
}

// FrontendConfig describes the datacentre box's public side, used to scope
// the DNAT rules so they only match traffic arriving from the internet.
type FrontendConfig struct {
	PublicIface string `json:"public_iface"` // e.g. eth0
	PublicIP    string `json:"public_ip"`    // optional; empty matches any address on the interface

	// BackendEgress sends traffic the backend originates from its overlay
	// address out through the frontend's public address, instead of out the
	// house's own internet service.
	//
	// It exists for game server registration. A Source server is listed in the
	// server browser at the address Steam observes its heartbeat coming from -
	// there is no way to declare a different one, deliberately, as anti-
	// spoofing. Without this the heartbeat leaves via pfSense and the server is
	// advertised at the home WAN address: not the published address, no port
	// forward behind it, changes when the service does, and unreachable
	// entirely while a CGNAT'd LTE path is carrying the traffic. Players who
	// found the server through the browser would bypass the failover.
	//
	// Off by default. It is opt-in because it also puts everything else the
	// backend sends from the overlay address onto the tunnel, and therefore
	// through the LTE quota during a failover.
	BackendEgress bool `json:"backend_egress"`
}

// OverlayConfig describes the stable addressing that makes failover invisible
// to clients. Neither address ever changes; only the interface the packets
// leave through does.
type OverlayConfig struct {
	FrontendIP string `json:"frontend_ip"` // e.g. 10.99.0.1
	BackendIP  string `json:"backend_ip"`  // e.g. 10.99.0.2

	// Device carries the overlay address. It is a dummy interface rather than
	// one of the tunnels on purpose: the address has to survive any tunnel
	// going down, or the source address would vanish with the link and the
	// whole point of the stable addressing would be lost.
	Device string `json:"device"`

	// Subnet is the range the frontend routes down the active tunnel, instead
	// of the backend's single address. Empty is the normal case and means
	// exactly what it always meant: one host at the far end, reached by a /32.
	//
	// It is only set on a site that runs linker agents. A site with one host at
	// the far end has no reason to route a range down its tunnel, so nothing
	// here is derived or assumed: an empty Subnet keeps the /32 behaviour byte
	// for byte.
	//
	// It also has to be covered by AllowedIPs on the frontend's peers, which is
	// why the shipped setup puts the whole range there from the start rather
	// than the backend's address - the narrower value fails silently, and only
	// on the day a second host appears.
	//
	// Like the rest of this struct it is bootstrap-owned, never portal-edited.
	// Both ends have to agree on it.
	Subnet string `json:"subnet"` // e.g. 10.99.0.0/24; empty = the backend alone

	ProbePort   int `json:"probe_port"`
	ControlPort int `json:"control_port"`
}

// MatchPrefix is what nftables rules match the overlay on, and RoutePrefix is
// what `ip route` installs and reads back for it.
//
// They differ in one respect only: with no subnet configured, MatchPrefix
// returns the backend's bare address and RoutePrefix an explicit /32. The
// kernel treats those as identical, but they are what each of the two already
// generated before this field existed - and a site with no linkers must produce
// byte-identical rules and commands, or every deployment gets a diff in
// ruleset.nft for a feature it does not use. Both are pinned by tests.
//
// Probing and the control channel deliberately use neither: those address the
// primary backend specifically and stay a /32 however many hosts sit behind it.
// Only the published data plane widens.
func (o OverlayConfig) MatchPrefix() string {
	if o.Subnet != "" {
		return o.Subnet
	}
	return o.BackendIP
}

// RoutePrefix is the destination the frontend routes down the active tunnel.
func (o OverlayConfig) RoutePrefix() string {
	if o.Subnet != "" {
		return o.Subnet
	}
	return o.BackendIP + "/32"
}

// PathConfig is one WireGuard tunnel and the policy attached to it.
type PathConfig struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`     // main, lte1, lte2
	Iface    string `json:"iface"`    // wg-main, wg-lte1, wg-lte2
	Priority int    `json:"priority"` // lower wins; 1 = most preferred
	Table    int    `json:"table"`    // routing table used to probe this path specifically
	Mark     int    `json:"mark"`     // fwmark selecting that table
	Enabled  bool   `json:"enabled"`
	Metered  bool   `json:"metered"` // subject to quota accounting
	Quota    Quota  `json:"quota"`

	// Shape is the queue discipline for this tunnel. Zero in both directions
	// means no shaping at all and no tc command is ever issued, which is the
	// state every existing site is in.
	Shape ShapeConfig `json:"shape,omitempty"`
}

// ShapeConfig is the rate each end may put into one tunnel.
//
// Two numbers because a queue only controls the direction it sits in front of,
// and the two ends face opposite ways: the frontend's queue on wg-lte1 governs
// what arrives at the house, the backend's queue on the same interface governs
// what leaves it. Naming them after the *link* rather than after the host means
// the operator enters the two figures a speed test gives them.
//
// The value belongs slightly under the real line rate. Set at or above it the
// queue forms in the carrier's buffer instead of ours and nothing has been
// gained; that queue is the whole point, because it is the one we can keep
// short.
type ShapeConfig struct {
	ToBackendMbit  float64 `json:"to_backend_mbit,omitempty"`  // frontend egress: the home's download
	ToFrontendMbit float64 `json:"to_frontend_mbit,omitempty"` // backend egress: the home's upload
}

// Quota is the monthly data allowance for a metered path.
type Quota struct {
	LimitBytes        int64   `json:"limit_bytes"`         // 0 disables the quota
	CeilingBytes      int64   `json:"ceiling_bytes"`       // absolute stop, 0 = none
	ResetDay          int     `json:"reset_day"`           // day of month, 1 = the 1st
	Timezone          string  `json:"timezone"`            // IANA zone for the reset boundary
	Calibration       float64 `json:"calibration"`         // percent, 100 = no correction
	OverheadPerPacket int     `json:"overhead_per_packet"` // bytes per packet for WG+UDP+IP
}

// ProbeConfig tunes end-to-end path testing. These probe the backend
// through each tunnel, not the state of the tunnel itself.
type ProbeConfig struct {
	ActiveIntervalMs  int     `json:"active_interval_ms"`
	StandbyIntervalMs int     `json:"standby_interval_ms"`
	TimeoutMs         int     `json:"timeout_ms"`
	FailThreshold     int     `json:"fail_threshold"`    // consecutive losses before down
	RecoverThreshold  int     `json:"recover_threshold"` // consecutive successes before up
	WindowSize        int     `json:"window_size"`       // sliding window for loss and jitter
	MaxLossPct        float64 `json:"max_loss_pct"`      // above this the path is degraded
	MaxRTTMs          int     `json:"max_rtt_ms"`        // above this the path is degraded
}

// DetectMs is roughly how long a dead active path takes to be condemned with
// this tuning: the first lost probe goes out, FailThreshold-1 more follow at
// the active interval, and the last of them has to time out. It is the floor
// under the lag spike a failover causes. The portal shows the same figure
// beside the tuning, computed in app.js from the live fields (it cannot call
// this), so the two must be kept in step by hand. FailThreshold is at least 1
// by validation; anything less is treated as 1.
func (p ProbeConfig) DetectMs() int {
	n := p.FailThreshold
	if n < 1 {
		n = 1
	}
	return (n-1)*p.ActiveIntervalMs + p.TimeoutMs
}

// DetectionPreset is a named tuning of the four settings that decide how fast a
// failing active path is condemned. The presets are portal convenience and
// nothing more: choosing one writes these numbers into ProbeConfig, the stored
// configuration carries only the numbers, and the engine has never heard of a
// preset. A site that never opens the dropdown is untouched.
//
// Note carries the trade-off. A faster condemnation is not free, it is bought
// with false failovers on links that drop bursts of packets, and each one of
// those parks players on a metered path for the length of the failback
// hold-down. The portal shows the note beside the choice so nobody picks the
// fast tuning thinking it is simply better.
type DetectionPreset struct {
	Name             string `json:"name"`
	Label            string `json:"label"`
	Note             string `json:"note"`
	ActiveIntervalMs int    `json:"active_interval_ms"`
	TimeoutMs        int    `json:"timeout_ms"`
	FailThreshold    int    `json:"fail_threshold"`
	WindowSize       int    `json:"window_size"`
}

// Apply writes the preset's numbers into a ProbeConfig, leaving recovery and
// the degraded thresholds alone. The standby interval is raised only if the
// new active interval would overtake it: validation refuses a standby cadence
// faster than the active one, and a preset the portal offers must never
// produce a form the portal then refuses to save. app.js does the same when
// the dropdown is used; this is the copy the tests run through validate.
func (d DetectionPreset) Apply(p *ProbeConfig) {
	p.ActiveIntervalMs = d.ActiveIntervalMs
	p.TimeoutMs = d.TimeoutMs
	p.FailThreshold = d.FailThreshold
	p.WindowSize = d.WindowSize
	if p.StandbyIntervalMs < d.ActiveIntervalMs {
		p.StandbyIntervalMs = d.ActiveIntervalMs
	}
}

// Names of the shipped presets. PresetStandard is the shipped tuning and must
// stay equal to Defaults().Probe, which model/presets_test.go pins.
const (
	PresetStandard = "standard"
	PresetFast     = "fast"
	PresetRelaxed  = "relaxed"
)

// DetectionPresets lists the shipped tunings, fastest detection first.
//
// The detection figures quoted in the notes are DetectMs for each tuning,
// which the test pins, so the prose cannot drift from the numbers. The probe
// data figure for the fast preset is 10 probes a second at roughly 130 bytes
// on the wire, request and reply both crossing the WAN, which is about 6.7 GB
// a month. It is only billed while a metered path is the active one.
func DetectionPresets() []DetectionPreset {
	return []DetectionPreset{
		{
			Name:  PresetFast,
			Label: "Fast",
			Note: "Condemns a dead path in about 0.6s, so a failover is a stutter rather than a freeze. " +
				"The trade: 400ms of silence is enough to move traffic, and LTE produces that on its own during a tower handover, " +
				"so expect the occasional failover that nothing was wrong for. Every false trip parks players on a metered link " +
				"until failback clears the hold-down (a couple of minutes), costs a visible switch each way, and counts towards quarantine. " +
				"The 300ms timeout must stay above the worst round trip on your slowest link, or late replies are booked as losses and " +
				"a loaded path reads as degraded. A reply slower than the timeout is never measured, so a Max RTT above 300 can no longer trip: " +
				"lower it, or accept that latency is judged by the timeout alone. " +
				"Probing at 100ms also costs about 6.7 GB a month of data, both directions billed, while an LTE path is the active one.",
			ActiveIntervalMs: 100,
			TimeoutMs:        300,
			FailThreshold:    4,
			WindowSize:       150,
		},
		{
			Name:  PresetStandard,
			Label: "Standard (default)",
			Note: "Condemns a dead path in about 2.6s. Tolerates the short bursts of loss LTE produces without moving traffic, " +
				"and the 800ms timeout sits well above any round trip a working link should see. " +
				"A real outage freezes the game for roughly three seconds before play resumes on the next path.",
			ActiveIntervalMs: 250,
			TimeoutMs:        800,
			FailThreshold:    8,
			WindowSize:       60,
		},
		{
			Name:  PresetRelaxed,
			Label: "Relaxed (for poor links)",
			Note: "For links that drop packets in bursts or spike in latency. Condemns a dead path in about 7s, so a real outage " +
				"freezes the game for longer, but a flaky link is not abandoned over a two second hiccup and then kept off traffic " +
				"for the whole failback hold-down. The 1500ms timeout stops latency spikes being counted as loss, and the loss figure " +
				"is averaged over 30 seconds rather than 15. Choose this when the dashboard shows the main link being condemned " +
				"and recovering on its own, which is the fingerprint of a tuning that is too tight for the link.",
			ActiveIntervalMs: 500,
			TimeoutMs:        1500,
			FailThreshold:    12,
			WindowSize:       60,
		},
	}
}

// ProtectPreset is a named filling of the five per-source limits in
// ProtectConfig. Portal convenience, exactly as DetectionPreset is: choosing
// one writes these numbers into the form, the stored configuration carries
// only the numbers, and nothing below the portal has ever heard of a preset.
//
// The numbers are grounded in what real clients send, because every limit
// here can drop a packet a real player sent and a threshold set from a guess
// produces "some people cannot connect". The anchors: a browser holds at most
// six connections to one host; a Source client sends its commands at 30 to 66
// packets a second, capped by the tick rate; the engine's own out-of-band
// throttle gives up near 60 queries a second, so a single-digit edge limit is
// already far below what would hurt it; and a carrier NAT routinely puts 16
// to 64 subscribers behind one address, which is why every figure leaves room
// for several clients sharing an address rather than exactly one.
type ProtectPreset struct {
	Name              string `json:"name"`
	Label             string `json:"label"`
	Note              string `json:"note"`
	NewConnsPerSec    int    `json:"new_conns_per_sec"`
	MaxConnsPerSource int    `json:"max_conns_per_source"`
	PacketsPerSec     int    `json:"packets_per_sec"`
	QueriesPerSec     int    `json:"queries_per_sec"`
	BlockSeconds      int    `json:"block_seconds"`
}

// Apply writes the preset's numbers into a ProtectConfig and touches nothing
// else: not the master switch, not the edge filtering toggles, not the
// regions. The dropdown fills five boxes; enabling the feature stays a
// separate, deliberate act.
func (p ProtectPreset) Apply(pr *ProtectConfig) {
	pr.NewConnsPerSec = p.NewConnsPerSec
	pr.MaxConnsPerSource = p.MaxConnsPerSource
	pr.PacketsPerSec = p.PacketsPerSec
	pr.QueriesPerSec = p.QueriesPerSec
	pr.BlockSeconds = p.BlockSeconds
}

// Names of the shipped per-source presets. ProtectPresetOff is every limit at
// zero and must stay equal to the shipped ProtectConfig, which
// model/protect_presets_test.go pins: a fresh install reads "Off", not
// "Custom", because all-zero is the state the system ships in rather than a
// choice somebody typed.
const (
	ProtectPresetOff    = "off"
	ProtectPresetTight  = "tight"
	ProtectPresetPublic = "public"
	ProtectPresetShared = "shared"
)

// ProtectPresets lists the shipped per-source tunings, tightest first after
// Off. Each note carries the data its numbers were sized from, shown beside
// the choice, because nothing else on the page says what a real client sends.
func ProtectPresets() []ProtectPreset {
	return []ProtectPreset{
		{
			Name:  ProtectPresetOff,
			Label: "Off (no per-source limits)",
			Note: "Every limit at zero: nothing is counted, nothing is dropped and nobody is parked. This is the shipped state. " +
				"The edge filtering and region locks below are separate switches and this choice does not touch them.",
		},
		{
			Name:  ProtectPresetTight,
			Label: "Small community (tight)",
			Note: "For a server whose players are known and mostly on home connections. 10 new connections a second and 50 concurrent " +
				"per address still clear a browser comfortably, which holds at most 6 connections to one host, but leave little room " +
				"for big shared networks. 150 UDP packets a second covers two Source players on one address, each sending at the usual " +
				"30 to 66 packets a second, and not a house full. 2 queries a second is ample for server browsers. A tripping source " +
				"is parked for 10 minutes, the classic fail2ban ban. Pick this only when the dashboard counters show real traffic " +
				"sitting far below these figures, because a player behind a shared carrier address is the one it will bite first.",
			NewConnsPerSec:    10,
			MaxConnsPerSource: 50,
			PacketsPerSec:     150,
			QueriesPerSec:     2,
			BlockSeconds:      600,
		},
		{
			Name:  ProtectPresetPublic,
			Label: "Public server",
			Note: "A defensible starting point for a public server. 20 new connections a second and 100 concurrent per address sit " +
				"well clear of a browser's 6 per host and of a small office NAT. 400 UDP packets a second covers five or six Source " +
				"players sharing one carrier address, each sending at the usual 30 to 66 packets a second. 3 queries a second is " +
				"ample for server browsers, and the query flood is the usual attack on a Source server. A tripping source is parked " +
				"for 10 minutes. Watch the counters after choosing this: a limit that trips in normal play reads from outside as " +
				"the service being down.",
			NewConnsPerSec:    20,
			MaxConnsPerSource: 100,
			PacketsPerSec:     400,
			QueriesPerSec:     3,
			BlockSeconds:      600,
		},
		{
			Name:  ProtectPresetShared,
			Label: "Shared networks (CGNAT-heavy)",
			Note: "For audiences heavy on mobile and university networks, where carrier NAT routinely puts 16 to 64 subscribers " +
				"behind one address. 1000 UDP packets a second covers a dozen Source players on one address; 40 new connections and " +
				"250 concurrent cover their browsers beside them. Parking is the dangerous half on shared addresses, since one park " +
				"is every household behind that NAT, so a tripping source is parked for one minute rather than ten. The limits " +
				"still stop a single flood; they are just sized so a busy shared address is not mistaken for one.",
			NewConnsPerSec:    40,
			MaxConnsPerSource: 250,
			PacketsPerSec:     1000,
			QueriesPerSec:     10,
			BlockSeconds:      60,
		},
	}
}

// Selection is how the engine chooses between eligible paths.
const (
	// SelectionPriority is strict priority order: the lowest priority number
	// that is usable wins, always.
	SelectionPriority = "priority"

	// SelectionQuality keeps priority order but allows a clearly better path to
	// take over. "Clearly" is QualityConfig.MarginPct; without a margin the
	// choice would change on measurement noise, and every change costs players
	// a freeze.
	SelectionQuality = "quality"
)

// FailoverConfig governs how paths are chosen and un-chosen.
type FailoverConfig struct {
	HoldDownSec      int `json:"hold_down_sec"`      // higher path must be clean this long before failback
	FlapWindowSec    int `json:"flap_window_sec"`    // circuit breaker observation window
	FlapThreshold    int `json:"flap_threshold"`     // failures in window before quarantine
	QuarantineSec    int `json:"quarantine_sec"`     // initial cooldown
	QuarantineMaxSec int `json:"quarantine_max_sec"` // cap on exponential backoff

	Selection string        `json:"selection"` // priority (default) or quality
	Quality   QualityConfig `json:"quality"`
}

// QualityConfig scores a path from its measurements. Lower is better.
//
// The weights are in milliseconds-equivalent, so they can be reasoned about
// against each other: LossWeight is how many milliseconds of latency one
// percent of packet loss is considered worth. It defaults high because for a
// game server that is the truth - a clean 60ms link beats a lossy 30ms one, and
// a scoring function that says otherwise would move traffic the wrong way.
type QualityConfig struct {
	LossWeight   float64 `json:"loss_weight"`   // ms-equivalent per 1% loss
	RTTWeight    float64 `json:"rtt_weight"`    // multiplier on mean RTT
	JitterWeight float64 `json:"jitter_weight"` // multiplier on jitter

	// MarginPct is how much better a path must score before it may take traffic
	// from the preferred one. This is what stops two similar links trading
	// places on noise: without it, 40ms and 45ms would swap every few seconds
	// and each swap is a visible stall.
	MarginPct float64 `json:"margin_pct"`

	// MinDwellSec is the floor under how often quality may move traffic.
	//
	// The margin and the hold-down between them make oscillation on noise
	// impossible - the two comparisons cannot both be satisfied at once, so
	// there is a dead zone rather than a threshold. What they do not do is cap
	// how often a *genuine* alternation can switch: two links really taking
	// turns being much better, which is what a carrier working on a tower
	// produces, would move traffic every hold-down indefinitely, and every move
	// costs connected players a freeze.
	//
	// It never delays a failover away from a path that has become unusable, nor
	// a failback to the preferred path. It only rate-limits choosing between
	// fallbacks that both work. Zero disables it.
	MinDwellSec int `json:"min_dwell_sec"`
}

// Service is a published port forwarded from the frontend's public address to
// the backend's overlay address. DNAT only, never SNAT, so the backend sees
// the real client IP.
type Service struct {
	Name    string `json:"name"`
	Proto   string `json:"proto"` // tcp or udp
	Port    int    `json:"port"`
	PortEnd int    `json:"port_end"` // 0 for a single port
	Enabled bool   `json:"enabled"`

	// Target is the overlay address this service is published to. Empty means
	// the backend, which is what every service meant before linkers existed and
	// what almost every service still means.
	//
	// It is an overlay address rather than a host name because that is what the
	// DNAT rule needs and what the routing already knows how to reach; a name
	// would be a second thing to keep in step for no gain.
	Target string `json:"target"`

	// SourceEngine marks a Source-engine game port, which changes nothing
	// unless protection is on. It is what lets the connectionless packets - the
	// A2S queries and connection attempts, which are the flood vector - be rate
	// limited without touching the traffic of players already in the game.
	SourceEngine bool `json:"source_engine,omitempty"`

	// CeilingPPS caps this service in total, across every client. Zero is no
	// cap. It exists because the scarce thing is the tunnel, not this box: an
	// attack that the datacentre link shrugs off will still bury a 20 Mbit LTE
	// service and bill you for it.
	CeilingPPS int `json:"ceiling_pps,omitempty"`

	// GeoRegions locks this service to sources inside the named protection
	// regions: with one or more set, everything arriving from outside their
	// union is dropped before it is translated or sent down a tunnel. Empty
	// means reachable from anywhere, which is what every service meant before
	// this existed.
	//
	// Like SourceEngine and CeilingPPS it does nothing unless protection is
	// on. The drop lives in the protection table, and that is not just
	// tidiness: unticking the protection master switch must remain the one
	// action that backs every filter out at once, region locks included.
	GeoRegions []string `json:"geo_regions,omitempty"`

	// GeoBlock inverts the lock: instead of admitting only the named regions,
	// drop them and admit everywhere else. False, the shipped and historical
	// value, is the allow-only lock above. The regions themselves are
	// direction-neutral lists; which way a port uses one is decided here, per
	// service, so one "au" region can lock a game server to Australia and bar
	// Australia from something else at the same time.
	GeoBlock bool `json:"geo_block,omitempty"`

	// GeoAutoPPS makes the lock conditional: the port stays open to the world
	// until its total arriving traffic exceeds this many packets per second,
	// and only then is everything outside GeoRegions dropped. The lock
	// engages in the kernel at line rate, holds while the flood continues,
	// and releases GeoLockSeconds after it stops - the agent decides nothing
	// and polls nothing, so a flood arriving at 3am is met at once.
	//
	// Zero with regions set means the lock is unconditional. The threshold
	// counts every packet to the row's ports together, in-region traffic
	// included, so it belongs above the busiest legitimate moment measured -
	// a full server tripping it costs out-of-region players their access.
	GeoAutoPPS int `json:"geo_auto_pps,omitempty"`
}

// TargetOr resolves where a service is published, defaulting to the backend.
func (s Service) TargetOr(backendIP string) string {
	if s.Target != "" {
		return s.Target
	}
	return backendIP
}

// NotifyConfig configures outbound alerts. Strongly recommended: quota
// exhaustion parks the system waiting for a human to click approve.
type NotifyConfig struct {
	Enabled    bool   `json:"enabled"`
	Kind       string `json:"kind"` // webhook, ntfy, telegram
	URL        string `json:"url"`
	Token      string `json:"token"`
	OnSwitch   bool   `json:"on_switch"`
	OnPathDown bool   `json:"on_path_down"`
	OnQuota    bool   `json:"on_quota"`
	OnHeld     bool   `json:"on_held"`
}

// PathState is the live runtime view of one path, as shown in the portal.
type PathState struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Iface    string `json:"iface"`
	Priority int    `json:"priority"`

	Health Health `json:"health"`
	Block  Block  `json:"block"`
	Active bool   `json:"active"`

	RTTms      float64 `json:"rtt_ms"`
	JitterMs   float64 `json:"jitter_ms"`
	LossPct    float64 `json:"loss_pct"`
	ConsecLoss int     `json:"consec_loss"`
	ConsecOK   int     `json:"consec_ok"`

	LastReply    time.Time `json:"last_reply"`
	HandshakeAge float64   `json:"handshake_age_sec"` // corroborating signal only

	// PeerEndpoint is the address this tunnel's peer is currently seen at, as
	// observed by the frontend. Because the backend dials out from behind
	// CGNAT, it is the public address of the service that tunnel actually rode
	// - which is the only direct evidence that pfSense pinned each tunnel to a
	// different WAN. Two paths showing one address is that fault, and it is
	// otherwise invisible: all three probe perfectly while there is only one
	// link underneath them.
	PeerEndpoint  string    `json:"peer_endpoint,omitempty"`
	CleanSince    time.Time `json:"clean_since"` // for failback hold-down
	QuarantineEnd time.Time `json:"quarantine_end"`

	UsedBytes   int64     `json:"used_bytes"`
	LimitBytes  int64     `json:"limit_bytes"`
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	GrantUntil  time.Time `json:"grant_until"`
	GrantBytes  int64     `json:"grant_bytes"`
}

// Eligible reports whether the selector may choose this path.
//
// Suspect counts as eligible: it only means a probe was missed recently, and
// treating a single lost packet as disqualifying would make the system thrash
// between tunnels. Sustained loss is caught by the degraded block instead.
func (p PathState) Eligible() bool {
	return (p.Health == HealthUp || p.Health == HealthSuspect) && p.Block == BlockNone
}

// Status is the whole system snapshot the portal renders.
type Status struct {
	Mode       string      `json:"mode"`
	ActivePath int         `json:"active_path"`
	ActiveName string      `json:"active_name"`
	Held       bool        `json:"held"` // no eligible path, waiting on approval
	HeldReason string      `json:"held_reason"`
	Paths      []PathState `json:"paths"`
	LastSwitch time.Time   `json:"last_switch"`
	BackendUp  bool        `json:"backend_up"` // control channel connected
	// RulesActive reports that traffic-affecting rules are installed. It can be
	// true while the mode is observe: disarming stops further changes but does
	// not tear down what is already published.
	RulesActive bool    `json:"rules_active"`
	Uptime      float64 `json:"uptime_sec"`
	DecisionSeq uint64  `json:"decision_seq"`

	// Reverted reports the post-revert hold: probing is stopped and nothing is
	// installed or repaired until settings are saved or the mode is changed.
	// Said here because the trackers freeze at whatever they last measured, so
	// without it the portal showed three healthy-looking paths on a system
	// measuring nothing, indefinitely.
	Reverted bool `json:"reverted"`

	// PreferredPath is the most preferred enabled path - the one the system
	// returns to on its clean streak. Reported so the portal can say whether
	// traffic is on it or on a fallback without reimplementing the rule, which
	// would then be free to drift from the selector's own definition.
	PreferredPath int `json:"preferred_path"`

	// PublicAddress is the WAN address published services are reachable at:
	// the configured Frontend.PublicIP, or, with that blank, read from the
	// public interface at the time of asking, preferring a publicly routable
	// IPv4 over private and carrier-NAT space when the interface holds both.
	// Display only; nothing routes or matches on it.
	PublicAddress string `json:"public_address,omitempty"`

	// Versions are here because there was no way to tell what a running host
	// was from the portal, and a stale idea of the deployed build sends any
	// procedure that depends on it down the wrong path. The backend's arrives
	// in its Hello frame; it is the last one reported, so it can outlive the
	// connection - BackendUp is what says whether the channel is live.
	FrontendVersion string `json:"frontend_version"`
	BackendVersion  string `json:"backend_version,omitempty"`
	BackendHost     string `json:"backend_host,omitempty"`

	// LinkerStates is liveness for the extra hosts, and it sits here beside the
	// paths rather than among them on purpose. A game server box being down is
	// not a path problem: feeding it to the trackers would make rebooting one
	// look like a failing tunnel and move traffic to a metered link.
	LinkerStates []LinkerState `json:"linker_states,omitempty"`

	// Protect is what the edge limiters have actually done. Absent unless the
	// feature is switched on and its rules are really loaded.
	Protect *ProtectStatus `json:"protect,omitempty"`

	// QueryCache is one row per cached port. Absent unless the cache is
	// running. Reported for the reason the protect counters are, doubled: a
	// cache serving stale data looks exactly like a healthy server with the
	// wrong map name, and only this says which is happening.
	QueryCache []QueryCacheState `json:"query_cache,omitempty"`

	// SharedEndpoints lists tunnels seen arriving from one public address,
	// which means they are riding the same internet service. Empty is healthy
	// and the normal case.
	//
	// It is reported separately from the paths, and loudly, because it is not a
	// path fault: each of those tunnels works perfectly and probes perfectly.
	// What has failed is the assumption the whole system rests on - that there
	// are three independent links underneath - and nothing else in here can
	// see that.
	SharedEndpoints []SharedEndpoint `json:"shared_endpoints,omitempty"`
}

// SharedEndpoint is one public address that more than one tunnel is arriving
// from, and the paths involved.
type SharedEndpoint struct {
	Address string   `json:"address"`
	Paths   []string `json:"paths"`
}

// ProtectStatus is the running state of the edge filtering.
//
// The counters are the whole point of reporting any of this. A limit that is
// dropping traffic and a service that is broken look identical from outside, so
// a limiter nobody can see the effect of is worse than no limiter: it turns a
// tuning mistake into an unexplained outage.
type ProtectStatus struct {
	Counters []ProtectCounter `json:"counters,omitempty"`
	Blocked  []BlockedSource  `json:"blocked,omitempty"`

	// GeoLocked lists the ports whose automatic region lock is currently
	// engaged. Reported for the same reason the counters are: an engaged lock
	// looks exactly like the service being down to everybody outside the
	// region, and only this says which of the two is happening.
	GeoLocked []GeoLockedPort `json:"geo_locked,omitempty"`
}

// ProtectCounter is one limiter's tally since the rules were last loaded.
// Saving a change to the protection settings reloads them, so these reset
// when a limit is edited; a save that leaves protection untouched does not.
type ProtectCounter struct {
	Name    string `json:"name"`
	Packets int64  `json:"packets"`
	Bytes   int64  `json:"bytes"`

	// Drops says whether the packets counted were discarded. The auto-lock
	// trip counter observes a threshold being crossed and drops nothing, and
	// the portal's "packets dropped" total must not include it. Read from
	// the rule's own drop verdict in the kernel readback rather than sniffed
	// off the counter's name in the portal: a name is a label, not a
	// semantic, and the verdict cannot go stale when a counter is added.
	Drops bool `json:"drops"`
}

// BlockedSource is an address parked by a limit, and the seconds it has left.
type BlockedSource struct {
	Address    string `json:"address"`
	ExpiresSec int    `json:"expires_sec"`
}

// QueryCacheState is the running state of one cached port.
type QueryCacheState struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Target  string `json:"target"`

	// Answered counts payloads served from cache; Challenged counts the
	// challenge replies that every new source gets first, so under a spoofed
	// flood this is the number climbing. Unanswered counts correctly
	// challenged queries the cache had nothing fresh to serve - a steady
	// climb here with the age high is the fingerprint of the upstream being
	// unreachable.
	Answered   uint64 `json:"answered"`
	Challenged uint64 `json:"challenged"`
	Unanswered uint64 `json:"unanswered"`

	// The ages are how old each cached reply is, -1 for never fetched. The
	// cache stops serving a reply past its staleness bound, so a port can be
	// listed here and still answer nothing.
	InfoAgeSec   float64 `json:"info_age_sec"`
	PlayerAgeSec float64 `json:"player_age_sec"`
	RulesAgeSec  float64 `json:"rules_age_sec"`

	// Error is a port whose socket could not be bound: something else on the
	// frontend holds it, and every query to it is being redirected to nothing.
	// Loud in the portal for that reason.
	Error string `json:"error,omitempty"`

	// RefreshError is the last upstream refresh failure, cleared by the next
	// success. "Never fetched" without this is a question rather than a
	// report: it cannot distinguish a game server that is down or missing
	// from a port that only scanners ever query - scanners complete
	// challenges like anybody else, so a port with nothing behind it still
	// shows counters climbing while its cache stays empty, and this is the
	// line that says why.
	RefreshError string `json:"refresh_error,omitempty"`
}

// GeoLockedPort is one port with its automatic region lock engaged, and the
// seconds until it releases if the traffic that engaged it has stopped. While
// the flood continues the expiry keeps being refreshed, so a lock that will
// not count down is one whose flood is still arriving.
type GeoLockedPort struct {
	Proto      string `json:"proto"`
	Port       int    `json:"port"`
	ExpiresSec int    `json:"expires_sec"`
}

// LinkerState is what the frontend knows about one extra host.
type LinkerState struct {
	Name      string    `json:"name"`
	OverlayIP string    `json:"overlay_ip"`
	LanIP     string    `json:"lan_ip"`
	Up        bool      `json:"up"`
	Version   string    `json:"version,omitempty"`
	Hostname  string    `json:"hostname,omitempty"`
	Since     time.Time `json:"since,omitempty"`

	// LastSeen is when a frame last arrived from this host, and it is kept
	// after the connection goes. Since answers how long the host has been
	// connected; once it is not, the only useful question is how long it has
	// been quiet - and a blank there reads exactly like a host that has never
	// connected at all, which is a different fault with a different fix.
	LastSeen time.Time `json:"last_seen,omitempty"`

	// ConfiguredTable is what the portal holds for this host.
	ConfiguredTable int `json:"configured_table,omitempty"`

	// Table is what the host reported it is actually using. It can disagree
	// with the configured value, because that value has to be present in the
	// host's own bootstrap file before it can be told anything - so the portal
	// says so rather than letting the two drift unnoticed.
	Table int `json:"table,omitempty"`
}

// Defaults returns a configuration matching the agreed design: strict
// main > LTE1 > LTE2 priority, 2-3 second detection, quotas on both LTE paths,
// and observe mode so a fresh install cannot move traffic until it is armed.
func Defaults() Config {
	quota := func(limit int64) Quota {
		return Quota{
			LimitBytes:        limit,
			CeilingBytes:      0,
			ResetDay:          1,
			Timezone:          DefaultTimezone,
			Calibration:       100,
			OverheadPerPacket: 60,
		}
	}
	return Config{
		Mode: ModeObserve,
		Frontend: FrontendConfig{
			PublicIface: "eth0",
		},
		Overlay: OverlayConfig{
			FrontendIP:  "10.99.0.1",
			BackendIP:   "10.99.0.2",
			Device:      "dummy0",
			ProbePort:   51999,
			ControlPort: 51998,
		},
		Paths: []PathConfig{
			{ID: 1, Name: "main", Iface: "wg-main", Priority: 1, Table: 101, Mark: 0x101, Enabled: true},
			{ID: 2, Name: "lte1", Iface: "wg-lte1", Priority: 2, Table: 102, Mark: 0x102, Enabled: true, Metered: true, Quota: quota(60 << 30)},
			{ID: 3, Name: "lte2", Iface: "wg-lte2", Priority: 3, Table: 103, Mark: 0x103, Enabled: true, Metered: true, Quota: quota(20 << 30)},
		},
		Probe: ProbeConfig{
			ActiveIntervalMs: 250,
			// Standby paths are probed far more slowly than the active one,
			// because the two answer different questions. The active path is
			// being watched for failure and every extra second of detection is
			// a second of dropped traffic; a standby path only has to be
			// known-good by the time it is needed, and probing it is itself
			// billed against the LTE quota it is being kept in reserve for.
			//
			// At one second a standby tunnel spends roughly 650 MB a month on
			// probes alone - 66 bytes of payload plus about 60 of encapsulation,
			// both ways, 86400 times a day. Five seconds costs about 130 MB and
			// changes nothing that matters: a standby path still condemns after
			// FailThreshold losses, and failback to a recovered path is governed
			// by HoldDownSec, which is far longer either way.
			StandbyIntervalMs: 5000,
			TimeoutMs:         800,
			FailThreshold:     8,
			RecoverThreshold:  10,
			WindowSize:        60,
			MaxLossPct:        15,
			MaxRTTMs:          400,
		},
		Failover: FailoverConfig{
			HoldDownSec:      90,
			FlapWindowSec:    600,
			FlapThreshold:    4,
			QuarantineSec:    300,
			QuarantineMaxSec: 3600,

			// Strict priority by default. Priority order is not merely a
			// preference here - it is the cost ordering, the main link being unmetered
			// and the LTE services capped - so choosing on measurements alone
			// is opt-in.
			Selection: SelectionPriority,
			Quality: QualityConfig{
				LossWeight:   25, // 1% loss is worth about 25ms of latency
				RTTWeight:    1,
				JitterWeight: 3,
				MarginPct:    25,
				MinDwellSec:  300,
			},
		},
		// Shipped as examples, and every one of them disabled.
		//
		// They are the ports this system was built for, so they are worth
		// having in the table as a starting shape - but a service row is a DNAT
		// rule, and enabling one publishes a port on the frontend's public
		// address to whatever happens to be listening at the far end. A fresh
		// install should not be doing that because nobody deleted a row: the
		// operator ticks what this site actually serves. Observe mode delays
		// that rather than preventing it - arming a site is the moment the
		// shipped list would have gone live.
		//
		// The list is the shape of the deployment this was built for: the web
		// front, a Pterodactyl panel's SFTP and Wings daemon, the Source
		// engine's port range - one rule for every server the panel spawns -
		// and a Minecraft server.
		Services: []Service{
			{Name: "http", Proto: "tcp", Port: 80},
			{Name: "https", Proto: "tcp", Port: 443},
			{Name: "pterodactyl-sftp", Proto: "tcp", Port: 2022},
			{Name: "pterodactyl-wings", Proto: "tcp", Port: 8080},
			{Name: "source", Proto: "udp", Port: 27015, PortEnd: 27030},
			{Name: "minecraft", Proto: "tcp", Port: 25565},
		},
		// The Docker network a Pterodactyl install puts its containers on,
		// ready to tick once Frontend.BackendEgress is on. Disabled for the
		// same reason the services above are: a row that arrives enabled
		// would pull every container on that bridge onto the tunnel, and
		// through the metered quota, on the strength of nobody deleting it.
		Egress: EgressConfig{
			Sources: []EgressSource{
				{Name: "pterodactyl", CIDR: "172.18.0.0/16", Enabled: false},
			},
		},
		Notify: NotifyConfig{
			Enabled: false, Kind: "ntfy",
			OnSwitch: true, OnPathDown: true, OnQuota: true, OnHeld: true,
		},
	}
}

// PathByID looks up a path config by its id.
func (c Config) PathByID(id int) (PathConfig, bool) {
	for _, p := range c.Paths {
		if p.ID == id {
			return p, true
		}
	}
	return PathConfig{}, false
}
