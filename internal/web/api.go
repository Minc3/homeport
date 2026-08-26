package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/quota"
	"github.com/quinlan102/homeport/internal/store"
	"github.com/quinlan102/homeport/internal/sysx"
)

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	st := s.eng.Status()
	writeJSON(w, http.StatusOK, map[string]any{
		"status": st,
		"pinned": s.eng.PinnedPath(),
	})
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.eng.Config())
}

// handlePresets serves the shipped detection tunings for the settings page's
// dropdown. They live in model so a test can pin the standard one to the
// shipped defaults; the portal is only a consumer.
func (s *Server) handlePresets(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, model.DetectionPresets())
}

// handleProtectPresets serves the shipped per-source limit tunings for the
// protection section's dropdown, on the same contract as handlePresets: the
// portal is only a consumer, and the stored configuration never carries a
// preset name.
func (s *Server) handleProtectPresets(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, model.ProtectPresets())
}

// handlePutConfig replaces the whole configuration. The portal is the single
// source of truth, so this is the only way settings change; the backend picks
// up its half over the control channel within a couple of seconds.
func (s *Server) handlePutConfig(w http.ResponseWriter, r *http.Request) {
	var cfg model.Config
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxConfigBytes)).Decode(&cfg); err != nil {
		clientErr(w, fmt.Errorf("invalid configuration: %w", err))
		return
	}

	pinServerOwnedFields(&cfg, s.eng.Config())

	if err := validate(&cfg); err != nil {
		clientErr(w, err)
		return
	}
	if err := s.eng.Reconfigure(cfg); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// pinServerOwnedFields overwrites the parts of a PUT body that the settings
// page carries but must never change, with the running engine's own values.
//
// Overlay addressing comes from the bootstrap file on both hosts and is not
// editable here. Changing it through the portal would tear down the very
// channel the change has to travel over: the probes would rebind to a new
// address, the control server would still be listening on the old one, and
// the backend could never be told. It was also silently reverted on the next
// restart, so an edit looked accepted and then vanished.
//
// The mode rides inside the blob but is not a setting on the page that sends
// it: it changes from the dashboard (POST /api/mode), from failoverctl, and
// by a revert dropping the system to observe. Applying the copy a browser tab
// loaded would re-impose however the system stood when that tab last
// refreshed. A settings save from a tab left open across a revert would
// silently re-arm the frontend, and Reconfigure clears the revert latch, so
// the rules the revert had just removed came straight back.
func pinServerOwnedFields(cfg *model.Config, current model.Config) {
	cfg.Overlay = current.Overlay
	cfg.Mode = current.Mode
}

// validate rejects configurations that would leave the system unable to make a
// decision, and normalises the fields the UI is allowed to leave blank.
func validate(cfg *model.Config) error {
	if cfg.Mode != model.ModeObserve && cfg.Mode != model.ModeArmed {
		return fmt.Errorf("mode must be %q or %q", model.ModeObserve, model.ModeArmed)
	}
	if net.ParseIP(cfg.Overlay.FrontendIP) == nil {
		return errors.New("overlay frontend IP is not a valid address")
	}
	if net.ParseIP(cfg.Overlay.BackendIP) == nil {
		return errors.New("overlay backend IP is not a valid address")
	}
	if cfg.Overlay.ProbePort < 1 || cfg.Overlay.ProbePort > 65535 {
		return errors.New("overlay probe port is out of range")
	}
	if cfg.Overlay.ControlPort < 1 || cfg.Overlay.ControlPort > 65535 {
		return errors.New("overlay control port is out of range")
	}
	if cfg.Overlay.ProbePort == cfg.Overlay.ControlPort {
		return errors.New("overlay probe and control ports must differ")
	}
	if len(cfg.Paths) == 0 {
		return errors.New("at least one path is required")
	}
	// Rejected rather than quietly ignored: without an output interface the
	// rule would have to match every way out, including the tunnels, and
	// rewriting the source of a reply heading back to a player is the one thing
	// this system exists not to do.
	if cfg.Frontend.BackendEgress && trimmed(cfg.Frontend.PublicIface) == "" {
		return errors.New("backend egress needs the frontend's public interface set")
	}
	// IPv4 specifically, for the reason parseIPv4Network exists a few hundred
	// lines down: this value is rendered into `table ip failover` as `ip daddr`
	// and into `table ip failover_egress` as `snat to`, and nft rejects a whole
	// table over one address of the wrong family. A bare ParseIP accepted
	// "2001:db8::1" and an IPv4-mapped "::ffff:203.0.113.7" alike, and stored
	// each unchanged, so the first save carrying either took every published
	// service off the air - the DNAT ruleset does not load at all, so it is not
	// one broken rule, it is all of them. The lesson was learned twice already,
	// for the region lists and for the egress sources; this field was simply
	// not on either list.
	//
	// The two are answered differently, matching sysx.AddressLiteral rather
	// than inventing a rule here: the wrong family is refused, while a mapped
	// address is flattened to the dotted quad it denotes. Unlike a mapped
	// *network*, whose mask stays 128 wide and renders a form nft refuses, To4
	// on a bare address yields something the ruleset can carry.
	//
	// The gate is here rather than in the generator on purpose. A generator
	// that dropped an address it could not use would drop the `ip daddr` match
	// with it, publishing every service on every address this host holds -
	// failing open in the one direction that must never happen. So the value is
	// normalised at the boundary and the generator is not asked to second-guess
	// it.
	//
	// What that leaves is a value an older build stored before this gate
	// existed, which no save has ever been through. It is not silently carried:
	// `nft -f` is atomic, so the table it renders is rejected whole and the
	// working ruleset already loaded stays up with a loud error beside it,
	// while this check refuses every save naming the field until the form is
	// corrected. Loud in two places and open in neither is the right answer for
	// a value only an operator can have typed - which is why there is no
	// re-parse in the generator to match the ones on the pushed egress
	// networks and overlay address. Those arrive from a socket; this one does
	// not.
	if cfg.Frontend.PublicIP != "" {
		v, err := parseIPv4Address(cfg.Frontend.PublicIP)
		if err != nil {
			return fmt.Errorf("frontend public IP: %w", err)
		}
		cfg.Frontend.PublicIP = v
	}
	// An older portal, or a hand-written PUT, sends nothing for fields it does
	// not know about. Treated the same as an older stored config.
	model.Normalise(cfg)

	switch cfg.Failover.Selection {
	case model.SelectionPriority, model.SelectionQuality:
	default:
		return fmt.Errorf("selection must be %q or %q", model.SelectionPriority, model.SelectionQuality)
	}
	// A negative weight would make a worse measurement improve the score, and
	// the path that was losing the most packets would win.
	q := &cfg.Failover.Quality
	if q.LossWeight < 0 || q.RTTWeight < 0 || q.JitterWeight < 0 {
		return errors.New("quality weights cannot be negative")
	}
	// At 100% nothing can ever beat anything, which reads as the feature being
	// broken; above it the comparison inverts.
	if q.MarginPct < 0 || q.MarginPct >= 100 {
		return errors.New("switch margin must be between 0 and 99 percent")
	}
	if q.MinDwellSec < 0 {
		return errors.New("minimum dwell cannot be negative")
	}
	if q.LossWeight == 0 && q.RTTWeight == 0 && q.JitterWeight == 0 &&
		cfg.Failover.Selection == model.SelectionQuality {
		return errors.New("quality selection needs at least one non-zero weight")
	}

	// Linkers first. Both the egress rows and the published services are
	// checked against this list, so it has to be known-good before anything is
	// assigned or published to one.
	seenLinker := map[string]bool{}
	cfg.BackendLAN = trimmed(cfg.BackendLAN)
	if len(cfg.Linkers) > 0 {
		if cfg.BackendLAN == "" {
			return fmt.Errorf("set the backend's address on the linker network: " +
				"a linker reaches the backend as a neighbour, and its own config cannot be generated without it")
		}
		if net.ParseIP(cfg.BackendLAN) == nil {
			return fmt.Errorf("the backend's LAN address %q is not an address", cfg.BackendLAN)
		}
		if cfg.BackendLAN == cfg.Overlay.BackendIP {
			return fmt.Errorf("the backend's LAN address is %s, its overlay address: "+
				"overlay traffic reaches the backend as a neighbour on the linker network, so this is its address there",
				cfg.BackendLAN)
		}
	}
	for i := range cfg.Linkers {
		lk := &cfg.Linkers[i]
		lk.Name = trimmed(lk.Name)
		lk.OverlayIP = trimmed(lk.OverlayIP)
		lk.LanIP = trimmed(lk.LanIP)

		if lk.Name == "" {
			return fmt.Errorf("every linker needs a name")
		}
		if cfg.Overlay.Subnet == "" {
			return fmt.Errorf("linker %s cannot be configured: this site has no overlay subnet. "+
				"Set overlay.subnet in the frontend's and the backend's bootstrap files first, "+
				"and check the frontend's WireGuard peers cover that range", lk.Name)
		}
		if net.ParseIP(lk.OverlayIP) == nil {
			return fmt.Errorf("linker %s has overlay address %q, which is not an address", lk.Name, lk.OverlayIP)
		}
		if net.ParseIP(lk.LanIP) == nil {
			return fmt.Errorf("linker %s has LAN address %q, which is not an address", lk.Name, lk.LanIP)
		}
		// The two addresses are easy to transpose, and doing so produces a
		// route pointing at the address it is meant to reach.
		if lk.OverlayIP == lk.LanIP {
			return fmt.Errorf("linker %s has the same address for its overlay and its LAN: "+
				"the LAN address is the neighbour the backend forwards to, not the address it is forwarding for", lk.Name)
		}
		if lk.LanIP == cfg.BackendLAN {
			return fmt.Errorf("linker %s has the backend's own LAN address %s", lk.Name, lk.LanIP)
		}
		if lk.OverlayIP == cfg.Overlay.BackendIP || lk.OverlayIP == cfg.Overlay.FrontendIP {
			return fmt.Errorf("linker %s claims %s, which is already the frontend's or the backend's overlay address",
				lk.Name, lk.OverlayIP)
		}
		if !overlayContains(cfg.Overlay, lk.OverlayIP) {
			return fmt.Errorf("linker %s claims %s, which is outside the overlay subnet %s",
				lk.Name, lk.OverlayIP, cfg.Overlay.Subnet)
		}
		// The reserved numbers are the kernel's own, and 253-255 in particular
		// are default/main/local - writing a default route into one of those
		// would redirect the whole host.
		if lk.Table < 0 || lk.Table > 252 {
			return fmt.Errorf("linker %s has routing table %d; it must be between 1 and 252, or 0 for the default",
				lk.Name, lk.Table)
		}
		// The linker's table is that host's own namespace, so this cannot check
		// what else is using it there - but it can refuse the numbers this
		// system is definitely using at the far end, which are the ones an
		// operator copying from the docs is most likely to reach for.
		if t := lk.TableOr(0); t != 0 {
			if t == sysx.ReturnTable || t == sysx.ControlTable {
				return fmt.Errorf("linker %s uses routing table %d, which this system already uses elsewhere; pick another",
					lk.Name, t)
			}
			for _, p := range cfg.Paths {
				if p.Table == t {
					return fmt.Errorf("linker %s uses routing table %d, which is path %s's probe table; pick another",
						lk.Name, t, p.Name)
				}
			}
		}
		// Two linkers on one address means two routes for the same
		// destination, and whichever the backend installed last silently wins.
		if seenLinker[lk.OverlayIP] {
			return fmt.Errorf("two linkers both claim the overlay address %s", lk.OverlayIP)
		}
		seenLinker[lk.OverlayIP] = true
	}

	for i := range cfg.Egress.Sources {
		s := &cfg.Egress.Sources[i]
		s.Name = trimmed(s.Name)
		s.CIDR = trimmed(s.CIDR)
		if s.CIDR == "" {
			return errors.New("every egress source needs a network in CIDR form, e.g. 172.18.0.0/16")
		}
		// Parsed rather than passed through, because it ends up inside a
		// generated nftables rule. A malformed value would fail the whole
		// ruleset load, taking the backend's reply marking down with it.
		netw, err := parseIPv4Network(s.CIDR)
		if err != nil {
			return fmt.Errorf("egress source %v", err)
		}
		s.CIDR = netw // normalise 172.18.0.5/16 to 172.18.0.0/16

		s.Host = trimmed(s.Host)
		if s.Host != "" {
			if net.ParseIP(s.Host) == nil {
				return fmt.Errorf("egress source %q names an owner that is not an address: %q", s.CIDR, s.Host)
			}
			// Fail closed, like a service target. A row naming a host nothing
			// will ever deliver it to is not an error the operator can see:
			// the portal accepts it, the list is filtered on the way out, and
			// nothing at all happens on any machine.
			if overlayContains(cfg.Overlay, s.Host) && s.Host != cfg.Overlay.BackendIP && !seenLinker[s.Host] {
				return fmt.Errorf("egress network %s is assigned to %s, which is not a configured linker: "+
					"add it under Linkers first, or leave the host blank for the backend", s.CIDR, s.Host)
			}
			if !overlayContains(cfg.Overlay, s.Host) {
				return fmt.Errorf("egress source %q is owned by %s, which is not in the overlay range", s.CIDR, s.Host)
			}
		}
	}

	// The same network on two hosts is normal and must stay legal: Docker's
	// default bridge is 172.17.0.0/16 on every machine, and the allocator walks
	// 172.18, 172.19 and so on in the same order on each one. Only a repeat
	// within a single host is a mistake - two rules generating the same mark
	// and SNAT twice.
	seenSource := map[string]bool{}
	for _, s := range cfg.Egress.Sources {
		key := s.HostOr(cfg.Overlay.BackendIP) + " " + s.CIDR
		if seenSource[key] {
			return fmt.Errorf("egress source %s is listed twice for the same host", s.CIDR)
		}
		seenSource[key] = true
	}

	seenID := map[int]bool{}
	seenTable := map[int]bool{}
	seenMark := map[int]bool{}
	for i := range cfg.Paths {
		p := &cfg.Paths[i]
		if p.ID <= 0 {
			return errors.New("every path needs a positive id")
		}
		// Two rule priorities are derived from the id: the lookup at
		// ProbeRulePrefBase+id and the refusal at ProbeDenyRulePrefBase+id.
		// An id of 100 lands the lookup on the egress rule's priority, and a
		// large one carries the refusal past the source rules, where a probe
		// would be routed by table 100 before it was refused.
		if p.ID >= sysx.ProbeDenyBandSize {
			return fmt.Errorf("path id %d is too large; ids must be below %d", p.ID, sysx.ProbeDenyBandSize)
		}
		if seenID[p.ID] {
			return fmt.Errorf("duplicate path id %d", p.ID)
		}
		seenID[p.ID] = true
		if trimmed(p.Name) == "" {
			return fmt.Errorf("path %d needs a name", p.ID)
		}
		if trimmed(p.Iface) == "" {
			return fmt.Errorf("path %s needs an interface", p.Name)
		}
		if p.Table <= 0 || p.Table > 252 {
			return fmt.Errorf("path %s needs a routing table between 1 and 252", p.Name)
		}
		// Table 100 and mark 0x100 belong to the control channel on the
		// frontend and the reply path on the backend. A path that took either
		// would fight them for the same traffic.
		if p.Table == sysx.ControlTable {
			return fmt.Errorf("path %s uses routing table %d, which is reserved for the control and return paths",
				p.Name, sysx.ControlTable)
		}
		if seenTable[p.Table] {
			return fmt.Errorf("path %s reuses routing table %d", p.Name, p.Table)
		}
		seenTable[p.Table] = true
		if p.Mark == 0 {
			return fmt.Errorf("path %s needs a non-zero fwmark", p.Name)
		}
		// Every mark this system uses for something else, not just the control
		// channel's. A path sharing one is not a cosmetic clash: on the backend
		// the reserved rule and the path rule both select the same packets, the
		// reserved one is installed ahead of the probe band, and it wins - so
		// that path's probe replies leave by whichever tunnel is active instead
		// of the one their request arrived on. The standby still answers and
		// still reads healthy; what it measures is a round trip over two
		// different tunnels, which means a link dead in the return direction
		// tests as perfect. That is the failure the per-path marks exist to
		// prevent, and until this check existed it was reachable from the
		// settings form.
		for _, reserved := range []struct {
			mark int
			what string
		}{
			{sysx.ControlMark, "the frontend's control channel"},
			{sysx.ReturnMark, "the backend's reply-path marking"},
			{sysx.EgressMark, "the backend's egress selection"},
			{sysx.LinkerReturnMark, "a linker's reply-path marking"},
			{sysx.LinkerEgressMark, "a linker's egress selection"},
		} {
			if p.Mark == reserved.mark {
				return fmt.Errorf("path %s uses fwmark %#x, which is reserved for %s; "+
					"the shipped path marks are 0x101, 0x102 and 0x103",
					p.Name, reserved.mark, reserved.what)
			}
		}
		if seenMark[p.Mark] {
			return fmt.Errorf("path %s reuses fwmark %#x", p.Name, p.Mark)
		}
		seenMark[p.Mark] = true
		// NaN first, because every ordered comparison below is false for it, so
		// it would pass the low bound and the high one alike and quota.Metered
		// would then substitute 100 with nothing said.
		//
		// Nothing can deliver one today and the check is kept anyway: JSON has
		// no NaN literal, so neither a PUT body nor the stored blob can decode
		// into one, and json.Marshal refuses to write one, so SaveConfig could
		// never have produced it either. What this guards is the shape of the
		// comparison rather than a reachable input - the next float bound added
		// beside it inherits the same trap, and Metered carries the matching
		// guard for the same reason.
		if math.IsNaN(p.Quota.Calibration) {
			return fmt.Errorf("path %s has a calibration that is not a number", p.Name)
		}
		if p.Quota.Calibration <= 0 {
			p.Quota.Calibration = 100
		}
		// Bounded above as well as below, because both of these are
		// multipliers on every metered byte and neither had a ceiling. A
		// calibration is a correction for what the carrier counts against what
		// the interface does, so a factor of ten in either direction is a typo
		// rather than a setting; an overhead is the per-packet cost of
		// WireGuard, UDP and IP together, which is about sixty bytes, and a
		// kilobyte is already past anything real.
		//
		// quota.Metered clamps the same two values, and neither check is
		// redundant. This one is the message an operator can act on. That one
		// is the boundary, for a value stored by an older build or arriving
		// from a socket, and it clamps silently because there is nobody there
		// to tell.
		//
		// Keyed on quota's own constants rather than on a copy of the numbers,
		// the way the region checks key on sysx.GeoSetName: raise one alone and
		// the portal accepts a figure Metered silently clamps, which under-bills
		// every metered byte with nothing anywhere saying so.
		if p.Quota.Calibration > quota.MaxCalibration || p.Quota.Calibration < quota.MinCalibration {
			return fmt.Errorf("path %s has a calibration of %g%%; it corrects for what the carrier counts "+
				"against what the interface does, so anything outside %g%% to %g%% is a typo. "+
				"Below it is the dangerous direction: it under-bills every metered byte and the quota never trips",
				p.Name, p.Quota.Calibration, quota.MinCalibration, quota.MaxCalibration)
		}
		if p.Quota.OverheadPerPacket < 0 || p.Quota.OverheadPerPacket > quota.MaxOverheadPerPacket {
			return fmt.Errorf("path %s has a per-packet overhead of %d bytes; it must be between 0 and %d, "+
				"and WireGuard, UDP and IP together come to about 60",
				p.Name, p.Quota.OverheadPerPacket, quota.MaxOverheadPerPacket)
		}
		if p.Quota.ResetDay < 1 {
			p.Quota.ResetDay = 1
		}
		if p.Quota.Timezone == "" {
			p.Quota.Timezone = model.DefaultTimezone
		}
		if _, err := time.LoadLocation(p.Quota.Timezone); err != nil {
			return fmt.Errorf("path %s has an unknown timezone %q", p.Name, p.Quota.Timezone)
		}
		if p.Quota.CeilingBytes > 0 && p.Quota.CeilingBytes < p.Quota.LimitBytes {
			return fmt.Errorf("path %s has a ceiling below its quota", p.Name)
		}
		// Bounded above by the ledger's own ceiling, and keyed on it for the
		// reason the calibration bound is keyed on quota's constants: the
		// portal's quota boxes clamp to this same value (MAX_QUOTA_GB in
		// app.js), and a bound that lived only in the browser is decoration
		// for a hand-written PUT. The ledger saturates at
		// store.MaxLedgerValue, so a limit above it is one the recorded usage
		// can never reach: the quota never trips, silently, which is the
		// under-enforcement direction everything else here refuses.
		if p.Quota.LimitBytes > store.MaxLedgerValue || p.Quota.CeilingBytes > store.MaxLedgerValue {
			return fmt.Errorf("path %s has a quota past what the usage ledger can record; "+
				"the limit and the ceiling must not exceed %d bytes", p.Name, int64(store.MaxLedgerValue))
		}
	}

	// Shaping. A negative rate is meaningless, and a very small one is almost
	// always a typo for a much larger one - 2 instead of 20 - which would throttle
	// the link to uselessness while reading as a deliberate setting.
	for i := range cfg.Paths {
		p := &cfg.Paths[i]
		for _, s := range []struct {
			what string
			mbit float64
		}{
			{"download", p.Shape.ToBackendMbit},
			{"upload", p.Shape.ToFrontendMbit},
		} {
			if s.mbit < 0 {
				return fmt.Errorf("path %s has a negative %s rate", p.Name, s.what)
			}
			if s.mbit > 0 && s.mbit < 1 {
				return fmt.Errorf("path %s has a %s rate of %g Mbit/s; that is almost certainly a typo, "+
					"and shaping this hard would be worse than none", p.Name, s.what, s.mbit)
			}
		}
	}

	// Protection. Fails closed on the one thing that cannot be worked around:
	// without an output interface to scope to, every rule here would also match
	// traffic arriving on a tunnel - including the probes and the control
	// channel, which is the one thing this feature must never be able to touch.
	if cfg.Protect.Enabled && trimmed(cfg.Frontend.PublicIface) == "" {
		return errors.New("protection needs the frontend's public interface set: " +
			"the rules must be scoped to it, or they would also match probes arriving on a tunnel")
	}
	pr := &cfg.Protect
	for _, v := range []struct {
		what string
		n    int
	}{
		{"connections per second", pr.NewConnsPerSec},
		{"connections per source", pr.MaxConnsPerSource},
		{"packets per second", pr.PacketsPerSec},
		{"queries per second", pr.QueriesPerSec},
		{"block seconds", pr.BlockSeconds},
		{"region lock seconds", pr.GeoLockSeconds},
	} {
		if v.n < 0 {
			return fmt.Errorf("protection: %s cannot be negative", v.what)
		}
	}
	for i := range cfg.Services {
		if cfg.Services[i].CeilingPPS < 0 {
			return fmt.Errorf("service %s has a negative packet ceiling", cfg.Services[i].Name)
		}
	}

	// The query cache's refresh interval. Zero is the shipped default; the
	// ceiling exists because the cache stops serving a reply older than 90
	// seconds, and a refresh slower than a third of that leaves no room for
	// a failed fetch to be retried before the cache goes dark and the
	// server drops out of browsers on a healthy site.
	if cfg.QueryCache.RefreshMs < 0 {
		return errors.New("query cache: the refresh interval cannot be negative")
	}
	if cfg.QueryCache.RefreshMs > 30000 {
		return fmt.Errorf("query cache: a refresh of %d ms cannot keep the cache inside its 90s staleness bound; "+
			"the most is 30000, and 0 means the default 3000", cfg.QueryCache.RefreshMs)
	}

	// Regions. The names become nftables set names and the networks their
	// elements, so both are held to what nft will load: a bad entry here is
	// not cosmetic, it is the whole protection table refused at once, every
	// limit included.
	regionDefined := map[string]bool{}
	regionNetworks := map[string]bool{}
	seenRegionSet := map[string]string{}
	regionsBytes := 0
	for i := range pr.Regions {
		rg := &pr.Regions[i]
		rg.Name = trimmed(rg.Name)
		if rg.Name == "" {
			return errors.New("every protection region needs a name")
		}
		if len(rg.Name) > maxRegionName {
			return fmt.Errorf("region name %q is %d bytes; the most a name can be is %d", rg.Name, len(rg.Name), maxRegionName)
		}
		if bad := firstBadRegionRune(rg.Name); bad != "" {
			return fmt.Errorf("region name %q contains %q; use lowercase letters, digits, hyphens and underscores, "+
				"because the name becomes an nftables set name", rg.Name, bad)
		}
		// The per-protocol lockdown sets live in the same namespace as the
		// region sets, so a name that folds onto one of theirs would define
		// the set twice with two types, and nft refuses the whole table.
		if sysx.GeoNameReserved(rg.Name) {
			return fmt.Errorf("region name %q is reserved: it becomes the nftables set the automatic lock "+
				"writes engaged ports into; pick another name", rg.Name)
		}
		// Uniqueness is measured on the set the name renders to, where a
		// hyphen folds to an underscore: "south-america" and "south_america"
		// would otherwise be one set defined twice, and nft refuses the table.
		// Keyed on the generator's own fold, so validate and generation cannot
		// disagree about which names are one set.
		key := sysx.GeoSetName(rg.Name)
		if other, dup := seenRegionSet[key]; dup {
			return fmt.Errorf("regions %q and %q are the same name to nftables; rename one", other, rg.Name)
		}
		seenRegionSet[key] = rg.Name
		regionDefined[rg.Name] = true

		cleaned := make([]string, 0, len(rg.CIDRs))
		for _, c := range rg.CIDRs {
			c = trimmed(c)
			if c == "" {
				continue
			}
			// A bare address is a /32. The lists get pasted from country zone
			// files, and refusing the odd single address in one would send
			// somebody off to edit a thousand-line paste by hand.
			if !strings.Contains(c, "/") {
				c += "/32"
			}
			netw, err := parseIPv4Network(c)
			if err != nil {
				return fmt.Errorf("region %s: %v", rg.Name, err)
			}
			cleaned = append(cleaned, netw)
			regionsBytes += len(netw) + 1
		}
		rg.CIDRs = cleaned
		if len(cleaned) > 0 {
			regionNetworks[rg.Name] = true
		}

		// The remembered fetch recipe. It generates nothing, but it is
		// replayed into the fetch endpoint by the button, so it is held to
		// the same shape the endpoint demands - through the endpoint's own
		// cleaner, so the two cannot drift.
		codes, err := cleanCountryCodes(rg.Countries)
		if err != nil {
			return fmt.Errorf("region %s: %v", rg.Name, err)
		}
		rg.Countries = codes
	}
	// Bounded in total, not per region, because what has to survive is the
	// save that carries every region at once: a configuration validate
	// accepted must always fit back through the PUT body cap, or one generous
	// region blocks every later save of anything with an error that does not
	// say why.
	if regionsBytes > maxRegionsBytes {
		return fmt.Errorf("the region lists hold %d MB of networks; the most a configuration can carry is %d MB - "+
			"trim a list, or fetch fewer countries into one region", regionsBytes>>20, maxRegionsBytes>>20)
	}

	if cfg.Probe.ActiveIntervalMs < 50 {
		return errors.New("active probe interval must be at least 50ms")
	}
	if cfg.Probe.StandbyIntervalMs < cfg.Probe.ActiveIntervalMs {
		return errors.New("standby probe interval must not be shorter than the active one")
	}
	if cfg.Probe.TimeoutMs < 50 {
		return errors.New("probe timeout must be at least 50ms")
	}
	if cfg.Probe.FailThreshold < 1 || cfg.Probe.RecoverThreshold < 1 {
		return errors.New("fail and recover thresholds must be at least 1")
	}
	if cfg.Probe.WindowSize < 5 {
		cfg.Probe.WindowSize = 5
	}
	for i := range cfg.Services {
		sv := &cfg.Services[i]
		// The name is not decoration: it is rendered into the generated
		// ruleset as an nftables comment, on the DNAT rule and again on the
		// protection ceiling beside it. nft bounds a comment's length and
		// cannot parse a quote or a newline inside one, and it rejects the
		// *whole table* when it meets one - so a single awkward name takes
		// every published service down with it, or rather leaves the previous
		// ones installed while the save reports success and nothing new
		// reaches the kernel. Bounded here so it cannot get as far as the file.
		sv.Name = trimmed(sv.Name)
		// Bytes rather than runes, because bytes are what the kernel counts:
		// a name well inside the limit read as characters can be over it once
		// anything non-ASCII is in there, and the error has to name the same
		// unit the bound is in or it reads as arithmetic nobody can follow.
		if len(sv.Name) > maxServiceName {
			return fmt.Errorf("service name %q is %d bytes; the most a name can be is %d, "+
				"because it becomes an nftables comment and the kernel bounds those in bytes",
				sv.Name, len(sv.Name), maxServiceName)
		}
		if bad := firstBadCommentRune(sv.Name); bad != "" {
			return fmt.Errorf("service name %q contains %q, which cannot appear in an nftables comment",
				sv.Name, bad)
		}
		if sv.Proto != "tcp" && sv.Proto != "udp" {
			return fmt.Errorf("service %s must be tcp or udp", sv.Name)
		}
		if sv.Port < 1 || sv.Port > 65535 {
			return fmt.Errorf("service %s has an invalid port", sv.Name)
		}
		// Without an interface to scope it to, a DNAT rule matches the port
		// on every interface this host has - the admin tunnel included, which
		// is the one the portal is reached over. A row naming the portal's own
		// port would then hand the operator's portal connections to the
		// backend and take away the only way to undo it, and every other row
		// takes the admin tunnel's copy of that port with it.
		if sv.Enabled && trimmed(cfg.Frontend.PublicIface) == "" {
			return fmt.Errorf("service %s cannot be published without a public interface to scope it to", sv.Name)
		}
		if sv.PortEnd != 0 && (sv.PortEnd < sv.Port || sv.PortEnd > 65535) {
			return fmt.Errorf("service %s has an invalid port range", sv.Name)
		}
		sv.Target = trimmed(sv.Target)
		if sv.Target != "" {
			if net.ParseIP(sv.Target) == nil {
				return fmt.Errorf("service %s is published to %q, which is not an address", sv.Name, sv.Target)
			}
			// Fail closed. A target the frontend has no route to would DNAT
			// every request into a black hole, and the symptom - a published
			// port that accepts nothing - looks identical to the service being
			// down at the far end.
			if !overlayContains(cfg.Overlay, sv.Target) {
				if cfg.Overlay.Subnet == "" {
					return fmt.Errorf("service %s is published to %s, but this site has no overlay subnet: "+
						"set overlay.subnet in the bootstrap file before publishing to another host", sv.Name, sv.Target)
				}
				return fmt.Errorf("service %s is published to %s, which is outside the overlay subnet %s",
					sv.Name, sv.Target, cfg.Overlay.Subnet)
			}
			// Fail closed again, one level further in. Being inside the subnet
			// only means the frontend can route it down the tunnel; the
			// backend still has to know which neighbour holds it, and it only
			// knows that from the linker list. Publishing to an address with
			// no linker behind it DNATs every request to a host the backend
			// will drop on the floor.
			if sv.Target != cfg.Overlay.BackendIP && !seenLinker[sv.Target] {
				return fmt.Errorf("service %s is published to %s, but no linker is configured for that address: "+
					"add it under Linkers first, or the backend has nowhere to forward the traffic",
					sv.Name, sv.Target)
			}
		}

		// Region locks fail closed the way Target does. A lock naming a region
		// that does not exist, or one with nothing in it, would either silently
		// not lock the port or silently drop everything arriving at it, and
		// neither fault is visible from where it was made.
		seenRef := map[string]bool{}
		refs := sv.GeoRegions[:0]
		for _, name := range sv.GeoRegions {
			name = trimmed(name)
			if name == "" || seenRef[name] {
				continue
			}
			seenRef[name] = true
			if !regionDefined[name] {
				return fmt.Errorf("service %s is locked to region %q, which is not defined under Protection", sv.Name, name)
			}
			if !regionNetworks[name] {
				return fmt.Errorf("service %s is locked to region %q, which has no networks in it: "+
					"an empty allowlist would drop everything arriving at the port", sv.Name, name)
			}
			refs = append(refs, name)
		}
		sv.GeoRegions = refs
		// A direction with nothing to point it at. Cleared rather than
		// refused: it is what unpicking a block lock leaves behind, and it
		// changes nothing.
		if len(sv.GeoRegions) == 0 {
			sv.GeoBlock = false
		}
		if sv.GeoAutoPPS < 0 {
			return fmt.Errorf("service %s has a negative auto-lock threshold", sv.Name)
		}
		// A threshold with no regions has nothing to lock the port to, and the
		// operator who set it believes a protection now exists.
		if sv.GeoAutoPPS > 0 && len(sv.GeoRegions) == 0 {
			return fmt.Errorf("service %s has an auto-lock threshold but no regions to lock to; "+
				"name at least one region, or clear the threshold", sv.Name)
		}
	}
	return nil
}

// parseIPv4Network parses a CIDR that is destined for a generated nftables
// ruleset and returns it normalised to its network address. Everything the
// portal accepts into an ip-family table goes through here, so validation and
// generation cannot disagree about what IPv4 means: To4 alone also admits an
// IPv4-mapped IPv6 network ("::ffff:1.128.0.0/120"), which String() renders
// with a 128-bit mask length that the generators skip in silence and a later
// ParseCIDR refuses outright - a lock that saves, does not exist, and then
// blocks every unrelated save. The mask width is the real test.
func parseIPv4Network(c string) (string, error) {
	ip, netw, err := net.ParseCIDR(c)
	if err != nil {
		return "", fmt.Errorf("%q is not a network in CIDR form: %v", c, err)
	}
	if _, bits := netw.Mask.Size(); ip.To4() == nil || bits != 32 {
		return "", fmt.Errorf("%q is not IPv4; the ruleset is an ip table", c)
	}
	return netw.String(), nil
}

// parseIPv4Address is the single-address companion to parseIPv4Network, and it
// exists for exactly the same reason: every address the portal accepts into an
// ip-family table goes through here, so validation and generation cannot
// disagree about what IPv4 means. To4 alone also admits an IPv4-mapped IPv6
// address, which renders into the ruleset in its mapped form and takes the
// whole table down with it.
//
// It calls sysx.AddressLiteral rather than restating it, which is what keeps
// that from being a promise. The generator applies exactly this check to
// whatever reaches it, and two hand-kept copies of the same rule drift in a way
// that shows up as an agent reporting its rules installed and having none -
// the empty file nft loads without complaint. model.ipv4Literal is a third copy
// and has to be, because sysx imports model and the dependency cannot run the
// other way; this one is on the same host as the generator and does not.
//
// The cost is one message where there were two. AddressLiteral answers with an
// empty string whether the value is not an address at all or is an address of
// the wrong family, and a portal message naming both is worth more than a
// second definition of what IPv4 means on this host.
func parseIPv4Address(a string) (string, error) {
	v := sysx.AddressLiteral(a)
	if v == "" {
		return "", fmt.Errorf("%q is not an IPv4 address; the ruleset is an ip table", a)
	}
	return v, nil
}

// maxRegionName bounds a protection region's name. It becomes an nftables set
// name (geo_<name>) and part of a set comment, and nft bounds identifiers too;
// 32 is far under either limit and long enough for any part of the world.
const maxRegionName = 32

// The three size caps are one story and must stay in this order:
// geoFetchMaxTotal < maxRegionsBytes < maxConfigBytes. A fetch fills one
// region, validate bounds what every region together may hold, and the PUT
// body cap sits above that with room for the rest of the configuration and
// JSON quoting. Any config that ever validated must fit back through a save,
// and anything the Fetch button produces must survive one - the alternative
// is a portal that fills a form its own save endpoint then refuses, with the
// opaque "request body too large" where a real message should be, on every
// save until the list is trimmed by hand.
const (
	// maxConfigBytes bounds one PUT /api/config body. The portal is on the
	// admin tunnel, so this is a sanity ceiling rather than a defence.
	maxConfigBytes = 32 << 20
	// maxRegionsBytes bounds the region lists across the whole configuration,
	// with a clear message where the body cap has none.
	maxRegionsBytes = 24 << 20
)

// firstBadRegionRune returns the first character a region name cannot carry,
// or "" when the name is safe. Stricter than a comment: the name becomes an
// nftables set identifier, so it is held to the characters an identifier can
// hold rather than folded into shape behind the operator's back.
func firstBadRegionRune(s string) string {
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return string(r)
	}
	return ""
}

// maxServiceName is a bound, not a style rule. nftables caps a rule comment at
// 128 bytes and rejects the table that carries an over-long one; this leaves
// room for the "ceiling:" prefix the protection rules add. In bytes, which is
// the unit the kernel bounds, so a name of multi-byte characters is measured
// the way nft will measure it rather than the way it reads.
const maxServiceName = 64

// firstBadCommentRune returns the first character that cannot be rendered into
// an nftables comment, or "" when the string is safe.
//
// A quote ends the comment early and a backslash starts an escape, so either
// one turns the rest of the name into rule syntax; a newline does the same at
// the level of the file. None of that is a privilege the operator does not
// already have - they are editing the ruleset by definition - but all of it
// fails as a rejected table rather than as anything anybody meant.
func firstBadCommentRune(s string) string {
	for _, r := range s {
		if r == '"' || r == '\\' || r < 0x20 || r == 0x7f {
			return string(r)
		}
	}
	return ""
}

// overlayContains reports whether an address is somewhere this site can route.
//
// With no subnet configured the only reachable overlay host is the backend,
// which is the state every site is in until it deliberately adds linkers. That
// is why this is not simply a CIDR test: an empty subnet has to mean "one host
// at the far end", not "anything goes".
func overlayContains(ov model.OverlayConfig, ip string) bool {
	if ip == ov.BackendIP {
		return true
	}
	if ov.Subnet == "" {
		return false
	}
	_, netw, err := net.ParseCIDR(ov.Subnet)
	if err != nil {
		return false
	}
	addr := net.ParseIP(ip)
	return addr != nil && netw.Contains(addr)
}

// handlePSK returns the shared secret, for the linker setup instructions.
//
// A linker's bootstrap file needs the identical string, and every other value
// in that file is already on this page - so without this the one thing that
// cannot be copied from the portal is the one thing that is unforgiving about
// typos. See the note on Server.psk for what is and is not being given away.
func (s *Server) handlePSK(w http.ResponseWriter, r *http.Request) {
	if s.psk == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "this frontend has no shared secret to show",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"psk": s.psk})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	limit := intParam(r, "limit", 100)
	if limit > 500 {
		limit = 500
	}
	events, err := s.st.Events(limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	pathID := intParam(r, "path_id", 0)
	hours := intParam(r, "hours", 6)
	if hours < 1 {
		hours = 1
	}
	if hours > 720 {
		hours = 720
	}
	bucket := hours * 3600 / 240 // roughly 240 points regardless of window
	if bucket < 10 {
		bucket = 10
	}
	points, err := s.st.PathHistory(pathID, time.Now().Add(-time.Duration(hours)*time.Hour), bucket)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, points)
}

func (s *Server) handleUsage(w http.ResponseWriter, r *http.Request) {
	pathID := intParam(r, "path_id", 0)
	days := intParam(r, "days", 31)
	if days < 1 {
		days = 1
	}
	if days > 400 {
		days = 400
	}
	points, err := s.st.UsageHistory(pathID, time.Now().AddDate(0, 0, -days), 3600)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, points)
}

type modeRequest struct {
	Mode string `json:"mode"`
}

// handleMode is the arm/disarm switch. Observe mode computes and displays every
// decision without touching the system, which is how a fresh install is meant
// to be run for a few days before it is trusted with live traffic.
func (s *Server) handleMode(w http.ResponseWriter, r *http.Request) {
	var req modeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil {
		clientErr(w, err)
		return
	}
	if req.Mode != model.ModeObserve && req.Mode != model.ModeArmed {
		clientErr(w, fmt.Errorf("mode must be %q or %q", model.ModeObserve, model.ModeArmed))
		return
	}
	cfg := s.eng.Config()
	cfg.Mode = req.Mode
	if err := s.eng.Reconfigure(cfg); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"mode": req.Mode})
}

type pathRequest struct {
	PathID int `json:"path_id"`
}

func (s *Server) handlePin(w http.ResponseWriter, r *http.Request) {
	var req pathRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil {
		clientErr(w, err)
		return
	}
	if err := s.eng.Pin(req.PathID); err != nil {
		clientErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"pinned": req.PathID})
}

type approveRequest struct {
	PathID  int     `json:"path_id"`
	Hours   float64 `json:"hours"`
	ExtraGB float64 `json:"extra_gb"`
}

// handleApprove is the button that appears when every usable path is blocked
// by quota. The grant is time-boxed on purpose: an approval clicked at 2am must
// not silently disable quota enforcement for the rest of the month.
func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	var req approveRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil {
		clientErr(w, err)
		return
	}
	if req.Hours <= 0 {
		req.Hours = 24
	}
	if req.Hours > 24*31 {
		clientErr(w, errors.New("an approval cannot outlast the billing period"))
		return
	}
	extra := int64(req.ExtraGB * float64(1<<30))
	if err := s.eng.Approve(req.PathID, time.Duration(req.Hours*float64(time.Hour)), extra); err != nil {
		clientErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "approved",
		"until":  time.Now().Add(time.Duration(req.Hours * float64(time.Hour))).Format(time.RFC3339),
		"extra":  quota.HumanBytes(extra),
	})
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var req pathRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil {
		clientErr(w, err)
		return
	}
	if err := s.eng.RevokeApproval(req.PathID); err != nil {
		clientErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *Server) handleClearQuarantine(w http.ResponseWriter, r *http.Request) {
	var req pathRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil {
		clientErr(w, err)
		return
	}
	s.eng.ClearQuarantine(req.PathID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
}

// handleRevert is the panic button: it removes the nftables table and every
// policy route the agent installed, leaving the WireGuard tunnels untouched.
//
// The request's context is deliberately detached first. ExecRunner builds every
// command with exec.CommandContext, so a cancelled context does not abort the
// revert - it makes each command fail instantly while Revert, which checks none
// of their errors, goes on to record dataPlane = false and answer "reverted".
// The rules stay live and the engine believes they are gone, which is the exact
// state a revert exists to escape.
//
// Reaching that needed the client to give up first, which used to mean the
// revert itself outrunning the timeout - unlikely, at a dozen commands. Now
// that Revert waits for reconfMu and applyMu it can also be cancelled before it
// has done anything at all, and the wait is longest when a settings save is
// stuck on a slow nft: the moment somebody reaches for this button.
// failoverctl gives up after 15s, and a browser tab closes whenever its owner
// decides to.
//
// No outer timeout, because there is nothing to protect against: ExecRunner
// caps every command at 10s on its own, so this is bounded by construction, and
// a ceiling low enough to matter could truncate a slow revert - reintroducing
// the same fault in a smaller form.
func (s *Server) handleRevert(w http.ResponseWriter, r *http.Request) {
	s.eng.Revert(context.WithoutCancel(r.Context()))
	writeJSON(w, http.StatusOK, map[string]string{"status": "reverted"})
}

func intParam(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// serveSocket exposes the same API without authentication over a unix socket
// with restrictive permissions, which is what failoverctl talks to.
func (s *Server) serveSocket(ctx context.Context, path string) {
	// The socket serves an unauthenticated API, so access is gated by a 0700
	// parent directory created before the socket exists. Relying on chmod
	// after net.Listen leaves a window in which the socket carries whatever
	// the umask allowed, and any local user could reach the trusted API.
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		s.log.Warn("cannot create control socket directory", "path", dir, "err", err)
		return
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		s.log.Warn("cannot restrict control socket directory", "path", dir, "err", err)
		return
	}

	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		s.log.Warn("cannot open control socket", "path", path, "err", err)
		return
	}
	if err := os.Chmod(path, 0o600); err != nil {
		s.log.Warn("cannot restrict control socket permissions", "path", path, "err", err)
	}
	srv := &http.Server{Handler: s.Handler(true), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
		_ = os.Remove(path)
	}()
	s.log.Info("control socket listening", "path", path)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.log.Warn("control socket closed", "err", err)
	}
}
