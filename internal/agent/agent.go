// Package agent is the backend half of the system.
//
// It is deliberately thin. It answers probes, keeps its reply routing in step
// with the frontend's decision, meters LTE usage, and reports upward. It makes
// no routing decisions of its own and has no web interface: the frontend is
// authoritative and the portal lives there, because the frontend is the side
// that stays reachable when every path is down.
package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/proto"
	"github.com/quinlan102/homeport/internal/sysx"
)

// Agent holds the backend's runtime state.
type Agent struct {
	log      *slog.Logger
	psk      []byte
	boot     model.Bootstrap
	stateDir string

	// real acts on the system whatever the mode, backing the measurement
	// plumbing and the reconciler's kernel reads. It and ifaceExists are set
	// once in New and swapped only by tests, which have no Linux network
	// stack to inspect.
	real        sysx.Runner
	ifaceExists func(string) bool

	mu        sync.RWMutex
	cfg       proto.BackendConfig
	runner    sysx.Runner
	haveCfg   bool
	active    int
	lastSeq   uint64
	meter     *Meter
	responder *Responder

	// Decisions are applied by a worker rather than inline, so shelling out to
	// `ip` can never stall the probe responder. Only the newest is kept: an
	// older queued decision is worthless the moment a newer one arrives.
	pendingMu sync.Mutex
	pending   pathDecision
	wake      chan struct{}

	// Sequence plausibility: the anchor the ceiling is measured from, and the
	// throttle for reporting a refusal. See plausibleDecisionSeq.
	//
	// seqBaseAt is a monotonic reading deliberately, and seqBase is the
	// frontend's own number rather than anything this host believes about the
	// time. Neither is ever re-anchored: the ceiling grows with elapsed time
	// on its own.
	//
	// The warning is throttled because it is reached from the probe read loop,
	// which runs at the active cadence: unthrottled it would be the flood
	// rather than a report of one. Responder.flushThrottles is its trailing
	// edge, so a burst that stops inside the window is still counted.
	seqMu       sync.Mutex
	seqBase     uint64
	seqBaseAt   time.Time
	implausible throttle

	// applyMu serialises the shell-outs that write routes, so only one
	// goroutine is running `ip` at a time.
	//
	// applyDecision and reconcileRouting already share applyLoop's goroutine,
	// so a repair cannot race a switch being applied. ApplyConfig is the writer
	// that reasoning missed: it runs on the control client's goroutine and
	// re-asserts the return path, which is the same table 100 default route a
	// decision installs. A configuration push arriving as a failover landed
	// could put the outgoing tunnel back over the incoming one, sending every
	// published reply down a link that had just failed - requests arriving
	// fine, answers going nowhere - until the reconciler noticed up to 10s
	// later.
	//
	// Not taken inside applyPlumbing: ApplyConfig holds this across it and two
	// further groups of shell-outs, so that a decision cannot slip between
	// them, and Run calls it before any of these goroutines exist.
	applyMu sync.Mutex
}

// New builds a backend agent.
func New(log *slog.Logger, boot model.Bootstrap) *Agent {
	a := &Agent{
		log:         log,
		psk:         boot.Key(),
		boot:        boot,
		stateDir:    boot.StateDir,
		runner:      &sysx.DryRunner{Log: log},
		real:        &sysx.ExecRunner{Log: log},
		ifaceExists: sysx.IfaceExists,
		wake:        make(chan struct{}, 1),
	}
	a.meter = NewMeter(log, filepath.Join(boot.StateDir, "usage-buffer.jsonl"))
	a.responder = NewResponder(a, log)
	return a
}

// Run starts the responder, meter and control client.
func (a *Agent) Run(ctx context.Context) error {
	if err := os.MkdirAll(a.stateDir, 0o755); err != nil {
		return err
	}
	a.loadCachedConfig()

	// The plumbing has to be in place before anything else starts. The probe
	// responder binds to the overlay address, and the control client dials the
	// frontend from it over a tunnel - so waiting for the frontend's first
	// configuration push deadlocks, because that push can only arrive over the
	// channel this plumbing is what makes possible. A fresh backend sat
	// retrying both forever.
	//
	// A cached config is used when there is one. On a first-ever start there
	// is not, so the shipped defaults stand in: they carry the interface names
	// and tables of the intended deployment, and the frontend's first push
	// replaces them within seconds of the channel coming up.
	cfg, cached := a.Config()
	if !cached {
		cfg = a.provisionalConfig()
		a.log.Warn("no configuration yet; installing bootstrap plumbing so the control channel can dial",
			"paths", len(cfg.Paths))
	}
	a.applyPlumbing(ctx, cfg)

	var wg sync.WaitGroup
	wg.Add(4)
	go func() { defer wg.Done(); a.responder.Run(ctx) }()
	go func() { defer wg.Done(); a.meter.Run(ctx, a) }()
	go func() { defer wg.Done(); a.runControlClient(ctx) }()
	go func() { defer wg.Done(); a.applyLoop(ctx) }()
	wg.Wait()
	return ctx.Err()
}

// Config returns the last configuration received from the frontend.
func (a *Agent) Config() (proto.BackendConfig, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cfg, a.haveCfg
}

// ApplyConfig installs a configuration pushed by the frontend and caches it to
// disk, so a frontend outage does not leave the backend unable to route
// replies correctly after a restart.
func (a *Agent) ApplyConfig(ctx context.Context, cfg proto.BackendConfig) {
	// Against applyDecision and reconcileRouting, which write the same routes
	// from applyLoop's goroutine. Held across everything below, not each group
	// separately, so a decision cannot land between them. See applyMu.
	//
	// Taken before the state swap, not after: applyDecision reads the runner
	// under a.mu at its start and then shells out for as long as `ip` takes, so
	// a swap outside this lock could land in the middle of a decision that had
	// already captured the previous one - one route installed with the armed
	// runner after the mode had gone to observe. Lock order is applyMu then
	// a.mu, the same as every other holder.
	a.applyMu.Lock()
	defer a.applyMu.Unlock()

	a.mu.Lock()
	prev := a.cfg
	a.cfg = cfg
	a.haveCfg = true
	a.runner = runnerFor(cfg.Mode, a.log)
	a.mu.Unlock()

	a.cacheConfig(cfg)

	a.applyPlumbing(ctx, cfg)
	// Against the config this one replaced, which after a restart is the one
	// loaded from disk - so a linker removed while the backend was down still
	// gets its route withdrawn rather than outliving the decision silently.
	a.withdrawRemovedLinkers(ctx, prev.Linkers, cfg.Linkers)
	a.reassertReturnPath(ctx)

	a.log.Info("configuration applied", "paths", len(cfg.Paths), "mode", cfg.Mode)
	a.responder.Reload()
}

// reassertReturnPath reinstalls the routing for the path already in use.
//
// applyDecision deliberately does nothing when the frontend's choice has not
// changed, which is right for probes but wrong here: arming the system changes
// the runner from dry to real without changing the decision, so the return
// path default route - the thing that actually carries reply traffic - was
// never installed. The system reported armed, the frontend DNAT'd, and every
// connection hung with the replies going out the LAN to pfSense instead.
func (a *Agent) reassertReturnPath(ctx context.Context) {
	a.mu.RLock()
	active, cfg, runner := a.active, a.cfg, a.runner
	a.mu.RUnlock()
	if active == 0 {
		return // no decision yet; the first probe will install it
	}
	for _, p := range cfg.Paths {
		if p.ID != active {
			continue
		}
		if err := sysx.SetReturnPath(ctx, runner, p.Iface); err != nil {
			a.log.Error("cannot reinstall return path after a configuration change",
				"iface", p.Iface, "err", err)
		}
		return
	}
}

// provisionalConfig is what the backend runs on before the frontend has ever
// pushed anything: bootstrap-owned overlay addressing plus the shipped default
// path list. It is never cached to disk - it is scaffolding to get the control
// channel up, not a configuration anybody chose.
func (a *Agent) provisionalConfig() proto.BackendConfig {
	ov := a.Overlay()
	cfg := proto.BackendConfig{
		Mode: model.ModeObserve,
		Overlay: proto.OverlayInfo{
			FrontendIP: ov.FrontendIP,
			BackendIP:  ov.BackendIP,
			Device:     ov.Device,
			Subnet:     ov.Subnet,
		},
	}
	for _, p := range model.Defaults().Paths {
		cfg.Paths = append(cfg.Paths, proto.PathInfo{
			ID: p.ID, Name: p.Name, Iface: p.Iface, Table: p.Table, Mark: p.Mark,
		})
	}
	return cfg
}

// applyPlumbing installs everything the backend needs in order to be reachable
// and measurable: the overlay address, sysctls, per-path probe reply routes and
// the return rule. None of it moves published traffic, so it runs in observe
// mode too - see the observe-mode invariant in CLAUDE.md. The one nftables
// table here, the connection marking, is the exception: it moves nothing in
// observe mode either, but observe mode promises to load no table at all.
func (a *Agent) applyPlumbing(ctx context.Context, cfg proto.BackendConfig) {
	paths := make([]model.PathConfig, 0, len(cfg.Paths))
	ifaces := make([]string, 0, len(cfg.Paths))
	for _, p := range cfg.Paths {
		paths = append(paths, model.PathConfig{
			ID: p.ID, Name: p.Name, Iface: p.Iface, Table: p.Table, Mark: p.Mark,
		})
		ifaces = append(ifaces, p.Iface)
	}

	// As on the frontend, measurement and control plumbing is installed for
	// real even in observe mode. Without the overlay address the probe
	// responder cannot bind and the control channel cannot dial out, so the
	// backend would look permanently dead while supposedly being observed.
	real := a.realRunner()

	if err := sysx.EnsureOverlayAddress(ctx, real, cfg.Overlay.BackendIP, cfg.Overlay.Device); err != nil {
		a.log.Error("cannot establish the overlay address; nothing works without it",
			"address", cfg.Overlay.BackendIP, "device", cfg.Overlay.Device, "err", err)
	}

	sysx.EnsureSysctls(ctx, real, ifaces)

	// Probe reply routing: each path gets a table pointing at its own tunnel,
	// so a reply always leaves the way its request came in.
	if err := sysx.EnsureProbeRoutes(ctx, real, paths, cfg.Overlay.FrontendIP, cfg.Overlay.BackendIP); err != nil {
		a.log.Warn("probe reply routing incomplete", "err", err)
	}

	// Client reply routing: traffic sourced from the overlay address goes back
	// out the active tunnel instead of out pfSense, which is what lets the
	// frontend DNAT without SNAT and keep real client IPs intact. The rule is
	// harmless on its own - an empty table 100 falls through to main - so only
	// the default route inside it is gated by mode.
	if err := sysx.EnsureReturnRule(ctx, real, cfg.Overlay.BackendIP, cfg.Overlay.Subnet); err != nil {
		a.log.Warn("return path rule not installed", "err", err)
	}

	// ...and an exception to it, so overlay hosts can still talk to each other.
	// The rule above matches on source, and with a subnet configured that
	// source range includes the frontend - so without this a packet the
	// frontend sends to a linker is routed by the return table and goes back
	// down the tunnel it arrived on.
	if err := sysx.EnsureOverlayLocalRule(ctx, real, cfg.Overlay.Subnet); err != nil {
		a.log.Warn("overlay-local rule not installed; a linker's control channel cannot complete", "err", err)
	}

	// Extra hosts behind this one. The frontend routes the whole overlay range
	// down the active tunnel, so a packet for a linker arrives here addressed
	// to a machine that is not this one and has to be forwarded - and an
	// overlay address says nothing about which neighbour holds it.
	//
	// Installed for real in observe mode too, for the same reason the linker
	// agent has no observe mode at all: nothing sends to these addresses
	// unless the frontend's DNAT points at them, and that is gated by the
	// frontend's own mode. Having the route already in place is what makes
	// arming take effect immediately rather than a reconcile tick later.
	// ...and permission to forward to them at all. This host terminated
	// everything until linkers existed, so a drop-policy forward chain - which
	// is what Docker leaves behind on a box that runs containers - had nothing
	// of ours to drop. Now it has: every packet to or from a linker crosses
	// this host's FORWARD hook, and a drop there is a timeout, which reads as
	// the far host being down.
	//
	// Installed for real in observe mode, like the rest of the plumbing above:
	// an accept moves no traffic on its own, and without it the linker's
	// control channel cannot come up to be observed. Only when there are
	// linkers, so a site with none issues nothing - invariant 19.
	if len(cfg.Linkers) > 0 {
		// The subnet, which a site with linkers always has: the portal refuses a
		// linker row without one, because the frontend could not route to it.
		if err := sysx.EnsureOverlayForwardExceptions(ctx, real, cfg.Overlay.Subnet); err != nil {
			a.log.Warn("forward exceptions for the overlay range not installed; "+
				"traffic to and from extra hosts will be dropped by the forward policy", "err", err)
		}
	}

	for _, l := range cfg.Linkers {
		if err := sysx.EnsureLinkerHostRoute(ctx, real, l.OverlayIP, l.LanIP); err != nil {
			a.log.Error("cannot install the route to a linker; anything published there will time out with nothing in any log",
				"overlay", l.OverlayIP, "via", l.LanIP, "err", err)
		}
	}

	// The rule above matches on the overlay source address, which is enough
	// only while the service listens on the host itself. Anything that DNATs
	// further - a container on a bridge network - is routed before its source
	// is rewritten back, so it needs the connection mark instead. Both are
	// installed: they cost nothing and cover each other.
	//
	// The marking table goes through the gated runner. It is inert in observe
	// mode - the mark it restores selects a table whose default route observe
	// mode never installs - but it is an nftables table loaded on the host,
	// and the portal's promise for observe mode is that there is none. The
	// ip rule beside it stays plumbing: a rule into an empty table is the
	// same nothing as the probe rules, and it is what makes arming take
	// effect with a single reload rather than a rule add that can fail.
	if _, err := sysx.ApplyReturnRuleset(ctx, a.gatedRunner(), a.stateDir, sysx.BuildReturnRuleset(ifaces)); err != nil {
		a.log.Warn("return path marking not installed; containerised services will not reply through the tunnel",
			"err", err)
	}
	if err := sysx.EnsureReturnMarkRule(ctx, real); err != nil {
		a.log.Warn("return path mark rule not installed", "err", err)
	}

	a.applyEgress(ctx, cfg, ifaces)
	a.applyShaping(ctx, cfg)

	// Give the control channel a route to the frontend immediately, using the
	// first tunnel that exists. Every wg-quick config sets Table = off, so
	// without this there is no route to the frontend overlay at all and the
	// backend could never report in.
	if a.ActivePath() == 0 {
		for _, p := range cfg.Paths {
			if a.ifaceExists(p.Iface) {
				if err := sysx.SetActivePath(ctx, real, cfg.Overlay.FrontendIP+"/32", cfg.Overlay.BackendIP, p.Iface); err == nil {
					a.log.Info("seeded control-channel route", "iface", p.Iface)
				}
				break
			}
		}
	}
}

// applyShaping puts a queue discipline on each tunnel this host sends into.
//
// This is the direction that matters most for a game server: srcds sends far
// more than it receives, and the house's upload is the smaller half of every
// service here. Without a queue of our own the packets wait in the carrier's,
// which is enormous and serves them in arrival order - so a file transfer puts
// seconds of delay in front of every player's traffic.
//
// Mode-gated, like the egress rules: it decides what gets dropped and when, and
// observe mode's promise is that nothing the agent does can be felt.
func (a *Agent) applyShaping(ctx context.Context, cfg proto.BackendConfig) {
	gated := a.gatedRunner()

	for _, p := range cfg.Paths {
		if !a.ifaceExists(p.Iface) {
			continue
		}
		// Zero is passed through rather than skipped: it is how the frontend
		// says the operator has turned shaping off, and the shaper has to come
		// back off the interface for that to mean anything.
		changed, err := sysx.EnsureQdisc(ctx, gated, p.Iface, p.ShapeMbit)
		if err != nil {
			a.log.Error("cannot shape this tunnel; traffic is unshaped in this direction",
				"path", p.Name, "iface", p.Iface, "mbit", p.ShapeMbit, "err", err,
				"hint", "needs the sch_cake module: modprobe sch_cake")
			continue
		}
		if changed && gated.Applying() {
			a.log.Info("tunnel shaping updated", "path", p.Name, "iface", p.Iface, "mbit", p.ShapeMbit)
		}
	}
}

// applyEgress installs or removes the rules that pull a backend-side network
// onto the tunnel, so a containerised game server is seen at the frontend's
// address rather than the house's.
//
// Unlike the rest of applyPlumbing this moves real traffic - it takes a
// network's internet access off pfSense and puts it on a metered link - so it
// runs through the mode-gated runner. Observe mode installs nothing.
//
// The frontend only sends these networks when its own source NAT is enabled, so
// an empty list is both "the feature is off" and "the far end is not ready",
// and either way the right thing is to take the rules down.
func (a *Agent) applyEgress(ctx context.Context, cfg proto.BackendConfig, ifaces []string) {
	gated := a.gatedRunner()

	// An address the generator cannot use is a fault, not an instruction. Both
	// render as an empty ruleset, and below that is read as "the feature is
	// off" and tears the rules down - so without this a typo in the frontend's
	// overlay address arrives here as a silent teardown with nothing in the
	// journal. Checked before the build, because afterwards the two are the
	// same empty string. See sysx.AddressLiteral.
	if len(cfg.EgressCIDRs) > 0 && sysx.AddressLiteral(cfg.Overlay.BackendIP) == "" {
		a.log.Error("cannot pull networks onto the tunnel: the overlay address is not an address; "+
			"leaving the egress rules as they are",
			"overlay_ip", cfg.Overlay.BackendIP, "networks", cfg.EgressCIDRs)
		return
	}

	// The same fault reached through the other input, and the guard above did
	// not cover it. The generator drops the networks it cannot parse, so a push
	// where none of them survive renders the same empty string an absent
	// feature does - and the teardown below then runs with nothing in the
	// journal at all, because the warning that names them is past the point of
	// no return. Containers lose their tunnel egress and the server browser
	// starts advertising the house's address, silently.
	//
	// Parsed once, here, and carried down: the branch that decides and the
	// ruleset that is written must not be able to disagree about what usable
	// meant.
	installed := sysx.EgressNetworks(cfg.EgressCIDRs)
	if len(installed) != len(cfg.EgressCIDRs) {
		a.log.Warn("ignoring egress networks that are not IPv4 networks",
			"asked", cfg.EgressCIDRs, "usable", installed)
	}
	if len(cfg.EgressCIDRs) > 0 && len(installed) == 0 {
		a.log.Error("cannot pull networks onto the tunnel: none of them are IPv4 networks; "+
			"leaving the egress rules as they are",
			"networks", cfg.EgressCIDRs)
		return
	}

	ruleset := sysx.BuildBackendEgressRuleset(installed, ifaces, cfg.Overlay.BackendIP)
	if ruleset == "" {
		real := a.realRunner()
		sysx.RemoveEgressRuleset(ctx, real)
		sysx.RemoveEgressRule(ctx, real)
		return
	}
	if !gated.Applying() {
		a.log.Info("observe mode: not pulling networks onto the tunnel", "networks", cfg.EgressCIDRs)
		return
	}
	if err := sysx.EnsureEgressRule(ctx, gated); err != nil {
		a.log.Error("cannot install the egress routing rule; these networks stay on the local service",
			"networks", cfg.EgressCIDRs, "err", err)
		return
	}
	if _, err := sysx.ApplyEgressRuleset(ctx, gated, a.stateDir, ruleset); err != nil {
		a.log.Error("cannot apply the egress ruleset", "err", err)
		return
	}
	// What was installed, not what arrived: entries the parse could not use were
	// dropped on the way in, and naming them here as routed would have the
	// journal disagree with the kernel. The linker reports the same way.
	a.log.Info("networks routed out through the frontend", "networks", installed)
}

// realRunner always acts on the system, regardless of mode. It backs the
// measurement and control plumbing, which observe mode must not suppress.
func (a *Agent) realRunner() sysx.Runner { return a.real }

// gatedRunner is the mode-following runner, read under the state lock because
// ApplyConfig swaps it. Everything that moves traffic goes through this one.
func (a *Agent) gatedRunner() sysx.Runner {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.runner
}

func runnerFor(mode string, log *slog.Logger) sysx.Runner {
	if mode == model.ModeArmed {
		return &sysx.ExecRunner{Log: log}
	}
	return &sysx.DryRunner{Log: log}
}

// SetActivePath follows the frontend's decision, which arrives stamped on every
// probe. Reply traffic must leave by the same tunnel requests arrive on, or
// pfSense sees an asymmetric flow and drops it.
//
// It is called from the probe read loop, so it must not block.
// Installing routes shells out to `ip`, which can take a noticeable moment
// under load; doing that inline would stall probe replies on every path at
// once, and a slow `ip` would look exactly like all three tunnels dying.
//
// The decision is handed to a worker that always applies the newest one.
func (a *Agent) SetActivePath(ctx context.Context, pathID int, decisionSeq uint64) {
	if pathID == 0 {
		return // the frontend has not chosen anything yet
	}
	// Refused before it can become the high-water mark. Everything below only
	// ever compares sequences against each other, so a single implausible one
	// is not a bad decision that a good one corrects - it is a ceiling nothing
	// legitimate can reach again, and the frontend then routes down one tunnel
	// while replies leave by another with no counter or log to show for it,
	// until this process restarts. See plausibleDecisionSeq.
	now := time.Now()
	base, baseAt := a.decisionSeqAnchor()
	if !plausibleDecisionSeq(decisionSeq, base, baseAt, now) {
		a.warnImplausibleSeq(pathID, decisionSeq)
		return
	}
	if base == 0 {
		// Only ever true once. anchorDecisionSeq re-checks under the lock, so
		// skipping the call when an anchor is already recorded loses nothing
		// and keeps the second lock off a path invariant 16 asks to stay free
		// of avoidable work: this runs from the probe read loop, for all three
		// paths, four times a second on the active one.
		a.anchorDecisionSeq(decisionSeq, now)
	}
	a.mu.RLock()
	active, lastSeq := a.active, a.lastSeq
	a.mu.RUnlock()
	if decisionSeq < lastSeq || (pathID == active && decisionSeq <= lastSeq) {
		return // nothing to do; keeps the common case off the worker entirely
	}

	// Only a newer decision may replace the queued one. The filter above
	// reads active and lastSeq, which the worker updates only after its apply
	// has finished, so while it is inside `ip` for one decision a straggling
	// probe carrying the sequence before it still passes. Unconditional, that
	// straggler overwrote the newer decision already queued, the worker
	// applied the abandoned path a second time, and replies kept leaving by
	// the tunnel the frontend had just moved off until the next regular probe.
	// The frontend's burst on a switch made that interleaving the common one.
	//
	// Equal is admitted, as applyDecision admits it, because an equal sequence
	// on a different path is a real decision and not a straggler: the
	// frontend seeds its sequence from the clock, and a process that switched
	// once and was restarted quickly enough hands its successor a first switch
	// numbered the same as its own. Refused here, that decision was never
	// queued, the frontend routed down one tunnel while replies left by
	// another, and nothing corrected it until a later switch moved the
	// number on. A straggler is always strictly lower, so it is still kept out.
	a.pendingMu.Lock()
	if decisionSeq >= a.pending.seq {
		a.pending = pathDecision{pathID: pathID, seq: decisionSeq}
	}
	a.pendingMu.Unlock()
	select {
	case a.wake <- struct{}{}:
	default: // a decision is already queued; the worker will read the newest
	}
}

// The bound on a decision sequence.
//
// The frontend seeds decisionSeq from `UnixMilli() << 16` and increments it by
// one per switch, so a legitimate sequence tracks real time in those units.
// Everything downstream compares sequences only against each other, so a
// number planted near the top of a uint64 is not a wrong decision that a right
// one corrects: it is a ceiling no honest decision can ever clear again.
// Replies keep leaving by the pinned tunnel while the frontend routes down
// whichever one it chose, all three paths go on measuring perfectly, and only
// restarting this process clears it, because lastSeq lives in memory.
//
// It takes a peer holding the shared secret to send one deliberately. The
// cheaper reason to bound it is that no attacker is required: the seed is a
// clock reading, so a frontend booting with a wildly wrong clock plants the
// same ceiling by accident.
//
// **This host's wall clock may widen the ceiling and may never narrow it, and
// that is the whole design rather than a detail.** The first version of this
// check compared against `time.Now()` alone, and it was wrong in a way that
// mattered far more than the attack: a backend whose clock
// is behind computes a ceiling below every real sequence and refuses the lot.
// That host then never installs a return path at all, because `active` is not
// persisted and `reassertReturnPath` returns early on zero - the first accepted
// decision is what installs it. And the way to arrive at a stale clock is the
// exact scenario this system exists for: the house loses power, comes back with
// every link down, so there is no route to NTP, so the clock stays stale, so the
// decision that would recover the site is refused. A hardening step must not be
// able to hold the recovery shut.
//
// Anchoring on elapsed time takes the wall clock out of that direction
// entirely. seqBase is the frontend's own first sequence, seqBaseAt is a
// monotonic reading, and the ceiling grows from there at the rate real time
// passes. The clock is then admitted back on one side only, as a floor under
// that ceiling, because the anchor alone cannot cover a frontend restart -
// see plausibleDecisionSeq, which is where both halves are argued.
const (
	// decisionSeqSkew is how far past the elapsed-time ceiling a sequence may
	// sit. Generous on purpose: a frontend whose own clock is corrected
	// forward reseeds by the size of the correction, and that is a legitimate
	// jump this must not refuse. A week bounds a pin to a week, which is the
	// difference between an outage that ends and one that does not.
	decisionSeqSkew = 7 * 24 * time.Hour

	// decisionSeqHorizonMs is the absolute backstop, in the millisecond units
	// the sequence carries: the year 2100. It is the only bound that applies
	// to the very first decision, when there is no anchor yet, and it depends
	// on nothing at all - so it can refuse 2^64-1 without any risk of refusing
	// something real.
	decisionSeqHorizonMs = 4102444800000 // 2100-01-01T00:00:00Z
)

// plausibleDecisionSeq reports whether a sequence could have come from the
// frontend, given the anchor this host has established. See the constants
// above; base of zero means no anchor yet.
//
// The ceiling is the higher of two references, and it is a maximum rather than
// a choice between them because each covers the case the other gets wrong.
//
// The anchor reference - the first sequence this host accepted, plus the time
// that has actually elapsed since - is what makes a stale wall clock harmless,
// which is the property the whole check is built around: see the constants.
//
// The wall reference is what a legitimate frontend restart needs, and leaving
// it out was a hole rather than a simplification. A sequence is
// `frontendStart << 16` plus one per switch, so it tracks the frontend's *start*
// and not the passage of time: a frontend that restarts reseeds by however long
// the previous process had been running. The anchor cannot bound that, because
// the anchor was stamped with the *previous* frontend's seed and this host has
// no idea how old that process already was. So a backend restarting while the
// frontend had been up longer than decisionSeqSkew, followed by the frontend
// restarting - the documented upgrade order, and a crash under Restart=always -
// anchored on a seed a fortnight behind and then refused every real decision
// from the new process, permanently: the ceiling only grows at the rate real
// time passes, so it would take that same fortnight to catch up. Nothing
// corrects it, because the anchor is never re-established, and the symptom is
// the one this check exists to prevent, reached from the other side. The
// backend never queues a decision, `active` stays zero, the return path stays
// where applyPlumbing seeded it, and all three paths measure perfectly while
// replies leave by a tunnel the frontend abandoned.
//
// Taking the maximum is what keeps that fix from reintroducing the fault it
// replaced. A wall clock that is behind loses to the anchor and can refuse
// nothing; a wall clock that is ahead only ever widens the ceiling, which at
// worst degrades this check to the horizon. There is no reading of this host's
// clock that makes it stricter, which is the only property the clock was ever
// dangerous for.
func plausibleDecisionSeq(seq, base uint64, baseAt, now time.Time) bool {
	// Applies always, anchor or not. No legitimate sequence reaches it this
	// century, and it is what keeps the unanchored first decision from being
	// a free pin.
	if seq>>16 > decisionSeqHorizonMs {
		return false
	}
	if base == 0 {
		return true // nothing to measure from; the horizon is the only bound
	}
	elapsed := now.Sub(baseAt)
	if elapsed < 0 {
		// Reachable without a wrong clock, which is why it is a clamp rather
		// than an assertion: the caller reads the time before it reads the
		// anchor, so a caller preempted between the two can find an anchor
		// stamped after its own `now`. Clamping costs at most the scheduling
		// delay off a ceiling with seven days of slack in it.
		elapsed = 0
	}
	ceiling := base + (uint64(elapsed.Milliseconds()) << 16)
	// A frontend that restarted seeded itself from a clock no later than this
	// host's own - unless this host's clock is itself stale, which is the one
	// case neither reference covers. A backend more than the skew behind real
	// time, whose anchor was also stamped while the frontend had been up
	// longer than the skew, refuses a restarted frontend's decisions until
	// the ceiling catches up: staleness minus the skew, at the rate real time
	// passes. It is bounded and it self-heals - probes arriving means a
	// tunnel is up, which means a route to NTP exists again - and closing it
	// outright needs the frontend's clock on the wire, which is a protocol
	// change. Named here so the residual is a decision rather than a
	// surprise.
	//
	// Bounded by the same horizon the sequences are, because the shift can
	// overflow. Past about the year 10889 `ms << 16` no longer fits in a
	// uint64 and wraps to an unrelated number, which taking the maximum cannot
	// make safe: it cannot narrow the ceiling, since a low wrap simply loses
	// the comparison, but a high one widens it by an arbitrary amount. A clock
	// at the year 300000 wraps to 7.6e18 and admits a sequence two months past
	// the anchor, which is the pin this whole check exists to refuse, handed
	// over by a number that means nothing. A reading outside the horizon is not
	// a reference at all, and the anchor is still there to carry the decision.
	// Below zero is a clock set before 1970, ignored for the same reason.
	if ms := now.UnixMilli(); ms > 0 && ms <= decisionSeqHorizonMs && uint64(ms)<<16 > ceiling {
		ceiling = uint64(ms) << 16
	}
	return seq <= ceiling+(uint64(decisionSeqSkew.Milliseconds())<<16)
}

// anchorDecisionSeq records the first sequence this host accepted, which every
// later ceiling is measured from. Never re-anchored: the ceiling grows with
// elapsed time on its own, and moving the anchor to each new decision would
// let a sequence walk the ceiling upward a step at a time.
func (a *Agent) anchorDecisionSeq(seq uint64, now time.Time) {
	a.seqMu.Lock()
	defer a.seqMu.Unlock()
	if a.seqBase == 0 {
		a.seqBase, a.seqBaseAt = seq, now
	}
}

// decisionSeqAnchor reads the anchor for the check.
func (a *Agent) decisionSeqAnchor() (uint64, time.Time) {
	a.seqMu.Lock()
	defer a.seqMu.Unlock()
	return a.seqBase, a.seqBaseAt
}

// warnImplausibleSeq reports a refused sequence at a rate that cannot flood
// the journal. Called from the probe read loop, so it does no work beyond a
// mutex and a comparison in the common case.
// The throttle's lock covers the counter and nothing else. Logging inside it
// would put a write to the journal on the probe read loop's path, which is
// the one thing invariant 16 asks this loop never to do: a slow or full
// journal would stall replies on every path at once, and three tunnels going
// quiet together is indistinguishable from three tunnels dying.
// Responder.flushThrottles carries its trailing edge, so a burst that stops
// inside the window - a frontend clock corrected minutes after it was wrong -
// is still counted rather than swallowed.
func (a *Agent) warnImplausibleSeq(pathID int, seq uint64) {
	seen := a.implausible.take()
	if seen == 0 {
		return
	}
	a.seqMu.Lock()
	base, baseAt := a.seqBase, a.seqBaseAt
	a.seqMu.Unlock()

	// Named for what the check actually measures. The first version of this
	// message blamed "this host's clock" and sent the operator to compare the
	// two hosts, which is the one thing plausibleDecisionSeq deliberately does
	// not decide on: a stale clock here can only widen the ceiling. So the
	// hint was pointing at something that could never be the cause, and its
	// second branch sent whoever read it hunting an attack instead.
	a.log.Warn("refusing a routing decision whose sequence is beyond the plausible ceiling",
		"probes", seen, "path_id", pathID, "seq", seq, "anchor", base, "ceiling_from", baseAt,
		"hint", "the ceiling is the frontend's first sequence this agent saw plus elapsed time, or this host's clock, whichever is higher, plus a week; if the frontend is healthy, restarting failover-backend re-anchors it, and if it recurs something holding the shared secret is forging probes")
}

// flushImplausibleSeq is warnImplausibleSeq's trailing edge, ticked by
// Responder.flushThrottles because the refusals arrive on its read loop.
func (a *Agent) flushImplausibleSeq() {
	if n := a.implausible.flush(); n > 0 {
		a.log.Warn("further routing decisions were refused; their sequences were beyond the plausible ceiling",
			"probes", n, "since", throttleWindow,
			"hint", "if the frontend is healthy, restarting failover-backend re-anchors the ceiling; if it recurs something holding the shared secret is forging probes")
	}
}

// pathDecision is the frontend's choice, waiting to be applied.
type pathDecision struct {
	pathID int
	seq    uint64
}

// applyLoop serialises route changes off the probe read path.
//
// The reconciler shares this goroutine rather than running on its own: both it
// and applyDecision write routes, and applyDecision deliberately installs them
// before recording the new active path. A reconciler running concurrently
// could read the kernel inside that window and undo the change in flight.
func (a *Agent) applyLoop(ctx context.Context) {
	reconcile := time.NewTicker(10 * time.Second)
	defer reconcile.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.wake:
			a.pendingMu.Lock()
			d := a.pending
			a.pendingMu.Unlock()
			if d.pathID != 0 {
				a.applyDecision(ctx, d.pathID, d.seq)
			}
		case <-reconcile.C:
			a.reconcileRouting(ctx)
		}
	}
}

// reconcileRouting repairs routing the kernel discarded behind the agent's
// back, and is what lets a restarted tunnel start answering probes again.
//
// Deleting an interface takes every route that used it with it - and deleting
// the interface is exactly what `wg-quick down` does. Bringing the tunnel back
// up does not bring the routes back, and nothing else reinstalls them:
// applyPlumbing runs at startup and on a configuration push only. So after
// `systemctl restart wg-quick@wg-main` that path's reply table is empty, its
// probe replies can no longer leave by the tunnel their request arrived on,
// and the frontend goes on reporting the path down however healthy the tunnel
// is. That is the failure this exists to end.
//
// It only repairs what the kernel has actually lost, so a healthy backend
// issues nothing but `ip route show` every ten seconds. Observe mode is still
// honoured for the one route that carries published traffic.
func (a *Agent) reconcileRouting(ctx context.Context) {
	// Shares applyLoop's goroutine with applyDecision, so this is only ever
	// contended against a configuration push. See applyMu.
	a.applyMu.Lock()
	defer a.applyMu.Unlock()

	cfg, ok := a.Config()
	if !ok {
		return
	}
	a.mu.RLock()
	active, gated := a.active, a.runner
	a.mu.RUnlock()

	real := a.realRunner()

	for _, p := range cfg.Paths {
		// A tunnel that is still down is a path that is down, not a repair.
		if !a.ifaceExists(p.Iface) {
			continue
		}

		// Checked every tick, not only when a route is missing: rp_filter
		// belongs to the interface, so a recreated tunnel comes back with the
		// system default (2) however correct its routing is - and then every
		// probe arriving on it is dropped below the socket, which looks
		// exactly like a dead link.
		if changed, err := sysx.RPFilterOff(ctx, real, p.Iface); err != nil {
			a.log.Warn("cannot read reverse-path filtering", "iface", p.Iface, "err", err)
		} else if changed {
			a.log.Warn("reverse-path filtering was back on after the tunnel was recreated; disabled it",
				"path", p.Name, "iface", p.Iface)
		}

		// The shaper belongs to the interface exactly as rp_filter does, and
		// `wg-quick down` deletes the interface. Nothing reports the loss:
		// traffic keeps flowing, unshaped, and the only sign is that latency
		// under load quietly gets bad again.
		if p.ShapeMbit > 0 {
			if changed, err := sysx.EnsureQdisc(ctx, gated, p.Iface, p.ShapeMbit); err != nil {
				a.log.Warn("cannot check tunnel shaping", "path", p.Name, "iface", p.Iface, "err", err)
			} else if changed && gated.Applying() {
				a.log.Warn("restored tunnel shaping lost when the tunnel was recreated",
					"path", p.Name, "iface", p.Iface, "mbit", p.ShapeMbit)
			}
		}

		via, err := sysx.RouteVia(ctx, real, cfg.Overlay.FrontendIP+"/32", p.Table)
		if err != nil || via == p.Iface {
			continue
		}
		pc := model.PathConfig{ID: p.ID, Name: p.Name, Iface: p.Iface, Table: p.Table, Mark: p.Mark}
		if err := sysx.EnsureProbeRoute(ctx, real, pc, cfg.Overlay.FrontendIP, cfg.Overlay.BackendIP); err != nil {
			a.log.Error("cannot restore probe reply routing; this path cannot answer probes",
				"path", p.Name, "iface", p.Iface, "err", err)
			continue
		}
		a.log.Warn("restored probe reply routing lost when the tunnel was recreated",
			"path", p.Name, "iface", p.Iface, "was", via)
	}

	iface := ""
	for _, p := range cfg.Paths {
		if p.ID == active {
			iface = p.Iface
		}
	}
	if iface == "" || !a.ifaceExists(iface) {
		return
	}

	// The backend's own route to the frontend overlay carries probes and the
	// control channel only, so it is repaired in observe mode too - without it
	// the backend cannot report in at all.
	if via, err := sysx.RouteVia(ctx, real, cfg.Overlay.FrontendIP+"/32", 0); err == nil && via != iface {
		if err := sysx.SetActivePath(ctx, real, cfg.Overlay.FrontendIP+"/32", cfg.Overlay.BackendIP, iface); err != nil {
			a.log.Error("cannot restore the overlay route to the frontend", "iface", iface, "err", err)
		} else {
			a.log.Warn("restored the overlay route to the frontend", "iface", iface, "was", via)
		}
	}

	// A linker's route points at a neighbour rather than a device, so the
	// kernel drops it when the LAN interface bounces and nothing else would
	// ever put it back. This is the whole reason it belongs to an agent rather
	// than to somebody's shell history.
	for _, l := range cfg.Linkers {
		via, err := sysx.LinkerHostRouteVia(ctx, real, l.OverlayIP)
		if err != nil || via == l.LanIP {
			continue
		}
		if err := sysx.EnsureLinkerHostRoute(ctx, real, l.OverlayIP, l.LanIP); err != nil {
			a.log.Error("cannot restore the route to a linker",
				"overlay", l.OverlayIP, "via", l.LanIP, "err", err)
			continue
		}
		a.log.Warn("restored the route to a linker",
			"overlay", l.OverlayIP, "via", l.LanIP, "was", via)
	}

	// The return path carries published reply traffic, so observe mode must
	// not install it - in observe mode there is deliberately nothing there.
	if !gated.Applying() {
		return
	}
	if via, err := sysx.DefaultVia(ctx, real, sysx.ReturnTable); err == nil && via != iface {
		if err := sysx.SetReturnPath(ctx, gated, iface); err != nil {
			a.log.Error("cannot restore the return path", "iface", iface, "err", err)
		} else {
			a.log.Warn("restored the return path", "iface", iface, "was", via)
		}
	}
}

// applyDecision installs the routing for one decision. It is the synchronous
// half of SetActivePath and is what the tests exercise.
func (a *Agent) applyDecision(ctx context.Context, pathID int, decisionSeq uint64) {
	if pathID == 0 {
		return
	}

	// Held for the whole decision, not just the route write: the routing is
	// installed first and the active path recorded second (invariant 10), and a
	// configuration push re-asserting the return path inside that gap writes
	// the outgoing tunnel back over the incoming one. See applyMu.
	a.applyMu.Lock()
	defer a.applyMu.Unlock()

	a.mu.RLock()
	prev, lastSeq, cfg, runner := a.active, a.lastSeq, a.cfg, a.runner
	a.mu.RUnlock()

	if decisionSeq < lastSeq {
		return // reordered probe; it must not rewind the decision
	}
	if pathID == prev {
		// Already where we should be. Record the sequence so a later reordered
		// probe cannot resurrect an older decision.
		a.mu.Lock()
		if decisionSeq > a.lastSeq {
			a.lastSeq = decisionSeq
		}
		a.mu.Unlock()
		return
	}

	var iface, name string
	for _, p := range cfg.Paths {
		if p.ID == pathID {
			iface, name = p.Iface, p.Name
		}
	}
	// Nothing below this point commits state until the routes are actually
	// installed. Recording the new path first would mean a failure here - most
	// often config not having arrived yet - was never retried, because every
	// later probe would look like a decision already applied.
	if iface == "" {
		a.log.Warn("frontend chose a path this backend does not know about yet", "path_id", pathID)
		return
	}
	// Reply routing for published services moves real traffic, so it respects
	// observe mode.
	if err := sysx.SetReturnPath(ctx, runner, iface); err != nil {
		a.log.Error("cannot install return path", "iface", iface, "err", err)
		return
	}
	// The backend's own route to the frontend overlay carries only probes and
	// the control channel, never published traffic, so it always follows the
	// decision - otherwise observe mode would leave the control channel pinned
	// to a tunnel that has since died.
	if err := sysx.SetActivePath(ctx, a.realRunner(), cfg.Overlay.FrontendIP+"/32", cfg.Overlay.BackendIP, iface); err != nil {
		a.log.Warn("cannot update overlay route", "iface", iface, "err", err)
	}

	a.mu.Lock()
	a.active = pathID
	if decisionSeq > a.lastSeq {
		a.lastSeq = decisionSeq
	}
	a.mu.Unlock()

	a.log.Info("return path follows frontend decision", "from", prev, "to", name, "seq", decisionSeq)
}

// ActivePath reports the path the backend currently returns traffic over.
func (a *Agent) ActivePath() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.active
}

// Overlay returns the overlay addressing, preferring pushed config and falling
// back to the bootstrap file before the first push arrives.
func (a *Agent) Overlay() model.OverlayConfig {
	a.mu.RLock()
	defer a.mu.RUnlock()
	ov := a.boot.Overlay
	if a.haveCfg {
		if a.cfg.Overlay.FrontendIP != "" {
			ov.FrontendIP = a.cfg.Overlay.FrontendIP
		}
		if a.cfg.Overlay.BackendIP != "" {
			ov.BackendIP = a.cfg.Overlay.BackendIP
		}
	}
	return ov
}

func (a *Agent) cachePath() string {
	return filepath.Join(a.stateDir, "backend-config.json")
}

func (a *Agent) cacheConfig(cfg proto.BackendConfig) {
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return
	}
	tmp := a.cachePath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		a.log.Warn("cannot cache config", "err", err)
		return
	}
	if err := os.Rename(tmp, a.cachePath()); err != nil {
		a.log.Warn("cannot replace cached config", "err", err)
	}
}

func (a *Agent) loadCachedConfig() {
	raw, err := os.ReadFile(a.cachePath())
	if err != nil {
		return
	}
	var cfg proto.BackendConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		a.log.Warn("cached config unreadable", "err", err)
		return
	}
	a.mu.Lock()
	a.cfg = cfg
	a.haveCfg = true
	a.runner = runnerFor(cfg.Mode, a.log)
	a.mu.Unlock()
	a.log.Info("loaded cached configuration", "paths", len(cfg.Paths))
	a.responder.Reload()
}

// Revert removes everything this agent installed on the backend, and nothing
// else. It is the other half of `failoverctl revert`, which only ever reached
// the frontend.
//
// Run the frontend's revert first. This takes down the reply path, and while
// the frontend is still armed and DNATing, every published service breaks the
// moment it goes: requests keep arriving down the tunnel and their replies
// leave by the LAN to pfSense, where the client's flow has no state.
//
// And stop this host's unit before running it. This is a separate process with
// no way to tell a running agent anything, and reconcileRouting re-reads the
// kernel every ten seconds and reinstalls whatever it finds missing: the probe
// tables and their rules, the overlay route to the frontend, the routes to
// every extra host, and the return path too if the cached mode is still armed.
// The nftables tables and the source rules stay gone, so what is left is a host
// that is half reverted and reports itself clean. The frontend has no such
// problem because its revert runs inside the engine and disarms it, which is
// invariant 12; there is no equivalent here to disarm.
//
// The WireGuard tunnels are left alone because the agent never created them,
// and the overlay address is left in place for the reason the linker's revert
// leaves its own: a service may still be bound to it, and taking an address out
// from under a listening process turns a routing change into a crash.
func (a *Agent) Revert(ctx context.Context) {
	if _, ok := a.Config(); !ok {
		a.loadCachedConfig()
	}
	cfg, ok := a.Config()
	if !ok {
		cfg = a.provisionalConfig()
		a.log.Warn("no cached configuration to revert against; using the shipped defaults",
			"note", "anything installed for a path this build does not ship is left behind")
	}

	// Always acts, whatever the mode: observe mode means the agent installed
	// less, not that there is nothing to take down - the measurement plumbing
	// goes in either way.
	r := a.realRunner()

	paths := make([]model.PathConfig, 0, len(cfg.Paths))
	for _, p := range cfg.Paths {
		paths = append(paths, model.PathConfig{
			ID: p.ID, Name: p.Name, Iface: p.Iface, Table: p.Table, Mark: p.Mark,
		})
	}

	sysx.RemoveReturnRuleset(ctx, r)
	sysx.RemoveEgressRuleset(ctx, r)
	sysx.RemoveEgressRule(ctx, r)

	// Only tunnels this agent shaped. An interface it never touched keeps
	// whatever queue discipline its owner gave it.
	for _, p := range cfg.Paths {
		if p.ShapeMbit > 0 {
			sysx.RemoveQdisc(ctx, r, p.Iface)
		}
	}

	for _, l := range cfg.Linkers {
		sysx.RemoveLinkerHostRoute(ctx, r, l.OverlayIP)
	}
	// By comment, so an operator's own rules in a chain this agent does not own
	// are untouched. A site with no linkers never had them, and the listing then
	// carries nothing of ours to find.
	sysx.RemoveOverlayForwardExceptions(ctx, r)

	// Both sources, because both were installed: the backend's own address
	// always, and the overlay range wherever a subnet is configured.
	sysx.RemoveReturnRoutes(ctx, r, cfg.Overlay.BackendIP, cfg.Overlay.Subnet)
	sysx.RemoveOverlayLocalRule(ctx, r, cfg.Overlay.Subnet)
	sysx.RemoveProbeRoutes(ctx, r, paths, cfg.Overlay.FrontendIP+"/32", cfg.Overlay.FrontendIP+"/32")

	a.log.Warn("reverted all system changes on the backend",
		"note", "the WireGuard tunnels and the overlay address are left in place; "+
			"restart the agent to reinstall",
		"hint", "if failover-backend.service is still running, its reconciler puts the routing "+
			"back within ten seconds: stop the unit and run this again")
}

// withdrawRemovedLinkers deletes routes for linkers that are no longer
// configured, or have been disabled.
//
// The frontend stops publishing to a linker the moment it is unticked, so a
// route left behind is not a harmless leftover: it is the backend still
// forwarding to a machine the operator has taken out of service, and nothing
// anywhere would say so.
func (a *Agent) withdrawRemovedLinkers(ctx context.Context, prev, now []proto.LinkerRoute) {
	if len(prev) == 0 {
		return
	}
	keep := make(map[string]bool, len(now))
	for _, l := range now {
		keep[l.OverlayIP] = true
	}
	real := a.realRunner()
	for _, l := range prev {
		if keep[l.OverlayIP] {
			continue
		}
		sysx.RemoveLinkerHostRoute(ctx, real, l.OverlayIP)
		a.log.Info("withdrew the route to a linker that is no longer configured",
			"overlay", l.OverlayIP)
	}
}
