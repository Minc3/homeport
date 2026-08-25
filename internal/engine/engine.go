package engine

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/notify"
	"github.com/quinlan102/homeport/internal/proto"
	"github.com/quinlan102/homeport/internal/quota"
	"github.com/quinlan102/homeport/internal/store"
	"github.com/quinlan102/homeport/internal/sysx"
)

// Version is the frontend's build, reported in Status so the portal can say
// what is actually running on this host. Stamped by main at startup.
var Version = "dev"

// Engine is the frontend's decision loop. It owns the probers, the per-path
// health trackers, the quota view and the single route that decides which
// tunnel carries everything.
type Engine struct {
	log      *slog.Logger
	st       *store.Store
	notifier *notify.Notifier
	stateDir string
	psk      []byte
	started  time.Time

	// real acts on the system whatever the mode, backing the measurement
	// plumbing, the reconciler's kernel reads and revert. It and ifaceExists
	// are set once in New and swapped only by tests, which have no Linux
	// network stack to inspect.
	real        sysx.Runner
	ifaceExists func(string) bool

	mu       sync.RWMutex
	cfg      model.Config
	runner   sysx.Runner
	trackers map[int]*Tracker
	probers  map[int]*Prober

	// baseCtx outlives any single request. Probers must never be started from
	// an HTTP request's context: it is cancelled the moment the handler
	// returns, which would silently stop all probing on the first settings
	// save.
	//
	// proberDone is the generation currently running. stopProbers waits on it,
	// so the old sockets are closed before the new ones bind - two generations
	// probing at once perturb the very measurement every decision is made
	// from, and on a metered path they bill twice for it.
	baseCtx      context.Context
	proberCancel context.CancelFunc
	proberDone   *sync.WaitGroup
	results      chan Result

	// liveProbers counts prober goroutines across every generation, which is
	// precisely the number the orphaned-generation fault got wrong. It exists
	// so that fault is assertable at all: from outside, an extra generation is
	// invisible except as a path being probed faster than its configured
	// interval.
	liveProbers atomic.Int64

	// The WAN address shown in the portal header, cached for a few seconds.
	// Reading it is two netlink dumps and the portal polls Status every
	// second, so without the cache the kernel is enumerated once a second to
	// re-answer a question that changes on the order of never. Guarded by its
	// own mutex because Status holds only mu.RLock, and two concurrent Status
	// calls (the portal and failoverctl) may both refresh it.
	wanMu   sync.Mutex
	wanKey  string
	wanAddr string
	wanAt   time.Time

	// reconfMu serialises Reconfigure and Revert against each other. It is
	// deliberately a separate lock from mu: it has to be held across
	// applySystemConfig, which shells out to ip, nft and tc and is far too slow
	// to hold the state lock for. See Reconfigure for the fault it prevents.
	reconfMu sync.Mutex

	// applyMu serialises the shell-outs that write routes, so that only one
	// goroutine is running `ip` at a time.
	//
	// evaluate and reconcileRouting already share Run's goroutine, because a
	// reconciler reading the kernel between a route going in and the switch
	// being recorded would undo it - invariant 18. applySystemConfig is the
	// third writer that reasoning missed: it runs on the HTTP handler's
	// goroutine, and it re-asserts the route for the active path. A settings
	// save landing as a failover fires could read the outgoing path, wait for
	// evaluate to install the new route, and then write the dead tunnel back
	// over it - published traffic down a link that had just failed, with the
	// portal showing the new one, until the reconciler noticed up to 10s later.
	// Revert is a fourth: it removes routes evaluate may be installing.
	//
	// Always taken *after* reconfMu, never before. Run's goroutine takes only
	// this one, so there is no cycle.
	applyMu sync.Mutex

	active      int
	pinned      int // operator override; 0 means automatic selection
	decisionSeq uint64
	lastSwitch  time.Time

	// wake asks Run to evaluate now rather than on its next 500ms tick. It is
	// raised whenever an input to selectPath changes outside the tick: a
	// tracker changing a path's eligibility either way - condemning it, where
	// the tick is the only thing between a known-dead route and the switch
	// away from it, or recovering it, where in the held state the tick is the
	// only thing between a working tunnel and the traffic still blackholed on
	// a dead one - the operator's own actions (pin, approve, revoke, clear
	// quarantine), which exist to change the decision and should not then
	// wait on a timer to see it, and a settings save, which can retire the
	// active path. Buffered one deep and written without blocking: two
	// changes in one tick are one evaluation, and nothing ever waits on it.
	// The tick remains for the purely time-based inputs: hold-down, quarantine
	// and grant expiry.
	wake chan struct{}

	// beatenSince is when the active path started being out-scored by the
	// margin, in quality selection mode. It is the hold-down for moving *down*
	// to a less preferred path, and it is tracked against the active path
	// rather than against a particular challenger so that two candidates
	// trading the lead cannot postpone the switch indefinitely.
	beatenSince time.Time
	held        bool
	heldReason  string
	backendUp   bool

	// What the backend last said it was, from its Hello frame. Deliberately not
	// cleared when the channel drops: knowing which build was there a minute ago
	// is more use than a blank, and backendUp already reports liveness.
	backendVersion string
	backendHost    string

	// linkers is liveness for the extra hosts, keyed by overlay address. Only
	// hosts that have connected appear; a configured linker that has never
	// dialled in is reported as down from the configuration instead, which is
	// the distinction between "not running" and "not configured".
	linkers map[string]linkerConn

	// linkerSeen is when each extra host was last heard from, kept after its
	// connection has gone - that is the moment it becomes the only thing worth
	// reporting. linkerSaved is what has been written to the store, so the
	// stamp survives a frontend restart without a database write every
	// keepalive. Both keyed by overlay address.
	linkerSeen  map[string]time.Time
	linkerSaved map[string]time.Time

	// linkerSession numbers control connections, so a teardown can be matched
	// to the session that is actually ending. See SetLinkerDown.
	linkerSession uint64

	quotaDec map[int]quota.Decision
	blocks   map[int]model.Block

	// peerEndpoints is where each tunnel's peer was last seen, by path id, and
	// sharedEndpoints is the subset that are the same address - two tunnels on
	// one internet service, which is the fault the portal shouts about.
	// endpointClash is the last signature warned about, so the log records a
	// change rather than repeating every tick.
	peerEndpoints   map[int]string
	sharedEndpoints []model.SharedEndpoint
	endpointClash   string

	// protectOn records that the edge filtering table is really loaded, so the
	// counters are only read when there is something to read. protectCounters
	// and protectBlocked are the last sample of what the kernel reports.
	protectOn        bool
	protectCounters  []model.ProtectCounter
	protectBlocked   []model.BlockedSource
	protectGeoLocked []model.GeoLockedPort
	// protectApplied is the ruleset text last really loaded, so a save that
	// leaves protection untouched can skip the reload. A reload is not free:
	// it resets every counter, unparks every blocked source and releases
	// every engaged region lock, and an operator saving a probe interval
	// mid-flood must not hand the flood a clean slate. Cleared whenever the
	// table's presence is in doubt, because a stale latch skips a reload the
	// kernel actually needs.
	protectApplied string

	// backendConns counts live control connections. A plain boolean was wrong:
	// when the backend reconnects, the old connection's deferred teardown runs
	// after the new one has already registered, and the portal would show the
	// backend as unreachable forever while the channel was healthy.
	backendConns int

	// dataPlane records that traffic-affecting rules were actually installed.
	// Switching back to observe does not remove them - dropping DNAT would take
	// the published services offline instantly - so the portal has to say so
	// rather than implying nothing is applied.
	dataPlane bool

	// reverted latches after Revert and holds until the next Reconfigure. It
	// exists because a revert is the one state the running engine must not
	// repair: observe mode deliberately keeps the measurement plumbing alive,
	// so without this the reconciler reinstalled the probe tables, their rules
	// and rp_filter within one 10s tick of Revert removing them, and evaluate
	// reinstalled the control route within 500ms. On a running host that was
	// merely surprising; during uninstall it was a race - the script stops the
	// unit moments after the revert returns, and a tick landing in that gap
	// put rules back that the about-to-be-deleted binary was the only thing
	// able to remove. While set, nothing is installed and nothing is measured;
	// a settings save or a mode change is what brings the engine back.
	//
	// It is persisted (revertedMetaKey) and reloaded in New, because the unit
	// runs under Restart=always: held only in memory, any crash or restart in
	// the window between `failoverctl revert` and `systemctl stop` brought the
	// process back with the startup sequence reinstalling everything the
	// revert had just removed - and during uninstall that window ends with the
	// only binary able to remove them being deleted.
	reverted bool

	// cfgVersion increments on every configuration change. The control server
	// watches it to know when to push a fresh config down to the backend.
	cfgVersion uint64
}

// New builds an engine from stored configuration.
func New(log *slog.Logger, st *store.Store, notifier *notify.Notifier, cfg model.Config, psk []byte, stateDir string) *Engine {
	e := &Engine{
		log:      log,
		st:       st,
		notifier: notifier,
		stateDir: stateDir,
		psk:      psk,
		started:  time.Now(),
		cfg:      cfg,
		results:  make(chan Result, 1024),
		trackers: map[int]*Tracker{},
		probers:  map[int]*Prober{},
		quotaDec: map[int]quota.Decision{},
		wake:     make(chan struct{}, 1),
		blocks:   map[int]model.Block{},
		linkers:  map[string]linkerConn{},
		baseCtx:  context.Background(),

		linkerSeen:  map[string]time.Time{},
		linkerSaved: map[string]time.Time{},

		// Seeded from the wall clock rather than starting at zero, so the
		// sequence keeps increasing across a frontend restart. Otherwise the
		// backend, which remembers the highest sequence it has seen, would
		// ignore every decision from a freshly restarted frontend until it had
		// been out-switched - leaving reply traffic on the wrong tunnel.
		//
		// Milliseconds, not seconds. Seeded to the second, a process that
		// started, switched once and was restarted inside that same second
		// handed its successor the same seed, and the successor's first switch
		// the same sequence number as the one it replaced, on a different
		// path. That is reachable: Restart=always brings a crashed process
		// back within the second, a fresh tracker is usable after one reply,
		// and every prober sends on entry. The backend keeps the two apart
		// only by the number.
		decisionSeq: uint64(time.Now().UnixMilli()) << 16,

		real:        &sysx.ExecRunner{Log: log},
		ifaceExists: sysx.IfaceExists,
	}
	e.runner = runnerFor(cfg.Mode, log)
	reportQuotaSubstitutions(log, cfg)
	e.loadLinkerSeen()
	// A latch left by a previous process. See the field: without this,
	// Restart=always turned every crash after a revert into a full reinstall.
	if st.Meta(revertedMetaKey) != "" {
		e.reverted = true
	}
	return e
}

// revertedMetaKey is the persisted form of the reverted latch. Set by Revert
// before it tears anything down, cleared by Reconfigure - the same lifecycle
// as the in-memory flag, so a restart lands in the state the operator left.
const revertedMetaKey = "reverted"

func runnerFor(mode string, log *slog.Logger) sysx.Runner {
	if mode == model.ModeArmed {
		return &sysx.ExecRunner{Log: log}
	}
	return &sysx.DryRunner{Log: log}
}

// Run drives the engine until the context is cancelled.
func (e *Engine) Run(ctx context.Context) error {
	// The startup install sequence holds reconfMu like the other two callers
	// of applySystemConfig/startProbers. The failoverctl socket opens on its
	// own goroutine, so a revert can be served while this is still installing:
	// unserialised, Revert latched, found no probers to stop, tore everything
	// down - and this then reinstalled the plumbing and started a generation
	// of probers on a "reverted" engine, measuring 100% loss against removed
	// routes. The latch check below is the other half: a latch restored from
	// the store (or set by a revert that won the lock first) means start held,
	// exactly as the process that served the revert was.
	e.reconfMu.Lock()
	e.mu.Lock()
	e.baseCtx = ctx
	reverted := e.reverted
	e.mu.Unlock()
	if reverted {
		e.log.Warn("starting latched after a revert",
			"note", "nothing is installed or measured until settings are saved or the mode is changed")
	} else {
		e.applySystemConfig(ctx)
		e.seedActiveFromKernel(ctx)
		e.startProbers(ctx)
	}
	e.reconfMu.Unlock()
	defer e.stopProbers()

	decide := time.NewTicker(500 * time.Millisecond)
	defer decide.Stop()
	// Shares this goroutine with evaluate() on purpose: both write routes, and
	// evaluate installs a route before recording the switch. On a separate
	// timer the reconciler could read the kernel inside that window, decide the
	// route disagreed with e.active, and undo the switch that was in progress.
	reconcile := time.NewTicker(10 * time.Second)
	defer reconcile.Stop()
	sample := time.NewTicker(5 * time.Second)
	defer sample.Stop()
	housekeep := time.NewTicker(time.Hour)
	defer housekeep.Stop()

	e.refreshQuota(time.Now())
	_ = e.st.AddEvent(store.EventSystem, 0, "frontend started in %s mode", e.Mode())

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case r := <-e.results:
			e.onResult(ctx, r)

		case <-decide.C:
			e.evaluate(ctx, time.Now())

		case <-e.wake:
			e.evaluate(ctx, time.Now())

		case <-reconcile.C:
			e.reconcileRouting(ctx)

		case <-sample.C:
			now := time.Now()
			e.refreshQuota(now)
			e.persistSamples(now)
			e.sampleProtect(ctx)
			e.samplePeerEndpoints(ctx)

		case <-housekeep.C:
			if err := e.st.Prune(); err != nil {
				e.log.Warn("prune failed", "err", err)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Probing
// ---------------------------------------------------------------------------

// startProbers replaces the running generation of probers with one built from
// the current configuration.
//
// It cancels whatever it finds still recorded before installing its own. That
// is not belt and braces for the balanced stop/start pair below: overwriting
// e.proberCancel without cancelling it *loses* the only handle to that
// generation, and since its context is derived from baseCtx it then probes
// until the process exits. Two generations on a 5s standby ticker read as one
// path being probed every 2-3s, bill the metered quota twice, and halve the
// wall-clock time in which FailThreshold consecutive losses condemn a path -
// with nothing anywhere reporting any of it.
func (e *Engine) startProbers(parent context.Context) {
	e.mu.Lock()
	cfg := e.cfg
	if e.proberCancel != nil {
		// A caller reached here without stopping first. Take the old
		// generation down rather than orphaning it.
		e.log.Warn("probers started while a generation was still running; cancelling the old one")
		e.proberCancel()
	}
	ctx, cancel := context.WithCancel(parent)
	e.proberCancel = cancel
	done := &sync.WaitGroup{}
	e.proberDone = done

	// Carry health across a restart of the probers. Editing a quota or adding
	// a published port says nothing about whether a link is up, and rebuilding
	// every tracker as unknown would make each settings save look momentarily
	// like a total outage and fire a spurious urgent alert.
	previous := e.trackers
	e.trackers = map[int]*Tracker{}
	e.probers = map[int]*Prober{}

	for _, p := range cfg.Paths {
		if old, ok := previous[p.ID]; ok && old.cfg.Iface == p.Iface {
			old.Retune(p, cfg.Probe, cfg.Failover)
			e.trackers[p.ID] = old
		} else {
			e.trackers[p.ID] = NewTracker(p, cfg.Probe, cfg.Failover)
		}
		pr, err := NewProber(p, cfg.Probe, cfg.Overlay, e.psk, e.results, e.decision, e.log)
		if err != nil {
			e.log.Error("cannot start prober", "path", p.Name, "err", err)
			continue
		}
		pr.SetActive(p.ID == e.active)
		e.probers[p.ID] = pr
	}
	probers := make([]*Prober, 0, len(e.probers))
	for _, pr := range e.probers {
		probers = append(probers, pr)
	}
	done.Add(len(probers))
	e.mu.Unlock()

	for _, pr := range probers {
		go func() {
			e.liveProbers.Add(1)
			defer func() {
				e.liveProbers.Add(-1)
				done.Done()
			}()
			pr.Run(ctx)
		}()
	}
}

// stopProbers cancels the running generation and waits for it to be gone.
//
// The wait is the point. A cancelled prober is not a stopped prober: it holds a
// marked UDP socket until its send loop next reaches the select and its read
// loop's deadline expires, and until then a replacement generation started
// underneath it is probing the same path in parallel. That window is short, but
// it is on every settings save, and the measurement it disturbs is the one
// every failover decision is made from. Same reasoning as invariant 17.
func (e *Engine) stopProbers() {
	e.mu.Lock()
	cancel := e.proberCancel
	done := e.proberDone
	e.proberCancel = nil
	e.proberDone = nil
	e.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		done.Wait()
	}
}

// decision is what each probe carries to the backend: the currently chosen
// path and a monotonic sequence number so a reordered probe cannot rewind it.
func (e *Engine) decision() (uint16, uint64) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return uint16(e.active), e.decisionSeq
}

func (e *Engine) onResult(ctx context.Context, r Result) {
	e.mu.Lock()
	tr, ok := e.trackers[r.PathID]
	if !ok {
		e.mu.Unlock()
		return
	}
	now := time.Now()
	tn := tr.Observe(r, now)
	name := tr.cfg.Name
	quarantine := tn.Quarantine
	failThreshold := e.cfg.Probe.FailThreshold // read under the lock; Reconfigure replaces e.cfg
	e.mu.Unlock()

	if !tn.Changed {
		return
	}
	// Decide now if the transition changed whether the selector may choose
	// this path. Down is the obvious case: the streak that condemned it took
	// DetectMs to build, and the tick would add up to another 500ms on top for
	// no reason other than that it is periodic. Recovery is the one that was
	// missed: with every path down the route is left on a dead tunnel, and the
	// first path to come back is switched to with no hold-down at all - so the
	// tick was the whole of the delay, with players blackholed for its length.
	// Up to suspect changes nothing the selector reads, and a loss that changes
	// nothing never gets here; evaluate on every lost probe would be a busy
	// loop on a flapping link.
	if usableHealth(tn.To) != usableHealth(tn.From) {
		e.wakeDecision()
	}
	switch tn.To {
	case model.HealthDown:
		_ = e.st.AddEvent(store.EventPathDown, r.PathID, "%s went down (%d consecutive probe losses)", name, failThreshold)
		e.log.Warn("path down", "path", name)
		e.notifier.Send(ctx, notify.KindPathDown, "down:"+name,
			fmt.Sprintf("Path %s is down", name),
			"End-to-end probes through this tunnel stopped reaching the backend.",
			notify.PriorityWarning)
		if quarantine > 0 {
			_ = e.st.AddEvent(store.EventQuarantine, r.PathID,
				"%s quarantined for %s after repeated failures", name, quarantine.Round(time.Second))
		}
	case model.HealthUp:
		_ = e.st.AddEvent(store.EventPathUp, r.PathID, "%s recovered", name)
		e.log.Info("path up", "path", name)
	}
}

// wakeDecision asks Run for an evaluation now. Safe from any goroutine and
// safe on an engine built without Run (the tests' literal), where the nil
// channel simply never accepts.
func (e *Engine) wakeDecision() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

// ---------------------------------------------------------------------------
// Decision
// ---------------------------------------------------------------------------

// evaluate recomputes policy blocks, picks a path and applies the choice.
func (e *Engine) evaluate(ctx context.Context, now time.Time) {
	e.mu.Lock()
	if e.reverted {
		// A reverted system has no probe routes and no probers, so every
		// verdict here would be stale and every choice would reinstall routing
		// the operator just removed - applyActivePath's control-route repair
		// runs through the real runner whatever the mode. Reconfigure resumes.
		e.mu.Unlock()
		return
	}
	cfg := e.cfg

	for _, p := range cfg.Paths {
		tr := e.trackers[p.ID]
		if tr == nil {
			continue
		}
		block := model.BlockNone
		switch {
		case !p.Enabled:
			block = model.BlockDisabled
		case tr.Quarantined(now):
			block = model.BlockQuarantine
		case e.quotaDec[p.ID].Blocked:
			block = model.BlockQuota
		case tr.Degraded():
			block = model.BlockDegraded
		}
		e.blocks[p.ID] = block
	}

	chosen, held, reason := e.selectPath(cfg, now)
	prevActive := e.active
	prevHeld := e.held
	e.held, e.heldReason = held, reason
	e.mu.Unlock()

	// Install the route before recording the switch. Committing first and
	// applying afterwards would leave the portal claiming a path the kernel
	// never moved to, and because the next pass sees the choice as already
	// current, a failed `ip route replace` would never be retried.
	//
	// applyMu covers exactly that pair and no more. It has to cover both,
	// because applySystemConfig reads e.active and re-asserts its route under
	// the same lock: interleaved, a settings save would read the outgoing
	// tunnel, wait behind the install below, and then write the dead path back
	// over the one just chosen. Held either side of the pair it lands wholly
	// before or wholly after, and both orders end on the chosen path.
	//
	// It deliberately does not cover the rest of this function. The lock is
	// also held across every shell-out in applySystemConfig, so a settings save
	// taken at the top would park Run's whole select for the length of the
	// save: no decision, no reconcile, and no draining of e.results. prevActive
	// is read without it on purpose - it only decides whether the choice
	// changed, and a save landing beside that read still leaves the route
	// pointing at chosen.
	if chosen != 0 && chosen != prevActive {
		newCfg, _ := cfg.PathByID(chosen)
		e.applyMu.Lock()
		// Re-checked under the apply lock: a Revert that won the lock between
		// the check at the top and here has just torn everything down, and this
		// install would put the control route straight back.
		e.mu.RLock()
		reverted := e.reverted
		e.mu.RUnlock()
		if reverted {
			e.applyMu.Unlock()
			return
		}
		err := e.applyActivePath(ctx, newCfg)
		if err == nil {
			e.commitSwitch(ctx, cfg, chosen, prevActive, now)
		}
		e.applyMu.Unlock()
		if err != nil {
			e.log.Error("failed to install route, will retry", "path", newCfg.Name, "err", err)
			_ = e.st.AddEvent(store.EventSystem, chosen, "failed to install route via %s: %v", newCfg.Iface, err)
		}
	}

	e.mu.RLock()
	newActive := e.active
	e.mu.RUnlock()

	if held && !prevHeld {
		e.onHeld(ctx, reason, newActive)
	}
	if !held && prevHeld {
		_ = e.st.AddEvent(store.EventSystem, 0, "recovered: a usable path is available again")
	}
}

// selectPath implements strict priority with a failback hold-down.
//
// Failing over to a worse path is immediate - being on a working link matters
// more than being on the preferred one. Failing back to a better path waits
// for an unbroken clean streak, which is what stops a marginal fixed line service
// from dragging traffic back and forth every time it briefly recovers.
func (e *Engine) selectPath(cfg model.Config, now time.Time) (chosen int, held bool, reason string) {
	if e.pinned != 0 {
		if p, ok := cfg.PathByID(e.pinned); ok {
			tr := e.trackers[e.pinned]
			usable := tr != nil && tr.Usable() && e.blocks[e.pinned] == model.BlockNone
			if usable {
				return e.pinned, false, ""
			}
			// Honour the pin - it is an explicit instruction - but raise the
			// alarm. Silently sitting on a pinned path that has gone down would
			// be an outage nobody is told about.
			why := "unreachable"
			if tr != nil && e.blocks[e.pinned] != model.BlockNone {
				why = string(e.blocks[e.pinned])
			}
			return e.pinned, true, fmt.Sprintf(
				"pinned to %s, which is %s; unpin to let it fail over", p.Name, why)
		}
	}

	paths := append([]model.PathConfig(nil), cfg.Paths...)
	sort.Slice(paths, func(i, j int) bool { return paths[i].Priority < paths[j].Priority })

	var eligible []model.PathConfig
	for _, p := range paths {
		tr := e.trackers[p.ID]
		if tr == nil || !tr.Usable() || e.blocks[p.ID] != model.BlockNone {
			continue
		}
		eligible = append(eligible, p)
	}

	if len(eligible) == 0 {
		// Dead-man: keep the last route installed rather than withdrawing it
		// and blackholing traffic. A path that comes back finds the route
		// already pointing at it.
		return 0, true, e.heldReasonFor(cfg, now)
	}

	// The preferred path is the highest-priority eligible one. In quality mode
	// a clearly better path may displace it; in priority mode nothing can.
	target := eligible[0]
	if cfg.Failover.Selection == model.SelectionQuality {
		target = e.qualityTarget(eligible, cfg)
	}

	if e.active == 0 {
		return target.ID, false, ""
	}
	activeCfg, ok := cfg.PathByID(e.active)
	if !ok {
		return target.ID, false, ""
	}
	activeEligible := false
	for _, p := range eligible {
		if p.ID == e.active {
			activeEligible = true
			break
		}
	}
	if !activeEligible {
		e.beatenSince = time.Time{}
		return target.ID, false, "" // failover, immediate
	}
	if target.ID == e.active {
		e.beatenSince = time.Time{}
		return e.active, false, ""
	}

	hold := time.Duration(cfg.Failover.HoldDownSec) * time.Second
	failback := func() (int, bool, string) {
		e.beatenSince = time.Time{}
		if tr := e.trackers[target.ID]; tr != nil && tr.CleanFor(now) >= hold {
			return target.ID, false, "" // hold-down satisfied
		}
		return e.active, false, ""
	}

	if cfg.Failover.Selection != model.SelectionQuality {
		if target.Priority < activeCfg.Priority {
			return failback()
		}
		return e.active, false, ""
	}

	// Returning to the preferred link is governed by its clean streak, never by
	// its score. Priority order is the cost order here - the preferred path is
	// the unmetered one - so a slower but free link still wins the traffic
	// back. Scoring it would park traffic on LTE for being 10ms quicker.
	if target.ID == preferredPathID(cfg) {
		return failback()
	}

	// Both paths are fallbacks, so measurements decide - subject to the margin
	// and the hold-down, without which two similar links trade places on noise
	// and each swap is a visible stall. The margin is against the path actually
	// running, not against the preferred one: otherwise a third path could pull
	// traffic off a second one it is no better than, merely because both beat
	// the link that is down.
	if !e.beatsByMargin(target.ID, e.active, cfg) {
		e.beatenSince = time.Time{}
		return e.active, false, ""
	}
	// Timed from when the active path started being beaten, not from when this
	// particular challenger appeared. Two candidates alternating for the lead
	// would otherwise reset the clock forever and the switch would never
	// happen, however badly the active path was performing.
	if e.beatenSince.IsZero() {
		e.beatenSince = now
	}
	if now.Sub(e.beatenSince) < hold {
		return e.active, false, ""
	}

	// Floor under how often this may move traffic. The margin and the hold-down
	// already make oscillation on noise impossible, but neither caps a genuine
	// alternation: two links really taking turns being much better - which is
	// what a carrier working on a tower produces - would otherwise switch every
	// hold-down, for as long as it lasted. The clock keeps running underneath,
	// so the move happens the moment the dwell expires if the lead still holds.
	//
	// Only reached for a choice between two working fallbacks. A path that has
	// become unusable, and a failback to the preferred path, both returned long
	// before here and are never delayed by this.
	if dwell := time.Duration(cfg.Failover.Quality.MinDwellSec) * time.Second; dwell > 0 {
		if !e.lastSwitch.IsZero() && now.Sub(e.lastSwitch) < dwell {
			return e.active, false, ""
		}
	}
	return target.ID, false, ""
}

// preferredPathID is the most preferred enabled path - the one quality
// selection is not allowed to second-guess.
func preferredPathID(cfg model.Config) int {
	best := 0
	bestPrio := 0
	for _, p := range cfg.Paths {
		if !p.Enabled {
			continue
		}
		if best == 0 || p.Priority < bestPrio {
			best, bestPrio = p.ID, p.Priority
		}
	}
	return best
}

// qualityTarget returns the path that should carry traffic.
//
// Measurements only get a vote once the preferred link is out. While it is
// usable it keeps the traffic whatever the numbers say, so this cannot move
// traffic onto a metered link for being faster - it only decides *which*
// fallback to use once there is no longer a choice about falling back.
func (e *Engine) qualityTarget(eligible []model.PathConfig, cfg model.Config) model.PathConfig {
	top := eligible[0] // eligible is sorted by priority
	if top.ID == preferredPathID(cfg) {
		return top
	}
	best := top
	bestScore := e.score(top.ID, cfg)
	for _, p := range eligible {
		if s := e.score(p.ID, cfg); s < bestScore {
			best, bestScore = p, s
		}
	}
	return best
}

// beatsByMargin reports whether one path scores enough better than another to
// justify moving traffic.
//
// Strictly better, so a flawless path cannot be displaced by another flawless
// one: both score zero, and zero is not less than zero. Without that, two idle
// tunnels would swap on every tick.
func (e *Engine) beatsByMargin(candidate, incumbent int, cfg model.Config) bool {
	ct, it := e.trackers[candidate], e.trackers[incumbent]
	if ct == nil || it == nil {
		return false
	}
	margin := cfg.Failover.Quality.MarginPct / 100
	if margin < 0 {
		margin = 0
	}
	return ct.Score(cfg.Failover.Quality) < it.Score(cfg.Failover.Quality)*(1-margin)
}

func (e *Engine) score(pathID int, cfg model.Config) float64 {
	tr := e.trackers[pathID]
	if tr == nil {
		return math.Inf(1)
	}
	return tr.Score(cfg.Failover.Quality)
}

// heldReasonFor explains why nothing is usable, distinguishing "the links are
// dead" from "the links work but you have not approved paying for them".
func (e *Engine) heldReasonFor(cfg model.Config, now time.Time) string {
	var quotaBlocked []string
	var otherBlocked []string
	for _, p := range cfg.Paths {
		tr := e.trackers[p.ID]
		if tr == nil {
			continue
		}
		switch e.blocks[p.ID] {
		case model.BlockQuota:
			if tr.Usable() {
				quotaBlocked = append(quotaBlocked, p.Name)
			}
		case model.BlockNone:
		default:
			otherBlocked = append(otherBlocked, p.Name)
		}
	}
	if len(quotaBlocked) > 0 {
		return fmt.Sprintf("no usable path: %v healthy but over quota, waiting for approval", quotaBlocked)
	}
	if len(otherBlocked) > 0 {
		return fmt.Sprintf("no usable path: all paths unreachable or blocked (%v)", otherBlocked)
	}
	return "no usable path: all tunnels unreachable"
}

func (e *Engine) onHeld(ctx context.Context, reason string, active int) {
	e.log.Error("no usable path", "reason", reason, "keeping_route_to_path", active)
	_ = e.st.AddEvent(store.EventHeld, 0, "%s; keeping the last route installed", reason)
	e.notifier.Send(ctx, notify.KindHeld, "held",
		"No usable path",
		reason+"\n\nThe last route is still installed. Open the portal to approve an over-quota path if you want to stay online.",
		notify.PriorityUrgent)
}

// applyActivePath installs the route and reports whether the kernel accepted
// it. It changes no engine state, so a failure simply leaves the previous
// choice in place to be retried on the next pass.
func (e *Engine) applyActivePath(ctx context.Context, p model.PathConfig) error {
	e.mu.RLock()
	runner := e.runner
	cfg := e.cfg
	e.mu.RUnlock()

	// The control channel follows the same tunnel, and does so in observe mode
	// too - it is source-selected, so it carries no published traffic. Failing
	// to move it would leave the channel pinned to a tunnel that may be the one
	// that just died.
	if err := sysx.EnsureControlRoute(ctx, e.realRunner(), cfg.Overlay.RoutePrefix(),
		cfg.Overlay.BackendIP, cfg.Overlay.FrontendIP, p.Iface); err != nil {
		e.log.Warn("control-channel route not updated", "iface", p.Iface, "err", err)
	}
	return sysx.SetActivePath(ctx, runner, cfg.Overlay.RoutePrefix(), cfg.Overlay.FrontendIP, p.Iface)
}

// dropSupersededHostRoute removes the /32 to the backend once overlay.subnet
// has widened what this agent installs.
//
// `ip route replace` writes the new prefix and leaves the old one behind, and
// the old one is more specific - so on a site that has been running, setting a
// subnet would leave the backend pinned to whichever tunnel was active at the
// moment of the change, while every failover afterwards moved only the range.
// Nothing would report it: probes and the control channel are steered into
// their own tables by fwmark, so all three paths would go on measuring
// perfectly while published traffic went down a tunnel that was no longer
// carrying anything.
//
// Only in the widening direction. Removing a subnet later leaves a range this
// cannot identify - it does not know what the previous value was - and that
// case is a deliberate operator action on a config file, not an upgrade that
// happens to somebody.
func (e *Engine) dropSupersededHostRoute(ctx context.Context, cfg model.Config, real, gated sysx.Runner) {
	if cfg.Overlay.Subnet == "" || !gated.Applying() {
		return
	}
	host := cfg.Overlay.BackendIP + "/32"
	via, err := sysx.RouteVia(ctx, real, host, 0)
	if err != nil || via == "" {
		return
	}
	if err := sysx.DeleteRoute(ctx, gated, host); err != nil {
		e.log.Error("could not remove the superseded host route to the backend",
			"route", host, "via", via, "err", err)
		_ = e.st.AddEvent(store.EventSystem, 0,
			"could not remove the superseded %s route via %s: %v", host, via, err)
		return
	}
	e.log.Warn("removed the superseded host route to the backend",
		"route", host, "was", via, "now", cfg.Overlay.RoutePrefix())
	_ = e.st.AddEvent(store.EventSystem, 0,
		"removed the superseded %s route; %s now carries published traffic",
		host, cfg.Overlay.RoutePrefix())
}

// commitSwitch records a switch that the kernel has already accepted.
func (e *Engine) commitSwitch(ctx context.Context, cfg model.Config, chosen, prev int, now time.Time) {
	e.mu.Lock()
	e.active = chosen
	e.decisionSeq++
	e.lastSwitch = now
	for id, pr := range e.probers {
		pr.SetActive(id == chosen)
		// Carry the decision to the backend now, on every tunnel, rather than
		// on whichever standby ticker fires first. Until it lands the backend
		// is still answering down the path that was just abandoned.
		pr.Nudge()
	}
	seq := e.decisionSeq
	applying := e.runner.Applying()
	e.mu.Unlock()

	p, _ := cfg.PathByID(chosen)
	prevName := "none"
	if pc, ok := cfg.PathByID(prev); ok {
		prevName = pc.Name
	}
	mode := ""
	if !applying {
		mode = " (observe mode, not applied)"
	}
	e.log.Info("active path changed", "from", prevName, "to", p.Name, "seq", seq, "applied", applying)
	_ = e.st.AddEvent(store.EventSwitch, chosen, "switched %s -> %s%s", prevName, p.Name, mode)
	e.notifier.Send(ctx, notify.KindSwitch, fmt.Sprintf("switch:%d", chosen),
		fmt.Sprintf("Path switched to %s", p.Name),
		fmt.Sprintf("Traffic moved from %s to %s%s.", prevName, p.Name, mode),
		notify.PriorityWarning)
}

func (e *Engine) seedActiveFromKernel(ctx context.Context) {
	e.mu.Lock()
	cfg := e.cfg
	runner := e.runner
	e.mu.Unlock()

	iface, err := sysx.ActiveIface(ctx, runner, cfg.Overlay.BackendIP)
	if err != nil || iface == "" {
		return
	}
	for _, p := range cfg.Paths {
		if p.Iface == iface {
			e.mu.Lock()
			e.active = p.ID
			e.mu.Unlock()
			e.log.Info("adopted existing route", "path", p.Name, "iface", iface)
			return
		}
	}
}

// applySystemConfig installs the overlay address, sysctls, probe tables and
// DNAT ruleset.
//
// The split here is deliberate. Measurement plumbing is installed for real even
// in observe mode, because observing requires measuring: without the overlay
// address the probe sockets cannot bind, and without the per-path tables and
// fwmark rules every probe follows the single active route, so all three paths
// would be testing the same tunnel and the observation would be worthless.
//
// None of it moves traffic. The per-path tables are consulted only for packets
// this agent marks, and the overlay address is inert until something routes to
// it. What observe mode does suppress is the two things that do move traffic:
// the main-table route to the backend, and the DNAT ruleset.
func (e *Engine) applySystemConfig(ctx context.Context) {
	// Against evaluate and reconcileRouting, which write the same routes from
	// Run's goroutine. See applyMu.
	e.applyMu.Lock()
	defer e.applyMu.Unlock()

	e.mu.RLock()
	cfg := e.cfg
	gated := e.runner
	e.mu.RUnlock()

	real := e.realRunner()

	if err := sysx.EnsureOverlayAddress(ctx, real, cfg.Overlay.FrontendIP, cfg.Overlay.Device); err != nil {
		e.log.Error("cannot establish the overlay address; no path can be probed without it",
			"address", cfg.Overlay.FrontendIP, "device", cfg.Overlay.Device, "err", err)
		_ = e.st.AddEvent(store.EventSystem, 0, "overlay address %s unavailable: %v", cfg.Overlay.FrontendIP, err)
	}

	ifaces := make([]string, 0, len(cfg.Paths))
	for _, p := range cfg.Paths {
		ifaces = append(ifaces, p.Iface)
	}
	sysx.EnsureSysctls(ctx, real, ifaces)

	if err := sysx.EnsureProbeRoutes(ctx, real, cfg.Paths, cfg.Overlay.BackendIP, cfg.Overlay.FrontendIP); err != nil {
		e.log.Warn("probe routing setup incomplete", "err", err)
		_ = e.st.AddEvent(store.EventSystem, 0, "probe routing incomplete: %v", err)
	}

	// Seed the control-channel route before any decision has been made, using
	// the first tunnel that exists. The backend dials in as soon as it starts,
	// which is usually long before the frontend has chosen a path.
	e.mu.RLock()
	active := e.active
	e.mu.RUnlock()
	if active == 0 {
		for _, p := range cfg.Paths {
			if sysx.IfaceExists(p.Iface) {
				if err := sysx.EnsureControlRoute(ctx, real, cfg.Overlay.RoutePrefix(),
					cfg.Overlay.BackendIP, cfg.Overlay.FrontendIP, p.Iface); err != nil {
					e.log.Warn("control-channel route not seeded", "iface", p.Iface, "err", err)
				} else {
					e.log.Info("seeded control-channel route", "iface", p.Iface)
				}
				break
			}
		}
	}

	// Re-assert the route for the path already in use.
	//
	// evaluate() installs a route only when the choice changes, which is right
	// for a decision loop but wrong here: arming a running system changes the
	// runner, not the choice, so nothing would install the main-table route.
	// The DNAT rules would go in while the kernel still had no route to the
	// backend, every published packet would follow the default route out the
	// public interface, and every connection would hang. This uses the gated
	// runner, so observe mode still installs nothing.
	e.mu.RLock()
	current := e.active
	e.mu.RUnlock()
	if p, ok := cfg.PathByID(current); ok {
		if err := e.applyActivePath(ctx, p); err != nil {
			e.log.Error("cannot reinstall the route for the active path", "path", p.Name, "err", err)
			_ = e.st.AddEvent(store.EventSystem, current, "could not reinstall route via %s: %v", p.Iface, err)
		}
	}
	e.dropSupersededHostRoute(ctx, cfg, real, gated)

	// Published traffic is forwarded, so a drop-policy forward chain owned by
	// something else - Docker installs one - discards it no matter how correct
	// the DNAT and routing are. This installs nothing when there is no such
	// chain, and moves no traffic by itself: without the DNAT ruleset there is
	// nothing to forward.
	if err := sysx.EnsureForwardExceptions(ctx, real, cfg.Overlay.MatchPrefix()); err != nil {
		e.log.Warn("could not add forward exceptions; published traffic may be dropped", "err", err)
		_ = e.st.AddEvent(store.EventSystem, 0, "forward exceptions not installed: %v", err)
	} else if sysx.ForwardIsBlocked(ctx, real) {
		e.log.Warn("something on this host drops forwarded traffic by default; " +
			"published services depend on the agent's exceptions staying in place")
	}

	// Publishing services does move traffic, so it respects observe mode.
	if _, err := sysx.ApplyRuleset(ctx, gated, e.stateDir, sysx.BuildRuleset(cfg)); err != nil {
		e.log.Error("failed to apply nftables ruleset", "err", err)
		_ = e.st.AddEvent(store.EventSystem, 0, "nftables apply failed: %v", err)
	} else if gated.Applying() {
		e.mu.Lock()
		e.dataPlane = true
		e.mu.Unlock()
	}

	e.applyEgress(ctx, cfg, gated, real)
	e.applyProtect(ctx, cfg, gated, real)
	e.applyShaping(ctx, cfg, gated)
}

// applyShaping installs the queue discipline on each tunnel this end sends into.
//
// Gated by mode. A shaper does not misdirect traffic the way a route does, but
// it does decide what gets dropped and when, and observe mode's promise is that
// nothing the agent does can be felt by a player.
//
// Removal is as important as installation and is why a rate of zero is passed
// through rather than skipped: a shaper is generated from configuration, so
// turning it off produces nothing to install, which would leave the previous
// rate in place with nothing in the portal to explain it.
func (e *Engine) applyShaping(ctx context.Context, cfg model.Config, gated sysx.Runner) {
	for _, p := range cfg.Paths {
		if !e.ifaceExists(p.Iface) {
			continue
		}
		changed, err := sysx.EnsureQdisc(ctx, gated, p.Iface, p.Shape.ToBackendMbit)
		if err != nil {
			e.log.Error("cannot shape this tunnel; traffic is unshaped in this direction",
				"path", p.Name, "iface", p.Iface, "mbit", p.Shape.ToBackendMbit, "err", err,
				"hint", "needs the sch_cake module: modprobe sch_cake")
			_ = e.st.AddEvent(store.EventSystem, p.ID, "could not shape %s: %v", p.Iface, err)
			continue
		}
		if changed && gated.Applying() {
			if p.Shape.ToBackendMbit > 0 {
				e.log.Info("tunnel shaped", "path", p.Name, "iface", p.Iface, "mbit", p.Shape.ToBackendMbit)
			} else {
				e.log.Info("tunnel shaping removed", "path", p.Name, "iface", p.Iface)
			}
		}
	}
}

// applyProtect installs or removes the edge filtering table.
//
// Removal has to be explicit, as with the egress NAT: a disabled feature
// renders an empty ruleset, and an empty ruleset loads nothing at all rather
// than replacing what is there. Without the removal, unticking the master
// switch would leave every limit running.
func (e *Engine) applyProtect(ctx context.Context, cfg model.Config, gated, real sysx.Runner) {
	ruleset := sysx.BuildProtectRuleset(sysx.ProtectSpecFrom(cfg))
	if ruleset == "" {
		if cfg.Protect.Enabled && cfg.Frontend.PublicIface == "" {
			e.log.Warn("protection is enabled but cannot be applied; set the frontend's public interface")
			_ = e.st.AddEvent(store.EventSystem, 0,
				"protection not applied: the frontend has no public interface configured")
		}
		sysx.RemoveProtectRuleset(ctx, real)
		e.mu.Lock()
		e.protectOn = false
		e.protectApplied = ""
		// The samples describe rules that no longer exist; kept, they would
		// be served again the moment protection is re-armed, for up to one
		// sample tick - an engaged-lock alert for a lock not in the kernel.
		e.protectCounters, e.protectBlocked, e.protectGeoLocked = nil, nil, nil
		e.mu.Unlock()
		return
	}
	// An unchanged ruleset is not reloaded. The reload resets the counters,
	// unparks every blocked source and releases every engaged region lock, so
	// a save that did not touch protection must not pay it - a settings save
	// mid-flood would otherwise let the whole flood back in at once. Only a
	// ruleset this process really loaded counts: observe mode and a failed
	// apply both leave the latch empty, and sampleProtect drops it when the
	// kernel stops answering for the table.
	armed := gated.Applying()
	e.mu.Lock()
	unchanged := armed && e.protectOn && e.protectApplied == ruleset
	e.mu.Unlock()
	if unchanged {
		return
	}
	if _, err := sysx.ApplyProtectRuleset(ctx, gated, e.stateDir, ruleset); err != nil {
		e.log.Error("failed to apply the protection ruleset", "err", err)
		_ = e.st.AddEvent(store.EventSystem, 0, "protection apply failed: %v", err)
		e.mu.Lock()
		e.protectApplied = ""
		e.mu.Unlock()
		return
	}
	e.mu.Lock()
	e.protectOn = armed
	if armed {
		e.protectApplied = ruleset
	} else {
		e.protectApplied = ""
	}
	e.mu.Unlock()
	if armed {
		e.log.Info("edge protection active", "iface", cfg.Frontend.PublicIface)
	}
}

// samplePeerEndpoints records where each tunnel's peer is currently seen, and
// says so when two of them are the same address.
//
// This is the only direct check on the one thing this system depends on and
// cannot arrange for itself: that pfSense pinned each tunnel to its own WAN.
// When it has not - a gateway group instead of a single gateway, or gateway
// monitoring withdrawing a policy route so the traffic falls through to the
// default - two tunnels ride one link. Nothing else notices. Every probe
// succeeds, every path reads healthy, and the failover has nothing to fail over
// to, which is discovered at the exact moment it is needed.
//
// Logged on change rather than every tick: the address is stable for weeks at a
// time, and a warning repeated every five seconds is one nobody reads.
func (e *Engine) samplePeerEndpoints(ctx context.Context) {
	ends := sysx.PeerEndpoints(ctx, e.realRunner())

	e.mu.Lock()
	byPath := map[int]string{}
	hosts := map[string][]string{} // endpoint address -> path names sharing it
	for _, p := range e.cfg.Paths {
		ep, ok := ends[p.Iface]
		if !ok {
			continue
		}
		byPath[p.ID] = ep
		if host := sysx.EndpointHost(ep); host != "" {
			hosts[host] = append(hosts[host], p.Name)
		}
	}
	e.peerEndpoints = byPath

	var shared []model.SharedEndpoint
	var clashes []string
	for host, names := range hosts {
		if len(names) > 1 {
			sort.Strings(names)
			shared = append(shared, model.SharedEndpoint{Address: host, Paths: names})
			clashes = append(clashes, strings.Join(names, "+")+" at "+host)
		}
	}
	sort.Slice(shared, func(i, j int) bool { return shared[i].Address < shared[j].Address })
	e.sharedEndpoints = shared
	sort.Strings(clashes)
	signature := strings.Join(clashes, ", ")
	changed := signature != e.endpointClash
	e.endpointClash = signature
	e.mu.Unlock()

	if !changed {
		return
	}
	if signature == "" {
		e.log.Info("every tunnel is on its own WAN again")
		_ = e.st.AddEvent(store.EventSystem, 0, "tunnels are on separate WANs again")
		return
	}
	e.log.Warn("tunnels are on the same WAN; they are riding one internet service",
		"paths", signature,
		"hint", "pfSense: policy-route each tunnel to a single gateway, not a gateway group, "+
			"and disable the gateway monitoring action")
	_ = e.st.AddEvent(store.EventSystem, 0,
		"tunnels are on the same WAN (%s): one internet service under both, so a failover between them has nowhere to go", signature)
}

// sampleProtect reads the counters and the blocklist back out of the kernel.
//
// Read on a timer rather than accumulated, because the numbers live in the
// rules and a reload resets them. Skipped entirely when nothing is installed,
// so an ordinary site never runs `nft` for this.
func (e *Engine) sampleProtect(ctx context.Context) {
	e.mu.RLock()
	on := e.protectOn
	e.mu.RUnlock()
	if !on {
		return
	}
	counters, blocked, locked, err := sysx.ProtectState(ctx, e.realRunner())
	if err != nil {
		e.log.Debug("cannot read protection state", "err", err)
		// The table may be gone underneath the agent - flushed by hand, or
		// nft restarted. Dropping the reload latch makes the next save load
		// the ruleset again instead of skipping it as unchanged; a transient
		// read failure costs one reload, which was every save's price before
		// the latch existed.
		e.mu.Lock()
		e.protectApplied = ""
		e.mu.Unlock()
		return
	}
	e.mu.Lock()
	e.protectCounters = counters
	e.protectBlocked = blocked
	e.protectGeoLocked = locked
	e.mu.Unlock()
}

// applyEgress installs or removes the source NAT that makes traffic the backend
// originates leave by the frontend's public address.
//
// Turning it off has to actively remove both halves. The ruleset is generated
// from config, so a disabled feature simply produces nothing to load - which
// would leave the previous table in place, still translating, with nothing in
// the configuration to explain it.
func (e *Engine) applyEgress(ctx context.Context, cfg model.Config, gated, real sysx.Runner) {
	ruleset := sysx.BuildEgressRuleset(cfg)
	if ruleset == "" {
		if cfg.Frontend.BackendEgress {
			e.log.Warn("backend egress is enabled but cannot be applied; set the frontend's public interface")
			_ = e.st.AddEvent(store.EventSystem, 0,
				"backend egress not applied: the frontend has no public interface configured")
		}
		sysx.RemoveEgressRuleset(ctx, real)
		sysx.RemoveEgressForwardException(ctx, real)
		return
	}

	// The exception opens the forward path but moves nothing on its own - there
	// is no route out for the backend's overlay address without the NAT below -
	// so it goes in with the real runner, like the published exceptions.
	if err := sysx.EnsureEgressForwardException(ctx, real, cfg.Overlay.MatchPrefix()); err != nil {
		e.log.Warn("egress forward exception not installed; backend-originated traffic may be dropped", "err", err)
	}

	// The NAT itself rewrites live traffic, so it respects observe mode.
	if _, err := sysx.ApplyEgressRuleset(ctx, gated, e.stateDir, ruleset); err != nil {
		e.log.Error("failed to apply the backend egress ruleset", "err", err)
		_ = e.st.AddEvent(store.EventSystem, 0, "backend egress apply failed: %v", err)
		return
	}
	if gated.Applying() {
		e.log.Info("backend egress active; traffic from the backend overlay leaves via the public address",
			"iface", cfg.Frontend.PublicIface, "address", cfg.Frontend.PublicIP)
	}
}

// reconcileRouting repairs routing the kernel discarded behind the agent's
// back, and is what makes a restarted tunnel usable again.
//
// Deleting an interface takes every route that used it with it - and deleting
// the interface is exactly what `wg-quick down` does. Bringing the tunnel back
// up does not bring the routes back, and nothing else ever reinstalls them:
// applySystemConfig runs at startup and on a configuration change only. So
// after `systemctl restart wg-quick@wg-main` that path's probe table is empty,
// its probes no longer have a route out of their own tunnel, and it reads as
// permanently down however healthy the link is. The same purge takes out the
// control-channel route and the main-table route to the backend when the
// tunnel they use is the one restarted.
//
// It only ever repairs a route the kernel has actually lost or pointed
// somewhere unexpected, so a healthy system issues nothing but `ip route show`
// every ten seconds. Observe mode is still honoured for the one route that
// moves traffic.
func (e *Engine) reconcileRouting(ctx context.Context) {
	// Shares Run's goroutine with evaluate, so this is only ever contended
	// against applySystemConfig and Revert. See applyMu.
	e.applyMu.Lock()
	defer e.applyMu.Unlock()

	e.mu.RLock()
	cfg := e.cfg
	gated := e.runner
	active := e.active
	reverted := e.reverted
	e.mu.RUnlock()

	// After a revert there is nothing to repair: what looks missing is missing
	// because the operator removed it, and this loop putting the probe tables
	// and rp_filter back within a tick is exactly what let an uninstall strand
	// them. Read after taking applyMu, so a Revert holding the lock is seen the
	// moment it releases. Reconfigure clears the latch.
	if reverted {
		return
	}

	real := e.realRunner()

	for _, p := range cfg.Paths {
		// A tunnel that is still down is not a repair, it is a path that is
		// down. EnsureProbeRoute would only fail, noisily, once per tick.
		if !e.ifaceExists(p.Iface) {
			continue
		}

		// Checked every tick, not only when a route is missing: rp_filter
		// belongs to the interface, so a recreated tunnel comes back with the
		// system default (2) however correct its routing is.
		if changed, err := sysx.RPFilterOff(ctx, real, p.Iface); err != nil {
			e.log.Warn("cannot read reverse-path filtering", "iface", p.Iface, "err", err)
		} else if changed {
			e.log.Warn("reverse-path filtering was back on after the tunnel was recreated; disabled it",
				"path", p.Name, "iface", p.Iface)
			_ = e.st.AddEvent(store.EventSystem, p.ID,
				"disabled reverse-path filtering on %s, which %s reset when it was recreated", p.Iface, p.Name)
		}

		// The queue discipline belongs to the interface exactly as rp_filter
		// does, and `wg-quick down` deletes the interface: the shaper is gone
		// and nothing says so. Traffic keeps flowing, unshaped, and the only
		// symptom is that latency under load quietly gets worse again.
		e.reconcileShaping(ctx, gated, p)

		via, err := sysx.RouteVia(ctx, real, cfg.Overlay.BackendIP+"/32", p.Table)
		if err != nil || via == p.Iface {
			continue
		}
		if err := sysx.EnsureProbeRoute(ctx, real, p, cfg.Overlay.BackendIP, cfg.Overlay.FrontendIP); err != nil {
			e.log.Error("cannot restore probe routing; this path cannot be measured",
				"path", p.Name, "iface", p.Iface, "err", err)
			continue
		}
		e.log.Warn("restored probe routing lost when the tunnel was recreated",
			"path", p.Name, "iface", p.Iface, "was", via)
		_ = e.st.AddEvent(store.EventSystem, p.ID,
			"restored probe routing for %s after %s was recreated", p.Name, p.Iface)
	}

	ap, ok := cfg.PathByID(active)
	if !ok || !e.ifaceExists(ap.Iface) {
		return
	}

	// The control channel is source-selected and carries no published traffic,
	// so it is repaired in observe mode too - losing it is what makes the
	// backend look permanently unreachable in the portal.
	//
	// Read back by the prefix that was installed, never by an address inside
	// it: `ip route show` filters on an exact prefix, so asking about the
	// backend's /32 on a site with a subnet answers "no route" on every tick
	// and reinstalls what is already there. Invariant 20.
	if via, err := sysx.RouteVia(ctx, real, cfg.Overlay.RoutePrefix(), sysx.ControlTable); err == nil && via != ap.Iface {
		if err := sysx.EnsureControlRoute(ctx, real, cfg.Overlay.RoutePrefix(),
			cfg.Overlay.BackendIP, cfg.Overlay.FrontendIP, ap.Iface); err != nil {
			e.log.Warn("cannot restore the control-channel route", "iface", ap.Iface, "err", err)
		} else {
			e.log.Warn("restored the control-channel route", "iface", ap.Iface, "was", via)
		}
	}

	// The route below is the failover action itself, so observe mode must not
	// install it - in observe mode there is deliberately no route to restore.
	if !gated.Applying() {
		return
	}
	if via, err := sysx.RouteVia(ctx, real, cfg.Overlay.RoutePrefix(), 0); err == nil && via != ap.Iface {
		if err := sysx.SetActivePath(ctx, gated,
			cfg.Overlay.RoutePrefix(), cfg.Overlay.FrontendIP, ap.Iface); err != nil {
			e.log.Error("cannot restore the route to the backend", "iface", ap.Iface, "err", err)
			_ = e.st.AddEvent(store.EventSystem, active,
				"could not restore the route via %s: %v", ap.Iface, err)
		} else {
			e.log.Warn("restored the route to the backend", "iface", ap.Iface, "was", via)
			_ = e.st.AddEvent(store.EventSystem, active,
				"restored the route to the backend via %s after it was lost", ap.Iface)
		}
	}

	// Checked here as well as on apply. A stale /32 left by a subnet that was
	// set while the agent was stopped would otherwise sit there until the next
	// configuration save, pinning the backend to one tunnel across every
	// failover in between.
	e.dropSupersededHostRoute(ctx, cfg, real, gated)
}

// reconcileShaping puts back a queue discipline the kernel discarded with its
// interface. Silent when the path is unshaped, and silent when what is
// installed already matches, so a healthy system issues one `tc qdisc show` per
// path per tick and nothing else.
func (e *Engine) reconcileShaping(ctx context.Context, gated sysx.Runner, p model.PathConfig) {
	if p.Shape.ToBackendMbit <= 0 {
		return
	}
	changed, err := sysx.EnsureQdisc(ctx, gated, p.Iface, p.Shape.ToBackendMbit)
	if err != nil {
		e.log.Warn("cannot check tunnel shaping", "path", p.Name, "iface", p.Iface, "err", err)
		return
	}
	if changed && gated.Applying() {
		e.log.Warn("restored tunnel shaping lost when the tunnel was recreated",
			"path", p.Name, "iface", p.Iface, "mbit", p.Shape.ToBackendMbit)
		_ = e.st.AddEvent(store.EventSystem, p.ID,
			"restored shaping on %s after %s was recreated", p.Iface, p.Name)
	}
}

// realRunner always acts on the system, regardless of mode. It backs the
// measurement plumbing and the revert command.
func (e *Engine) realRunner() sysx.Runner { return e.real }

// ---------------------------------------------------------------------------
// Quota and usage
// ---------------------------------------------------------------------------

func (e *Engine) refreshQuota(now time.Time) {
	grants, err := e.st.Grants()
	if err != nil {
		e.log.Warn("cannot read grants", "err", err)
		return
	}
	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()

	e.mu.RLock()
	previous := e.quotaDec
	e.mu.RUnlock()

	decisions := map[int]quota.Decision{}
	for _, p := range cfg.Paths {
		start, _ := quota.PeriodBounds(p.Quota, now)
		used, err := e.st.Usage(p.ID, start)
		if err != nil {
			// Carry the last known verdict forward rather than omitting the
			// path. Dropping it from the map reads as "not blocked", so a
			// transient database error would quietly unblock a path that is
			// over its cap and start spending money.
			e.log.Warn("cannot read usage, keeping previous quota verdict", "path", p.Name, "err", err)
			if prev, ok := previous[p.ID]; ok {
				decisions[p.ID] = prev
			}
			continue
		}
		g, has := grants[p.ID]
		decisions[p.ID] = quota.Evaluate(p, used, g, has, now)
	}

	e.mu.Lock()
	prev := e.quotaDec
	e.quotaDec = decisions
	e.mu.Unlock()

	for id, d := range decisions {
		if d.Blocked && !prev[id].Blocked {
			p, _ := cfg.PathByID(id)
			_ = e.st.AddEvent(store.EventQuota, id, "%s blocked: %s", p.Name, d.Reason)
			e.log.Warn("path blocked by quota", "path", p.Name, "reason", d.Reason)
			e.notifier.Send(context.Background(), notify.KindQuota, fmt.Sprintf("quota:%d", id),
				fmt.Sprintf("%s is over quota", p.Name), d.Reason, notify.PriorityWarning)
		}
		if !d.Blocked && prev[id].Blocked {
			p, _ := cfg.PathByID(id)
			_ = e.st.AddEvent(store.EventQuota, id, "%s is within quota again", p.Name)
		}
	}
}

// usageSample is one raw metering delta on its way to the ledger: the counts
// as the backend reported them and the stamp it took them at, before any of
// this package's bounds or quota's conversion have been applied.
type usageSample struct {
	Bytes   int64
	Packets int64
	At      time.Time
}

// addUsageBatch records a run of metering deltas for one path and advances that
// path's dedupe watermark, all inside one transaction.
//
// Two things are resolved once for the batch rather than once per delta, and
// both were per-delta costs on the control read loop, which cannot answer a
// ping while it works. The path, because PathByID takes its receiver by value,
// so every call copied the whole configuration to read one entry. And the
// timezone, which is the more expensive of the two by orders of magnitude:
// time.LoadLocation re-parses the zoneinfo entry on every call, so a five
// hundred delta batch was five hundred tzdata parses. Every delta here belongs
// to one path and therefore to one zone.
//
// Unexported, because usageSample is: an exported method taking a type no other
// package can construct advertises a boundary that does not exist. There was an
// exported single-delta wrapper here for one commit, kept on the reasoning that
// the store's equivalent is what every test in that package drives. That
// reasoning did not transfer - no test drove this one and nothing called it -
// so it was a dead method carrying a claim about coverage it did not have.
func (e *Engine) addUsageBatch(pathID int, samples []usageSample, seqKey, seqVal string) error {
	e.mu.RLock()
	p, ok := e.cfg.PathByID(pathID)
	e.mu.RUnlock()

	if !ok || !p.Metered {
		// Nothing to account for; the deltas are discarded, and only the
		// watermark advances so the backend stops resending them.
		return e.st.SetMeta(seqKey, seqVal)
	}

	now := time.Now()
	loc := quota.Location(p.Quota)
	entries := make([]store.UsageEntry, 0, len(samples))
	for _, s := range samples {
		// Clamped here as well as inside Metered, because the two columns must
		// not be able to disagree. Metered clamps its own copy, so a negative
		// packet count produced zero metered bytes and was then handed to the
		// ledger unchanged, where it decremented the period's packet total.
		// checkDelta covers the control path, and this is an exported entry
		// point: a caller three files away is not the place its guarantees
		// live.
		bytes, packets, _ := clampCounts(s.Bytes, s.Packets)
		// The stamp too, for the reason the counts are. PeriodBounds takes
		// whatever it is handed, and a stamp outside the window puts the bytes
		// in a period nothing ever reads while the current one stays at zero
		// and the quota never trips.
		//
		// One test for both directions, and clamped to now rather than to
		// either edge, which is what checkDelta does with the same value. The
		// first version of this guard clamped to now+skew and tested only
		// at.After, so it caught nothing at all: an overflowed time.Unix
		// compares as *before* now whichever end it came from, an ordinary
		// stale stamp is in the past, and clamping a genuine future stamp to
		// now+skew can still land it in the next billing period when the batch
		// is processed near a reset day.
		//
		// The shape differs from checkDelta's deliberately. That one holds the
		// raw int64 and has to name the direction in a log, so it compares
		// seconds, which do not wrap. Here the seconds are already
		// unrecoverable - a time.Time built from an overflowing value does not
		// report it back - and there is no message to get right, only a value
		// to refuse. Both extremes land on the same side of this comparison, so
		// one test covers them.
		at := s.At
		if at.After(now.Add(maxDeltaSkew)) || at.Before(now.Add(-maxDeltaAge)) {
			at = now
		}
		start, _ := quota.PeriodBoundsIn(p.Quota, loc, at)
		entries = append(entries, store.UsageEntry{
			PeriodStart: start,
			At:          at,
			Bytes:       quota.Metered(bytes, packets, p.Quota),
			Packets:     packets,
		})
	}
	if err := e.st.AddUsageBatch(pathID, entries, seqKey, seqVal); err != nil {
		e.log.Warn("cannot record usage", "path", p.Name, "deltas", len(entries), "err", err)
		return err
	}
	return nil
}

// reportQuotaSubstitutions says out loud where a stored configuration carries a
// quota multiplier quota.Metered will refuse to use.
//
// The two bounds on those multipliers are enforced in two places and neither
// covers this one. web.validate rejects an out-of-range value with a message an
// operator can act on, and it runs only on PUT /api/config. Metered clamps
// whatever it is handed, silently, because there is nobody at a socket to tell.
// Between them sits the config blob: it is unmarshalled by store.LoadConfig,
// model.Normalise does not touch Quota, and nothing re-validates it, so a value
// stored by an older build is never seen by either.
//
// That gap is not cosmetic, because MinCalibration is newer than the field it
// bounds. A site that saved 5 under a build whose only rule was "above zero"
// went on billing at 5% until this change and bills at 100% after it, a factor
// of twenty, from one restart to the next with nothing anywhere saying so. The
// portal does refuse the next save and name the path, which is the other half
// of the story and no use at all until somebody opens the form.
//
// It reports rather than repairs, deliberately. Metered already substitutes, so
// rewriting the stored blob would change no billing and would take away the
// save-time error that is how an operator learns which figure to correct.
//
// Anything at or below zero is not reported, not just zero itself. validate
// runs `if Calibration <= 0 { = 100 }` before its range check, so a stored -5
// saves cleanly and means 100 everywhere, exactly as an unset value does. The
// first version of this tested `cal != 0` and so fired on it with a hint saying
// the settings form would refuse to save, which is the one thing that is not
// true of it: an operator following that line finds the form saving fine and no
// field out of range. A zero overhead is a real setting and is left alone for
// the same reason from the other side.
func reportQuotaSubstitutions(log *slog.Logger, cfg model.Config) {
	for _, p := range cfg.Paths {
		// NaN outside the ordered test rather than inside it. Every ordered
		// comparison against NaN is false, so `cal > 0` short-circuits and the
		// IsNaN branch beside it is never evaluated: written as one condition,
		// tightening the guard from `!= 0` to `> 0` silently made the NaN case
		// unreachable, and a NaN is exactly what Metered turns into 100 with
		// nothing said. It is the ordering trap this whole function exists to
		// report, reintroduced inside the report.
		cal := p.Quota.Calibration
		if math.IsNaN(cal) || (cal > 0 && (cal < quota.MinCalibration || cal > quota.MaxCalibration)) {
			log.Warn("stored calibration is outside the range this build accepts; billing at 100% instead",
				"path", p.Name, "stored", cal, "billing_at", 100.0,
				"min", quota.MinCalibration, "max", quota.MaxCalibration,
				"hint", "every metered byte on this path is now billed differently than it was. Set a calibration inside the range in the portal; until you do, the settings form refuses to save")
		}
		if o := p.Quota.OverheadPerPacket; o < 0 || o > quota.MaxOverheadPerPacket {
			log.Warn("stored per-packet overhead is outside the range this build accepts; clamping it",
				"path", p.Name, "stored", o, "max", quota.MaxOverheadPerPacket,
				"hint", "WireGuard, UDP and IP together come to about 60 bytes")
		}
	}
}

// SetHandshakeAges records the backend's tunnel report.
func (e *Engine) SetHandshakeAges(ages map[int]float64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, age := range ages {
		if tr := e.trackers[id]; tr != nil {
			tr.SetHandshakeAge(age)
		}
	}
}

// SetBackendUp registers or releases a control connection.
//
// It counts rather than sets, because a reconnecting backend briefly has two
// connections: the new one authenticates before the old one's teardown runs.
// With a plain boolean the stale teardown would clear the flag and, since it is
// only raised at connect time, the portal would report the backend unreachable
// until the next reconnect.
func (e *Engine) SetBackendUp(up bool) {
	e.mu.Lock()
	if up {
		e.backendConns++
	} else if e.backendConns > 0 {
		e.backendConns--
	}
	nowUp := e.backendConns > 0
	changed := e.backendUp != nowUp
	e.backendUp = nowUp
	e.mu.Unlock()
	if changed {
		if nowUp {
			_ = e.st.AddEvent(store.EventSystem, 0, "backend control channel connected")
		} else {
			_ = e.st.AddEvent(store.EventSystem, 0, "backend control channel lost")
		}
	}
}

// SetBackendInfo records what the backend reported about itself at connect.
func (e *Engine) SetBackendInfo(version, hostname string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.backendVersion = version
	e.backendHost = hostname
}

// linkerConn is one connected extra host.
type linkerConn struct {
	version  string
	hostname string
	table    int
	since    time.Time
	session  uint64
}

// metaLinkerSeen is the store key holding one host's last-contact stamp.
func metaLinkerSeen(overlayIP string) string { return "linker_seen:" + overlayIP }

// linkerSeenPersistEvery bounds how stale the on-disk stamp can be. The value
// is refreshed in memory every keepalive; writing it out that often to record
// something nobody reads until the host goes quiet is not worth the database
// traffic, and being five minutes pessimistic about a host that has been silent
// for hours changes nothing an operator would do.
const linkerSeenPersistEvery = 5 * time.Minute

// SetLinkerUp records that a linker has authenticated and identified itself,
// and returns the session number its teardown must quote.
func (e *Engine) SetLinkerUp(overlayIP, version, hostname string, table int) uint64 {
	now := time.Now()
	e.mu.Lock()
	e.linkerSession++
	session := e.linkerSession
	e.linkers[overlayIP] = linkerConn{
		version: version, hostname: hostname, table: table, since: now, session: session,
	}
	e.linkerSeen[overlayIP] = now
	e.mu.Unlock()
	e.persistLinkerSeen(overlayIP, now, true)
	return session
}

// MarkLinkerSeen records that a frame arrived from an extra host.
//
// Called for every frame, keepalive answers included, so last contact means the
// last time bytes actually arrived rather than the last time a connection was
// established. A session can sit open for weeks; the two are not the same
// question, and only this one distinguishes a host that is talking from one
// whose connection nobody has noticed is dead yet.
func (e *Engine) MarkLinkerSeen(overlayIP string) {
	now := time.Now()
	e.mu.Lock()
	e.linkerSeen[overlayIP] = now
	e.mu.Unlock()
	e.persistLinkerSeen(overlayIP, now, false)
}

// SetLinkerDown releases a linker's control connection.
//
// Keyed on the session that is ending, not merely on the address. A linker
// whose TCP connection dies silently - which is what a failover looks like from
// up here - redials and authenticates while the old session is still parked on
// its read deadline, and the teardown that follows would otherwise delete the
// entry the new one had just made. The portal would then show a healthy host as
// disconnected indefinitely, because the host has a working channel and no
// reason to dial again. Same fault the backend's connection count exists for.
func (e *Engine) SetLinkerDown(overlayIP string, session uint64) {
	e.mu.Lock()
	c, ok := e.linkers[overlayIP]
	if !ok || c.session != session {
		e.mu.Unlock()
		return
	}
	delete(e.linkers, overlayIP)
	last := e.linkerSeen[overlayIP]
	e.mu.Unlock()

	// Write the final stamp out unthrottled: this is the value the portal will
	// be reporting from now on, and the next chance to save it is the host
	// coming back.
	if !last.IsZero() {
		e.persistLinkerSeen(overlayIP, last, true)
	}
}

// persistLinkerSeen records the stamp in the store, so a host that was already
// silent before a frontend restart still reports when it was last heard from
// rather than reading as one that has never connected at all - a different
// fault, with a different thing to go and check.
func (e *Engine) persistLinkerSeen(overlayIP string, at time.Time, force bool) {
	if e.st == nil {
		return
	}
	e.mu.Lock()
	saved, ok := e.linkerSaved[overlayIP]
	due := force || !ok || at.Sub(saved) >= linkerSeenPersistEvery
	if due {
		e.linkerSaved[overlayIP] = at
	}
	e.mu.Unlock()
	if !due {
		return
	}
	if err := e.st.SetMeta(metaLinkerSeen(overlayIP), at.UTC().Format(time.RFC3339)); err != nil {
		e.log.Warn("could not record linker last-contact time", "overlay", overlayIP, "err", err)
	}
}

// loadLinkerSeen recovers the stamps written by a previous run. Called from New,
// where the configuration is already in hand and nothing else is running yet.
func (e *Engine) loadLinkerSeen() {
	if e.st == nil {
		return
	}
	for _, l := range e.cfg.Linkers {
		v := e.st.Meta(metaLinkerSeen(l.OverlayIP))
		if v == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			continue
		}
		e.linkerSeen[l.OverlayIP] = t
		e.linkerSaved[l.OverlayIP] = t
	}
}

// LinkerConfigFor returns what one linker should be told.
//
// Only that host's own networks. The same bridge subnet exists on every machine
// Docker is installed on, so a row belongs to exactly one host and sending the
// list unfiltered would have each linker pulling containers onto the tunnel
// that belong to a different box - silently, and through the metered link.
func (e *Engine) LinkerConfigFor(overlayIP string) proto.LinkerConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var out proto.LinkerConfig
	if !e.cfg.Frontend.BackendEgress {
		// Same gate as the backend's: without the frontend's source NAT waiting
		// at the other end, pulling a network onto the overlay sends its traffic
		// somewhere it cannot be answered.
		return out
	}
	for _, s := range e.cfg.Egress.Sources {
		if s.Enabled && s.CIDR != "" && s.Host == overlayIP {
			out.EgressCIDRs = append(out.EgressCIDRs, s.CIDR)
		}
	}
	return out
}

// KnownBackend reports whether a control connection from this address is the
// backend's.
//
// The companion to KnownLinker, and it exists for the same reason: a peer's
// role arrives in its own Hello, and every host in the deployment holds the
// identical key. Without this the linker branch was checked and the backend
// branch was not, so omitting one JSON field was enough to be served as the
// backend and to write to the usage ledger.
//
// An address rather than a second credential because the backend already
// proves this for free: Agent.controlSession binds its socket to the overlay
// address, so a connection from anywhere else is not the backend whatever it
// says. Empty is refused rather than treated as "any", which cannot happen on
// a loaded configuration - LoadBootstrap defaults and then parses the field -
// but must not read as a wildcard if it ever does.
func (e *Engine) KnownBackend(host string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg.Overlay.BackendIP != "" && host == e.cfg.Overlay.BackendIP
}

// HasPath reports whether the running configuration holds this path id.
//
// Deliberately not "is this id in range": a configuration the portal accepted
// before the range existed is still a configuration this frontend is routing
// and metering, and its deltas have to keep reaching the ledger.
func (e *Engine) HasPath(id int) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, ok := e.cfg.PathByID(id)
	return ok
}

// BackendOverlayIP is the address the backend is expected to connect from.
//
// A field accessor rather than a Config() call at the one site that wants it:
// Config copies the whole configuration - every path, service, region, linker
// and egress row - under the state lock, and the caller is a refusal log on a
// path whose rate a peer chooses.
func (e *Engine) BackendOverlayIP() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg.Overlay.BackendIP
}

// KnownLinker reports whether this overlay address is a configured, enabled
// linker. The shared secret proves a peer belongs to this deployment, not that
// it is entitled to a particular address, so the address is checked against the
// configuration rather than taken on trust.
func (e *Engine) KnownLinker(overlayIP string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, l := range e.cfg.Linkers {
		if l.Enabled && l.OverlayIP == overlayIP {
			return true
		}
	}
	return false
}

func (e *Engine) persistSamples(now time.Time) {
	e.mu.RLock()
	if e.reverted {
		// The probers are stopped, so the trackers are frozen at whatever they
		// last saw. Writing that out every five seconds would draw a flat,
		// healthy-looking line over a window in which nothing was measured;
		// a gap in the graph is the honest record.
		e.mu.RUnlock()
		return
	}
	snaps := make([]model.PathState, 0, len(e.trackers))
	for _, tr := range e.trackers {
		snaps = append(snaps, tr.Snapshot(now))
	}
	e.mu.RUnlock()
	for _, s := range snaps {
		if err := e.st.AddPathSample(s.ID, now, s.RTTms, s.LossPct, s.JitterMs, s.Health); err != nil {
			e.log.Debug("cannot record path sample", "path", s.Name, "err", err)
		}
	}
}

// ---------------------------------------------------------------------------
// Operator actions
// ---------------------------------------------------------------------------

// Approve grants time-boxed permission to use an over-quota path.
//
// The grant expires on purpose. A single approval at 2am must not quietly
// disable quota enforcement for the rest of the month.
func (e *Engine) Approve(pathID int, dur time.Duration, extraBytes int64) error {
	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()

	p, ok := cfg.PathByID(pathID)
	if !ok {
		return fmt.Errorf("unknown path %d", pathID)
	}
	now := time.Now()
	start, _ := quota.PeriodBounds(p.Quota, now)
	used, err := e.st.Usage(pathID, start)
	if err != nil {
		return err
	}
	g := store.Grant{
		PathID:     pathID,
		Until:      now.Add(dur).Unix(),
		ExtraBytes: extraBytes,
		StartBytes: used,
	}
	if err := e.st.SetGrant(g); err != nil {
		return err
	}
	limit := "no byte limit"
	if extraBytes > 0 {
		limit = quota.HumanBytes(extraBytes) + " extra"
	}
	_ = e.st.AddEvent(store.EventGrant, pathID, "overage approved on %s for %s (%s)", p.Name, dur, limit)
	e.log.Warn("overage approved", "path", p.Name, "duration", dur, "extra_bytes", extraBytes)
	e.refreshQuota(now)
	e.wakeDecision()
	return nil
}

// RevokeApproval cancels an overage grant.
func (e *Engine) RevokeApproval(pathID int) error {
	if err := e.st.ClearGrant(pathID); err != nil {
		return err
	}
	_ = e.st.AddEvent(store.EventGrant, pathID, "overage approval revoked")
	e.refreshQuota(time.Now())
	e.wakeDecision()
	return nil
}

// Pin forces a path regardless of priority. Pass 0 to return to automatic
// selection.
func (e *Engine) Pin(pathID int) error {
	e.mu.Lock()
	if pathID != 0 {
		if _, ok := e.cfg.PathByID(pathID); !ok {
			e.mu.Unlock()
			return fmt.Errorf("unknown path %d", pathID)
		}
	}
	e.pinned = pathID
	e.mu.Unlock()

	if pathID == 0 {
		_ = e.st.AddEvent(store.EventSystem, 0, "pin cleared, automatic selection resumed")
	} else {
		_ = e.st.AddEvent(store.EventSystem, pathID, "path pinned by operator")
	}
	e.wakeDecision()
	return nil
}

// ClearQuarantine lifts the circuit breaker on a path.
func (e *Engine) ClearQuarantine(pathID int) {
	e.mu.Lock()
	if tr := e.trackers[pathID]; tr != nil {
		tr.ClearQuarantine()
	}
	e.mu.Unlock()
	_ = e.st.AddEvent(store.EventQuarantine, pathID, "quarantine cleared by operator")
	e.wakeDecision()
}

// ---------------------------------------------------------------------------
// Configuration and status
// ---------------------------------------------------------------------------

// Config returns the running configuration.
func (e *Engine) Config() model.Config {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg
}

// Mode reports whether the engine is armed or only observing.
func (e *Engine) Mode() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg.Mode
}

// Reconfigure persists a new configuration and restarts the affected parts.
//
// It deliberately takes no context. Callers are HTTP handlers, and starting the
// probers from a request context would tie their lifetime to that request:
// probing would stop the instant the settings page returned a response.
//
// It is serialised against itself for the sibling reason. Callers are HTTP
// handlers, which net/http serves concurrently - a settings save and a mode
// toggle, or a double-clicked Save - and the stop/start pair below is not
// atomic on its own. Interleaved, the second caller's stopProbers finds the
// handle already nil, cancels nothing, and both callers then start a
// generation; the first handle is overwritten and that generation probes until
// the process exits. The symptom is a standby path on a 5000ms interval
// reporting every 2-3s, and it compounds with each racing pair.
func (e *Engine) Reconfigure(cfg model.Config) error {
	// Held across applySystemConfig, which is why this is not e.mu.
	e.reconfMu.Lock()
	defer e.reconfMu.Unlock()

	if err := e.st.SaveConfig(cfg); err != nil {
		return err
	}
	e.stopProbers()

	// The swap is made under applyMu, briefly, for the same reason the backend's
	// is: evaluate reads the runner under e.mu at its start and then shells out
	// for as long as `ip` takes, so a swap outside this lock could land mid
	// decision, after the previous runner had been captured - one route
	// installed with the armed runner after the mode had gone to observe.
	// Released again immediately, because applySystemConfig takes it itself and
	// these mutexes are not reentrant; evaluate running in the gap sees the new
	// configuration and is correct to.
	e.applyMu.Lock()
	e.mu.Lock()
	prevMode := e.cfg.Mode
	e.cfg = cfg
	e.runner = runnerFor(cfg.Mode, e.log)
	e.cfgVersion++
	// A configuration save is what ends the post-revert hold: applySystemConfig
	// and startProbers below reinstall and re-measure everything a revert took
	// down, so the latch that was suppressing the reconciler comes off with it.
	e.reverted = false
	ctx := e.baseCtx
	dataPlane := e.dataPlane
	e.mu.Unlock()
	e.applyMu.Unlock()

	// The persisted copy comes off with it, or the next restart would start
	// held on a latch the operator already released.
	if err := e.st.SetMeta(revertedMetaKey, ""); err != nil {
		e.log.Warn("cannot clear the persisted revert latch", "err", err)
	}

	e.notifier.SetConfig(cfg.Notify)
	e.applySystemConfig(ctx)
	e.startProbers(ctx)
	e.refreshQuota(time.Now())
	// A save changes selectPath's inputs as surely as the operator's other
	// actions do - a path disabled, priorities reordered, a quota changed -
	// and disabling the active path then waited on the tick for the switch.
	e.wakeDecision()

	_ = e.st.AddEvent(store.EventConfig, 0, "configuration updated (mode: %s)", cfg.Mode)
	e.log.Info("configuration reloaded", "mode", cfg.Mode)

	// Disarming stops the agent making further changes; it deliberately does
	// not tear down what is already installed, because deleting the DNAT rules
	// would drop every published service on the spot. Say so plainly instead of
	// letting "observe only" imply nothing is applied.
	if prevMode == model.ModeArmed && cfg.Mode == model.ModeObserve && dataPlane {
		_ = e.st.AddEvent(store.EventSystem, 0,
			"disarmed: no further changes will be made, but the rules already installed stay active until you revert")
		e.log.Warn("disarmed with rules still installed", "hint", "use revert to remove them")
	}
	return nil
}

// Status renders the whole system for the portal.
// publicAddress is the WAN address the frontend is publishing on, for the
// portal's header. The configured Frontend.PublicIP wins because it is what
// the DNAT rules match; with it blank the rules match any address on the
// public interface, so the address shown is read from that interface instead.
// Read with the stdlib rather than the runner: it is a display-only read that
// must behave identically in observe mode and after a revert, and it asks the
// kernel the same question `ip addr show dev` would. IPv4 only, like
// everything else here.
func publicAddress(publicIP, publicIface string) string {
	if publicIP != "" {
		return publicIP
	}
	if publicIface == "" {
		return ""
	}
	ifi, err := net.InterfaceByName(publicIface)
	if err != nil {
		return ""
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return ""
	}
	return pickWANAddress(addrs)
}

// pickWANAddress chooses which of an interface's addresses to call the WAN.
// A publicly routable IPv4 wins over anything else there: a datacentre NIC
// often carries a management or carrier-NAT address alongside the public one,
// and the kernel lists addresses in the order they were added, not in order
// of meaning, so "first in the list" showed players an address they could
// never reach. With only private addresses to choose from, the first ordinary
// one is shown rather than nothing: a deliberately private deployment is
// better served by the truth than by a blank.
func pickWANAddress(addrs []net.Addr) string {
	first := ""
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipn.IP.To4()
		if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
			continue
		}
		// 100.64.0.0/10 is carrier-grade NAT space: not private to Go's
		// IsPrivate, not reachable from the internet either.
		cgnat := ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127
		if !ip4.IsPrivate() && !cgnat {
			return ip4.String()
		}
		if first == "" {
			first = ip4.String()
		}
	}
	return first
}

// cachedPublicAddress serves the WAN address from the cache described on the
// fields, refreshing it when it is older than a few seconds or the settings
// it was derived from have changed. Five seconds keeps a renumbered interface
// visible in the portal within a breath while cutting the per-second netlink
// enumeration to a fifth.
func (e *Engine) cachedPublicAddress(publicIP, publicIface string) string {
	e.wanMu.Lock()
	defer e.wanMu.Unlock()
	key := publicIP + "|" + publicIface
	if key == e.wanKey && time.Since(e.wanAt) < 5*time.Second {
		return e.wanAddr
	}
	e.wanAddr = publicAddress(publicIP, publicIface)
	e.wanKey = key
	e.wanAt = time.Now()
	return e.wanAddr
}

func (e *Engine) Status() model.Status {
	now := time.Now()

	// The interface read is kernel I/O, so it happens before the state lock is
	// taken rather than under it.
	e.mu.RLock()
	pubIP, pubIface := e.cfg.Frontend.PublicIP, e.cfg.Frontend.PublicIface
	e.mu.RUnlock()
	wan := e.cachedPublicAddress(pubIP, pubIface)

	e.mu.RLock()
	defer e.mu.RUnlock()

	st := model.Status{
		Mode:        e.cfg.Mode,
		ActivePath:  e.active,
		Held:        e.held,
		HeldReason:  e.heldReason,
		LastSwitch:  e.lastSwitch,
		BackendUp:   e.backendUp,
		RulesActive: e.dataPlane,
		Uptime:      now.Sub(e.started).Seconds(),
		DecisionSeq: e.decisionSeq,
		Reverted:    e.reverted,

		Protect:         e.protectStatus(),
		SharedEndpoints: e.sharedEndpoints,
		LinkerStates:    e.linkerStates(),
		PreferredPath:   preferredPathID(e.cfg),
		PublicAddress:   wan,
		FrontendVersion: Version,
		BackendVersion:  e.backendVersion,
		BackendHost:     e.backendHost,
	}
	for _, p := range e.cfg.Paths {
		tr := e.trackers[p.ID]
		if tr == nil {
			continue
		}
		s := tr.Snapshot(now)
		s.Active = p.ID == e.active
		s.PeerEndpoint = e.peerEndpoints[p.ID]
		s.Block = e.blocks[p.ID]
		if d, ok := e.quotaDec[p.ID]; ok {
			s.UsedBytes = d.Used
			s.LimitBytes = d.Limit
			s.PeriodStart = d.PeriodStart
			s.PeriodEnd = d.PeriodEnd
			s.GrantUntil = d.GrantUntil
			s.GrantBytes = d.GrantBytes
		}
		if s.Active {
			st.ActiveName = p.Name
		}
		st.Paths = append(st.Paths, s)
	}
	sort.Slice(st.Paths, func(i, j int) bool { return st.Paths[i].Priority < st.Paths[j].Priority })
	return st
}

// PinnedPath reports the operator override, or 0.
func (e *Engine) PinnedPath() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.pinned
}

// Revert removes everything the agent installed: the DNAT table, the per-path
// probe tables and their rules, and the backend route. It is the one-command
// undo for a bad change, and it deliberately leaves the WireGuard tunnels
// alone because the agent never created them.
// It is serialised against Reconfigure, and that is the load-bearing part.
// Revert reads the configuration, spends a few hundred milliseconds tearing
// down a dozen things, and only records dataPlane = false at the end. A
// settings save landing in that gap runs applySystemConfig and puts the DNAT
// ruleset and the route straight back - and then this finishes and reports the
// system reverted. Nothing corrects that afterwards, precisely because the
// engine believes there is nothing installed: the rules stay live while the
// portal says they are gone, which is invariant 13 failing in the one
// direction it must not, on the one command that exists to be trusted.
func (e *Engine) Revert(ctx context.Context) {
	e.reconfMu.Lock()
	defer e.reconfMu.Unlock()

	// And against the decision loop, which would otherwise install a route
	// between two of the removals below. Always after reconfMu; see applyMu.
	e.applyMu.Lock()
	defer e.applyMu.Unlock()

	// Latched before anything is torn down, so a reconcile or evaluate parked
	// on applyMu behind this cannot repair the removals the moment it is
	// released - see the field. Cleared only by Reconfigure.
	e.mu.Lock()
	e.reverted = true
	cfg := e.cfg
	e.mu.Unlock()

	// Persisted before the teardown too, and for the same reason in a longer
	// window: the unit restarts itself, so a crash anywhere between here and
	// the `systemctl stop` that follows a revert would otherwise bring the
	// process back reinstalling what this is about to remove.
	if err := e.st.SetMeta(revertedMetaKey, "1"); err != nil {
		e.log.Error("cannot persist the revert latch",
			"err", err, "note", "a restart before the unit is stopped will reinstall and resume probing")
	}

	// The probers go too. Their routes and rules are removed below, so left
	// running they would report every path down and fire the no-usable-path
	// alarm about a state the operator just asked for. Reconfigure restarts
	// them.
	e.stopProbers()

	runner := e.realRunner() // revert always acts, even in observe mode
	sysx.RemoveRuleset(ctx, runner)
	sysx.RemoveEgressRuleset(ctx, runner)
	sysx.RemoveProtectRuleset(ctx, runner)
	// Only tunnels this system shapes. An interface it never touched keeps
	// whatever queue discipline its owner gave it - revert takes down what the
	// agent installed and nothing else.
	for _, p := range cfg.Paths {
		if p.Shape.ToBackendMbit > 0 {
			sysx.RemoveQdisc(ctx, runner, p.Iface)
		}
	}
	// The probe tables always carry the backend's /32; only the main-table
	// route widens with a subnet. Passing one prefix for both would have revert
	// asking the kernel to delete a range from a table that holds a host route.
	sysx.RemoveProbeRoutes(ctx, runner, cfg.Paths, cfg.Overlay.BackendIP+"/32", cfg.Overlay.RoutePrefix())
	sysx.RemoveControlRoute(ctx, runner, cfg.Overlay.RoutePrefix(),
		cfg.Overlay.BackendIP, cfg.Overlay.FrontendIP)
	sysx.RemoveForwardExceptions(ctx, runner)
	sysx.RemoveEgressForwardException(ctx, runner)

	// Dropping to observe is part of the revert, not a nicety. Without it the
	// next decision tick - 500ms later - sees no active path, picks one, and
	// reinstalls the route through the armed runner. The host would end up
	// half reverted: route back, nftables gone.
	cfg.Mode = model.ModeObserve
	if err := e.st.SaveConfig(cfg); err != nil {
		e.log.Error("reverted the system but could not persist observe mode", "err", err)
	}

	e.mu.Lock()
	e.cfg = cfg
	e.runner = runnerFor(model.ModeObserve, e.log)
	e.cfgVersion++ // propagates observe mode to the backend too
	e.active = 0
	e.pinned = 0
	e.dataPlane = false
	e.protectOn = false
	e.protectApplied = ""
	// All three samples, not two: a stale engaged-lock reading served after a
	// later re-arm is an attack alert for a lock that is not in the kernel.
	e.protectCounters, e.protectBlocked, e.protectGeoLocked = nil, nil, nil
	e.mu.Unlock()

	_ = e.st.AddEvent(store.EventSystem, 0,
		"reverted: nftables table and policy routes removed, mode set to observe; "+
			"probing is stopped until settings are saved or the mode is changed")
	e.log.Warn("reverted all system changes, now in observe mode",
		"note", "nothing is measured or repaired until the next settings save or mode change")
}

// ConfigVersion increments on every configuration change, so the control
// server can push a fresh copy to the backend without a subscription.
func (e *Engine) ConfigVersion() uint64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfgVersion
}

// Logger exposes the engine's logger to sibling components.
func (e *Engine) Logger() *slog.Logger { return e.log }

// Store exposes the durable state to sibling components.
func (e *Engine) Store() *store.Store { return e.st }

// protectStatus reports what the edge limiters have done, or nil when none are
// installed - which is what keeps the portal's protection card absent entirely
// on a site that has never turned the feature on. Caller holds the lock.
func (e *Engine) protectStatus() *model.ProtectStatus {
	if !e.protectOn {
		return nil
	}
	return &model.ProtectStatus{
		Counters:  e.protectCounters,
		Blocked:   e.protectBlocked,
		GeoLocked: e.protectGeoLocked,
	}
}

// linkerStates reports every configured linker and whether it is connected.
//
// Driven by the configuration rather than by the connection map, so a linker
// that has never dialled in is reported as down instead of being absent. A host
// that is missing from the portal entirely looks like one nobody configured,
// which is exactly the confusion this is meant to remove. Caller holds the lock.
func (e *Engine) linkerStates() []model.LinkerState {
	if len(e.cfg.Linkers) == 0 {
		return nil
	}
	out := make([]model.LinkerState, 0, len(e.cfg.Linkers))
	for _, l := range e.cfg.Linkers {
		st := model.LinkerState{
			Name:            l.Name,
			OverlayIP:       l.OverlayIP,
			LanIP:           l.LanIP,
			ConfiguredTable: l.TableOr(sysx.DefaultLinkerTable),
			LastSeen:        e.linkerSeen[l.OverlayIP],
		}
		if c, ok := e.linkers[l.OverlayIP]; ok {
			st.Up = true
			st.Version = c.version
			st.Hostname = c.hostname
			st.Since = c.since
			st.Table = c.table
		}
		out = append(out, st)
	}
	return out
}
