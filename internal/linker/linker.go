// Package linker is the agent for a host that holds an overlay address but
// terminates no tunnels.
//
// It is deliberately the smallest of the three. A linker makes no decisions,
// answers no probes, meters nothing, and never learns which tunnel is carrying
// traffic - it only has to put replies onto the backend, and the backend
// already tracks the active path. Everything that makes failover-backend
// non-trivial exists to serve probing and decision handling, and none of it
// applies here.
//
// What it does is install two rules and then keep re-checking them:
//
//	ip rule  add from 10.99.0.3 lookup 200
//	ip route replace default via <backend LAN> table 200
//
// plus the overlay address itself on a dummy interface, for the same reason the
// other two hosts use one: the address must not belong to any link that can go
// away.
package linker

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/sysx"
)

// reconcileInterval matches the other two agents. Anything the kernel drops -
// the table's default route goes with the LAN interface if it bounces - is back
// within this long.
const reconcileInterval = 10 * time.Second

// Linker is the agent.
type Linker struct {
	log    *slog.Logger
	boot   model.Bootstrap
	runner sysx.Runner

	// Egress state, in two halves on purpose. egressWant is the last list the
	// frontend pushed; egressHave is the list actually installed, recorded only
	// once the kernel has taken it. They differ only after a failed attempt.
	//
	// One value would not do, and recording it up front was a real bug: the
	// list was marked applied before `nft -f` had run, so a failure - the LAN
	// interface not up yet at boot being the ordinary one - left the agent
	// believing the networks were on the overlay when they were not. Nothing
	// retried, because a push arrives once per configuration version and this
	// host's own reconcile never looked at egress, so the containers stayed on
	// the local service until somebody happened to save settings again.
	//
	// egressKnown separates "never been told anything" from "told an empty
	// list", which are different instructions.
	mu          sync.Mutex
	egressKnown bool
	egressWant  []string
	egressHave  []string
	egressOK    bool

	// applyMu serialises the shell-outs themselves. Both the control session
	// and the reconcile loop can reach applyEgress, and two runs interleaving
	// would race `nft -f` against `ip rule add` for the same table.
	applyMu sync.Mutex
}

// table is the routing table this host uses for overlay traffic.
//
// From the bootstrap file rather than the control channel, because the rule and
// route it names are what carry that channel - the agent cannot be told a value
// it needs in order to be told anything.
func (l *Linker) table() int {
	if l.boot.Linker.Table != 0 {
		return l.boot.Linker.Table
	}
	return sysx.DefaultLinkerTable
}

// New builds a linker from its bootstrap file.
func New(log *slog.Logger, boot model.Bootstrap) *Linker {
	return &Linker{
		log:    log,
		boot:   boot,
		runner: &sysx.ExecRunner{Log: log},
	}
}

// Run installs the plumbing and then reconciles it until the context is done.
//
// There is no observe mode here, and that is not an oversight. The other two
// agents have one because their rules move published traffic the moment they
// exist. These rules match only packets sourced from this host's overlay
// address, and nothing on the box uses that address unless a service was
// deliberately bound to it - so on a host where nothing has opted in, the rules
// are inert. What actually directs traffic here is the frontend's DNAT, which
// has its own observe mode and is where the decision belongs.
func (l *Linker) Run(ctx context.Context) error {
	l.apply(ctx)

	// The control channel is what carries the egress networks down. It is not
	// required for anything else: routing published traffic works whether or
	// not the frontend is reachable, which is the property that lets a linker
	// keep serving through a frontend restart.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); l.runControlClient(ctx) }()

	tick := time.NewTicker(reconcileInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return nil
		case <-tick.C:
			l.reconcile(ctx)
		}
	}
}

// applyEgress installs the source NAT for container networks the frontend has
// named for this host.
//
// Called from the control session's goroutine on every push, and from the
// reconcile loop when a previous attempt failed. It shells out, which is why it
// must not be called from anywhere that also has to stay responsive - but
// neither of those callers has anything else to do meanwhile.
func (l *Linker) applyEgress(ctx context.Context, cidrs []string) {
	l.mu.Lock()
	l.egressKnown = true
	l.egressWant = append([]string(nil), cidrs...)
	unchanged := l.egressOK && equalStrings(l.egressHave, cidrs)
	l.mu.Unlock()
	if unchanged {
		return
	}

	l.applyMu.Lock()
	defer l.applyMu.Unlock()

	if err := l.installEgress(ctx, cidrs); err != nil {
		l.mu.Lock()
		l.egressOK = false
		l.mu.Unlock()
		l.log.Error("egress networks not installed; this host's containers stay on the local service",
			"networks", cidrs, "err", err,
			"hint", "retried on the next reconcile tick")
		return
	}

	// Recorded only now the kernel has accepted it, so a failure is retried
	// rather than remembered as a success.
	l.mu.Lock()
	l.egressHave = append([]string(nil), cidrs...)
	l.egressOK = true
	l.mu.Unlock()

	if len(cidrs) == 0 {
		l.log.Info("no egress networks configured for this host; source NAT removed")
		return
	}
	l.log.Info("egress networks installed", "networks", cidrs,
		"source", l.boot.Linker.OverlayIP)
}

// installEgress does the work, and reports whether the system took it. Split
// out so applyEgress has exactly one success path to commit on.
func (l *Linker) installEgress(ctx context.Context, cidrs []string) error {
	if len(cidrs) == 0 {
		sysx.RemoveLinkerEgressRuleset(ctx, l.runner, l.table())
		return nil
	}

	// Discovered rather than configured: the interface that carries the route
	// to the backend is the one these packets leave by, so asking the kernel
	// cannot be wrong in the way a typed interface name can.
	iface, err := sysx.LanIfaceTo(ctx, l.runner, l.boot.Linker.BackendLAN)
	if err != nil {
		return fmt.Errorf("cannot determine which interface reaches the backend at %s: %w",
			l.boot.Linker.BackendLAN, err)
	}
	if iface == "" {
		return fmt.Errorf("no route to the backend at %s, so no interface to scope the source NAT to",
			l.boot.Linker.BackendLAN)
	}

	ruleset := sysx.BuildLinkerEgressRuleset(cidrs, iface, l.boot.Linker.OverlayIP)
	if _, err := sysx.ApplyLinkerEgressRuleset(ctx, l.runner, l.boot.StateDir, ruleset); err != nil {
		return fmt.Errorf("load the egress source NAT: %w", err)
	}
	if err := sysx.EnsureLinkerEgressRule(ctx, l.runner, l.table()); err != nil {
		return fmt.Errorf("install the egress mark rule: %w", err)
	}
	return nil
}

// retryEgress re-attempts an install the kernel refused last time.
//
// A push arrives once per configuration version, so without this a transient
// failure is permanent: the frontend has nothing more to say, and the agent
// would sit believing it had been told something it never managed to apply.
func (l *Linker) retryEgress(ctx context.Context) {
	l.mu.Lock()
	pending := l.egressKnown && !(l.egressOK && equalStrings(l.egressHave, l.egressWant))
	want := append([]string(nil), l.egressWant...)
	l.mu.Unlock()
	if !pending {
		return
	}
	l.applyEgress(ctx, want)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// apply installs everything, unconditionally. Each step is idempotent.
func (l *Linker) apply(ctx context.Context) {
	ov := l.boot.Overlay
	li := l.boot.Linker

	if err := sysx.EnsureOverlayAddress(ctx, l.runner, li.OverlayIP, ov.Device); err != nil {
		l.log.Error("cannot establish the overlay address; nothing published to this host will work",
			"address", li.OverlayIP, "device", ov.Device, "err", err)
	}
	if err := sysx.EnsureLinkerRule(ctx, l.runner, li.OverlayIP, l.table()); err != nil {
		l.log.Error("cannot install the overlay policy rule; replies will leave by the LAN default route",
			"address", li.OverlayIP, "err", err)
	}
	if err := sysx.EnsureLinkerRoute(ctx, l.runner, li.BackendLAN, l.table()); err != nil {
		l.log.Error("cannot point the overlay table at the backend",
			"backend", li.BackendLAN, "err", err)
	}

	// Containers cannot bind the overlay address - it does not exist in their
	// namespace - so they are published by Docker DNAT and their replies come
	// back carrying the container's own address, which the source rule above
	// cannot match. Marking the connection on the way in is what lets the reply
	// be routed on the way out. Costs nothing where no container is published:
	// nothing is addressed to the overlay address unless the frontend sends it.
	if _, err := sysx.ApplyLinkerReturnRuleset(ctx, l.runner, l.boot.StateDir,
		sysx.BuildLinkerReturnRuleset(li.OverlayIP)); err != nil {
		l.log.Error("cannot install return marking; containerised services published here will time out",
			"err", err)
	}
	if err := sysx.EnsureLinkerMarkRule(ctx, l.runner, l.table()); err != nil {
		l.log.Error("cannot install the return mark rule", "err", err)
	}

	// Not set, only reported. On a host with one route to the internet the
	// reverse lookup for a client address resolves to the same interface the
	// packet arrived on, so filtering passes and there is nothing to fix. On a
	// multi-homed box it may not, and this is the first thing to suspect - but
	// turning it off system-wide is a change to a machine that is somebody's
	// server first and a linker second, so it is theirs to make.
	if on, err := sysx.RPFilterOn(ctx, l.runner); err == nil && on {
		l.log.Warn("reverse-path filtering is on system-wide",
			"hint", "harmless on a host with a single route to the internet; suspect it first if published traffic arrives but is never answered")
	}
}

// reconcile re-reads the kernel and reinstalls only what is missing.
//
// The route is the part that actually goes: it points at a neighbour rather
// than a device, so the kernel drops it if the LAN interface bounces, and
// nothing would ever put it back. The address and the rule survive most things
// but cost one read each to confirm.
func (l *Linker) reconcile(ctx context.Context) {
	ov := l.boot.Overlay
	li := l.boot.Linker

	if err := sysx.EnsureOverlayAddress(ctx, l.runner, li.OverlayIP, ov.Device); err != nil {
		l.log.Error("overlay address missing and could not be restored",
			"address", li.OverlayIP, "err", err)
	}
	if err := sysx.EnsureLinkerRule(ctx, l.runner, li.OverlayIP, l.table()); err != nil {
		l.log.Error("overlay policy rule missing and could not be restored", "err", err)
	}
	if err := sysx.EnsureLinkerMarkRule(ctx, l.runner, l.table()); err != nil {
		l.log.Error("return mark rule missing and could not be restored", "err", err)
	}

	// An egress install the kernel refused is retried here, because nothing
	// else would: the frontend pushes once per configuration version, so a
	// transient failure at boot - most often the LAN interface not up yet, so
	// there is no route to the backend to scope the source NAT to - would
	// otherwise last until somebody saved settings again.
	l.retryEgress(ctx)

	via, err := sysx.LinkerRouteVia(ctx, l.runner, l.table())
	if err != nil {
		l.log.Warn("cannot read the overlay table", "err", err)
		return
	}
	if via == li.BackendLAN {
		return
	}
	if err := sysx.EnsureLinkerRoute(ctx, l.runner, li.BackendLAN, l.table()); err != nil {
		l.log.Error("cannot restore the route to the backend", "backend", li.BackendLAN, "err", err)
		return
	}
	l.log.Warn("restored the overlay route to the backend",
		"backend", li.BackendLAN, "was", via)
}

// Revert removes the two rules this agent installed and nothing else.
//
// The overlay address stays. A service may still be bound to it, and taking an
// address out from under a listening process turns a routing change into a
// crash - which is not what somebody running a revert is asking for.
//
// Stop this host's unit before running it. This is a separate process and
// cannot tell a running agent anything, while reconcile re-reads the kernel
// every ten seconds and puts back the overlay rule, the mark rule and the route
// to the backend. The result is a host that is half reverted and says it is
// clean.
func (l *Linker) Revert(ctx context.Context) {
	sysx.RemoveLinkerEgressRuleset(ctx, l.runner, l.table())
	sysx.RemoveLinkerReturnRuleset(ctx, l.runner, l.table())
	sysx.RemoveLinkerRouting(ctx, l.runner, l.boot.Linker.OverlayIP, l.table())
	l.log.Warn("removed the overlay policy rule and table",
		"note", "the overlay address is left in place; anything bound to it is still listening",
		"hint", "if failover-linker.service is still running, its reconciler puts the routing "+
			"back within ten seconds: stop the unit and run this again")
}
