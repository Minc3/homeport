package engine

import (
	"context"
	"sync"
	"time"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/qcache"
)

// queryCacheTimings resolves the refresh interval and staleness bound a
// stored configuration gives the cache. The floors are validate's, held
// again here for the values validate never saw - a blob stored by a build
// without them, where there is nobody at this boundary to tell. Below the
// refresh floor the refresher is a continuous poll of the operator's own
// server over the billed tunnel. The staleness floor is three effective
// refresh intervals: between polls every answer is served from that window
// and one failed fetch has to be retryable inside it, or a healthy port
// goes dark between refreshes - which is also what an unset bound must not
// be talked into by a slow stored refresh, so the comparison is made on the
// effective values, defaults filled in.
func queryCacheTimings(qc model.QueryCacheConfig) (refresh, stale time.Duration) {
	refresh = time.Duration(qc.RefreshMs) * time.Millisecond
	if refresh > 0 && refresh < 500*time.Millisecond {
		refresh = 500 * time.Millisecond
	}
	refreshEff := refresh
	if refreshEff == 0 {
		refreshEff = qcache.DefaultRefreshEvery
	}
	stale = time.Duration(qc.StaleMs) * time.Millisecond
	if stale == 0 {
		stale = qcache.DefaultStaleAfter
	}
	if stale < 3*refreshEff {
		stale = 3 * refreshEff
	}
	return refresh, stale
}

// startQueryCache replaces the running cache generation with one built from
// the current configuration, or with nothing where the cache is off, the
// mode is observe, or no service opts in.
//
// It stops the previous generation first, waiting, rather than carrying
// startProbers' cancel-and-carry-on orphan guard: the cache binds fixed
// service ports, so a new generation started while the old one still holds
// its sockets fails every bind against its own predecessor and comes up
// answering nothing. Every caller holds reconfMu, which is what makes the
// stop-then-start sequence atomic against the other callers.
//
// The cache runs where its redirect rules are: armed, or disarmed with the
// data plane still loaded. Observe with nothing loaded starts nothing, and
// that is a promise rather than an optimisation - the sockets would sit
// unreachable while the refresher sent query traffic down the active tunnel,
// and observe mode's promise is that nothing the agent does can be felt or
// billed.
func (e *Engine) startQueryCache(parent context.Context) {
	e.stopQueryCache()

	e.mu.RLock()
	cfg := e.cfg
	dataPlane := e.dataPlane
	e.mu.RUnlock()
	// Armed, or disarmed with the rules still loaded. Invariant 13: going
	// armed to observe deliberately leaves the installed ruleset in the
	// kernel, and the qcache redirects ride that ruleset - so a cache
	// stopped on the mode alone left every redirected query pointing at a
	// closed socket, and the server dropped out of browsers the moment the
	// operator disarmed, with the portal showing rules active throughout.
	// The sockets follow the rules, not the mode. Observe with nothing
	// loaded still starts nothing, which keeps observe's promise that no
	// refresh traffic is sent or billed. dataPlane is in-memory, so a
	// restart while disarmed-with-rules starts no cache; that is the same
	// approximation RulesActive itself reports after such a restart.
	if cfg.Mode != model.ModeArmed && !dataPlane {
		return
	}
	spans := model.QueryCachePorts(cfg)
	if len(spans) == 0 {
		return
	}
	var ports []qcache.Port
	for _, sp := range spans {
		for p := sp.From; p <= sp.To; p++ {
			ports = append(ports, qcache.Port{Port: p, Target: sp.Target, Service: sp.Service})
		}
	}

	refresh, stale := queryCacheTimings(cfg.QueryCache)
	c := qcache.New(qcache.Config{
		Ports:        ports,
		Bind:         e.qcBind,
		RefreshEvery: refresh,
		StaleAfter:   stale,
		Log:          e.log,
	})
	ctx, cancel := context.WithCancel(parent)
	done := &sync.WaitGroup{}
	done.Add(1)
	e.mu.Lock()
	e.qc, e.qcCancel, e.qcDone = c, cancel, done
	e.mu.Unlock()
	go func() {
		defer done.Done()
		c.Run(ctx)
	}()
	e.log.Info("query cache started", "ports", len(ports))
}

// queryCacheStates renders the running cache for the portal. Callers hold
// e.mu at least for reading, which is what makes the e.qc read safe; the
// snapshot's own counters are the cacher's to lock.
func (e *Engine) queryCacheStates() []model.QueryCacheState {
	if e.qc == nil {
		return nil
	}
	return e.qc.Snapshot()
}

// stopQueryCache cancels the running generation and waits for it to be gone,
// for the reason stopProbers does - and one more: the sockets it holds are
// the fixed ports the next generation must bind.
func (e *Engine) stopQueryCache() {
	e.mu.Lock()
	cancel, done := e.qcCancel, e.qcDone
	e.qc, e.qcCancel, e.qcDone = nil, nil, nil
	e.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		done.Wait()
	}
}
