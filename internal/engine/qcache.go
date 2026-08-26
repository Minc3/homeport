package engine

import (
	"context"
	"sync"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/qcache"
)

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
// Armed mode only, and that is a promise rather than an optimisation. The
// redirect rules ride the DNAT table, which observe mode never loads, so in
// observe the sockets would sit unreachable - but the refresher would still
// send query traffic down the active tunnel, and observe mode's promise is
// that nothing the agent does can be felt or billed.
func (e *Engine) startQueryCache(parent context.Context) {
	e.stopQueryCache()

	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()
	if cfg.Mode != model.ModeArmed {
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

	c := qcache.New(qcache.Config{Ports: ports, Bind: e.qcBind, Log: e.log})
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
