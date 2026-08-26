package engine

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/qcache"
)

// qcacheAppliedMetaKey records the enumeration the loaded ruleset actually
// redirects: written by applySystemConfig whenever an armed apply loads the
// ruleset, cleared by Revert when the ruleset comes out. That is the
// redirects' own lifecycle, and persisting it is not a nicety - the unit runs
// under Restart=always, so any in-memory record of "rules are loaded" dies
// with a crash while the rules themselves stay in the kernel, and a process
// that came back starting no cache left every redirected query pointing at a
// closed socket.
const qcacheAppliedMetaKey = "qcache_applied"

// persistAppliedQueryCache records what the ruleset just loaded redirects.
// Called only from applySystemConfig's success branch, beside dataPlane,
// because the record must describe the kernel and not the configuration: the
// two agree only at the moment an armed apply lands.
func (e *Engine) persistAppliedQueryCache(cfg model.Config) {
	val := ""
	if spans := model.QueryCachePorts(cfg); len(spans) > 0 {
		b, err := json.Marshal(spans)
		if err != nil {
			e.log.Error("cannot record the applied query cache ports", "err", err)
			return
		}
		val = string(b)
	}
	if err := e.st.SetMeta(qcacheAppliedMetaKey, val); err != nil {
		e.log.Error("cannot record the applied query cache ports", "err", err,
			"note", "after a disarm or a restart the cache may not match the loaded redirects")
	}
}

// appliedQueryCacheSpans reads that record back. A read failure starts no
// cache and says so loudly: with redirects loaded that is the blackhole, but
// there is no safe enumeration to invent, and the next armed apply rewrites
// the record.
func (e *Engine) appliedQueryCacheSpans() []model.QueryCacheSpan {
	raw, err := e.st.MetaChecked(qcacheAppliedMetaKey)
	if err != nil {
		e.log.Error("cannot read the applied query cache ports; starting no cache", "err", err,
			"hint", "if redirect rules are loaded their queries go unanswered until settings are saved while armed")
		return nil
	}
	if raw == "" {
		return nil
	}
	var spans []model.QueryCacheSpan
	if err := json.Unmarshal([]byte(raw), &spans); err != nil {
		e.log.Error("cannot parse the applied query cache ports; starting no cache", "err", err)
		return nil
	}
	return spans
}

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
// The cache serves the redirects the kernel actually holds, which is not
// always the saved configuration. Armed, the two agree: applySystemConfig has
// just loaded the ruleset generated from cfg and recorded its enumeration in
// the same breath. Not armed, the kernel holds whatever the last armed apply
// loaded - invariant 13's disarm deliberately keeps the installed ruleset,
// redirects included, and a disarmed save reloads nothing - so the sockets
// are built from the recorded enumeration, never from cfg. Building them from
// cfg was the blackhole twice over: a save that shrank the enumeration while
// disarmed (the cache unticked, a service disabled, a range narrowed) stopped
// sockets the still-loaded redirects kept delivering to, and a crash-restart
// while disarmed started none at all, because the old gate read an in-memory
// flag. Observe with nothing recorded still starts nothing, which keeps
// observe's promise that no refresh traffic is sent or billed.
func (e *Engine) startQueryCache(parent context.Context) {
	e.stopQueryCache()

	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()
	var spans []model.QueryCacheSpan
	if cfg.Mode == model.ModeArmed {
		spans = model.QueryCachePorts(cfg)
	} else {
		spans = e.appliedQueryCacheSpans()
	}
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
