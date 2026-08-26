package engine

import (
	"context"
	"testing"
	"time"

	"github.com/quinlan102/homeport/internal/model"
)

// engineForQueryCache is engineForProbers with a Source service opted in and
// the cache switched on, bound to loopback so the test never opens a
// wildcard socket on a development machine.
func engineForQueryCache(t *testing.T, mode string, enabled bool) *Engine {
	t.Helper()
	e := engineForProbers(t)
	e.qcBind = "127.0.0.1"
	cfg := e.cfg
	cfg.Mode = mode
	cfg.QueryCache.Enabled = enabled
	cfg.Services = []model.Service{
		{Name: "gmod", Proto: "udp", Port: 39115, PortEnd: 39117, Enabled: true, SourceEngine: true},
	}
	e.cfg = cfg
	return e
}

// The cache runs where its redirect rules are, and its Snapshot is what the
// portal shows. Observe with nothing loaded must start nothing: the sockets
// would sit unreachable while the refresher billed query traffic to whatever
// path is active, and observe mode's promise is that nothing the agent does
// can be felt or billed. But observe with the data plane still loaded is
// invariant 13's disarm, which deliberately keeps the installed ruleset -
// the qcache redirects included - so a cache stopped on the mode alone left
// every redirected query pointing at a closed socket, and the server dropped
// out of browsers the moment the operator disarmed, with the portal showing
// rules active throughout. The sockets follow the rules, not the mode.
func TestQueryCacheFollowsTheLoadedRulesNotTheMode(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mode      string
		enabled   bool
		dataPlane bool
		want      int // ports reported by Status
	}{
		{"armed and enabled", model.ModeArmed, true, false, 3},
		{"armed but disabled", model.ModeArmed, false, false, 0},
		{"observing with nothing loaded", model.ModeObserve, true, false, 0},
		{"disarmed with the rules still loaded", model.ModeObserve, true, true, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := engineForQueryCache(t, tc.mode, tc.enabled)
			e.dataPlane = tc.dataPlane
			e.startQueryCache(context.Background())
			defer e.stopQueryCache()
			if got := len(e.Status().QueryCache); got != tc.want {
				t.Errorf("Status reports %d cached ports, want %d", got, tc.want)
			}
		})
	}
}

// Stop really stops: the generation is waited out and Status stops reporting
// it. The wait matters beyond tidiness, because the sockets are fixed ports
// the next generation must bind - a stop that only cancelled would have every
// second settings save fail its binds against the generation before it.
func TestStopQueryCacheWaitsTheGenerationOut(t *testing.T) {
	e := engineForQueryCache(t, model.ModeArmed, true)
	e.startQueryCache(context.Background())
	if len(e.Status().QueryCache) == 0 {
		t.Fatalf("cache did not start")
	}
	e.stopQueryCache()
	if got := len(e.Status().QueryCache); got != 0 {
		t.Errorf("Status still reports %d ports after stop", got)
	}
	// And a restart binds the same ports cleanly, which is the property the
	// wait exists for.
	e.startQueryCache(context.Background())
	defer e.stopQueryCache()
	for _, st := range e.Status().QueryCache {
		if st.Error != "" {
			t.Errorf("port %d failed to rebind after a stop: %s", st.Port, st.Error)
		}
	}
}

// The timings the engine hands the cache hold validate's floors again, for
// the blob validate never saw. The staleness floor is the one that matters:
// three effective refresh intervals, because between polls every answer is
// served from that window, so a stored bound (or the unset default) that a
// slow stored refresh undercuts would have a healthy port going dark between
// refreshes - and there is nobody at this boundary to tell.
func TestQueryCacheTimingsHoldTheFloors(t *testing.T) {
	ms := func(d time.Duration) int { return int(d / time.Millisecond) }
	for _, tc := range []struct {
		name        string
		refreshMs   int
		staleMs     int
		wantRefresh time.Duration
		wantStale   time.Duration
	}{
		// The shipped state: the cache's own defaults, refresh passed as
		// zero so qcache fills it in, staleness resolved here.
		{"defaults", 0, 0, 0, 10 * time.Second},
		// A refresh below the floor is lifted, exactly as before.
		{"refresh floor", 200, 0, 500 * time.Millisecond, 10 * time.Second},
		// A slow stored refresh must lift an unset bound with it: the
		// default 10s covers three intervals only up to 3333ms.
		{"slow refresh lifts the default", 30000, 0, 30 * time.Second, 90 * time.Second},
		// An explicit bound a slow refresh undercuts is lifted the same way.
		{"slow refresh lifts an explicit bound", 10000, 12000, 10 * time.Second, 30 * time.Second},
		// An explicit bound that covers its refresh is not moved by a ms.
		{"explicit bound kept", 3000, 15000, 3 * time.Second, 15 * time.Second},
	} {
		refresh, stale := queryCacheTimings(model.QueryCacheConfig{
			RefreshMs: tc.refreshMs, StaleMs: tc.staleMs,
		})
		if refresh != tc.wantRefresh || stale != tc.wantStale {
			t.Errorf("%s: refresh %d ms stale %d ms -> refresh %d ms stale %d ms, want %d and %d",
				tc.name, tc.refreshMs, tc.staleMs, ms(refresh), ms(stale), ms(tc.wantRefresh), ms(tc.wantStale))
		}
	}
}
