package engine

import (
	"context"
	"testing"

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
