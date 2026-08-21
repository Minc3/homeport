package engine

import (
	"testing"
	"time"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/quota"
)

// testConfig mirrors the real deployment: the main link preferred, then LTE1, then LTE2.
func testConfig() model.Config {
	cfg := model.Defaults()
	cfg.Failover.HoldDownSec = 90
	return cfg
}

// newTestEngine builds an engine with trackers in a known health state.
func newTestEngine(cfg model.Config, health map[int]model.Health) *Engine {
	e := &Engine{
		cfg:      cfg,
		trackers: map[int]*Tracker{},
		blocks:   map[int]model.Block{},
		quotaDec: map[int]quota.Decision{},
		linkers:  map[string]linkerConn{},

		linkerSeen:  map[string]time.Time{},
		linkerSaved: map[string]time.Time{},
	}
	for _, p := range cfg.Paths {
		tr := NewTracker(p, cfg.Probe, cfg.Failover)
		tr.health = health[p.ID]
		if tr.health == model.HealthUp {
			// Clean for long enough that hold-down is satisfied unless a test
			// deliberately shortens it.
			tr.cleanSince = time.Now().Add(-time.Hour)
		}
		e.trackers[p.ID] = tr
		e.blocks[p.ID] = model.BlockNone
	}
	return e
}

func TestSelectsHighestPriorityHealthyPath(t *testing.T) {
	cfg := testConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthUp, 2: model.HealthUp, 3: model.HealthUp})

	got, held, _ := e.selectPath(cfg, time.Now())
	if held {
		t.Fatal("should not be held when every path is healthy")
	}
	if got != 1 {
		t.Errorf("chose path %d, want main (1)", got)
	}
}

func TestFailoverToNextPriorityIsImmediate(t *testing.T) {
	cfg := testConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthDown, 2: model.HealthUp, 3: model.HealthUp})
	e.active = 1

	got, held, _ := e.selectPath(cfg, time.Now())
	if held {
		t.Fatal("a healthy standby path means the system is not held")
	}
	if got != 2 {
		t.Errorf("chose path %d, want lte1 (2); failover must not wait", got)
	}
}

func TestFailoverSkipsToThirdPath(t *testing.T) {
	cfg := testConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthDown, 2: model.HealthDown, 3: model.HealthUp})
	e.active = 2

	got, _, _ := e.selectPath(cfg, time.Now())
	if got != 3 {
		t.Errorf("chose path %d, want lte2 (3)", got)
	}
}

func TestFailbackWaitsForHoldDown(t *testing.T) {
	cfg := testConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthUp, 2: model.HealthUp, 3: model.HealthUp})
	e.active = 2 // currently on LTE1 after a main-link outage

	// The main link has only just come back. Switching now would risk flapping straight
	// back if it is still marginal, so the hold-down must keep us on LTE1.
	e.trackers[1].cleanSince = time.Now().Add(-10 * time.Second)
	if got, _, _ := e.selectPath(cfg, time.Now()); got != 2 {
		t.Errorf("chose path %d during hold-down, want to stay on lte1 (2)", got)
	}

	// Once it has been continuously clean past the hold-down, fail back.
	e.trackers[1].cleanSince = time.Now().Add(-91 * time.Second)
	if got, _, _ := e.selectPath(cfg, time.Now()); got != 1 {
		t.Errorf("chose path %d after hold-down, want main (1)", got)
	}
}

func TestFailbackHoldDownResetsOnLoss(t *testing.T) {
	cfg := testConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthUp, 2: model.HealthUp})
	e.active = 2
	e.trackers[1].cleanSince = time.Now().Add(-2 * time.Hour)

	// A single lost probe ends the clean streak, so the hold-down starts over
	// rather than a marginal link qualifying on a technicality.
	e.trackers[1].Observe(Result{PathID: 1, Lost: true, At: time.Now()}, time.Now())
	if got, _, _ := e.selectPath(cfg, time.Now()); got != 2 {
		t.Errorf("chose path %d, want to stay on lte1 (2) after the streak broke", got)
	}
}

func TestQuotaBlockedPathIsSkipped(t *testing.T) {
	cfg := testConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthDown, 2: model.HealthUp, 3: model.HealthUp})
	e.blocks[2] = model.BlockQuota

	got, held, _ := e.selectPath(cfg, time.Now())
	if held {
		t.Fatal("lte2 is still available")
	}
	if got != 3 {
		t.Errorf("chose path %d, want lte2 (3); an over-quota path must be skipped", got)
	}
}

func TestHeldWhenEverythingIsBlockedByQuota(t *testing.T) {
	cfg := testConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthDown, 2: model.HealthUp, 3: model.HealthUp})
	e.blocks[2] = model.BlockQuota
	e.blocks[3] = model.BlockQuota
	e.active = 2

	got, held, reason := e.selectPath(cfg, time.Now())
	if !held {
		t.Fatal("no eligible path should put the system in the held state")
	}
	if got != 0 {
		t.Errorf("held state must not choose a path, got %d", got)
	}
	// The distinction matters: the operator needs to know this is a policy
	// decision they can override, not a dead link they cannot.
	if !contains(reason, "over quota") {
		t.Errorf("reason %q should say the healthy paths are over quota", reason)
	}
}

func TestHeldWhenEverythingIsUnreachable(t *testing.T) {
	cfg := testConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthDown, 2: model.HealthDown, 3: model.HealthDown})
	e.active = 1

	_, held, reason := e.selectPath(cfg, time.Now())
	if !held {
		t.Fatal("all paths down should be held")
	}
	if contains(reason, "over quota") {
		t.Errorf("reason %q should not blame quota when the links are dead", reason)
	}
}

func TestDeadManKeepsLastRoute(t *testing.T) {
	cfg := testConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthDown, 2: model.HealthDown, 3: model.HealthDown})
	e.active = 2

	got, held, _ := e.selectPath(cfg, time.Now())
	if !held || got != 0 {
		t.Fatalf("expected held with no new choice, got chosen=%d held=%v", got, held)
	}
	// Returning 0 means the caller leaves e.active alone, so the last route
	// stays installed instead of traffic being blackholed.
	if e.active != 2 {
		t.Errorf("active path changed to %d during a total outage", e.active)
	}
}

func TestPinOverridesPriority(t *testing.T) {
	cfg := testConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthUp, 2: model.HealthUp, 3: model.HealthUp})
	e.pinned = 3

	got, held, _ := e.selectPath(cfg, time.Now())
	if held {
		t.Fatal("a pin is an explicit operator choice, not a held state")
	}
	if got != 3 {
		t.Errorf("chose path %d, want the pinned lte2 (3)", got)
	}
}

func TestDisabledPathIsNeverChosen(t *testing.T) {
	cfg := testConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthUp, 2: model.HealthUp, 3: model.HealthUp})
	e.blocks[1] = model.BlockDisabled

	got, _, _ := e.selectPath(cfg, time.Now())
	if got != 2 {
		t.Errorf("chose path %d, want lte1 (2) with main disabled", got)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
