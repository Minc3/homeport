package engine

import (
	"testing"
	"time"

	"github.com/quinlan102/homeport/internal/model"
)

// qualityConfig is the real deployment with quality selection switched on.
func qualityConfig() model.Config {
	cfg := testConfig()
	cfg.Failover.Selection = model.SelectionQuality
	return cfg
}

// feedQuality drives a tracker's window to a known loss and RTT.
//
// Explicit timestamps rather than the wall clock: on Windows time.Now() returns
// identical values for calls microseconds apart, which is why every tracker
// test in this package is driven this way.
func feedQuality(e *Engine, pathID int, lossPct, rttMs float64, base time.Time) {
	tr := e.trackers[pathID]
	tr.window = NewWindow(100)
	const samples = 100
	lost := int(lossPct / 100 * samples)
	for i := 0; i < samples; i++ {
		r := Result{PathID: pathID, Seq: uint64(i + 1), At: base.Add(time.Duration(i) * time.Second)}
		if i < lost {
			r.Lost = true
		} else {
			r.RTT = time.Duration(rttMs * float64(time.Millisecond))
		}
		tr.window.Add(r)
	}
}

// The preferred link is never second-guessed, however much better a fallback
// measures. Priority order here is the cost order - the main link is unmetered and the
// LTE services are capped - so "better ping" must never be able to move traffic
// onto a metered link and quietly keep it there.
func TestQualityNeverDisplacesThePreferredPath(t *testing.T) {
	cfg := qualityConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthUp, 2: model.HealthUp, 3: model.HealthUp})
	e.active = 1
	base := time.Now().Add(-time.Hour)

	feedQuality(e, 1, 0, 300, base) // main: far worse on paper
	feedQuality(e, 2, 0, 10, base)  // lte1: dramatically better
	feedQuality(e, 3, 0, 12, base)

	// Long after any hold-down would have elapsed.
	for _, at := range []time.Time{time.Now(), time.Now().Add(time.Hour)} {
		if got, _, _ := e.selectPath(cfg, at); got != 1 {
			t.Errorf("chose %d, want main (1); quality must not get a vote while the preferred link is up", got)
		}
	}
}

// Once the preferred link is out, the fallback is chosen on measurements
// instead of on priority order. This is the whole point of the mode: LTE2 with
// a clean line beats LTE1 dropping one packet in ten.
func TestQualityPicksTheBestFallbackWhenThePreferredPathIsDown(t *testing.T) {
	cfg := qualityConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthDown, 2: model.HealthUp, 3: model.HealthUp})
	e.active = 1
	base := time.Now().Add(-time.Hour)

	feedQuality(e, 2, 10, 40, base) // lte1: 10% loss -> 10*25 + 40 = 290
	feedQuality(e, 3, 0, 45, base)  // lte2: clean    -> 45

	got, held, _ := e.selectPath(cfg, time.Now())
	if held {
		t.Fatal("two usable paths remain; must not be held")
	}
	if got != 3 {
		t.Errorf("chose %d, want lte2 (3): the lossy path is worse despite its higher priority", got)
	}
}

// In priority mode the same situation must still pick LTE1. The new policy has
// to be opt-in, not a change to what everyone already runs.
func TestPriorityModeIgnoresQualityEntirely(t *testing.T) {
	cfg := testConfig() // selection defaults to priority
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthDown, 2: model.HealthUp, 3: model.HealthUp})
	e.active = 1
	base := time.Now().Add(-time.Hour)

	feedQuality(e, 2, 10, 40, base)
	feedQuality(e, 3, 0, 45, base)

	if got, _, _ := e.selectPath(cfg, time.Now()); got != 2 {
		t.Errorf("chose %d, want lte1 (2): priority mode must not consult the score", got)
	}
}

// Moving between two fallbacks waits, because a single bad measurement window
// is not evidence and every switch costs players a freeze.
func TestQualityMovesBetweenFallbacksOnlyAfterHoldDown(t *testing.T) {
	cfg := qualityConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthDown, 2: model.HealthUp, 3: model.HealthUp})
	e.active = 2 // running on lte1
	base := time.Now().Add(-time.Hour)

	feedQuality(e, 2, 0, 200, base) // lte1: degraded
	feedQuality(e, 3, 0, 30, base)  // lte2: far better

	now := time.Now()
	if got, _, _ := e.selectPath(cfg, now); got != 2 {
		t.Errorf("chose %d immediately; a better fallback must serve the hold-down first", got)
	}
	later := now.Add(time.Duration(cfg.Failover.HoldDownSec) * time.Second)
	if got, _, _ := e.selectPath(cfg, later); got != 3 {
		t.Errorf("chose %d after the hold-down, want lte2 (3)", got)
	}
}

// A fallback that is merely a little better must not take the traffic. Without
// the margin two similar links trade places on measurement noise, and each swap
// is a visible stall for every connected player.
func TestQualityIgnoresAMarginallyBetterFallback(t *testing.T) {
	cfg := qualityConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthDown, 2: model.HealthUp, 3: model.HealthUp})
	e.active = 2
	base := time.Now().Add(-time.Hour)

	feedQuality(e, 2, 0, 40, base) // lte1: active
	feedQuality(e, 3, 0, 36, base) // lte2: 10% better, margin is 25%

	later := time.Now().Add(time.Duration(cfg.Failover.HoldDownSec*10) * time.Second)
	if got, _, _ := e.selectPath(cfg, later); got != 2 {
		t.Errorf("chose %d, want to stay on lte1 (2): 10%% better does not meet a 25%% margin", got)
	}
}

// Two flawless paths must not trade places. Both score zero and the comparison
// is strict, so neither can displace the other.
func TestQualityDoesNotSwapBetweenTwoFlawlessFallbacks(t *testing.T) {
	cfg := qualityConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthDown, 2: model.HealthUp, 3: model.HealthUp})
	e.active = 2
	base := time.Now().Add(-time.Hour)

	feedQuality(e, 2, 0, 0, base)
	feedQuality(e, 3, 0, 0, base)

	for i := 0; i < 10; i++ {
		if got, _, _ := e.selectPath(cfg, time.Now().Add(time.Duration(i)*time.Minute)); got != 2 {
			t.Fatalf("tick %d chose %d; identical paths must not displace each other", i, got)
		}
	}
}

// Loss has to outrank latency. For a game server a clean 60ms link beats a
// lossy 30ms one, and a scoring function that said otherwise would move traffic
// the wrong way while looking like it was optimising.
func TestQualityPrefersACleanSlowLinkOverALossyFastOne(t *testing.T) {
	cfg := qualityConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthUp, 2: model.HealthUp, 3: model.HealthUp})
	base := time.Now().Add(-time.Hour)

	feedQuality(e, 2, 0, 60, base) // clean, 60ms       -> 60
	feedQuality(e, 3, 5, 30, base) // 5% loss, 30ms     -> 5*25 + 30 = 155

	if e.score(2, cfg) >= e.score(3, cfg) {
		t.Errorf("clean 60ms scored %.0f and lossy 30ms scored %.0f; loss must dominate",
			e.score(2, cfg), e.score(3, cfg))
	}
}

// Failback to the preferred link stays governed by its clean streak, not by its
// score. This is the quota protection: once the main link is healthy the traffic returns
// to the unmetered link even though LTE is measurably faster.
func TestQualityStillFailsBackToTheUnmeteredPathWhenItIsSlower(t *testing.T) {
	cfg := qualityConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthUp, 2: model.HealthUp, 3: model.HealthUp})
	e.active = 2 // failed over to lte1 earlier
	base := time.Now().Add(-time.Hour)

	feedQuality(e, 1, 0, 55, base) // main: healthy but slower
	feedQuality(e, 2, 0, 40, base) // lte1: faster, and metered

	// newTestEngine leaves healthy paths clean for an hour, so the hold-down
	// is long satisfied.
	if got, _, _ := e.selectPath(cfg, time.Now()); got != 1 {
		t.Errorf("chose %d, want main (1); a slower unmetered link must still win the traffic back", got)
	}
}

// The hold-down is measured against the active path being beaten, not against a
// particular challenger. Two fallbacks trading the lead would otherwise restart
// the clock forever and the switch would never happen, however badly the active
// path was performing.
func TestQualityHoldDownSurvivesChallengersTradingPlaces(t *testing.T) {
	cfg := qualityConfig()
	cfg.Paths = append(cfg.Paths, model.PathConfig{
		ID: 4, Name: "lte3", Iface: "wg-lte3", Priority: 4,
		Table: 104, Mark: 0x104, Enabled: true,
	})
	e := newTestEngine(cfg, map[int]model.Health{
		1: model.HealthDown, 2: model.HealthUp, 3: model.HealthUp, 4: model.HealthUp,
	})
	e.active = 2
	base := time.Now().Add(-time.Hour)
	now := time.Now()

	feedQuality(e, 2, 0, 300, base) // lte1: active and bad
	feedQuality(e, 3, 0, 30, base)  // lte2 leads
	feedQuality(e, 4, 0, 35, base)
	e.selectPath(cfg, now) // starts the clock

	// Half way through the hold-down the other challenger takes the lead.
	mid := now.Add(time.Duration(cfg.Failover.HoldDownSec/2) * time.Second)
	feedQuality(e, 4, 0, 25, base)
	if got, _, _ := e.selectPath(cfg, mid); got != 2 {
		t.Fatalf("switched after %v, before the hold-down elapsed", mid.Sub(now))
	}

	done := now.Add(time.Duration(cfg.Failover.HoldDownSec) * time.Second)
	if got, _, _ := e.selectPath(cfg, done); got != 4 {
		t.Errorf("chose %d at the hold-down, want lte3 (4); the change of challenger restarted the clock", got)
	}
}

// Quality selection must not disturb the safety behaviours. Nothing usable
// still means keep the last route rather than withdrawing it.
func TestQualityStillHonoursTheDeadMan(t *testing.T) {
	cfg := qualityConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthDown, 2: model.HealthDown, 3: model.HealthDown})
	e.active = 2

	got, held, reason := e.selectPath(cfg, time.Now())
	if got != 0 || !held {
		t.Errorf("selectPath = (%d, %v), want (0, true) so the caller keeps the last route", got, held)
	}
	if reason == "" {
		t.Error("held state must explain itself")
	}
}

// A pin is an explicit instruction and outranks every policy, including this one.
func TestQualityDoesNotOverrideAPin(t *testing.T) {
	cfg := qualityConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthDown, 2: model.HealthUp, 3: model.HealthUp})
	e.pinned = 2
	base := time.Now().Add(-time.Hour)

	feedQuality(e, 2, 0, 400, base) // pinned path is much worse
	feedQuality(e, 3, 0, 20, base)

	if got, _, _ := e.selectPath(cfg, time.Now()); got != 2 {
		t.Errorf("chose %d, want the pinned lte1 (2) to be honoured", got)
	}
}

// The margin and the hold-down make oscillation on noise impossible, but
// neither caps a genuine alternation - two links really taking turns being much
// better, which is what a carrier working on a tower produces. Without a floor
// that switches traffic every hold-down for as long as the work lasts, and
// every switch is a visible stall for connected players.
func TestQualityWillNotSwitchAgainWithinTheDwell(t *testing.T) {
	cfg := qualityConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthDown, 2: model.HealthUp, 3: model.HealthUp})
	e.active = 3 // just landed on lte2
	base := time.Now().Add(-time.Hour)
	now := time.Now()
	e.lastSwitch = now

	// lte1 is now dramatically better, and stays that way.
	feedQuality(e, 2, 0, 20, base)
	feedQuality(e, 3, 0, 300, base)

	// Well past the hold-down but inside the dwell.
	held := now.Add(time.Duration(cfg.Failover.HoldDownSec+30) * time.Second)
	if got, _, _ := e.selectPath(cfg, held); got != 3 {
		t.Errorf("chose %d at %v after the last switch; the dwell floor was ignored",
			got, held.Sub(now))
	}

	// Once the dwell expires the move happens immediately - the hold-down clock
	// keeps running underneath rather than restarting.
	after := now.Add(time.Duration(cfg.Failover.Quality.MinDwellSec+1) * time.Second)
	if got, _, _ := e.selectPath(cfg, after); got != 2 {
		t.Errorf("chose %d once the dwell expired, want lte1 (2)", got)
	}
}

// The dwell must never delay getting off a path that has stopped working. It
// exists to stop churn between two links that both work, not to sit on a dead
// one because of a timer.
func TestQualityDwellNeverDelaysAFailover(t *testing.T) {
	cfg := qualityConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthDown, 2: model.HealthDown, 3: model.HealthUp})
	e.active = 2
	e.lastSwitch = time.Now() // switched a moment ago

	if got, _, _ := e.selectPath(cfg, time.Now()); got != 3 {
		t.Errorf("chose %d, want lte2 (3) immediately: the active path is unusable", got)
	}
}

// Nor may it delay the return to the preferred path. That is the cost rule and
// it outranks churn control - every second on a metered link costs money.
func TestQualityDwellNeverDelaysFailbackToThePreferredPath(t *testing.T) {
	cfg := qualityConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthUp, 2: model.HealthUp, 3: model.HealthUp})
	e.active = 2
	e.lastSwitch = time.Now()
	base := time.Now().Add(-time.Hour)

	feedQuality(e, 1, 0, 80, base) // main healthy, slower
	feedQuality(e, 2, 0, 30, base)

	if got, _, _ := e.selectPath(cfg, time.Now()); got != 1 {
		t.Errorf("chose %d, want main (1): failback must not wait on the dwell", got)
	}
}
