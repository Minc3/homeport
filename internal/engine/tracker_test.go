package engine

import (
	"testing"
	"time"

	"github.com/quinlan102/homeport/internal/model"
)

func testTracker() *Tracker {
	cfg := model.Defaults()
	return NewTracker(cfg.Paths[0], cfg.Probe, cfg.Failover)
}

// base is a fixed reference time. Tests drive the tracker with explicit
// timestamps rather than the wall clock, which keeps them independent of the
// host's timer granularity.
var base = time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC)

func feed(tr *Tracker, n int, lost bool, rtt time.Duration) {
	feedAt(tr, base, n, lost, rtt)
}

func feedAt(tr *Tracker, at time.Time, n int, lost bool, rtt time.Duration) time.Time {
	for i := 0; i < n; i++ {
		at = at.Add(250 * time.Millisecond)
		tr.Observe(Result{PathID: 1, Seq: uint64(i), Lost: lost, RTT: rtt, At: at}, at)
	}
	return at
}

func TestTrackerComesUpAfterRecoverThreshold(t *testing.T) {
	tr := testTracker()
	feed(tr, 9, false, 20*time.Millisecond)
	if tr.Health() == model.HealthUp {
		t.Error("came up before the recover threshold was met")
	}
	feed(tr, 1, false, 20*time.Millisecond)
	if tr.Health() != model.HealthUp {
		t.Errorf("health = %s, want up after 10 clean probes", tr.Health())
	}
}

func TestTrackerGoesDownAfterFailThreshold(t *testing.T) {
	tr := testTracker()
	feed(tr, 10, false, 20*time.Millisecond)

	feed(tr, 7, true, 0)
	if tr.Health() == model.HealthDown {
		t.Error("condemned the path one probe early")
	}
	if tr.Health() != model.HealthSuspect {
		t.Errorf("health = %s, want suspect while losses accumulate", tr.Health())
	}

	feed(tr, 1, true, 0)
	if tr.Health() != model.HealthDown {
		t.Errorf("health = %s, want down after 8 consecutive losses", tr.Health())
	}
}

func TestSingleLossDoesNotCondemn(t *testing.T) {
	tr := testTracker()
	feed(tr, 10, false, 20*time.Millisecond)
	feed(tr, 1, true, 0)
	if tr.Health() == model.HealthDown {
		t.Error("one lost probe must not take a path down")
	}
}

func TestCleanStreakResetsOnLoss(t *testing.T) {
	tr := testTracker()
	at := feedAt(tr, base, 10, false, 20*time.Millisecond)
	if tr.CleanFor(at.Add(time.Minute)) != time.Minute {
		t.Fatalf("clean streak = %v, want a minute of clean time", tr.CleanFor(at.Add(time.Minute)))
	}
	at = feedAt(tr, at, 1, true, 0)
	if tr.CleanFor(at) != 0 {
		t.Error("a lost probe must end the clean streak used for failback hold-down")
	}
}

func TestSuspectPathStaysUsable(t *testing.T) {
	tr := testTracker()
	at := feedAt(tr, base, 10, false, 20*time.Millisecond)
	feedAt(tr, at, 1, true, 0)

	// One dropped packet demotes the path to suspect, but it must remain
	// selectable. Treating a single loss as disqualifying would abandon the
	// active tunnel constantly - LTE loses the occasional packet as a matter
	// of course.
	if tr.Health() != model.HealthSuspect {
		t.Fatalf("health = %s, want suspect", tr.Health())
	}
	if !tr.Usable() {
		t.Error("a suspect path must still be usable, or one lost probe triggers a failover")
	}
}

func TestDownPathIsNotUsable(t *testing.T) {
	tr := testTracker()
	at := feedAt(tr, base, 10, false, 20*time.Millisecond)
	feedAt(tr, at, 8, true, 0)
	if tr.Usable() {
		t.Error("a condemned path must not be usable")
	}
}

func TestCircuitBreakerQuarantinesFlappingPath(t *testing.T) {
	cfg := model.Defaults()
	cfg.Failover.FlapThreshold = 2
	cfg.Failover.QuarantineSec = 60
	tr := NewTracker(cfg.Paths[0], cfg.Probe, cfg.Failover)

	at := base
	for i := 0; i < 2; i++ {
		at = feedAt(tr, at, cfg.Probe.RecoverThreshold, false, 20*time.Millisecond)
		at = feedAt(tr, at, cfg.Probe.FailThreshold, true, 0)
	}
	if !tr.Quarantined(at) {
		t.Fatal("a path that failed twice inside the window should be quarantined")
	}
	// The cooldown is finite: the path becomes selectable again on its own.
	if tr.Quarantined(at.Add(61 * time.Second)) {
		t.Error("quarantine should expire after its cooldown")
	}
	tr.ClearQuarantine()
	if tr.Quarantined(at) {
		t.Error("clearing the quarantine should lift it immediately")
	}
}

func TestQuarantineBackoffGrows(t *testing.T) {
	cfg := model.Defaults()
	cfg.Failover.FlapThreshold = 1
	cfg.Failover.QuarantineSec = 60
	cfg.Failover.QuarantineMaxSec = 3600
	tr := NewTracker(cfg.Paths[0], cfg.Probe, cfg.Failover)

	at := feedAt(tr, base, cfg.Probe.RecoverThreshold, false, 20*time.Millisecond)
	at = feedAt(tr, at, cfg.Probe.FailThreshold, true, 0)
	first := tr.quarantineUntil.Sub(at)

	at = feedAt(tr, at, cfg.Probe.RecoverThreshold, false, 20*time.Millisecond)
	at = feedAt(tr, at, cfg.Probe.FailThreshold, true, 0)
	second := tr.quarantineUntil.Sub(at)

	// A path that keeps flapping gets parked for longer each time, so the
	// system stops paying the cost of switching to it over and over.
	if second <= first {
		t.Errorf("second quarantine %v should exceed the first %v", second, first)
	}
}

func TestDegradedOnHighLoss(t *testing.T) {
	cfg := model.Defaults()
	cfg.Probe.MaxLossPct = 15
	tr := NewTracker(cfg.Paths[0], cfg.Probe, cfg.Failover)

	// Sprinkle losses through the window so the path is still reachable but
	// clearly unfit to carry a game server. It sits at suspect rather than up,
	// which is still selectable - the degraded block is what takes it out.
	at := base
	for i := 0; i < 60; i++ {
		at = at.Add(250 * time.Millisecond)
		tr.Observe(Result{PathID: 1, Seq: uint64(i), Lost: i%4 == 0, RTT: 20 * time.Millisecond, At: at}, at)
	}
	if !tr.Usable() {
		t.Fatalf("health = %s, want a reachable path", tr.Health())
	}
	if !tr.Degraded() {
		t.Error("25% loss should mark the path degraded")
	}
}

func TestNotDegradedOnCleanPath(t *testing.T) {
	tr := testTracker()
	feed(tr, 30, false, 20*time.Millisecond)
	if tr.Degraded() {
		t.Error("a clean, fast path must not be marked degraded")
	}
}

func TestDegradedOnHighLatency(t *testing.T) {
	cfg := model.Defaults()
	cfg.Probe.MaxRTTMs = 400
	tr := NewTracker(cfg.Paths[0], cfg.Probe, cfg.Failover)

	feed(tr, 30, false, 900*time.Millisecond)
	if !tr.Degraded() {
		t.Error("900ms round trips should mark the path degraded")
	}
}

func TestWindowStats(t *testing.T) {
	w := NewWindow(10)
	for i := 0; i < 8; i++ {
		w.Add(Result{RTT: 20 * time.Millisecond})
	}
	w.Add(Result{Lost: true})
	w.Add(Result{Lost: true})

	loss, rtt, _ := w.Stats()
	if loss != 20 {
		t.Errorf("loss = %.1f%%, want 20%%", loss)
	}
	if rtt < 19 || rtt > 21 {
		t.Errorf("rtt = %.1fms, want about 20ms", rtt)
	}
}
