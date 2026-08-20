package engine

import (
	"context"
	"testing"
	"time"

	"github.com/quinlan102/homeport/internal/model"
)

func TestRevertStaysReverted(t *testing.T) {
	e, runner := engineForApply(t, map[int]model.Health{1: model.HealthUp, 2: model.HealthUp, 3: model.HealthUp})

	// Get to a live state first.
	e.evaluate(context.Background(), time.Now())
	if e.active != 1 {
		t.Fatalf("setup failed, active = %d", e.active)
	}

	e.Revert(context.Background())
	if e.active != 0 {
		t.Fatalf("revert should clear the active path, got %d", e.active)
	}

	before := runner.count("route replace 10.99.0.2/32")
	// The decision loop keeps running after a revert. Without dropping to
	// observe it would notice there is no active path, choose one, and put the
	// route straight back - leaving the host half reverted, with routing
	// restored but nftables gone.
	e.evaluate(context.Background(), time.Now())
	e.evaluate(context.Background(), time.Now())

	if got := runner.count("route replace 10.99.0.2/32"); got != before {
		t.Errorf("revert was undone by the decision loop: %d new route installs", got-before)
	}
	if e.Mode() != model.ModeObserve {
		t.Errorf("mode = %s after revert, want observe", e.Mode())
	}
}

func TestPinnedPathDownRaisesTheAlarm(t *testing.T) {
	e, _ := engineForApply(t, map[int]model.Health{1: model.HealthUp, 2: model.HealthDown, 3: model.HealthUp})
	e.pinned = 2

	chosen, held, reason := e.selectPath(e.cfg, time.Now())

	// The pin is honoured - it is an explicit instruction - but a pinned path
	// that has gone down is an outage, and staying quiet about it would mean
	// nobody finds out until players complain.
	if chosen != 2 {
		t.Errorf("chosen = %d, want the pinned path 2 to be honoured", chosen)
	}
	if !held {
		t.Error("a pinned path that is not usable must raise the held alarm")
	}
	if reason == "" {
		t.Error("held reason should explain that the pin is the problem")
	}
}

func TestPinnedPathHealthyIsNotHeld(t *testing.T) {
	e, _ := engineForApply(t, map[int]model.Health{1: model.HealthUp, 2: model.HealthUp, 3: model.HealthUp})
	e.pinned = 3

	chosen, held, _ := e.selectPath(e.cfg, time.Now())
	if chosen != 3 || held {
		t.Errorf("chosen = %d held = %v, want the pin honoured quietly", chosen, held)
	}
}

func TestBackendUpSurvivesAReconnect(t *testing.T) {
	e, _ := engineForApply(t, map[int]model.Health{})

	e.SetBackendUp(true) // first connection
	if !e.Status().BackendUp {
		t.Fatal("backend should be up after connecting")
	}

	// The backend reconnects: the new connection registers before the old
	// one's deferred teardown runs.
	e.SetBackendUp(true)  // new connection
	e.SetBackendUp(false) // stale connection tearing down
	if !e.Status().BackendUp {
		t.Error("a stale connection's teardown must not mark a live backend unreachable")
	}

	e.SetBackendUp(false) // the real disconnect
	if e.Status().BackendUp {
		t.Error("backend should be down once every connection has gone")
	}

	// Counting must not go negative, or an extra teardown would leave the
	// portal permanently unable to show the backend as connected.
	e.SetBackendUp(false)
	e.SetBackendUp(true)
	if !e.Status().BackendUp {
		t.Error("connection counter went negative")
	}
}

func TestQuarantineBackoffDoesNotOverflow(t *testing.T) {
	cfg := model.Defaults()
	cfg.Failover.FlapThreshold = 1
	cfg.Failover.QuarantineSec = 300
	cfg.Failover.QuarantineMaxSec = 3600
	tr := NewTracker(cfg.Paths[0], cfg.Probe, cfg.Failover)

	// A path that flaps for weeks drives the level far past 63. Shifting by
	// that much overflows to a negative or zero duration, which slips past the
	// clamp and switches the circuit breaker off entirely - on exactly the path
	// that has proved it needs one.
	at := base
	for i := 0; i < 80; i++ {
		at = feedAt(tr, at, cfg.Probe.RecoverThreshold, false, 20*time.Millisecond)
		at = feedAt(tr, at, cfg.Probe.FailThreshold, true, 0)

		d := tr.quarantineUntil.Sub(at)
		if d <= 0 {
			t.Fatalf("quarantine collapsed to %v at level %d", d, tr.quarantineLevel)
		}
		if d > time.Duration(cfg.Failover.QuarantineMaxSec)*time.Second {
			t.Fatalf("quarantine %v exceeded the configured ceiling at level %d", d, tr.quarantineLevel)
		}
	}
}
