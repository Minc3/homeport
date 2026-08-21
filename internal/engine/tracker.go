package engine

import (
	"math"
	"time"

	"github.com/quinlan102/homeport/internal/model"
)

// Tracker is the health state machine for one path.
//
// It answers exactly one question - can traffic get to the backend through
// this tunnel right now - and deliberately knows nothing about quotas,
// priorities or what is currently active. Policy lives in the engine.
type Tracker struct {
	cfg      model.PathConfig
	probeCfg model.ProbeConfig
	failCfg  model.FailoverConfig

	health     model.Health
	consecLoss int
	consecOK   int
	window     *Window

	lastReply  time.Time
	cleanSince time.Time // when the current uninterrupted clean streak began

	// Circuit breaker. A path that fails, recovers, and fails again repeatedly
	// is worse than one that stays down: every oscillation costs a switch and
	// a burst of packet loss. After enough failures in the window it is parked
	// for a cooldown that doubles each time.
	failures        []time.Time
	quarantineUntil time.Time
	quarantineLevel int

	handshakeAge float64
}

// NewTracker creates a tracker for a path.
func NewTracker(p model.PathConfig, probeCfg model.ProbeConfig, failCfg model.FailoverConfig) *Tracker {
	return &Tracker{
		cfg:      p,
		probeCfg: probeCfg,
		failCfg:  failCfg,
		health:   model.HealthUnknown,
		window:   NewWindow(probeCfg.WindowSize),
	}
}

// Transition describes a health change worth logging or alerting on.
type Transition struct {
	Changed    bool
	From, To   model.Health
	Quarantine time.Duration
}

// Observe folds one probe result into the state machine.
func (t *Tracker) Observe(r Result, now time.Time) Transition {
	t.window.Add(r)
	from := t.health

	if r.Lost {
		t.consecLoss++
		t.consecOK = 0
		// Any loss ends the clean streak. Failback to a higher-priority path
		// requires an unbroken streak, so this is what stops a marginal fixed line
		// link from repeatedly stealing traffic back from a working LTE one.
		t.cleanSince = time.Time{}
		if t.health == model.HealthUp {
			t.health = model.HealthSuspect
		}
		if t.consecLoss >= t.probeCfg.FailThreshold && t.health != model.HealthDown {
			t.health = model.HealthDown
			t.recordFailure(now)
			return Transition{Changed: true, From: from, To: t.health, Quarantine: t.quarantineRemaining(now)}
		}
	} else {
		t.consecOK++
		t.consecLoss = 0
		t.lastReply = r.At
		if t.health != model.HealthUp && t.consecOK >= t.probeCfg.RecoverThreshold {
			t.health = model.HealthUp
			t.cleanSince = now
			return Transition{Changed: true, From: from, To: t.health}
		}
		if t.health == model.HealthUnknown && t.consecOK > 0 {
			t.health = model.HealthSuspect
		}
	}
	return Transition{Changed: from != t.health, From: from, To: t.health}
}

func (t *Tracker) recordFailure(now time.Time) {
	window := time.Duration(t.failCfg.FlapWindowSec) * time.Second
	t.failures = append(t.failures, now)
	cutoff := now.Add(-window)
	kept := t.failures[:0]
	for _, f := range t.failures {
		if f.After(cutoff) {
			kept = append(kept, f)
		}
	}
	t.failures = kept

	if t.failCfg.FlapThreshold > 0 && len(t.failures) >= t.failCfg.FlapThreshold {
		base := time.Duration(t.failCfg.QuarantineSec) * time.Second
		max := time.Duration(t.failCfg.QuarantineMaxSec) * time.Second

		// Doubled by multiplication with a ceiling rather than by shifting.
		// A path that flaps for long enough drives the level past 63, and
		// `base << level` then overflows to a negative or zero duration, which
		// slips past the clamp and switches the circuit breaker off entirely -
		// on exactly the path that has proved it needs one.
		d := base
		for i := 0; i < t.quarantineLevel; i++ {
			if max > 0 && d >= max {
				break
			}
			if d > time.Duration(math.MaxInt64)/2 {
				break
			}
			d *= 2
		}
		if max > 0 && d > max {
			d = max
		}
		if d < base {
			d = base
		}

		t.quarantineUntil = now.Add(d)
		t.quarantineLevel++
		t.failures = nil
	}
}

func (t *Tracker) quarantineRemaining(now time.Time) time.Duration {
	if t.quarantineUntil.IsZero() || !now.Before(t.quarantineUntil) {
		return 0
	}
	return t.quarantineUntil.Sub(now)
}

// Retune applies changed thresholds without discarding what is already known
// about the path. Editing a quota or a probe interval is not evidence that a
// link went down, so health, streaks and the circuit breaker are preserved.
func (t *Tracker) Retune(p model.PathConfig, probeCfg model.ProbeConfig, failCfg model.FailoverConfig) {
	t.cfg = p
	t.probeCfg = probeCfg
	t.failCfg = failCfg
	if probeCfg.WindowSize != t.window.size {
		resized := NewWindow(probeCfg.WindowSize)
		for _, e := range t.window.entries {
			resized.Add(e)
		}
		t.window = resized
	}
}

// ClearQuarantine lifts a circuit breaker early, for the portal's override.
func (t *Tracker) ClearQuarantine() {
	t.quarantineUntil = time.Time{}
	t.quarantineLevel = 0
	t.failures = nil
}

// SetHandshakeAge records the backend's report of WireGuard handshake age.
// Displayed for context only; it never influences the routing decision.
func (t *Tracker) SetHandshakeAge(age float64) { t.handshakeAge = age }

// Health returns the current probe verdict.
func (t *Tracker) Health() model.Health { return t.health }

// Usable reports whether the path may carry traffic.
//
// Suspect counts as usable on purpose. Suspect only means a probe has been
// missed recently, and every link loses the occasional packet - LTE routinely
// does. If a single loss made a path ineligible, the active path would be
// abandoned constantly and the system would thrash between tunnels for no
// reason. Sustained trouble is caught two other ways: enough consecutive
// losses condemn the path outright, and the loss and latency thresholds block
// it as degraded.
func (t *Tracker) Usable() bool {
	return t.health == model.HealthUp || t.health == model.HealthSuspect
}

// Degraded reports whether the path is reachable but too poor to carry
// traffic, per the configured loss and latency thresholds.
func (t *Tracker) Degraded() bool {
	if !t.Usable() {
		return false
	}
	loss, rtt, _ := t.window.Stats()
	if t.probeCfg.MaxLossPct > 0 && loss > t.probeCfg.MaxLossPct {
		return true
	}
	if t.probeCfg.MaxRTTMs > 0 && rtt > float64(t.probeCfg.MaxRTTMs) {
		return true
	}
	return false
}

// Score rates the path from its measurements, lower being better. It is only
// consulted in quality selection mode; priority mode never calls it.
//
// The weights are milliseconds-equivalent, so the number is readable: a path
// scoring 40 is about as good as a clean link with 40ms of latency, whatever
// mixture of loss, latency and jitter produced it.
//
// Zero is a perfect path, and deliberately unbeatable - the margin comparison
// is strict, so nothing can take traffic from a path that is losing nothing and
// answering instantly.
func (t *Tracker) Score(q model.QualityConfig) float64 {
	loss, rtt, jitter := t.window.Stats()
	return loss*q.LossWeight + rtt*q.RTTWeight + jitter*q.JitterWeight
}

// CleanFor reports how long the path has been continuously clean. Zero means
// it is not currently clean.
func (t *Tracker) CleanFor(now time.Time) time.Duration {
	if t.cleanSince.IsZero() {
		return 0
	}
	return now.Sub(t.cleanSince)
}

// Quarantined reports whether the circuit breaker is holding this path down.
func (t *Tracker) Quarantined(now time.Time) bool {
	return t.quarantineRemaining(now) > 0
}

// Snapshot renders the tracker for the portal.
func (t *Tracker) Snapshot(now time.Time) model.PathState {
	loss, rtt, jitter := t.window.Stats()
	return model.PathState{
		ID:            t.cfg.ID,
		Name:          t.cfg.Name,
		Iface:         t.cfg.Iface,
		Priority:      t.cfg.Priority,
		Health:        t.health,
		RTTms:         rtt,
		JitterMs:      jitter,
		LossPct:       loss,
		ConsecLoss:    t.consecLoss,
		ConsecOK:      t.consecOK,
		LastReply:     t.lastReply,
		HandshakeAge:  t.handshakeAge,
		CleanSince:    t.cleanSince,
		QuarantineEnd: t.quarantineUntil,
	}
}
