package engine

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/quinlan102/homeport/internal/model"
)

// The decision rides on probes and nowhere else, so the backend learns about
// a switch only when the next probe reaches it. A standby path probes every
// 5s, and its send loop picked up the new cadence only after the tick it was
// already waiting on fired. That put up to five seconds between the frontend
// moving the route and the backend moving its replies, during which every
// player stayed frozen, and it was not a number in any setting. A prober now
// sends on entry and on a nudge; with both intervals set far beyond the test,
// those are the only two probes that can arrive, and each is proved from
// outside by watching the socket. No tight timing bound: the assertion is
// that the probe arrives at all inside a generous deadline, where the ticker
// could not have produced it.
func TestDecisionChangeProbesAtOnceRatherThanOnTheStandbyTicker(t *testing.T) {
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer silent.Close()
	port := silent.LocalAddr().(*net.UDPAddr).Port

	cfg := model.Defaults()
	requireMarkedSocket(t, cfg.Paths[0].Mark)

	cfg.Overlay.FrontendIP = "127.0.0.1"
	cfg.Overlay.BackendIP = "127.0.0.1"
	cfg.Overlay.ProbePort = port
	cfg.Probe.ActiveIntervalMs = 30000
	cfg.Probe.StandbyIntervalMs = 30000

	results := make(chan Result, 64)
	pr, err := NewProber(cfg.Paths[0], cfg.Probe, cfg.Overlay, []byte("secret"), results,
		func() (uint16, uint64) { return 1, 1 }, quietLogger())
	if err != nil {
		t.Fatalf("new prober: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pr.Run(ctx)

	buf := make([]byte, 1500)
	_ = silent.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := silent.ReadFrom(buf); err != nil {
		t.Fatalf("no probe within 3s of the prober starting (%v); a new generation is waiting out a full interval before it measures anything", err)
	}

	pr.SetActive(true)
	pr.Nudge()

	_ = silent.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := silent.ReadFrom(buf); err != nil {
		t.Fatalf("no probe within 3s of the nudge (%v); the decision is still waiting on the standby ticker", err)
	}
}

// A nudge on a prober nobody is running must not block the caller. commitSwitch
// nudges every prober under the state lock, and a send that waited on a loop
// that is not there would hold that lock for good.
func TestNudgeNeverBlocks(t *testing.T) {
	cfg := model.Defaults()
	pr, err := NewProber(cfg.Paths[0], cfg.Probe, cfg.Overlay, []byte("secret"), make(chan Result),
		func() (uint16, uint64) { return 0, 0 }, quietLogger())
	if err != nil {
		t.Fatalf("new prober: %v", err)
	}
	done := make(chan struct{})
	go func() {
		for i := 0; i < 10; i++ {
			pr.Nudge()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Nudge blocked with no loop to receive it")
	}
}

// drainWake empties the wake channel and reports whether anything was queued.
func drainWake(e *Engine) bool {
	select {
	case <-e.wake:
		return true
	default:
		return false
	}
}

// Condemning a path is the one moment the decision tick is pure latency: the
// streak that condemned it took DetectMs to build, and the switch away from
// it then waited up to another 500ms for a timer. A transition to down wakes
// the decision loop; a loss that changes nothing does not, because evaluate
// on every lost probe would be a busy loop on a flapping link. The channel is
// drained between checks, because a full one-deep buffer drops further sends
// silently and would otherwise make the negative assertions vacuous.
func TestPathDownWakesTheDecisionLoopOnce(t *testing.T) {
	e, _ := engineForApply(t, map[int]model.Health{1: model.HealthUp, 2: model.HealthUp, 3: model.HealthUp})
	ctx := context.Background()
	cfg := e.cfg

	lost := func(seq uint64) Result {
		return Result{PathID: 1, Seq: seq, Lost: true, At: time.Now()}
	}

	// Every loss short of the threshold: suspect, still selectable, no wake.
	var seq uint64
	for i := 0; i < cfg.Probe.FailThreshold-1; i++ {
		seq++
		e.onResult(ctx, lost(seq))
		if drainWake(e) {
			t.Fatalf("loss %d of %d did not condemn the path but woke the decision loop", i+1, cfg.Probe.FailThreshold)
		}
	}

	seq++
	e.onResult(ctx, lost(seq))
	if !drainWake(e) {
		t.Fatal("path condemned but the decision loop was not woken")
	}

	// Further losses on a path already down change nothing and wake nothing.
	seq++
	e.onResult(ctx, lost(seq))
	if drainWake(e) {
		t.Fatal("a loss on a path already down woke the decision loop; that is the busy loop on a flapping link")
	}
}

// The operator's actions exist to change the decision, and each one used to
// land on the next 500ms tick: pinning a path, approving an overage when
// everything is blocked, revoking one, or clearing a quarantine. Each now
// wakes the loop directly.
func TestOperatorActionsWakeTheDecisionLoop(t *testing.T) {
	e, _ := engineForApply(t, map[int]model.Health{1: model.HealthUp, 2: model.HealthUp, 3: model.HealthUp})
	drainWake(e)

	steps := []struct {
		name string
		do   func() error
	}{
		{"pin", func() error { return e.Pin(2) }},
		{"unpin", func() error { return e.Pin(0) }},
		{"approve", func() error { return e.Approve(2, time.Hour, 0) }},
		{"revoke", func() error { return e.RevokeApproval(2) }},
		{"clear quarantine", func() error { e.ClearQuarantine(1); return nil }},
	}
	for _, s := range steps {
		if err := s.do(); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		if !drainWake(e) {
			t.Errorf("%s did not wake the decision loop", s.name)
		}
	}
}
