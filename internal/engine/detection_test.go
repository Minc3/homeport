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
// player stayed frozen, and it was not a number in any setting. Nudge sends at
// once; this test proves it from outside by watching the socket.
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
	// Both cadences far longer than the test, so the only probe that can
	// arrive is the one the nudge sends.
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

	// Nothing should arrive on its own: the ticker is 30s away.
	buf := make([]byte, 1500)
	_ = silent.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err := silent.ReadFrom(buf); err == nil {
		t.Fatal("a probe arrived before the nudge, so the test is not measuring the nudge")
	}

	pr.SetActive(true)
	pr.Nudge()

	_ = silent.SetReadDeadline(time.Now().Add(2 * time.Second))
	start := time.Now()
	if _, _, err := silent.ReadFrom(buf); err != nil {
		t.Fatalf("no probe within 2s of the nudge (%v); the decision is still waiting on the standby ticker", err)
	}
	if took := time.Since(start); took > 500*time.Millisecond {
		t.Fatalf("probe took %v to follow the nudge", took)
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

// Condemning a path is the one moment the decision tick is pure latency: the
// streak that condemned it took DetectSeconds to build, and the switch away
// from it then waited up to another 500ms for a timer. A transition to down
// wakes the decision loop; a loss that changes nothing does not, because
// evaluate on every lost probe would be a busy loop on a flapping link.
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
	}
	if len(e.wake) != 0 {
		t.Fatal("a loss that did not condemn the path woke the decision loop")
	}

	seq++
	e.onResult(ctx, lost(seq))
	if len(e.wake) != 1 {
		t.Fatalf("path condemned but the decision loop was not woken (%d queued)", len(e.wake))
	}

	// Further losses on a path already down change nothing and add nothing.
	seq++
	e.onResult(ctx, lost(seq))
	if len(e.wake) != 1 {
		t.Fatalf("wake queued %d deep; it must coalesce", len(e.wake))
	}
}
