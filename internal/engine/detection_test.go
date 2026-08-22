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

// A send the kernel refuses must not spin. The entry nudge removed the one
// delay in the dial/loop cycle, so a synchronous send failure became: dial,
// nudge, fail, return, dial - a core spinning, the 50ms sweep never reached,
// no loss delivered so the path was never condemned through this route, and
// pending growing without bound. Each failed probe is now booked as a loss on
// the spot and the prober holds one interval before rebuilding the socket.
//
// The failure here is a udp4 socket asked to write to an IPv6 address, which
// Go's net package refuses before any syscall, so it is the same on every
// platform and needs no routing to set up.
//
// It starts with one probe already outstanding, because that is how a link
// dies: a probe sent fine and never answered, then the next send refused.
// Results leave in sequence order, so that probe has to time out before any
// of the booked losses behind it can be delivered, and only expire does
// that. The first version of this fix ran expire only from the loop's sweep
// ticker, which the failing entry nudge never let it reach: every loss was
// booked, none was delivered, and this test passed because it began with an
// empty queue.
func TestASendFailureIsBookedAsALossAndHeldForOneInterval(t *testing.T) {
	cfg := model.Defaults()
	requireMarkedSocket(t, cfg.Paths[0].Mark)

	cfg.Overlay.FrontendIP = "127.0.0.1"
	cfg.Overlay.BackendIP = "::1"
	cfg.Probe.ActiveIntervalMs = 200
	cfg.Probe.StandbyIntervalMs = 200
	cfg.Probe.TimeoutMs = 300

	results := make(chan Result, 4096)
	pr, err := NewProber(cfg.Paths[0], cfg.Probe, cfg.Overlay, []byte("secret"), results,
		func() (uint16, uint64) { return 1, 1 }, quietLogger())
	if err != nil {
		t.Fatalf("new prober: %v", err)
	}
	pr.seq = 1
	pr.pending[1] = time.Now() // sent on the socket before this one, never answered
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	pr.Run(ctx)

	// One second at a 200ms hold is five or six attempts. Anything in the
	// hundreds is the spin.
	const most = 12
	var losses int
drain:
	for {
		select {
		case r := <-results:
			if !r.Lost {
				t.Fatalf("a probe that could not be sent was delivered as a reply: %+v", r)
			}
			losses++
		default:
			break drain
		}
	}
	if losses == 0 {
		t.Fatal("no loss delivered for a probe that could not be sent; the path would never be condemned")
	}
	if losses > most {
		t.Fatalf("%d losses in one second at a 200ms interval; the prober is spinning on the send failure", losses)
	}

	pr.mu.Lock()
	seq, pending := pr.seq, len(pr.pending)
	pr.mu.Unlock()
	if seq > most {
		t.Fatalf("%d probes attempted in one second at a 200ms interval; the prober is spinning on the send failure", seq)
	}
	if pending != 0 {
		t.Fatalf("%d probes still pending after their sends failed; they must be resolved as lost, not left for a sweep that never runs", pending)
	}
}

// Recovery is the transition the first pass missed. With every path down the
// route stays on a dead tunnel and the first path back is switched to with no
// hold-down, so the tick was the whole of that delay. A transition into a
// usable state wakes the loop exactly as a transition out of one does; a
// reply that changes nothing does not.
func TestPathRecoveryWakesTheDecisionLoopOnce(t *testing.T) {
	e, _ := engineForApply(t, map[int]model.Health{1: model.HealthDown, 2: model.HealthUp, 3: model.HealthUp})
	ctx := context.Background()
	cfg := e.cfg

	reply := func(seq uint64) Result {
		return Result{PathID: 1, Seq: seq, RTT: 20 * time.Millisecond, At: time.Now()}
	}

	var seq uint64
	for i := 0; i < cfg.Probe.RecoverThreshold-1; i++ {
		seq++
		e.onResult(ctx, reply(seq))
		if drainWake(e) {
			t.Fatalf("reply %d of %d did not recover the path but woke the decision loop", i+1, cfg.Probe.RecoverThreshold)
		}
	}

	seq++
	e.onResult(ctx, reply(seq))
	if !drainWake(e) {
		t.Fatal("path recovered but the decision loop was not woken; in the held state that is the whole of the delay before traffic moves")
	}

	seq++
	e.onResult(ctx, reply(seq))
	if drainWake(e) {
		t.Fatal("a reply on a path already up woke the decision loop")
	}

	// Up to suspect changes nothing the selector reads: both are eligible.
	seq++
	e.onResult(ctx, Result{PathID: 1, Seq: seq, Lost: true, At: time.Now()})
	if drainWake(e) {
		t.Fatal("a single loss demoting up to suspect woke the decision loop; suspect is still selectable")
	}

	// A fresh tracker's first reply is the other entrance to eligibility.
	e.trackers[2] = NewTracker(cfg.Paths[1], cfg.Probe, cfg.Failover)
	e.onResult(ctx, Result{PathID: 2, Seq: 1, RTT: 20 * time.Millisecond, At: time.Now()})
	if !drainWake(e) {
		t.Fatal("a fresh tracker's first reply made the path selectable but did not wake the decision loop")
	}
}

// A settings save changes the selector's inputs as surely as the operator's
// other actions do - a path disabled, priorities reordered, a quota changed -
// and was the one writer not wired to the wake. Disabling the active path
// then waited on the tick for the switch.
func TestReconfigureWakesTheDecisionLoop(t *testing.T) {
	e := engineForProbers(t)
	defer e.stopProbers()
	drainWake(e)

	cfg := e.Config()
	cfg.Paths[0].Enabled = false
	if err := e.Reconfigure(cfg); err != nil {
		t.Fatalf("reconfigure: %v", err)
	}
	if !drainWake(e) {
		t.Fatal("a settings save did not wake the decision loop")
	}
}
