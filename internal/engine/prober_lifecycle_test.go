package engine

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/notify"
	"github.com/quinlan102/homeport/internal/store"
	"github.com/quinlan102/homeport/internal/sysx"
)

// engineForProbers builds an engine whose probers will run for real - they are
// goroutines, not stubs - while every system command goes to a stub runner.
//
// The probe sockets cannot bind, because the overlay address does not exist on
// a development machine. That is the intended shape of the test: Prober.Run
// then sits in its dial/reportUnreachable cycle, which is a goroutine holding a
// context exactly like a working one, and it is the goroutine being counted.
func engineForProbers(t *testing.T) *Engine {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg := model.Defaults()
	log := quietLogger()
	e := New(log, st, notify.New(log), cfg, []byte("secret"), t.TempDir())
	e.runner = &stubRunner{}
	e.real = &stubRunner{}
	e.ifaceExists = func(string) bool { return true }
	return e
}

// waitForProbers polls until the live prober count settles on want.
func waitForProbers(t *testing.T, e *Engine, want int64, why string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		got := e.liveProbers.Load()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %d prober goroutines running, want %d", why, got, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A generation that is replaced without being cancelled probes until the
// process exits, because its context comes from baseCtx and the only handle to
// it has just been overwritten. Nothing reports that: the paths keep measuring,
// so the sole symptom is a standby path on a 5000ms interval reporting every
// 2-3s, the metered quota billed twice for it, and FailThreshold consecutive
// losses reached in half the wall-clock time they were configured for.
func TestStartProbersNeverOrphansAGeneration(t *testing.T) {
	e := engineForProbers(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	e.startProbers(ctx)
	first := e.proberDone
	if first == nil {
		t.Fatal("no generation recorded after startProbers")
	}
	waitForProbers(t, e, int64(len(e.cfg.Paths)), "after the first start")

	// The second start stands in for a caller that reached here without
	// stopping - which is what two interleaved Reconfigure calls produce.
	e.startProbers(ctx)

	done := make(chan struct{})
	go func() { first.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the replaced generation is still running: it was orphaned, not cancelled")
	}

	waitForProbers(t, e, int64(len(e.cfg.Paths)), "after the second start")

	e.stopProbers()
	waitForProbers(t, e, 0, "after stopProbers")
}

// stopProbers must not merely cancel. Until the old generation is actually
// gone it still holds its marked sockets and is still probing, so a replacement
// started underneath it doubles the traffic on every path - briefly, but on
// every settings save, and against the one measurement every failover decision
// is made from.
func TestStopProbersWaitsForTheGenerationToExit(t *testing.T) {
	e := engineForProbers(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	e.startProbers(ctx)
	waitForProbers(t, e, int64(len(e.cfg.Paths)), "after start")

	e.stopProbers()
	if got := e.liveProbers.Load(); got != 0 {
		t.Fatalf("stopProbers returned with %d probers still running; it cancelled but did not wait", got)
	}
}

// Reconfigure is called from HTTP handlers, which net/http serves
// concurrently: a settings save and a mode toggle, or a double-clicked Save.
// Unserialised, the second caller's stopProbers finds the handle already nil,
// cancels nothing, and both callers start a generation - leaving one of them
// running forever.
func TestConcurrentReconfigureLeavesOneProberPerPath(t *testing.T) {
	e := engineForProbers(t)

	cfg := e.Config()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := cfg
			// Alternate the mode, so these are the two handlers that really do
			// race in the portal rather than eight copies of one.
			if i%2 == 0 {
				c.Mode = model.ModeObserve
			} else {
				c.Mode = model.ModeArmed
			}
			if err := e.Reconfigure(c); err != nil {
				t.Errorf("reconfigure: %v", err)
			}
		}(i)
	}
	wg.Wait()

	waitForProbers(t, e, int64(len(cfg.Paths)), "after eight concurrent reconfigures")

	e.stopProbers()
	waitForProbers(t, e, 0, "after stopProbers")
}

// stopProbers must not be left waiting on a read deadline.
//
// Prober.loop was the one read loop here without the close-on-cancel watcher
// invariant 17 describes, relying on its one-second read deadline instead.
// While nothing waited on the probers that cost nothing. stopProbers waits now,
// so the deadline turned into a second of latency on every settings save - and
// it is invisible on a development machine, where the probe sockets cannot bind
// to the overlay address and there is no read loop to wait for at all.
//
// So this one binds real sockets on the loopback and points them at a listener
// that never answers, which is what puts the read loop where it has to be:
// blocked inside ReadFromUDP with the deadline still running.
//
// Both of its assertions are negative - a fast return, and no goroutines left -
// so it passes trivially if no read loop was ever created, which is exactly
// what happens when the sockets fail to bind. That is not hypothetical: the
// probe socket is stamped with the path's fwmark, and on Linux SO_MARK needs
// CAP_NET_ADMIN, so an unprivileged run there took the dial-failure path and
// reported a pass whether or not the watcher this guards existed at all. Hence
// the two checks below - a preflight that skips rather than lies when the
// sockets cannot be marked, and a probe read that proves the loops are real
// before anything is timed.
func TestStopProbersDoesNotWaitOnTheReadDeadline(t *testing.T) {
	// A socket that receives probes and never replies. Without it the sends
	// would draw ICMP port-unreachable, the read would return early, and the
	// test would pass without ever reaching the case it is about.
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer silent.Close()
	port := silent.LocalAddr().(*net.UDPAddr).Port

	requireMarkedSocket(t, model.Defaults().Paths[0].Mark)

	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg := model.Defaults()
	cfg.Overlay.FrontendIP = "127.0.0.1" // bindable here, unlike 10.99.0.1
	cfg.Overlay.BackendIP = "127.0.0.1"
	cfg.Overlay.ProbePort = port
	// The first send waits out one tick, and nothing is active yet, so the
	// shipped 5s standby cadence would put the first probe well past the point
	// this test wants to be measuring at.
	cfg.Probe.ActiveIntervalMs = 50
	cfg.Probe.StandbyIntervalMs = 50

	log := quietLogger()
	e := New(log, st, notify.New(log), cfg, []byte("secret"), t.TempDir())
	e.runner = &stubRunner{}
	e.real = &stubRunner{}
	e.ifaceExists = func(string) bool { return true }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	e.startProbers(ctx)
	waitForProbers(t, e, int64(len(cfg.Paths)), "after start")

	// A probe arriving is the only proof from out here that the sockets bound
	// and the read loops exist. Without it the timing check below measures
	// nothing, because there is no read to be blocked in.
	if err := silent.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, _, err := silent.ReadFrom(make([]byte, 1500)); err != nil {
		t.Fatalf("no probe arrived (%v); the sockets did not bind, so there is no read loop to wait on "+
			"and the timing below would pass without testing anything", err)
	}

	// Let the read loops settle back inside ReadFromUDP rather than still
	// handling the send, so the wait being measured is the one that matters.
	time.Sleep(100 * time.Millisecond)

	start := time.Now()
	e.stopProbers()
	took := time.Since(start)

	// The read deadline is a full second. Anything near it means the sockets
	// are being left to time out instead of being closed.
	if took > 400*time.Millisecond {
		t.Fatalf("stopProbers took %v; it is waiting out the read deadline rather than closing the sockets", took)
	}
	if n := e.liveProbers.Load(); n != 0 {
		t.Fatalf("%d probers still running after stopProbers", n)
	}
}

// requireMarkedSocket skips when this machine cannot open the kind of socket a
// prober opens.
//
// Off Linux sysx.MarkControl is a no-op and this always succeeds. On Linux
// SO_MARK needs CAP_NET_ADMIN, so an unprivileged run cannot bind a probe
// socket at all - and a test whose assertions are both negative would call that
// a pass. Skipping says out loud that the case went unexercised.
func requireMarkedSocket(t *testing.T, mark int) {
	t.Helper()
	lc := net.ListenConfig{Control: sysx.MarkControl(mark)}
	c, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot open an fwmark-stamped socket here (%v); "+
			"the probers would take the dial-failure path and never start a read loop", err)
	}
	_ = c.Close()
}
