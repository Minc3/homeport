package engine

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/notify"
	"github.com/quinlan102/homeport/internal/store"
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
