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

// overlapRunner reports whether two goroutines were ever inside a system
// command at the same time.
//
// That is the property at stake rather than any particular ordering: every
// fault in this family is two goroutines writing the same route, and which one
// lands last is a matter of timing. The delay widens the window so an unguarded
// interleaving is found rather than merely possible.
type overlapRunner struct {
	mu       sync.Mutex
	inFlight int
	max      int
	delay    time.Duration
}

func (r *overlapRunner) Run(_ context.Context, _ string, _ ...string) (string, error) {
	r.mu.Lock()
	r.inFlight++
	if r.inFlight > r.max {
		r.max = r.inFlight
	}
	r.mu.Unlock()

	time.Sleep(r.delay)

	r.mu.Lock()
	r.inFlight--
	r.mu.Unlock()
	return "", nil
}

func (r *overlapRunner) Applying() bool { return true }

func (r *overlapRunner) peak() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.max
}

// Reconfigure, Revert, evaluate and reconcileRouting all write routes. The
// first two run on HTTP handler goroutines and the last two on Run's, so
// nothing about being on one goroutine protects them from each other.
//
// The two faults this pins are both silent. A settings save landing as a
// failover fires can re-assert the outgoing tunnel over the incoming one, so
// published traffic goes down a link that has just failed while the portal
// shows the new one. A save landing inside a revert is worse: revert records
// dataPlane = false only at the end, so the save puts the ruleset and route
// back, revert then reports the system reverted, and nothing corrects it -
// because the engine believes there is nothing installed.
func TestRouteWritersNeverOverlap(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg := model.Defaults()
	cfg.Mode = model.ModeObserve
	log := quietLogger()
	e := New(log, st, notify.New(log), cfg, []byte("secret"), t.TempDir())

	// The detector goes on the always-real runner, which is the one Reconfigure
	// and Revert never replace, and which carries the overlay address, the
	// sysctls, the probe routes and every removal a revert performs.
	detector := &overlapRunner{delay: time.Millisecond}
	e.real = detector
	e.runner = &stubRunner{}
	e.ifaceExists = func(string) bool { return true }

	ctx := context.Background()
	var wg sync.WaitGroup
	start := make(chan struct{})

	run := func(f func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 4; i++ {
				f()
			}
		}()
	}

	run(func() { _ = e.Reconfigure(cfg) })
	run(func() { e.Revert(ctx) })
	run(func() { e.applySystemConfig(ctx) })
	run(func() { e.evaluate(ctx, time.Now()) })
	run(func() { e.reconcileRouting(ctx) })

	close(start)
	wg.Wait()
	e.stopProbers()

	if peak := detector.peak(); peak != 1 {
		t.Fatalf("%d goroutines were inside a system command at once, want 1", peak)
	}
	if detector.peak() == 0 {
		t.Fatal("the detector saw no commands at all; the test proved nothing")
	}
}
