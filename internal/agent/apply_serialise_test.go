package agent

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/quinlan102/homeport/internal/proto"
)

// overlapRunner reports whether two goroutines were ever inside a system
// command at the same time. See the frontend's copy for why that, rather than
// any particular ordering, is the property worth pinning.
type overlapRunner struct {
	mu       sync.Mutex
	inFlight int
	max      int
	calls    int
	delay    time.Duration
}

func (r *overlapRunner) Run(_ context.Context, _ string, _ ...string) (string, error) {
	r.mu.Lock()
	r.calls++
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

func (r *overlapRunner) total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// ApplyConfig runs on the control client's goroutine; applyDecision and
// reconcileRouting run on applyLoop's. Sharing applyLoop was enough to stop a
// repair racing a switch, but not to stop a configuration push racing either.
//
// All three write table 100's default route - the push through
// reassertReturnPath, the other two directly - so a push arriving as a failover
// landed could put the outgoing tunnel back over the incoming one. Every
// published reply would then leave down a link that had just failed: requests
// arriving normally, answers going nowhere, for up to the ten seconds until the
// reconciler next looked.
func TestBackendRouteWritersNeverOverlap(t *testing.T) {
	a, _ := testAgent(t, true)

	detector := &overlapRunner{delay: time.Millisecond}
	a.real = detector
	a.runner = detector

	cfg := proto.BackendConfig{
		Overlay: proto.OverlayInfo{FrontendIP: "10.99.0.1", BackendIP: "10.99.0.2"},
		Paths: []proto.PathInfo{
			{ID: 1, Name: "main", Iface: "wg-main", Table: 101, Mark: 0x101},
			{ID: 2, Name: "lte1", Iface: "wg-lte1", Table: 102, Mark: 0x102},
		},
	}

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

	run(func() { a.ApplyConfig(ctx, cfg) })
	run(func() { a.reconcileRouting(ctx) })
	// Alternating, so each call is a real switch rather than a no-op: a
	// decision that has not changed installs nothing and would race nothing.
	run(func() {
		a.applyDecision(ctx, 1, uint64(time.Now().UnixNano()))
		a.applyDecision(ctx, 2, uint64(time.Now().UnixNano()))
	})

	close(start)
	wg.Wait()

	if peak := detector.peak(); peak != 1 {
		t.Fatalf("%d goroutines were inside a system command at once, want 1", peak)
	}
	if detector.total() == 0 {
		t.Fatal("the detector was never called; the test proved nothing")
	}
}
