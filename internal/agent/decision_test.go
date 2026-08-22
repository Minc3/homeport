package agent

import (
	"context"
	"testing"
	"time"
)

// SetActivePath's pre-filter compares against active and lastSeq, which the
// worker records only after its apply has finished. While it is inside `ip`
// for one decision, a straggling probe carrying the sequence before it still
// passes the filter. The queued decision is the newest the frontend has made
// and must not be replaced by an older one that merely arrived later; the
// frontend's burst on every switch makes this interleaving routine rather
// than rare.
func TestAStaleDecisionCannotReplaceANewerQueuedOne(t *testing.T) {
	a, _ := testAgent(t, true)
	ctx := context.Background()

	a.SetActivePath(ctx, 2, 10)
	a.SetActivePath(ctx, 1, 9) // a late probe from the tunnel just abandoned

	a.pendingMu.Lock()
	d := a.pending
	a.pendingMu.Unlock()
	if d.pathID != 2 || d.seq != 10 {
		t.Fatalf("pending = %+v, want path 2 seq 10; an older decision replaced the newer one", d)
	}

	a.SetActivePath(ctx, 3, 11)
	a.pendingMu.Lock()
	d = a.pending
	a.pendingMu.Unlock()
	if d.pathID != 3 || d.seq != 11 {
		t.Fatalf("pending = %+v, want path 3 seq 11; a newer decision must still replace the queued one", d)
	}
}

// The frontend seeds its sequence from the clock, so a process that switched
// once and was restarted quickly enough hands its successor a first switch
// numbered the same as its own, on a different path. That is a real decision,
// and applyDecision would accept it; a strict guard here refused to queue it,
// so the frontend routed down one tunnel while replies left by another until a
// later switch moved the number on. A straggler is always strictly lower, so
// admitting equal keeps it out all the same.
func TestAnEqualSequenceOnAnotherPathIsStillQueued(t *testing.T) {
	a, _ := testAgent(t, true)
	ctx := context.Background()

	a.SetActivePath(ctx, 2, 10)
	a.SetActivePath(ctx, 1, 10)

	a.pendingMu.Lock()
	d := a.pending
	a.pendingMu.Unlock()
	if d.pathID != 1 || d.seq != 10 {
		t.Fatalf("pending = %+v, want path 1 seq 10; a decision with the same sequence on another path was refused", d)
	}
}

// The same two rules with the worker actually running, which the case above
// never does. It also pins an assumption the guard rests on: the worker takes
// the queued decision and leaves it queued, so the sequence it compares
// against is the last real decision rather than zero.
func TestTheWorkerAppliesTheNewestDecisionAndStragglersNeverReachIt(t *testing.T) {
	a, runner := testAgent(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.applyLoop(ctx)

	waitForActive := func(want int, why string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for a.ActivePath() != want {
			if time.Now().After(deadline) {
				t.Fatalf("active path = %d, want %d: %s", a.ActivePath(), want, why)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	a.SetActivePath(ctx, 2, 10)
	waitForActive(2, "the worker did not apply the queued decision")

	// A straggler from the abandoned tunnel: lower sequence, never applied.
	a.SetActivePath(ctx, 1, 9)
	time.Sleep(50 * time.Millisecond)
	if got := a.ActivePath(); got != 2 {
		t.Fatalf("active path = %d after a stale decision, want 2; a straggler rewound the decision", got)
	}
	if n := runner.count("dev wg-main"); n != 0 {
		t.Fatalf("the stale decision reached the kernel (%d route commands for wg-main)", n)
	}

	// The restarted frontend's first switch: same sequence, different path.
	a.SetActivePath(ctx, 1, 10)
	waitForActive(1, "an equal sequence on another path was never applied; replies stay on the tunnel the frontend has left")
}
