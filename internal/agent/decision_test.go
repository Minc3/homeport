package agent

import (
	"context"
	"testing"
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
