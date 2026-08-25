package agent

import (
	"testing"
	"time"
)

// The trailing edge is the half both of this package's hand-rolled throttles
// got wrong, and the reason the type exists: a burst that stops inside the
// window used to be counted into a report that never emitted, so five hundred
// refused decisions over five seconds produced one line saying "1". The
// engine pins its copy through the control server's log; this pins the mirror
// directly, so the two cannot drift apart in the half that matters.
func TestAgentThrottleReportsABurstThatStopsInsideTheWindow(t *testing.T) {
	var tr throttle
	if n := tr.take(); n != 1 {
		t.Fatalf("first event reported %d, want 1: the leading edge is immediate", n)
	}
	for i := 0; i < 4; i++ {
		if n := tr.take(); n != 0 {
			t.Fatalf("an event inside the window reported %d, want 0", n)
		}
	}
	if n := tr.flush(); n != 0 {
		t.Fatalf("a flush inside the window emitted %d, want 0", n)
	}
	tr.at = time.Now().Add(-throttleWindow - time.Second)
	if n := tr.flush(); n != 4 {
		t.Fatalf("flush = %d, want the 4 events counted behind the first report", n)
	}
	if n := tr.flush(); n != 0 {
		t.Fatalf("a quiet flush emitted %d, want 0: nothing owing means no line", n)
	}
}
