package store_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/store"
)

// Every path's sample for one tick lands, under the one timestamp, and reads
// back per path.
//
// The batch exists for the fsync rather than for the SQL: synchronous=FULL
// means a commit per path, five seconds apart forever, with every other reader
// in the process - the portal's own API calls - queued behind each one. What
// that must not cost is the graph, so this pins the rows arriving intact.
func TestPathSamplesForOneTickAreAllRecorded(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	at := time.Now()
	err = st.AddPathSamples(at, []store.PathSample{
		{PathID: 1, RTT: 12, Loss: 0, Jitter: 1, Health: model.HealthUp},
		{PathID: 2, RTT: 48, Loss: 2.5, Jitter: 4, Health: model.HealthSuspect},
		{PathID: 3, RTT: 90, Loss: 100, Jitter: 0, Health: model.HealthDown},
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	since := at.Add(-time.Minute)
	for _, want := range []struct {
		path int
		rtt  float64
	}{{1, 12}, {2, 48}, {3, 90}} {
		pts, err := st.PathHistory(want.path, since, 60)
		if err != nil {
			t.Fatalf("history for path %d: %v", want.path, err)
		}
		if len(pts) != 1 {
			t.Fatalf("path %d read back %d points, want 1: %+v", want.path, len(pts), pts)
		}
		if pts[0].RTT != want.rtt {
			t.Errorf("path %d read back rtt %v, want %v", want.path, pts[0].RTT, want.rtt)
		}
	}
}

// A tick with no paths writes nothing rather than opening a transaction to
// commit an empty one. Reachable on a configuration with no paths, and on the
// tick after a revert freezes the trackers.
func TestAnEmptyPathSampleTickWritesNothing(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if err := st.AddPathSamples(time.Now(), nil); err != nil {
		t.Fatalf("an empty tick errored: %v", err)
	}
}
