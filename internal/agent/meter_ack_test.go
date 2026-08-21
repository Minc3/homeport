package agent

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/quinlan102/homeport/internal/proto"
)

func testMeter(t *testing.T) *Meter {
	t.Helper()
	return NewMeter(slog.New(slog.NewTextHandler(io.Discard, nil)),
		filepath.Join(t.TempDir(), "usage-buffer.jsonl"))
}

// A delta stays buffered until the frontend's ack covers it. Dropping it on a
// successful send was the old behaviour, and it lost the batch in flight at
// every disconnect: a write that returns nil only means the bytes reached the
// local send buffer, and a failover kills the connection at exactly the moment
// the metered usage it caused is being reported.
func TestAckAppliedDropsOnlyWhatTheAckCovers(t *testing.T) {
	m := testMeter(t)
	m.pending = []proto.UsageDelta{
		{PathID: 2, Bytes: 10, Sequence: 1},
		{PathID: 2, Bytes: 20, Sequence: 2},
		{PathID: 2, Bytes: 30, Sequence: 3},
		{PathID: 3, Bytes: 40, Sequence: 1},
	}

	// The ack covers path 2 up to sequence 2 and says nothing about path 3, so
	// path 2's third delta and everything of path 3's must stay for resending.
	m.AckApplied(map[int]uint64{2: 2})

	got := m.Pending()
	if len(got) != 2 {
		t.Fatalf("pending = %v, want the unacked two", got)
	}
	if got[0].PathID != 2 || got[0].Sequence != 3 {
		t.Errorf("path 2's unacked delta was dropped; pending = %v", got)
	}
	if got[1].PathID != 3 || got[1].Sequence != 1 {
		t.Errorf("path 3 was never acked and must keep its delta; pending = %v", got)
	}
}
