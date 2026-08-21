package agent

import (
	"io"
	"log/slog"
	"os"
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

// The buffer file holds one JSON object per line, which is what its .jsonl
// name promises - but older builds wrote a single JSON array under the same
// name, and an upgrade must not discard the deltas that build had buffered:
// they exist precisely because they could not be delivered yet.
func TestBufferLoadsTheLegacyArrayFormatAndWritesJSONLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "usage-buffer.jsonl")
	legacy := `[{"path_id":2,"bytes":10,"packets":1,"at":1700000000,"seq":1},` +
		`{"path_id":2,"bytes":20,"packets":2,"at":1700000010,"seq":2}]`
	if err := os.WriteFile(path, []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := NewMeter(log, path)
	if got := m.Pending(); len(got) != 2 || got[1].Sequence != 2 {
		t.Fatalf("legacy array buffer not restored; pending = %v", got)
	}

	// Persisting rewrites it as JSON lines, and a fresh meter reads those back.
	m.persist()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if raw[0] == '[' {
		t.Errorf("buffer still written as a JSON array: %s", raw)
	}
	again := NewMeter(log, path)
	if got := again.Pending(); len(got) != 2 || got[0].Bytes != 10 {
		t.Fatalf("JSON-lines buffer not restored; pending = %v", got)
	}
}
