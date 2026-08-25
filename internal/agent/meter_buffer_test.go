package agent

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/quinlan102/homeport/internal/proto"
)

// A torn final line must not cost the whole file. writeAtomic syncs before the
// rename, but a crash mid-write is still reachable, and every delta ahead of
// the tear decoded fine - discarding them all threw away exactly the usage the
// buffer exists to protect, the deltas accrued while the frontend was
// unreachable.
func TestLoadKeepsTheDecodedPrefixOfADamagedBuffer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "usage-buffer.jsonl")
	damaged := `{"path_id":2,"bytes":10,"packets":1,"at":1700000000,"seq":1}` + "\n" +
		`{"path_id":2,"bytes":20,"packets":2,"at":1700000010,"seq":2}` + "\n" +
		`{"path_id":2,"byt` // the write died here
	if err := os.WriteFile(path, []byte(damaged), 0o644); err != nil {
		t.Fatal(err)
	}

	m := NewMeter(slog.New(slog.NewTextHandler(io.Discard, nil)), path)
	got := m.Pending()
	if len(got) != 2 {
		t.Fatalf("pending = %v, want the two intact deltas kept", got)
	}
	if got[0].Sequence != 1 || got[1].Sequence != 2 {
		t.Errorf("wrong deltas survived: %v", got)
	}
}

// persist is called from two goroutines - the sample ticker, and the control
// read loop via AckApplied - and unserialised both wrote the same tmp file
// before renaming it over the buffer, so one rename could publish the other's
// half-written file. persistMu holds across the snapshot and the write, so
// however the callers interleave, the file on disk is always one complete
// snapshot.
func TestConcurrentAcksAndSamplesLeaveOneCompleteBufferOnDisk(t *testing.T) {
	m := testMeter(t)
	m.mu.Lock()
	for i := 1; i <= 200; i++ {
		m.pending = append(m.pending, proto.UsageDelta{PathID: 2, Bytes: int64(i), Sequence: uint64(i)})
	}
	m.mu.Unlock()

	var wg sync.WaitGroup
	for g := 0; g < 3; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				m.persist()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 1; i <= 150; i++ {
			m.AckApplied(map[int]uint64{2: uint64(i)})
		}
	}()
	wg.Wait()

	// The final persist runs after every concurrent writer has finished, so
	// the file must decode cleanly and match the buffer exactly.
	m.persist()
	raw, err := os.ReadFile(m.bufferPath)
	if err != nil {
		t.Fatal(err)
	}
	decoded, derr := decodeBuffer(raw)
	if derr != nil {
		t.Fatalf("buffer on disk does not decode: %v", derr)
	}
	if !reflect.DeepEqual(decoded, m.Pending()) {
		t.Errorf("file holds %d deltas, buffer holds %d; the last persist must win",
			len(decoded), len(m.Pending()))
	}
}

// The report loop sends the oldest few hundred deltas per tick. Copying the
// entire backlog - up to maxBuffered - every ten seconds just to slice off its
// front was allocation for nothing, so PendingBatch copies only what will be
// sent.
func TestPendingBatchCopiesOnlyTheOldest(t *testing.T) {
	m := testMeter(t)
	m.mu.Lock()
	for i := 1; i <= 10; i++ {
		m.pending = append(m.pending, proto.UsageDelta{PathID: 2, Bytes: int64(i), Sequence: uint64(i)})
	}
	m.mu.Unlock()

	got := m.PendingBatch(3)
	if len(got) != 3 || got[0].Sequence != 1 || got[2].Sequence != 3 {
		t.Fatalf("batch = %v, want the three oldest", got)
	}
	// It is a copy: the caller hands it to the encoder, and a shared backing
	// array would let a concurrent ack shift deltas underneath the send.
	got[0].Bytes = 999
	if m.Pending()[0].Bytes == 999 {
		t.Error("PendingBatch returned the buffer's own backing array")
	}
	if all := m.PendingBatch(50); len(all) != 10 {
		t.Errorf("a batch larger than the backlog should return all of it, got %d", len(all))
	}
}

// A path the frontend will not accept must not take the whole deployment's
// billing down with it.
//
// `pending` is one FIFO across every path, and PendingBatch used to take a flat
// prefix of it. The frontend's refusals are per-path and deliberate - a bad
// sequence, a dropped path id - but a refused delta is never acked, so it stays
// buffered and another arrives every sample interval. Once the oldest n are all
// that path's, every batch consists solely of deltas that will be refused
// again, and no delta for any path reaches the ledger until maxBuffered evicts
// them days later.
func TestOneStuckPathCannotStarveTheOthersOutOfABatch(t *testing.T) {
	m := NewMeter(slog.New(slog.NewTextHandler(io.Discard, nil)), filepath.Join(t.TempDir(), "buf.jsonl"))

	// Path 2 is stuck: far more unackable deltas than a batch holds, all older
	// than anything else in the buffer.
	var pending []proto.UsageDelta
	for i := 1; i <= 4000; i++ {
		pending = append(pending, proto.UsageDelta{PathID: 2, Sequence: uint64(i), Bytes: 1})
	}
	for i := 1; i <= 40; i++ {
		pending = append(pending, proto.UsageDelta{PathID: 1, Sequence: uint64(i), Bytes: 1})
		pending = append(pending, proto.UsageDelta{PathID: 3, Sequence: uint64(i), Bytes: 1})
	}
	m.mu.Lock()
	m.pending = pending
	m.mu.Unlock()

	batch := m.PendingBatch(500)
	if len(batch) != 500 {
		t.Fatalf("batch = %d deltas, want a full 500; the buffer holds far more", len(batch))
	}

	seen := map[int]int{}
	for _, d := range batch {
		seen[d.PathID]++
	}
	if seen[1] != 40 || seen[3] != 40 {
		t.Errorf("batch carried %d deltas for path 1 and %d for path 3, want all 40 of each; "+
			"a stuck path crowded out every other path's usage", seen[1], seen[3])
	}
	// And the rest of the batch is still filled from the stuck path, so a
	// genuine single-path backlog drains at the full rate rather than at a
	// share of it.
	if seen[2] != 500-80 {
		t.Errorf("batch carried %d deltas for the stuck path, want %d; the leftover was not filled", seen[2], 500-80)
	}

	// Order within a path is what the frontend's watermark requires: it applies
	// deltas in sequence order and skips anything not strictly newer.
	last := map[int]uint64{}
	for _, d := range batch {
		if d.Sequence <= last[d.PathID] {
			t.Fatalf("path %d went backwards: %d after %d", d.PathID, d.Sequence, last[d.PathID])
		}
		last[d.PathID] = d.Sequence
	}
}

// A buffer holding one path must not pay for the fairness above: the share is
// the whole batch, so the result has to be the same flat prefix it always was.
//
// Not the ordinary site, which is what this said for two commits. model.Defaults
// meters two paths and Meter.sample emits a delta for every metered path with
// traffic in one pass, so an ordinary deployment always has at least two ids
// buffered. This covers a site with one metered link, or a backlog that has
// drained down to one path.
func TestASinglePathBacklogStillDrainsAsAFlatPrefix(t *testing.T) {
	m := NewMeter(slog.New(slog.NewTextHandler(io.Discard, nil)), filepath.Join(t.TempDir(), "buf.jsonl"))

	var pending []proto.UsageDelta
	for i := 1; i <= 2000; i++ {
		pending = append(pending, proto.UsageDelta{PathID: 2, Sequence: uint64(i), Bytes: 1})
	}
	m.mu.Lock()
	m.pending = pending
	m.mu.Unlock()

	batch := m.PendingBatch(500)
	if len(batch) != 500 {
		t.Fatalf("batch = %d deltas, want 500", len(batch))
	}
	for i, d := range batch {
		if d.Sequence != uint64(i+1) {
			t.Fatalf("batch[%d] has sequence %d, want %d; a single-path backlog must come off the front in order", i, d.Sequence, i+1)
		}
	}
}
