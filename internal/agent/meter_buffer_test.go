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
