package engine

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/notify"
	"github.com/quinlan102/homeport/internal/proto"
	"github.com/quinlan102/homeport/internal/quota"
	"github.com/quinlan102/homeport/internal/store"
)

func controlServerForUsage(t *testing.T) (*ControlServer, *Engine) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	log := quietLogger()
	e := New(log, st, notify.New(log), model.Defaults(), []byte("secret"), t.TempDir())
	return &ControlServer{eng: e, log: log}, e
}

// The ack is the backend's permission to drop its buffered copy, so it must
// name exactly what is durably in the ledger - and a resent batch must neither
// double-count nor be acked short, because the backend resends everything the
// last ack did not cover.
func TestApplyUsageAcksWhatIsInTheLedgerAndDedupesResends(t *testing.T) {
	s, e := controlServerForUsage(t)
	now := time.Now()
	batch := proto.Usage{Deltas: []proto.UsageDelta{
		{PathID: 2, Bytes: 1000, Packets: 10, AtUnix: now.Unix(), Sequence: 1},
		{PathID: 2, Bytes: 2000, Packets: 20, AtUnix: now.Unix(), Sequence: 2},
	}}

	ack := s.applyUsage(batch)
	if got := ack.Seqs[2]; got != 2 {
		t.Fatalf("ack for path 2 = %d, want 2", got)
	}
	// The watermark travels into the ledger transaction rather than being
	// written afterwards. Written separately, a crash between the two writes
	// left a watermark behind the ledger, and the resent batch - the backend
	// resends everything unacked - was billed a second time.
	if got := e.Store().Meta("usage_seq:2"); got != "2" {
		t.Fatalf("watermark = %q, want 2 recorded with the ledger", got)
	}

	p, _ := e.Config().PathByID(2)
	start, _ := quota.PeriodBounds(p.Quota, now)
	used, err := e.Store().Usage(2, start)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	if used <= 0 {
		t.Fatal("nothing reached the ledger")
	}

	// The same batch again is what a backend that never saw the ack sends. It
	// must not double-count, and the ack must still cover it - a batch of pure
	// resends is how that backend finally learns it may stop.
	ack = s.applyUsage(batch)
	if got := ack.Seqs[2]; got != 2 {
		t.Errorf("resend acked %d, want the standing watermark 2", got)
	}
	again, err := e.Store().Usage(2, start)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	if again != used {
		t.Errorf("a resent batch changed the ledger: %d -> %d", used, again)
	}
}

// A delta for an unmetered path is discardable, and the ack has to say so - a
// held-back ack would have the backend resending it forever.
func TestApplyUsageAcksUnmeteredDeltasSoTheyStopBeingResent(t *testing.T) {
	s, e := controlServerForUsage(t)
	ack := s.applyUsage(proto.Usage{Deltas: []proto.UsageDelta{
		{PathID: 1, Bytes: 1000, Packets: 10, AtUnix: time.Now().Unix(), Sequence: 7},
	}})
	if got := ack.Seqs[1]; got != 7 {
		t.Errorf("unmetered delta acked as %d, want 7", got)
	}
	// Discarded deltas still advance the durable watermark, so a restarted
	// frontend keeps filtering their resends too.
	if got := e.Store().Meta("usage_seq:1"); got != "7" {
		t.Errorf("watermark = %q, want 7", got)
	}
}
