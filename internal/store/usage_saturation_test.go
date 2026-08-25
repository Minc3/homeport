package store_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/quinlan102/homeport/internal/store"
)

// The ledger column and the usage_samples read path carry the same values and
// therefore the same hazard, and fixing only the write half missed it.
//
// SQLite does not promote an overflowing SUM the way it promotes a bare +: it
// fails the statement, which takes the portal's usage graph off the air for
// that path until the rows age out thirteen months later. Neither cap can be a
// per-row one, because in both cases the rows accumulate - in a column on one
// side, inside a query on the other.
func TestNeitherLedgerNorHistoryBreaksOnSaturatedUsage(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	now := time.Now()
	// The most one delta can carry after the engine's own clamps.
	const perDelta = int64(720752316243935232)
	for i := 0; i < 40; i++ {
		if err := st.AddUsage(2, now, perDelta, perDelta, now, "", ""); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}

	used, err := st.Usage(2, now)
	if err != nil {
		t.Fatalf("the ledger column is unreadable: %v", err)
	}
	if used != store.MaxLedgerValue {
		t.Errorf("ledger = %d, want it saturated at %d", used, int64(store.MaxLedgerValue))
	}

	points, err := st.UsageHistory(2, now.Add(-time.Hour), 3600)
	if err != nil {
		t.Fatalf("the portal's usage graph is broken: %v", err)
	}
	if len(points) == 0 {
		t.Fatal("no history points came back")
	}
	for _, p := range points {
		if p.Bytes < 0 || p.Bytes > store.MaxLedgerValue {
			t.Errorf("history bucket holds %d, outside 0..%d", p.Bytes, int64(store.MaxLedgerValue))
		}
	}
}

// An ordinary figure is not moved by either cap.
func TestOrdinaryUsageIsUnaffectedBySaturation(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	now := time.Now()
	for i := 0; i < 3; i++ {
		if err := st.AddUsage(2, now, 5<<30, 4_000_000, now, "", ""); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	if used, err := st.Usage(2, now); err != nil || used != 15<<30 {
		t.Errorf("ledger = %d (err %v), want %d", used, err, int64(15)<<30)
	}
	points, err := st.UsageHistory(2, now.Add(-time.Hour), 3600)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	var total int64
	for _, p := range points {
		total += p.Bytes
	}
	if total != 15<<30 {
		t.Errorf("history totals %d, want %d", total, int64(15)<<30)
	}
}

// The other end of the same column, and the direction that had no bound at all.
//
// The ceiling was here first, which made this method look like it enforced its
// own bounds when it enforced half of them. The floor matters more than the
// ceiling does: this column accumulates, so a negative figure does not record a
// wrong number for one sample, it erases usage already billed and the first
// anybody hears of it is the carrier's invoice. The engine clamps before it
// calls this, which is exactly why the omission survived - the guarantee was
// living in a caller three files away.
func TestTheLedgerCannotBeDrivenBelowZero(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	now := time.Now()
	if err := st.AddUsage(2, now, 8<<30, 1000, now, "", ""); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := st.AddUsage(2, now, -(600 << 30), -50_000, now, "", ""); err != nil {
		t.Fatalf("negative delta: %v", err)
	}

	used, err := st.Usage(2, now)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	if used != 8<<30 {
		t.Errorf("ledger = %d bytes, want the 8 GiB already billed left alone", used)
	}
	pkts, err := st.UsagePackets(2, now)
	if err != nil {
		t.Fatalf("read ledger packets: %v", err)
	}
	if pkts != 1000 {
		t.Errorf("ledger = %d packets, want 1000; the packet column is what quota.Metered multiplies by the per-packet overhead", pkts)
	}

	// And the accumulated sum has a floor of its own, not only the parameters:
	// a row already at zero must not be driven under by the next delta either.
	if err := st.AddUsage(2, now, -1, -1, now, "", ""); err != nil {
		t.Fatalf("second negative delta: %v", err)
	}
	if used, err := st.Usage(2, now); err != nil || used != 8<<30 {
		t.Errorf("ledger = %d bytes (err %v), want 8 GiB", used, err)
	}
}

// The saturation tests above drive Store.AddUsage, and for a while that was the
// method nothing in production called: the engine had been rewritten to go
// through AddUsageBatch, which held its own copy of the same SQL. So every
// bound this file exists to pin was pinned on a dead path, and dropping the
// floor or the ceiling from the live one left the suite green.
//
// AddUsage is a batch of one now, so those tests cover both. This one drives
// the batch entry point directly, because "both" is only true while that
// remains a fact about the code rather than about this comment.
func TestTheBatchEntryPointCarriesTheSameBounds(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	now := time.Now()
	const perDelta = int64(720752316243935232)
	// Enough entries that the usage_samples SUM overflows an int64, not merely
	// enough that the ledger column saturates. The two are different hazards and
	// the first version of this test only reached the second: three entries came
	// to 2.16e18, comfortably inside int64, so the UsageHistory assertion below
	// passed with or without the CAST that makes it safe. Twenty entries come to
	// 1.4e19, which is past it.
	var entries []store.UsageEntry
	for i := 0; i < 20; i++ {
		entries = append(entries, store.UsageEntry{
			PeriodStart: now, At: now, Bytes: perDelta, Packets: perDelta,
		})
	}
	// The floor, in the same transaction as the ceiling, because a batch is
	// where the two can meet.
	entries = append(entries, store.UsageEntry{
		PeriodStart: now, At: now, Bytes: -(600 << 30), Packets: -50_000,
	})
	if err := st.AddUsageBatch(2, entries, "usage_seq:2", "9"); err != nil {
		t.Fatalf("batch: %v", err)
	}

	used, err := st.Usage(2, now)
	if err != nil {
		t.Fatalf("the ledger column is unreadable, so the sum was promoted to a REAL: %v", err)
	}
	if used != store.MaxLedgerValue {
		t.Errorf("ledger = %d, want it saturated at %d", used, int64(store.MaxLedgerValue))
	}
	// The graph half, which no engine-level test reaches: these rows accumulate
	// inside a query rather than in a column, and an overflowing SUM fails the
	// statement outright rather than being promoted.
	points, err := st.UsageHistory(2, now.Add(-time.Hour), 3600)
	if err != nil {
		t.Fatalf("the portal's usage graph is broken: %v", err)
	}
	// A range over nothing is a pass, and this assertion exists precisely
	// because "the query ran" is not the property. If the bucketing expression
	// or the ts filter ever stops returning a row for this window, the loop
	// below never executes and the overflow it guards goes unchecked.
	if len(points) == 0 {
		t.Fatalf("usage graph returned no buckets, so the assertion below checks nothing")
	}
	// Not merely that the query ran. The float branch that reads the sum back
	// could be replaced by a bare int64(sum) and the query would still succeed,
	// handing the graph a bucket that overflowed on conversion - so the value
	// has to be asserted, not just the absence of an error.
	// And that it actually saturated, not merely that it landed in range: the
	// twenty entries sum past an int64 on purpose, so anything below the cap
	// means the clamp was not what produced this number.
	for _, pt := range points {
		if pt.Bytes != store.MaxLedgerValue {
			t.Errorf("usage graph bucket = %d bytes, want it saturated at %d",
				pt.Bytes, int64(store.MaxLedgerValue))
		}
	}
	// The watermark rides the same transaction, or a crash between them bills
	// the resend twice.
	if got := st.Meta("usage_seq:2"); got != "9" {
		t.Errorf("watermark = %q, want 9 written inside the batch transaction", got)
	}
}
