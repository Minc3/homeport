package store

import (
	"path/filepath"
	"testing"
	"time"
)

// The SQL floor, reached the only way it can be reached.
//
// MAX(bytes + excluded.bytes, 0) in the upsert protects a case clampLedger
// cannot: the parameters are floored before they reach SQL, so the sum only
// goes negative when the *column* is already negative. That is not
// hypothetical. Any deployment that ran a build predating clampLedger and took
// one negative delta has such a row sitting in its ledger, under-reporting that
// period for as long as it lasts, and this is what lifts it back.
//
// It lives in the package rather than beside the other saturation tests because
// seeding a negative row means writing one directly: no exported method can
// produce it any more, which is the point. Without this the SQL floor could be
// deleted with the whole suite staying green - store.go says "do not simplify
// either of these to a bare +" and nothing was holding it to that.
func TestTheSQLFloorLiftsALedgerRowLeftNegativeByAnOlderBuild(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	now := time.Now()
	period := now.Truncate(time.Hour)
	if _, err := s.db.Exec(
		`INSERT INTO ledger (path_id, period_start, bytes, packets) VALUES (?, ?, ?, ?)`,
		2, period.Unix(), -(50 << 30), -1_000_000); err != nil {
		t.Fatalf("seed the row an older build would have left: %v", err)
	}

	// An ordinary delta arrives. Its own values are already non-negative, so
	// only the sum can be below zero.
	if err := s.AddUsageBatch(2, []UsageEntry{
		{PeriodStart: period, At: now, Bytes: 1 << 30, Packets: 500},
	}, "", ""); err != nil {
		t.Fatalf("add: %v", err)
	}

	got, err := s.Usage(2, period)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got < 0 {
		t.Errorf("ledger = %d bytes, want it lifted to 0 rather than left negative; "+
			"a negative column under-reports the period for as long as it lasts and the quota never trips", got)
	}
	pkts, err := s.UsagePackets(2, period)
	if err != nil {
		t.Fatalf("read packets: %v", err)
	}
	if pkts < 0 {
		t.Errorf("ledger = %d packets, want it lifted to 0; the packet column is what Metered multiplies by the per-packet overhead", pkts)
	}
}
