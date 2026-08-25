package engine

import (
	"bytes"
	"io"
	"log/slog"
	"math"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/proto"
	"github.com/quinlan102/homeport/internal/quota"
	"github.com/quinlan102/homeport/internal/store"
)

// usageServer builds a control server over a real store, with one metered path
// carrying a quota, which is what makes the ledger worth attacking.
func usageServer(t *testing.T) (*ControlServer, *Engine, model.PathConfig) {
	t.Helper()
	cfg := testConfig()
	for i := range cfg.Paths {
		cfg.Paths[i].Metered = true
		cfg.Paths[i].Quota.LimitBytes = 20 << 30
		cfg.Paths[i].Quota.Calibration = 100
		cfg.Paths[i].Quota.OverheadPerPacket = 60
		cfg.Paths[i].Quota.ResetDay = 1
		cfg.Paths[i].Quota.Timezone = "UTC"
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	e := newTestEngine(cfg, nil)
	e.st = st
	e.log = quiet
	return &ControlServer{eng: e, log: quiet}, e, cfg.Paths[1]
}

func ledger(t *testing.T, e *Engine, p model.PathConfig, at time.Time) int64 {
	t.Helper()
	start, _ := quota.PeriodBounds(p.Quota, at)
	used, err := e.Store().Usage(p.ID, start)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	return used
}

// ledgerPackets reads the ledger's other column.
//
// It exists because the bytes column was the only one any of these tests could
// see, and the two are written together from one delta: a bound that covers one
// and not the other passes every assertion here while the column quota.Metered
// multiplies by the per-packet overhead goes wrong.
func ledgerPackets(t *testing.T, e *Engine, p model.PathConfig, at time.Time) int64 {
	t.Helper()
	start, _ := quota.PeriodBounds(p.Quota, at)
	pkts, err := e.Store().UsagePackets(p.ID, start)
	if err != nil {
		t.Fatalf("read ledger packets: %v", err)
	}
	return pkts
}

// The ledger is authoritative for quota enforcement, so a delta large enough
// to exhaust a quota in one frame takes every metered path out of the selector
// while the links themselves go on measuring perfectly. Nothing bounded these
// numbers: every other value arriving on this channel is re-parsed at the
// boundary and these went straight through.
func TestAnImplausibleUsageDeltaIsClampedRatherThanBilled(t *testing.T) {
	s, e, p := usageServer(t)
	now := time.Now()

	s.applyUsage(proto.Usage{Deltas: []proto.UsageDelta{
		{PathID: p.ID, Bytes: 500 << 30, Packets: 0, AtUnix: now.Unix(), Sequence: 1},
	}})
	if used := ledger(t, e, p, now); used != 500<<30 {
		t.Errorf("a 500 GiB delta billed %d bytes; it is under the ceiling and must not be moved", used)
	}

	// Past the ceiling it is clamped, not billed as sent.
	s.applyUsage(proto.Usage{Deltas: []proto.UsageDelta{
		{PathID: p.ID, Bytes: 1 << 62, Packets: 0, AtUnix: now.Unix(), Sequence: 2},
	}})
	used := ledger(t, e, p, now)
	if used > (500<<30)+maxDeltaBytes {
		t.Errorf("ledger reached %d bytes; a delta past the ceiling was billed as sent", used)
	}
}

// The other direction, and the worse one. Over-billing is at least visible in
// the portal with an approve button beside it; a negative delta erases real
// LTE usage from the one number the data cap depends on, silently. Meter.sample
// never emits one - it rebaselines instead - so nothing honest reaches this.
func TestANegativeUsageDeltaCannotCreditTheLedger(t *testing.T) {
	s, e, p := usageServer(t)
	now := time.Now()

	s.applyUsage(proto.Usage{Deltas: []proto.UsageDelta{
		{PathID: p.ID, Bytes: 8 << 30, Packets: 1000, AtUnix: now.Unix(), Sequence: 1},
		{PathID: p.ID, Bytes: -(600 << 30), Packets: -5000, AtUnix: now.Unix(), Sequence: 2},
	}})

	used := ledger(t, e, p, now)
	if used < 8<<30 {
		t.Errorf("ledger is at %d bytes after a negative delta; recorded usage was erased", used)
	}
	// Both columns, because only one of them could be read back before and the
	// packets one is the specific regression Engine.AddUsage's clamp names:
	// quota.Metered clamps its own copy, so a negative packet count produced
	// zero metered bytes and was then handed to the ledger unchanged, where it
	// decremented the period's packet total. It is held at two layers now,
	// clampCounts here and clampLedger in the store, and this asserts the
	// outcome rather than either one: store.TestTheLedgerCannotBeDrivenBelowZero
	// pins the lower layer on its own.
	if pkts := ledgerPackets(t, e, p, now); pkts < 1000 {
		t.Errorf("ledger is at %d packets after a negative delta; the packet column was credited back", pkts)
	}
}

// The relative half of the sequence bound. maxDeltaSequence rules out only the
// top of the range, and the damage a sequence does is not a function of how
// large it is: it is a function of how far past the watermark it is. A value
// well inside the absolute bound parks the watermark just as permanently, every
// later delta is skipped in silence, and the ack tells the backend to drop the
// bytes. It is the one failure here that is both silent and unrecoverable, so
// the refusal must not advance the watermark either.
func TestASequenceFarPastTheWatermarkIsRefusedRatherThanBecomingIt(t *testing.T) {
	s, e, p := usageServer(t)
	now := time.Now()

	s.applyUsage(proto.Usage{Deltas: []proto.UsageDelta{
		{PathID: p.ID, Bytes: 1 << 30, Packets: 100, AtUnix: now.Unix(), Sequence: 5},
	}})

	// Inside maxDeltaSequence, so the absolute bound admits it, and hundreds of
	// millions of samples past a watermark of 5.
	ack := s.applyUsage(proto.Usage{Deltas: []proto.UsageDelta{
		{PathID: p.ID, Bytes: 1 << 30, Packets: 100, AtUnix: now.Unix(), Sequence: maxSequenceJump + 6},
	}})
	if got := ack.Seqs[p.ID]; got != 5 {
		t.Fatalf("acked sequence %d; a refused delta must leave the watermark at 5, or the backend drops its buffer", got)
	}
	if got := e.Store().Meta("usage_seq:" + strconv.Itoa(p.ID)); got != "5" {
		t.Fatalf("watermark is %q; an implausible jump became the watermark and this path is now unbillable for good", got)
	}

	// And the path still bills, which is the half that proves the refusal did
	// not stall it: the next honest delta lands.
	s.applyUsage(proto.Usage{Deltas: []proto.UsageDelta{
		{PathID: p.ID, Bytes: 2 << 30, Packets: 200, AtUnix: now.Unix(), Sequence: 6},
	}})
	if used := ledger(t, e, p, now); used < 3<<30 {
		t.Errorf("ledger is at %d bytes; the delta after a refused sequence was not billed", used)
	}
}

// The other side of that bound, and the reason it is not tighter. The backend
// keeps sampling while the frontend is unreachable and its sequence keeps
// advancing even after maxBuffered drops the oldest deltas off the front, so a
// legitimate jump equals elapsed samples rather than buffered ones. A bound
// derived from the buffer would refuse exactly the delta that survives a long
// outage, which is the mistake maxDeltaBytes carries a paragraph about.
func TestASequenceAdvancedByALongOutageIsStillBilled(t *testing.T) {
	s, e, p := usageServer(t)
	now := time.Now()

	s.applyUsage(proto.Usage{Deltas: []proto.UsageDelta{
		{PathID: p.ID, Bytes: 1 << 30, Packets: 100, AtUnix: now.Unix(), Sequence: 1},
	}})
	// A year of ten-second sampling with nothing acked, which is far past
	// anything the backend's own buffer holds.
	const year = 6 * 60 * 24 * 365
	s.applyUsage(proto.Usage{Deltas: []proto.UsageDelta{
		{PathID: p.ID, Bytes: 4 << 30, Packets: 400, AtUnix: now.Unix(), Sequence: 1 + year},
	}})
	if used := ledger(t, e, p, now); used < 5<<30 {
		t.Errorf("ledger is at %d bytes; a delta from a backend that sampled through a long frontend outage was refused", used)
	}
}

// Two backend sessions at once is the ordinary case rather than the exotic one:
// a silently dead connection sits on its read deadline while its replacement
// dials in, and the connection dies at every failover, which is when LTE data
// is accruing hardest. The replacement resends everything unacked, so the same
// deltas are applied on two goroutines. The per-batch watermark memo is a
// database read held across a whole batch, so without serialisation neither
// goroutine sees the other's commits and the batch is billed twice.
func TestConcurrentUsageBatchesDoNotDoubleBill(t *testing.T) {
	s, e, p := usageServer(t)
	now := time.Now()

	batch := proto.Usage{}
	for i := 1; i <= 50; i++ {
		batch.Deltas = append(batch.Deltas, proto.UsageDelta{
			PathID: p.ID, Bytes: 1 << 20, Packets: 10, AtUnix: now.Unix(), Sequence: uint64(i),
		})
	}

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.applyUsage(batch)
		}()
	}
	wg.Wait()

	// 50 deltas of 1 MiB plus 10 packets at 60 bytes of overhead each.
	want := int64(50) * ((1 << 20) + 10*60)
	if used := ledger(t, e, p, now); used != want {
		t.Errorf("ledger is at %d bytes, want %d; the same batch was billed more than once", used, want)
	}
}

// Clamping rather than refusing is the whole design, and this is why. A refused
// delta leaves the watermark where it was, so the backend resends it on every
// tick and has it refused every time: that path's accounting stalls for good,
// which is a worse outcome than billing a bounded wrong number loudly.
func TestAClampedDeltaStillAdvancesTheWatermark(t *testing.T) {
	s, e, p := usageServer(t)
	now := time.Now()

	ack := s.applyUsage(proto.Usage{Deltas: []proto.UsageDelta{
		{PathID: p.ID, Bytes: -1, Packets: -1, AtUnix: now.Unix(), Sequence: 7},
	}})
	if ack.Seqs[p.ID] != 7 {
		t.Fatalf("ack was %d, want 7: the backend would resend this delta forever", ack.Seqs[p.ID])
	}
	if got := e.Store().Meta("usage_seq:" + strconv.Itoa(p.ID)); got != "7" {
		t.Errorf("watermark is %q, want \"7\"", got)
	}
}

// AddUsage picks the billing period from the delta's own stamp, so a delta
// dated into next month is usage that never counts against the quota it was
// incurred under. Old is ordinary and has to stay legal: the buffer holds days
// of backlog when the channel has been down, and those bytes belong to the
// period they were measured in.
func TestAFutureStampIsPulledBackWhileABackdatedOneIsKept(t *testing.T) {
	s, e, p := usageServer(t)
	now := time.Now()
	// The backdated stamp is anchored an hour before the current period's own
	// boundary rather than a fixed span into the past, and both halves of that
	// matter. It has to be in the previous period for "billed into its own
	// period" to be an assertion rather than a coincidence, and it has to be
	// well inside maxDeltaAge, because an honest buffered delta always is: the
	// backend's buffer holds under six days. Reaching a month back would sit on
	// that bound and make this test a calendar question.
	day := now.UTC().Day()
	if day > 28 {
		day = 28 // a day every month has
	}
	for i := range e.cfg.Paths {
		e.cfg.Paths[i].Quota.ResetDay = day
	}
	p.Quota.ResetDay = day
	start, _ := quota.PeriodBounds(p.Quota, now)
	past := start.Add(-time.Hour)

	s.applyUsage(proto.Usage{Deltas: []proto.UsageDelta{
		{PathID: p.ID, Bytes: 1 << 20, AtUnix: past.Unix(), Sequence: 1},
	}})
	if used := ledger(t, e, p, past); used != 1<<20 {
		t.Errorf("a backdated delta billed %d bytes into its own period, want %d", used, 1<<20)
	}
	if used := ledger(t, e, p, now); used != 0 {
		t.Errorf("a backdated delta put %d bytes into the current period", used)
	}

	// A year ahead is a period this quota will not reach for a year.
	future := now.AddDate(1, 0, 0)
	s.applyUsage(proto.Usage{Deltas: []proto.UsageDelta{
		{PathID: p.ID, Bytes: 2 << 20, AtUnix: future.Unix(), Sequence: 2},
	}})
	if used := ledger(t, e, p, future); used != 0 {
		t.Errorf("%d bytes were billed to a period a year away", used)
	}
	if used := ledger(t, e, p, now); used != 2<<20 {
		t.Errorf("the pulled-back delta billed %d bytes to the current period, want %d", used, 2<<20)
	}
}

// The property that matters for every working deployment: a delta a real meter
// produces is not touched. A bound that moved ordinary traffic would corrupt
// the ledger in the name of protecting it.
func TestAnOrdinaryUsageDeltaIsNotMoved(t *testing.T) {
	s, _, p := usageServer(t)
	now := time.Now()
	in := proto.UsageDelta{PathID: p.ID, Bytes: 4_812_993, Packets: 6_204, AtUnix: now.Unix(), Sequence: 1}

	if got := s.checkDelta(in, now); got != in {
		t.Errorf("checkDelta moved an ordinary delta: %+v -> %+v", in, got)
	}

	// And a delta covering a long agent outage, which is a single delta by
	// design: Meter persists its baseline across restarts so that usage
	// accrued while it was stopped is still accounted for. A bound derived
	// from one sample interval would refuse exactly this.
	outage := proto.UsageDelta{PathID: p.ID, Bytes: 900 << 30, Packets: 700_000_000,
		AtUnix: now.Add(-6 * 24 * time.Hour).Unix(), Sequence: 2}
	if got := s.checkDelta(outage, now); got != outage {
		t.Errorf("checkDelta moved a post-outage delta: %+v -> %+v", outage, got)
	}
}

// The past side of the stamp window, which the first version of this bound
// left open. It is not the adversarial case that matters: invariant 11
// describes the ordinary route to it, where the house loses power, comes back
// with every link down and therefore no route to NTP, and the backend stamps
// every delta with a stale clock. Billed into 1970, a month of metered LTE
// leaves the current period reading zero and the quota never trips.
func TestADeltaStampedBeforeTheWindowIsBilledToTheCurrentPeriod(t *testing.T) {
	s, e, p := usageServer(t)
	now := time.Now()

	// A backend whose clock came back at the epoch.
	s.applyUsage(proto.Usage{Deltas: []proto.UsageDelta{
		{PathID: p.ID, Bytes: 9 << 30, AtUnix: 0, Sequence: 1},
	}})
	if used := ledger(t, e, p, time.Unix(0, 0)); used != 0 {
		t.Errorf("%d bytes were billed into 1970, where no quota reads them", used)
	}
	if used := ledger(t, e, p, now); used != 9<<30 {
		t.Errorf("the current period holds %d bytes, want %d", used, 9<<30)
	}
}

// time.Unix overflows at both extremes and lands both of them in the same
// place: MinInt64 and MaxInt64 alike render as the year 292277026596 and both
// compare as *before* now. So a time.Time comparison misses MaxInt64 in the
// future branch and catches it in the past branch, reporting a stamp tens of
// billions of years ahead as one too far in the past to bill. Comparing raw
// seconds classifies both correctly, which is why the check does.
func TestBothOverflowingStampsAreClampedAndNamedCorrectly(t *testing.T) {
	s, _, p := usageServer(t)
	now := time.Now()

	for _, tc := range []struct {
		name string
		at   int64
		want string
	}{
		{"MinInt64", math.MinInt64, "past"},
		{"MaxInt64", math.MaxInt64, "future"},
	} {
		var buf bytes.Buffer
		s.log = slog.New(slog.NewTextHandler(&buf, nil))
		s.clamped = throttle{} // a fresh window, so each case gets its line

		got := s.checkDelta(proto.UsageDelta{
			PathID: p.ID, Bytes: 1 << 20, AtUnix: tc.at, Sequence: 1}, now)
		if at := time.Unix(got.AtUnix, 0); at.Year() != now.Year() {
			t.Errorf("%s: stamp landed in year %d, want the current period", tc.name, at.Year())
		}
		if !strings.Contains(buf.String(), tc.want) {
			t.Errorf("%s: log did not name it as %q: %s", tc.name, tc.want, buf.String())
		}
	}
}

// The path id is the one field of a delta that reaches the database whatever
// else it says. AddUsage acks an id it does not recognise, deliberately, so
// that deltas for a path an operator has just removed stop being resent - and
// that ack is a row in `meta`, which has no retention. Acking an id no
// configuration can hold is therefore a permanent row per id, chosen by
// whoever is sending, so an id outside the range validate allows is dropped
// before anything is read or written for it.
func TestAnOutOfRangePathIDNeverTouchesTheDatabase(t *testing.T) {
	s, e, p := usageServer(t)
	now := time.Now()

	ack := s.applyUsage(proto.Usage{Deltas: []proto.UsageDelta{
		{PathID: 1 << 20, Bytes: 1 << 30, AtUnix: now.Unix(), Sequence: 3},
		{PathID: -5, Bytes: 1 << 30, AtUnix: now.Unix(), Sequence: 4},
		// Zero too: web.validate requires a positive id, so this one is as
		// unreachable by a configuration as the other two and was admitted by a
		// bound that only refused negatives.
		{PathID: 0, Bytes: 1 << 30, AtUnix: now.Unix(), Sequence: 5},
		{PathID: p.ID, Bytes: 1 << 20, AtUnix: now.Unix(), Sequence: 1},
	}})
	for _, bad := range []string{"usage_seq:1048576", "usage_seq:-5", "usage_seq:0"} {
		if got := e.Store().Meta(bad); got != "" {
			t.Errorf("%s was written as %q; these rows are permanent and the sender picks the key", bad, got)
		}
	}
	if _, seen := ack.Seqs[1<<20]; seen {
		t.Errorf("an out-of-range id reached the ack: %v", ack.Seqs)
	}
	// The usable delta beside it is still applied, which is what keeps one bad
	// entry from taking a working batch down with it.
	if used := ledger(t, e, p, now); used != 1<<20 {
		t.Errorf("the usable delta billed %d bytes, want %d", used, 1<<20)
	}
	if ack.Seqs[p.ID] != 1 {
		t.Errorf("the usable delta was not acked: %v", ack.Seqs)
	}
}

// The field that does the most damage per byte sent, and the last one left
// unbounded. A sequence is a permanent per-path watermark: accepted once, it
// parks where no honest delta can follow, so every later delta for that path is
// skipped in silence; the ack tells the backend its whole buffer is applied, so
// the bytes are gone; and the `meta` row survives every restart. That path is
// never billed again and only editing the database clears it.
func TestAnImplausibleSequenceCannotBecomeTheWatermark(t *testing.T) {
	s, e, p := usageServer(t)
	now := time.Now()

	s.applyUsage(proto.Usage{Deltas: []proto.UsageDelta{
		{PathID: p.ID, Bytes: 1, AtUnix: now.Unix(), Sequence: math.MaxUint64},
	}})
	if got := e.Store().Meta("usage_seq:" + strconv.Itoa(p.ID)); got != "" {
		t.Fatalf("the watermark became %q; no honest delta can ever exceed it", got)
	}

	// And the path still bills afterwards, which is the whole point.
	ack := s.applyUsage(proto.Usage{Deltas: []proto.UsageDelta{
		{PathID: p.ID, Bytes: 5 << 30, AtUnix: now.Unix(), Sequence: 1},
		{PathID: p.ID, Bytes: 5 << 30, AtUnix: now.Unix(), Sequence: 2},
	}})
	if used := ledger(t, e, p, now); used != 10<<30 {
		t.Errorf("ledger holds %d bytes after two honest deltas, want %d", used, 10<<30)
	}
	if ack.Seqs[p.ID] != 2 {
		t.Errorf("ack is %d, want 2", ack.Seqs[p.ID])
	}
}

// A sequence counts samples, one per path per interval, and is persisted across
// restarts. The bound has to sit far above anything a real deployment reaches
// or it would stall a path that has simply been running a long time.
func TestAnOrdinarySequenceIsAccepted(t *testing.T) {
	s, e, p := usageServer(t)
	now := time.Now()

	// Ten years of ten-second sampling.
	seq := uint64(10 * 365 * 24 * 360)
	s.applyUsage(proto.Usage{Deltas: []proto.UsageDelta{
		{PathID: p.ID, Bytes: 4096, AtUnix: now.Unix(), Sequence: seq},
	}})
	if used := ledger(t, e, p, now); used != 4096 {
		t.Errorf("a delta at sequence %d billed %d bytes, want 4096", seq, used)
	}
}

// A frame is bounded only by proto.MaxFrameBytes, and a delta is about a
// hundred bytes, so an accepted frame can carry ten thousand of them. Each is a
// full SQLite transaction run inline on the control read loop, which cannot
// answer a ping or read the next frame while it works.
func TestAnOversizedUsageBatchIsTruncated(t *testing.T) {
	s, e, p := usageServer(t)
	now := time.Now()

	deltas := make([]proto.UsageDelta, 0, maxDeltasPerFrame+50)
	for i := 0; i < maxDeltasPerFrame+50; i++ {
		deltas = append(deltas, proto.UsageDelta{
			PathID: p.ID, Bytes: 1, AtUnix: now.Unix(), Sequence: uint64(i + 1)})
	}
	ack := s.applyUsage(proto.Usage{Deltas: deltas})
	if ack.Seqs[p.ID] > uint64(maxDeltasPerFrame) {
		t.Errorf("applied up to sequence %d, past the %d-delta limit", ack.Seqs[p.ID], maxDeltasPerFrame)
	}
	if used := ledger(t, e, p, now); used > int64(maxDeltasPerFrame) {
		t.Errorf("billed %d deltas' worth, past the limit", used)
	}
}

// A delta can trip two bounds at once, and a line naming one clamp beside
// values that show another sends whoever reads it after the wrong half.
func TestEveryClampReasonIsReported(t *testing.T) {
	var buf bytes.Buffer
	s, _, p := usageServer(t)
	s.log = slog.New(slog.NewTextHandler(&buf, nil))

	s.checkDelta(proto.UsageDelta{
		PathID: p.ID, Bytes: -1, Packets: -1, AtUnix: time.Now().Unix(), Sequence: 1}, time.Now())
	line := buf.String()
	for _, want := range []string{"negative bytes", "negative packets"} {
		if !strings.Contains(line, want) {
			t.Errorf("the log named only one clamp; %q is missing from: %s", want, line)
		}
	}
}

// The count is chosen by the peer: a batch is hundreds of deltas and every one
// of them can trip a bound. One line each is peer-driven journal volume, which
// is what ControlServer.throttle exists to bound everywhere else in this file.
func TestClampedDeltaLoggingIsThrottled(t *testing.T) {
	var buf bytes.Buffer
	s, _, p := usageServer(t)
	s.log = slog.New(slog.NewTextHandler(&buf, nil))
	now := time.Now()

	deltas := make([]proto.UsageDelta, 0, 200)
	for i := 0; i < 200; i++ {
		deltas = append(deltas, proto.UsageDelta{
			PathID: p.ID, Bytes: -1, AtUnix: now.Unix(), Sequence: uint64(i + 1)})
	}
	s.applyUsage(proto.Usage{Deltas: deltas})

	if n := strings.Count(buf.String(), "outside the bounds a meter can produce"); n > 1 {
		t.Errorf("200 clamped deltas produced %d log lines; the throttle is not in the path", n)
	}
}

// Metered multiplies every byte by two configuration values that had no
// ceiling of their own, and an int64 that wraps does not announce itself: it
// produces a plausible number, or a negative one that credits the month back.
func TestMeteredSaturatesRatherThanWrapping(t *testing.T) {
	q := model.Quota{Calibration: 1 << 30, OverheadPerPacket: 1 << 30}
	got := quota.Metered(1<<62, 1<<62, q)
	if got < 0 {
		t.Errorf("Metered returned %d: the arithmetic wrapped and credited the ledger", got)
	}

	if n := quota.Metered(-1<<40, -1<<40, model.Quota{Calibration: 100, OverheadPerPacket: 60}); n != 0 {
		t.Errorf("Metered turned a negative delta into %d, want 0", n)
	}
}

// A ledger column accumulates deltas, and SQLite does not error on integer
// overflow: the sum silently becomes a REAL, and every later Scan into an int64
// fails from then on. Bounding one delta cannot prevent that, because thirteen
// clamped ones reach the overflow inside a single frame, so the cap has to be
// on the sum. Engine.refreshQuota carries the previous verdict forward on a read
// error, so the path's quota would freeze where it stood with only the database
// to fix it.
func TestAFrameOfClampedDeltasCannotBreakTheLedgerColumn(t *testing.T) {
	s, e, p := usageServer(t)
	now := time.Now()
	p.Quota.Calibration = quota.MaxCalibration
	p.Quota.OverheadPerPacket = quota.MaxOverheadPerPacket
	for i := range e.cfg.Paths {
		e.cfg.Paths[i].Quota.Calibration = quota.MaxCalibration
		e.cfg.Paths[i].Quota.OverheadPerPacket = quota.MaxOverheadPerPacket
	}

	deltas := make([]proto.UsageDelta, 0, 40)
	for i := 0; i < 40; i++ {
		deltas = append(deltas, proto.UsageDelta{
			PathID: p.ID, Bytes: math.MaxInt64, Packets: math.MaxInt64,
			AtUnix: now.Unix(), Sequence: uint64(i + 1)})
	}
	s.applyUsage(proto.Usage{Deltas: deltas})

	used, err := e.Store().Usage(p.ID, mustPeriod(t, p, now))
	if err != nil {
		t.Fatalf("the ledger column is permanently unreadable: %v", err)
	}
	if used > store.MaxLedgerValue {
		t.Errorf("ledger reached %d, past the saturation cap %d", used, store.MaxLedgerValue)
	}
}

func mustPeriod(t *testing.T, p model.PathConfig, at time.Time) time.Time {
	t.Helper()
	start, _ := quota.PeriodBounds(p.Quota, at)
	return start
}
