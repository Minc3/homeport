package agent

import (
	"context"
	"testing"
	"time"
)

// SetActivePath's pre-filter compares against active and lastSeq, which the
// worker records only after its apply has finished. While it is inside `ip`
// for one decision, a straggling probe carrying the sequence before it still
// passes the filter. The queued decision is the newest the frontend has made
// and must not be replaced by an older one that merely arrived later; the
// frontend's burst on every switch makes this interleaving routine rather
// than rare.
func TestAStaleDecisionCannotReplaceANewerQueuedOne(t *testing.T) {
	a, _ := testAgent(t, true)
	ctx := context.Background()

	a.SetActivePath(ctx, 2, 10)
	a.SetActivePath(ctx, 1, 9) // a late probe from the tunnel just abandoned

	a.pendingMu.Lock()
	d := a.pending
	a.pendingMu.Unlock()
	if d.pathID != 2 || d.seq != 10 {
		t.Fatalf("pending = %+v, want path 2 seq 10; an older decision replaced the newer one", d)
	}

	a.SetActivePath(ctx, 3, 11)
	a.pendingMu.Lock()
	d = a.pending
	a.pendingMu.Unlock()
	if d.pathID != 3 || d.seq != 11 {
		t.Fatalf("pending = %+v, want path 3 seq 11; a newer decision must still replace the queued one", d)
	}
}

// The frontend seeds its sequence from the clock, so a process that switched
// once and was restarted quickly enough hands its successor a first switch
// numbered the same as its own, on a different path. That is a real decision,
// and applyDecision would accept it; a strict guard here refused to queue it,
// so the frontend routed down one tunnel while replies left by another until a
// later switch moved the number on. A straggler is always strictly lower, so
// admitting equal keeps it out all the same.
func TestAnEqualSequenceOnAnotherPathIsStillQueued(t *testing.T) {
	a, _ := testAgent(t, true)
	ctx := context.Background()

	a.SetActivePath(ctx, 2, 10)
	a.SetActivePath(ctx, 1, 10)

	a.pendingMu.Lock()
	d := a.pending
	a.pendingMu.Unlock()
	if d.pathID != 1 || d.seq != 10 {
		t.Fatalf("pending = %+v, want path 1 seq 10; a decision with the same sequence on another path was refused", d)
	}
}

// The same two rules with the worker actually running, which the case above
// never does. It also pins an assumption the guard rests on: the worker takes
// the queued decision and leaves it queued, so the sequence it compares
// against is the last real decision rather than zero.
func TestTheWorkerAppliesTheNewestDecisionAndStragglersNeverReachIt(t *testing.T) {
	a, runner := testAgent(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.applyLoop(ctx)

	waitForActive := func(want int, why string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for a.ActivePath() != want {
			if time.Now().After(deadline) {
				t.Fatalf("active path = %d, want %d: %s", a.ActivePath(), want, why)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	a.SetActivePath(ctx, 2, 10)
	waitForActive(2, "the worker did not apply the queued decision")

	// A straggler from the abandoned tunnel: lower sequence, never applied.
	a.SetActivePath(ctx, 1, 9)
	time.Sleep(50 * time.Millisecond)
	if got := a.ActivePath(); got != 2 {
		t.Fatalf("active path = %d after a stale decision, want 2; a straggler rewound the decision", got)
	}
	if n := runner.count("dev wg-main"); n != 0 {
		t.Fatalf("the stale decision reached the kernel (%d route commands for wg-main)", n)
	}

	// The restarted frontend's first switch: same sequence, different path.
	a.SetActivePath(ctx, 1, 10)
	waitForActive(1, "an equal sequence on another path was never applied; replies stay on the tunnel the frontend has left")
}

// A sequence far ahead of this host's clock is refused, and refused *before*
// it can become the high-water mark.
//
// Everything downstream compares sequences only against each other, so one
// number planted near the top of a uint64 is not a wrong decision that a right
// one corrects: it is a ceiling no honest decision can ever clear again. The
// frontend then routes down one tunnel while replies leave by another, all
// three paths go on measuring perfectly, and nothing but restarting this
// process clears it, because lastSeq lives in memory.
func TestAnImplausibleSequenceIsRefusedAndDoesNotBecomeTheCeiling(t *testing.T) {
	a, _ := testAgent(t, true)
	ctx := context.Background()

	a.SetActivePath(ctx, 2, ^uint64(0)) // the pin

	a.pendingMu.Lock()
	d := a.pending
	a.pendingMu.Unlock()
	if d.seq != 0 {
		t.Fatalf("pending = %+v, want nothing queued: an implausible sequence was accepted", d)
	}

	// And the decision that matters still lands. This is the half that would
	// be lost by refusing too much: a bound that also rejected real sequences
	// would produce the identical fault, with no attacker involved.
	real := uint64(time.Now().UnixMilli()) << 16
	a.SetActivePath(ctx, 3, real)
	a.pendingMu.Lock()
	d = a.pending
	a.pendingMu.Unlock()
	if d.pathID != 3 || d.seq != real {
		t.Fatalf("pending = %+v, want path 3 seq %d; a real decision was refused", d, real)
	}
}

// The ceiling grows with elapsed time from the first sequence this host
// accepted, and is anchored to nothing else.
func TestTheSequenceCeilingIsMeasuredFromElapsedTime(t *testing.T) {
	// Derived from the clock rather than written down, because the ceiling now
	// has a second reference - this host's own clock, as a floor under it - and
	// a hardcoded anchor would drift away from that reference by however long
	// ago this test was written, quietly turning the refusals below into
	// acceptances years after anybody looked.
	baseAt := time.Now()
	base := uint64(baseAt.UnixMilli()) << 16
	at := func(o time.Duration) time.Time { return baseAt.Add(o) }
	seqAfter := func(o time.Duration) uint64 { return base + (uint64(o.Milliseconds()) << 16) }

	for _, c := range []struct {
		name string
		seq  uint64
		now  time.Time
		want bool
	}{
		{"the anchor itself", base, baseAt, true},
		{"an hour of switching later", seqAfter(time.Hour), at(time.Hour), true},
		{"a frontend restart reseeding from its own clock", seqAfter(48 * time.Hour), at(48 * time.Hour), true},
		{"a frontend whose clock was corrected days forward", seqAfter(96 * time.Hour), at(time.Hour), true},
		{"a jump of a month with no time passing", seqAfter(30 * 24 * time.Hour), at(time.Minute), false},
		{"a month of real time, then that same jump", seqAfter(30 * 24 * time.Hour), at(30 * 24 * time.Hour), true},
		{"the top of the range", ^uint64(0), at(time.Hour), false},
	} {
		if got := plausibleDecisionSeq(c.seq, base, baseAt, c.now); got != c.want {
			t.Errorf("%s: plausible = %v, want %v", c.name, got, c.want)
		}
	}
}

// With no anchor yet only the horizon applies, so the very first decision a
// backend ever sees is never refused for being ahead of anything. There is
// nothing to measure from, and refusing it would be refusing the decision that
// installs the return path.
func TestTheFirstDecisionIsBoundedOnlyByTheHorizon(t *testing.T) {
	now := time.Now()
	real := uint64(now.UnixMilli()) << 16
	if !plausibleDecisionSeq(real, 0, time.Time{}, now) {
		t.Fatal("the first real decision was refused; it is what installs the return path")
	}
	if plausibleDecisionSeq(^uint64(0), 0, time.Time{}, now) {
		t.Fatal("an unanchored host accepted the top of the range; the horizon must still apply")
	}
}

// This host's wall clock can never refuse a real decision, which is the
// property that matters here rather than a stylistic one.
//
// The first version of this bound compared against time.Now() and nothing
// else. A backend whose clock is behind then computes a ceiling below every
// real sequence and refuses the lot - and such a host never installs a return
// path at all, because `active` is not persisted and reassertReturnPath
// returns early on zero, so the first accepted decision is what installs it.
// The way to arrive at a stale clock is the exact scenario this system exists
// for: the house loses power, comes back with every link down, so there is no
// route to NTP, so the clock stays stale, so the decision that would recover
// the site is refused. A bound that can hold the recovery shut is worse than
// the pin it prevents.
//
// The clock is admitted on one side only - as a floor under the ceiling, never
// a cap on it - so this is now a property of which direction it may move rather
// than of whether it is read at all. Pinned with a clock a decade out.
func TestAWildlyWrongWallClockCannotRefuseARealDecision(t *testing.T) {
	baseAt := time.Now()
	base := uint64(time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC).UnixMilli()) << 16

	// The anchor is a monotonic reading and the sequence is the frontend's own
	// number, so a real decision an hour after the anchor lands whatever this
	// host believes the date to be.
	seq := base + (uint64(time.Hour.Milliseconds()) << 16)
	if !plausibleDecisionSeq(seq, base, baseAt, baseAt.Add(time.Hour)) {
		t.Fatal("a real decision an hour after the anchor was refused")
	}

	// And the same with the clock itself a decade wrong, which is what the
	// first version of this check got backwards. Both times are built without a
	// monotonic reading so that the elapsed hour is measured from the wall
	// clock the test is choosing: the anchor's own reference is then the only
	// one left, and it is the one that has to carry the decision.
	stale := time.Date(2016, 8, 25, 12, 0, 0, 0, time.UTC)
	if !plausibleDecisionSeq(seq, base, stale, stale.Add(time.Hour)) {
		t.Fatal("a decade-stale clock refused a real decision; the ceiling must never be narrowed by it")
	}

	// And the same through SetActivePath, which is where it would actually
	// bite: a fresh agent whose first decision must land or the backend never
	// routes a reply.
	a, _ := testAgent(t, true)
	first := uint64(time.Now().UnixMilli()) << 16
	a.SetActivePath(context.Background(), 2, first)
	a.pendingMu.Lock()
	d := a.pending
	a.pendingMu.Unlock()
	if d.pathID != 2 || d.seq != first {
		t.Fatalf("pending = %+v, want path 2 seq %d; the first decision must always land", d, first)
	}
}

// A frontend restart after a long uptime is not a pin, and must not be refused
// as one. This is the fault the wall-clock floor under the ceiling exists for.
//
// Sequences are `frontendStart << 16` plus one per switch, so they track when
// the frontend *started* and not the passage of time. Anchor this host on a
// frontend that has already been up a fortnight - which is what a backend
// restart does, under Restart=always or in the documented "upgrade the backend
// first" order - and the anchor holds a seed a fortnight behind. The frontend
// then restarts and reseeds from its own clock, a fortnight ahead of that
// anchor in one step. Measured from elapsed time alone the ceiling would not
// cover it for another fortnight, and nothing re-anchors, so every decision
// from the new process was refused for as long as this agent ran: `active`
// stays zero, the return path stays where applyPlumbing seeded it, and all
// three paths measure perfectly while replies leave by an abandoned tunnel.
func TestAFrontendRestartAfterALongUptimeIsNotRefused(t *testing.T) {
	now := time.Now()
	uptime := 14 * 24 * time.Hour

	// This host restarts and anchors on the running frontend's current
	// sequence, which is a seed from when *that* process started.
	base := uint64(now.Add(-uptime).UnixMilli()) << 16
	baseAt := now

	// Moments later the frontend restarts and reseeds from its own clock.
	restarted := uint64(now.Add(time.Minute).UnixMilli()) << 16
	if !plausibleDecisionSeq(restarted, base, baseAt, now.Add(time.Minute)) {
		t.Fatal("a restarted frontend's first sequence was refused; the backend would never route a reply again")
	}

	// The bound is still a bound: a sequence far past this host's own clock is
	// not something any frontend restart can produce.
	beyond := uint64(now.Add(uptime+30*24*time.Hour).UnixMilli()) << 16
	if plausibleDecisionSeq(beyond, base, baseAt, now.Add(time.Minute)) {
		t.Fatal("a sequence a month past this host's clock was accepted; the ceiling is doing nothing")
	}
}

// A clock set absurdly far forward is ignored rather than trusted, and the
// anchor still carries the decision.
//
// The wall reading is shifted sixteen places to reach the sequence's units, and
// past about the year 10889 that no longer fits in a uint64. Taking the maximum
// of the two references makes a low wrap harmless - it simply loses the
// comparison - but not a high one: the year 300000 wraps to about 7.6e18, which
// as a ceiling admits anything, including the pin this check exists to refuse.
// So the wall reference is bounded by the same horizon the sequences are.
func TestAClockPastTheHorizonIsNotAReference(t *testing.T) {
	base := uint64(time.Now().UnixMilli()) << 16
	absurd := time.Date(300000, 1, 1, 0, 0, 0, 0, time.UTC)

	// The two times are five minutes apart on the absurd clock, which is how
	// this reaches the real code: baseAt and now are monotonic readings, so the
	// elapsed time between them is genuine process uptime whatever the wall
	// clock says, and only the wall half of `now` is wrong. Anchoring the pair
	// on the wrong clock keeps the elapsed five minutes honest.
	baseAt := absurd.Add(-5 * time.Minute)

	// The premise, stated rather than assumed: this clock really does overflow
	// the shift, and really does wrap to something high enough to matter.
	ms := uint64(absurd.UnixMilli())
	if ms < 1<<48 || ms<<16 <= base {
		t.Fatalf("this clock no longer overflows into a high wrap (%d); the test proves nothing", ms<<16)
	}

	// Two months past the anchor with a minute of real time elapsed: refused on
	// the anchor alone, and admitted by the wrapped clock if it is consulted.
	seq := base + (uint64((60 * 24 * time.Hour).Milliseconds()) << 16)
	if plausibleDecisionSeq(seq, base, baseAt, absurd) {
		t.Fatal("a clock past the horizon widened the ceiling by wrapping; it must not be a reference at all")
	}

	// And ignoring it costs nothing: a real decision an hour on still lands,
	// because the anchor was never the thing that needed rescuing here.
	real := base + (uint64(time.Hour.Milliseconds()) << 16)
	if !plausibleDecisionSeq(real, base, baseAt, baseAt.Add(time.Hour)) {
		t.Fatal("a real decision an hour after the anchor was refused")
	}
}

// A clock far in the future widens the ceiling but cannot lift it past the
// horizon, which is the backstop that applies with or without an anchor.
func TestTheHorizonStillBoundsAClockInTheFuture(t *testing.T) {
	baseAt := time.Now()
	base := uint64(baseAt.UnixMilli()) << 16
	// Year 2099: inside the horizon, so it is a legitimate reference and does
	// widen the ceiling by decades. Nothing past the horizon rides in on it.
	future := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	if !plausibleDecisionSeq(uint64(future.UnixMilli())<<16, base, baseAt, future) {
		t.Fatal("a clock in 2099 refused its own frontend's sequence")
	}
	if plausibleDecisionSeq(^uint64(0), base, baseAt, future) {
		t.Fatal("the horizon stopped applying once the clock moved forward")
	}
}
