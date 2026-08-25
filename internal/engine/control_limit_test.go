package engine

import (
	"context"
	"io"
	"log/slog"
	"reflect"
	"testing"
	"time"
)

// The concurrency limit admits up to its bound, refuses past it, and reuses a
// slot a finished connection released.
//
// The last of those is not padding: a limit that never gave a slot back would
// refuse everything after the first sixty-four callers the process ever saw,
// which is a worse outage than the one the limit prevents and would look
// identical to the frontend being unreachable.
func TestTheControlLimitAdmitsRefusesAndReleases(t *testing.T) {
	slots := make(chan struct{}, maxControlConns)

	admitted := 0
	for i := 0; i < maxControlConns; i++ {
		select {
		case slots <- struct{}{}:
			admitted++
		default:
		}
	}
	if admitted != maxControlConns {
		t.Fatalf("admitted %d connections, want %d", admitted, maxControlConns)
	}
	select {
	case slots <- struct{}{}:
		t.Fatal("admitted a connection past the limit")
	default:
	}
	<-slots // a connection finished
	select {
	case slots <- struct{}{}:
	default:
		t.Fatal("a released slot was not reusable")
	}
}

// listen fills in a concurrency limit it was not given, and that is a
// correctness fix rather than tidiness.
//
// The limit is a buffered channel consulted by a select with a default arm. A
// nil channel does not weaken that, it inverts it: a send on nil never
// proceeds, so default wins every time and the server refuses every connection
// it is ever offered, silently and for the life of the process. That is the
// direction this codebase keeps warning about, where the failure reports
// itself as normal operation.
//
// NewControlServer fills it in, so this can only be reached by building the
// struct literally - which three tests in this package already do. The
// constructor must not be the only thing between that and a server that
// accepts nothing.
func TestListenFillsInAConcurrencyLimitItWasNotGiven(t *testing.T) {
	s := &ControlServer{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		// Loopback, so this drives the real accept loop without needing the
		// overlay address, which a development machine does not hold.
		addr: "127.0.0.1:0",
	}
	if s.slots != nil {
		t.Fatal("this test is meaningless if a literal already carries slots")
	}

	// Cancelled up front. listen sets the limit as its first statement, before
	// it binds anything, so this needs no sleep and cannot flake on a loaded
	// machine: once listen has returned, that statement has run - whether the
	// bind succeeded, failed, or was never attempted.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { done <- s.listen(ctx) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("listen did not return")
	}
	// Reading s.slots after done gives a happens-before edge, so this does not
	// race with listen's write.

	if s.slots == nil {
		t.Fatal("listen left the concurrency limit nil; it would have refused every connection")
	}
	if cap(s.slots) != maxControlConns {
		t.Fatalf("limit has capacity %d, want %d", cap(s.slots), maxControlConns)
	}
}

// countingHandler counts log records so a throttle can be asserted from
// outside rather than by reading the code.
type countingHandler struct {
	slog.Handler
	n *int
}

func (h countingHandler) Handle(ctx context.Context, r slog.Record) error {
	*h.n++
	return nil
}

// Pre-authentication rejections are throttled, because a peer that cannot
// authenticate is a peer that redials.
//
// The connection limit caps how many connections are open at once and says
// nothing about how fast they can be cycled, so one Warn per failed attempt is
// unbounded output driven by a party that has proved nothing. Pushing real
// entries out of the journal is a cheap way to hide something, and every other
// noise report in this system is already throttled: the responder's three
// counters and the accept loop's own refusals.
func TestPreAuthRejectionsAreThrottled(t *testing.T) {
	var n int
	s := &ControlServer{log: slog.New(countingHandler{
		Handler: slog.NewTextHandler(io.Discard, nil), n: &n,
	})}

	for i := 0; i < 500; i++ {
		s.warnRejected("192.0.2.9:1234", "the peer could not prove it holds the shared secret", nil)
	}
	if n != 1 {
		t.Fatalf("500 rejections produced %d log records, want 1", n)
	}

	// And the throttle opens again, or a standing misconfiguration would be
	// reported once and never again for the life of the process.
	s.rejected.mu.Lock()
	s.rejected.at = time.Now().Add(-throttleWindow - time.Second)
	s.rejected.mu.Unlock()
	s.warnRejected("192.0.2.9:1234", "the peer could not prove it holds the shared secret", nil)
	if n != 2 {
		t.Fatalf("the throttle did not reopen after its interval: %d records", n)
	}
}

// A burst that stops inside the window is still reported, which is the half a
// throttle is for that the first version of this lost.
//
// Counting an event, reporting only when the window has passed since the last
// report, and resetting the counter means the tail of any burst that ends
// inside that window is discarded: 500 failed authentications in five seconds
// produced one line saying "1", and the other 499 were counted into a window
// that never emitted because the peer driving it had stopped. The journal then
// records a single rejected connection for a flood of five hundred, which is
// the opposite of what this log exists to surface.
func TestABurstThatStopsInsideTheWindowIsStillReported(t *testing.T) {
	var n int
	s := &ControlServer{log: slog.New(countingHandler{
		Handler: slog.NewTextHandler(io.Discard, nil), n: &n,
	})}

	for i := 0; i < 500; i++ {
		s.warnRejected("192.0.2.9:1234", "the peer could not prove it holds the shared secret", nil)
	}
	if n != 1 {
		t.Fatalf("500 rejections produced %d log records, want 1 so far", n)
	}

	// Nothing owing yet: the window is still open, and a flush inside it must
	// not turn the throttle into one line per tick.
	s.flushThrottles()
	if n != 1 {
		t.Fatalf("a flush inside the window logged: %d records, want 1", n)
	}

	// The peer has stopped. Once the window closes, the 499 counted behind the
	// first report are named rather than dropped.
	s.rejected.mu.Lock()
	s.rejected.at = time.Now().Add(-throttleWindow - time.Second)
	s.rejected.mu.Unlock()
	s.flushThrottles()
	if n != 2 {
		t.Fatalf("the tail of the burst was never reported: %d records, want 2", n)
	}

	// And a quiet server says nothing at all, however often this ticks.
	s.rejected.mu.Lock()
	s.rejected.at = time.Now().Add(-throttleWindow - time.Second)
	s.rejected.mu.Unlock()
	s.flushThrottles()
	if n != 2 {
		t.Fatalf("a flush with nothing owing logged: %d records, want 2", n)
	}
}

// One address cannot hold the whole connection pool, and the honest peer is
// the one that would have lost.
//
// maxControlConns bounds the total and reserves nothing, so before the
// per-address share every connection claimed from one pool before proving
// anything: sixty-four sockets from one machine, opened and left silent, held
// it for as long as they were re-dialled and the backend's reconnect was closed
// on sight. That is not a portal that looks wrong - no usage delta reaches the
// ledger, so LTE billing under-counts during exactly the window quota
// enforcement exists for, and no configuration reaches the backend.
func TestOneAddressCannotHoldTheWholePool(t *testing.T) {
	s := &ControlServer{
		log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		slots: make(chan struct{}, maxControlConns),
	}

	for i := 0; i < maxPerSource; i++ {
		if !s.claimSource("198.51.100.7") {
			t.Fatalf("refused connection %d from one address, want up to %d", i+1, maxPerSource)
		}
	}
	if s.claimSource("198.51.100.7") {
		t.Fatal("one address took more than its share of the pool")
	}

	// The peers that are not flooding are unaffected, which is the whole point
	// of counting per address rather than only in total.
	if !s.claimSource("198.51.100.8") {
		t.Fatal("a second address was refused while another was over its share")
	}

	// A finished connection gives its share back, or a peer that reconnects
	// four times over the life of the process would lock itself out.
	s.releaseSource("198.51.100.7")
	if !s.claimSource("198.51.100.7") {
		t.Fatal("a released per-address slot was not reusable")
	}

	// And the map does not grow with every address that ever dialled: the keys
	// are chosen by whoever connects, so an unbounded map would be a second
	// resource behind the limit meant to bound the first.
	for i := 0; i < maxPerSource; i++ {
		s.releaseSource("198.51.100.7")
	}
	s.releaseSource("198.51.100.8")
	s.srcMu.Lock()
	left := len(s.perSource)
	s.srcMu.Unlock()
	if left != 0 {
		t.Fatalf("per-source map kept %d entries after every connection finished", left)
	}
}

// Every throttle on the server has a trailing edge, checked by counting the
// fields rather than by reading the list.
//
// The failure this guards is silent by construction: a new reason needs a field
// and an entry in reports(), and omitting the entry compiles, passes every other
// test, and leaves a counter that fills up and never emits - which is precisely
// the defect the trailing edge was added to fix. Reflection is what makes the
// check independent of the thing it is checking.
func TestEveryThrottleHasATrailingEdge(t *testing.T) {
	s := &ControlServer{}
	v := reflect.ValueOf(s).Elem()
	throttleType := reflect.TypeOf(throttle{})

	var fields []string
	for i := 0; i < v.NumField(); i++ {
		if v.Type().Field(i).Type == throttleType {
			fields = append(fields, v.Type().Field(i).Name)
		}
	}
	if len(fields) == 0 {
		t.Fatal("no throttle fields found; this test is not looking at the right struct")
	}

	reported := map[uintptr]bool{}
	for _, r := range s.reports() {
		reported[reflect.ValueOf(r.t).Pointer()] = true
		if r.msg == "" || r.countKey == "" {
			t.Errorf("a report has no message or no count key: %+v", r)
		}
	}
	for i := 0; i < v.NumField(); i++ {
		f := v.Type().Field(i)
		if f.Type != throttleType {
			continue
		}
		if !reported[v.Field(i).Addr().Pointer()] {
			t.Errorf("throttle %q has no entry in reports(), so a burst that stops is counted and never reported", f.Name)
		}
	}
	if len(s.reports()) != len(fields) {
		t.Errorf("reports() has %d entries for %d throttles: %v", len(s.reports()), len(fields), fields)
	}
}
