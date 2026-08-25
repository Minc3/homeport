package agent

import (
	"sync"
	"time"
)

// throttleWindow is how often any one throttled report may reach the journal.
// The same thirty seconds as the frontend's, and for the same reason: a
// genuinely misconfigured peer retries on a backoff that tops out around
// there, so an operator sees a standing fault about as often as it happens.
const throttleWindow = 30 * time.Second

// throttle collapses a burst of one kind of report into a bounded number of
// journal entries. The first event is reported at once (take), and everything
// counted behind it is reported when the window closes (flush).
//
// A mirror of the engine's throttle in internal/engine/control.go, by hand,
// because the dependency cannot run either way: the engine must not be linked
// into the backend binary, and the engine imports nothing from here. If the
// rule moves in one, move it in the other - the same arrangement
// model.ipv4Literal has with sysx.AddressLiteral.
//
// It exists because this package had grown two fresh copies of exactly the
// shape that type was written to kill: count, report when the window has
// passed since the last report, reset. A burst that stopped inside the window
// was counted into a report that never emitted - five hundred refused
// decisions over five seconds produced one line saying "1", and the rest were
// silently forgotten, which is the opposite of what the log is for. The flush
// is the half that fixes it, and it needs a ticker behind it for as long as
// the events can occur: Responder.flushThrottles is that ticker.
type throttle struct {
	mu   sync.Mutex
	at   time.Time
	seen int
}

// take counts one event and reports how many this report should name, or zero
// when the window is still open and this one is only counted.
func (t *throttle) take() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.seen++
	if time.Since(t.at) < throttleWindow {
		return 0
	}
	n := t.seen
	t.at, t.seen = time.Now(), 0
	return n
}

// flush reports what has been counted since the last report, once the window
// has closed. It returns zero when there is nothing owing, so a quiet agent
// logs nothing at all.
func (t *throttle) flush() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.seen == 0 || time.Since(t.at) < throttleWindow {
		return 0
	}
	n := t.seen
	t.at, t.seen = time.Now(), 0
	return n
}
