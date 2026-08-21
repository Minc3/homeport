package agent

import (
	"testing"
	"time"
)

// The backoff has to come back down, and the reason is not politeness.
//
// It used to only ever grow: a session that had been up for a week ended the
// same way as one that never authenticated, so after five or six failovers -
// each of which drops the TCP connection - the backend waited the full thirty
// seconds before every later redial, including the one immediately after a
// switch, when the frontend most needs to hear from it.
func TestDialBackoffResetsAfterASessionThatWorked(t *testing.T) {
	// A run of failures climbs to the ceiling and stops there.
	d := dialBackoffMin
	for i := 0; i < 10; i++ {
		d = nextDialBackoff(d, time.Second)
	}
	if d != dialBackoffMax {
		t.Fatalf("backoff after ten quick failures = %v, want the %v ceiling", d, dialBackoffMax)
	}

	// A session that stayed up puts it back to the floor, whatever it had
	// climbed to.
	if got := nextDialBackoff(d, sessionSettled); got != dialBackoffMin {
		t.Errorf("backoff after a settled session = %v, want %v", got, dialBackoffMin)
	}

	// A session that ended just short of settling does not.
	if got := nextDialBackoff(dialBackoffMin, sessionSettled-time.Millisecond); got <= dialBackoffMin {
		t.Errorf("a session that never settled must still back off, got %v", got)
	}
}

// Doubling, from the floor, without overshooting the ceiling.
func TestDialBackoffGrowsWithinItsBounds(t *testing.T) {
	if got := nextDialBackoff(dialBackoffMin, 0); got != 2*dialBackoffMin {
		t.Errorf("first retry = %v, want %v", got, 2*dialBackoffMin)
	}
	if got := nextDialBackoff(dialBackoffMax, 0); got != dialBackoffMax {
		t.Errorf("backoff grew past its ceiling: %v", got)
	}
	if got := nextDialBackoff(0, 0); got != dialBackoffMin {
		t.Errorf("backoff from zero = %v, want the %v floor", got, dialBackoffMin)
	}
}
