package qcache

import (
	"net"
	"testing"
	"time"
)

// The challenge stops a spoofed source being served at all and says nothing
// about a real one: an address that has echoed its challenge could draw the
// whole cached reply, up to maxFragments datagrams, for every 9-byte query it
// sent, paced by nothing in this package. The bucket is what holds a real
// address to a rate, and it has to be charged per reply byte rather than per
// query, because the reply is what costs the uplink.
func TestAVerifiedSourceIsPacedByReplyBytes(t *testing.T) {
	u := newFakeUpstream(t)
	// Two INFO replies fit the burst, the third does not, and the refill is
	// slow enough that the test never sees it.
	c, addr, _ := startCacher(t, u, func(cfg *Config) {
		cfg.PaceBurst = 2 * len(u.infoBody)
		cfg.PaceRefill = 1
	})
	cl := newClient(t, addr)

	first := cl.queryInfo()
	if len(first) != len(u.infoBody) {
		t.Fatalf("first reply is % x, want the upstream's INFO", first)
	}
	cl.send(infoRequest(nil))
	ch := cl.mustChallenge()
	cl.send(infoRequest(ch))
	if b := cl.read(time.Second); b == nil {
		t.Fatal("the second reply is inside the burst and was not served")
	}
	cl.send(infoRequest(ch))
	if b := cl.read(300 * time.Millisecond); b != nil {
		t.Fatalf("a third reply was served past the burst: % x", b)
	}
	st := c.Snapshot()[0]
	if st.Paced != 1 || st.Answered != 2 {
		t.Fatalf("paced=%d answered=%d, want 1 paced after 2 answered", st.Paced, st.Answered)
	}
}

// A reply the bucket cannot cover is dropped whole. Half a multi-packet reply
// is worse than none: the browser waits on fragments that never come and
// then reassembles nothing, and the bytes that did go out were wasted.
func TestPacingNeverSendsAPartialReply(t *testing.T) {
	frag := func(total, index byte, body ...byte) []byte {
		d := append([]byte{}, headerMulti...)
		d = append(d, 0x11, 0x22, 0x33, 0x44, total, index, 0, 0)
		return append(d, body...)
	}
	u := newFakeUpstream(t, func(u *fakeUpstream) {
		u.multi = [][]byte{frag(2, 0, 'a', 'a', 'a', 'a'), frag(2, 1, 'b', 'b', 'b', 'b')}
	})
	total := len(u.multi[0]) + len(u.multi[1])
	c, addr, _ := startCacher(t, u, func(cfg *Config) {
		cfg.PaceBurst = total - 1 // one fragment fits, the reply does not
		cfg.PaceRefill = 1
	})
	cl := newClient(t, addr)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && c.Snapshot()[0].Paced == 0 {
		cl.send(infoRequest(nil))
		ch := cl.mustChallenge()
		cl.send(infoRequest(ch))
		if b := cl.read(100 * time.Millisecond); b != nil {
			t.Fatalf("a fragment was sent from a reply the bucket could not cover: % x", b)
		}
	}
	if st := c.Snapshot()[0]; st.Paced == 0 || st.Answered != 0 {
		t.Fatalf("paced=%d answered=%d, want the reply refused whole", st.Paced, st.Answered)
	}
}

// The budget is per source address. One address spending its burst must not
// cost the next player a reply, and the refill has to bring a spent source
// back exactly when its bucket covers the reply again, never later.
func TestPacingIsPerSourceAndRefills(t *testing.T) {
	p := newPacer(100, 10, time.Minute, 16)
	a, b := net.ParseIP("203.0.113.5"), net.ParseIP("198.51.100.9")
	now := time.Unix(1_700_000_000, 0)

	if !p.allow(a, 60, now) || !p.allow(a, 40, now) {
		t.Fatal("two replies inside the burst were refused")
	}
	if p.allow(a, 1, now) {
		t.Fatal("a spent source was served")
	}
	if !p.allow(b, 100, now) {
		t.Fatal("a second source was refused on the first source's account")
	}
	if p.allow(a, 50, now.Add(4*time.Second)) {
		t.Fatal("served before the refill covered the reply")
	}
	if !p.allow(a, 50, now.Add(5*time.Second)) {
		t.Fatal("not served once the refill covered the reply")
	}
}

// The table is bounded per port and pruned by idleness, because its keys are
// chosen by whoever sends: an unbounded map is a second thing a flood of real
// addresses could fill.
func TestPacingTableIsBoundedAndPruned(t *testing.T) {
	p := newPacer(100, 10, time.Minute, 4)
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < 10; i++ {
		p.allow(net.IPv4(10, 0, 0, byte(i)), 1, now)
	}
	if n := p.sources(); n != 4 {
		t.Fatalf("%d sources tracked, want the cap of 4", n)
	}
	p.allow(net.IPv4(10, 0, 1, 1), 1, now.Add(2*time.Minute))
	if n := p.sources(); n != 1 {
		t.Fatalf("%d sources tracked after the idle window, want only the live one", n)
	}
}

// RULES changes on a map change and is by far the largest reply, so it is
// refreshed at a multiple of the INFO cadence: at INFO's rate it was the bulk
// of what the refresh stream cost down a metered tunnel. Its staleness bound
// stretches with it, or a reply being served perfectly well would go dark
// between its own refreshes.
func TestRulesIsRefreshedAtAFractionOfTheInfoCadenceAndStaysServed(t *testing.T) {
	u := newFakeUpstream(t)
	c, addr, _ := startCacher(t, u, func(cfg *Config) {
		cfg.RefreshEvery = 40 * time.Millisecond
		cfg.StaleAfter = 130 * time.Millisecond // three INFO intervals, under one RULES interval
	})
	cl := newClient(t, addr)

	// Warm both, then keep both in demand for a while.
	cl.queryInfo()
	deadline := time.Now().Add(3 * time.Second)
	var rulesCh []byte
	for time.Now().Before(deadline) && rulesCh == nil {
		cl.send(rulesRequest(nil))
		ch := cl.mustChallenge()
		cl.send(rulesRequest(ch))
		if b := cl.read(200 * time.Millisecond); b != nil {
			rulesCh = ch
		}
	}
	if rulesCh == nil {
		t.Fatal("RULES never warmed")
	}
	u.infoFetches.Store(0)
	u.rulesFetches.Store(0)
	end := time.Now().Add(800 * time.Millisecond)
	served, dark := 0, 0
	for time.Now().Before(end) {
		cl.send(infoRequest(rulesCh))
		cl.read(100 * time.Millisecond)
		cl.send(rulesRequest(rulesCh))
		if cl.read(100*time.Millisecond) != nil {
			served++
		} else {
			dark++
		}
		time.Sleep(20 * time.Millisecond)
	}
	info, rules := u.infoFetches.Load(), u.rulesFetches.Load()
	if rules < 1 || rules*3 > info {
		t.Fatalf("%d RULES fetches against %d INFO fetches; RULES should be polled at a fraction of the INFO cadence", rules, info)
	}
	if dark > 0 {
		t.Fatalf("RULES went unanswered %d times of %d while in demand; its staleness bound has to cover its own refresh interval", dark, served+dark)
	}
	if st := c.Snapshot()[0]; st.RulesStaleSec <= st.StaleSec {
		t.Fatalf("rules_stale_sec %v is not longer than stale_sec %v", st.RulesStaleSec, st.StaleSec)
	}
}
