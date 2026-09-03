package qcache

import (
	"bytes"
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// fakeUpstream is a Source server for tests: it speaks the challenge dance
// and answers INFO and PLAYER from fixed payloads, counting the completed
// fetches so a test can assert how often the cache actually came upstream.
type fakeUpstream struct {
	conn      *net.UDPConn
	infoBody  []byte
	multi     [][]byte // when set, the INFO answer is these datagrams instead
	fetches   atomic.Int64
	challenge []byte

	// Per-type counts, for the tests that pin the RULES cadence against the
	// INFO one. fetches is still the total.
	infoFetches  atomic.Int64
	rulesFetches atomic.Int64
}

// tune runs before the serve goroutine starts, so a test setting the multi
// fragments does not race the reads in serve.
func newFakeUpstream(t *testing.T, tune ...func(*fakeUpstream)) *fakeUpstream {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("fake upstream: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	u := &fakeUpstream{
		conn:      conn,
		infoBody:  append(append([]byte{}, headerSingle...), 0x49, 'h', 'e', 'l', 'l', 'o'),
		challenge: []byte{1, 2, 3, 4},
	}
	for _, f := range tune {
		f(u)
	}
	go u.serve()
	return u
}

func (u *fakeUpstream) port() int { return u.conn.LocalAddr().(*net.UDPAddr).Port }

// rulesBody is the A2S_RULES answer: 'E' and a token payload.
func (u *fakeUpstream) rulesBody() []byte {
	return append(append([]byte{}, headerSingle...), 0x45, 0x01, 0x00, 's', 'v', 0x00)
}

func (u *fakeUpstream) serve() {
	buf := make([]byte, 4096)
	for {
		n, addr, err := u.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		kind, ch := classify(buf[:n])
		switch kind {
		case queryInfoBare, queryPlayerBare:
			u.conn.WriteToUDP(challengeReply(u.challenge), addr)
		case queryInfoChallenged:
			if !bytes.Equal(ch, u.challenge) {
				u.conn.WriteToUDP(challengeReply(u.challenge), addr)
				continue
			}
			u.fetches.Add(1)
			u.infoFetches.Add(1)
			if u.multi != nil {
				for _, d := range u.multi {
					u.conn.WriteToUDP(d, addr)
				}
				continue
			}
			u.conn.WriteToUDP(u.infoBody, addr)
		case queryPlayerChallenged:
			if !bytes.Equal(ch, u.challenge) {
				u.conn.WriteToUDP(challengeReply(u.challenge), addr)
				continue
			}
			u.fetches.Add(1)
			u.conn.WriteToUDP(append(append([]byte{}, headerSingle...), 0x44, 0x01), addr)
		case queryRulesBare:
			u.conn.WriteToUDP(challengeReply(u.challenge), addr)
		case queryRulesChallenged:
			if !bytes.Equal(ch, u.challenge) {
				u.conn.WriteToUDP(challengeReply(u.challenge), addr)
				continue
			}
			u.fetches.Add(1)
			u.rulesFetches.Add(1)
			u.conn.WriteToUDP(u.rulesBody(), addr)
		}
	}
}

// startCacher runs one cached port against the upstream and hands back the
// address a client should query. Knobs are tightened so the tests run in
// milliseconds rather than at deployment cadence.
func startCacher(t *testing.T, upstream *fakeUpstream, tune func(*Config)) (*Cacher, net.Addr, context.CancelFunc) {
	t.Helper()
	cfg := Config{
		Ports:           []Port{{Port: 0, Target: "127.0.0.1", TargetPort: upstream.port(), Service: "test"}},
		Bind:            "127.0.0.1",
		RefreshEvery:    40 * time.Millisecond,
		IdleAfter:       5 * time.Second,
		StaleAfter:      5 * time.Second,
		UpstreamTimeout: time.Second,
	}
	if tune != nil {
		tune(&cfg)
	}
	c := New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); c.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	<-c.bound
	if c.ports[0].conn == nil {
		t.Fatalf("cacher did not bind: %v", c.ports[0].bindErrString())
	}
	return c, c.ports[0].conn.LocalAddr(), cancel
}

// client is one querying socket.
type client struct {
	t    *testing.T
	conn *net.UDPConn
}

func newClient(t *testing.T, to net.Addr) *client {
	t.Helper()
	conn, err := net.DialUDP("udp4", nil, to.(*net.UDPAddr))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return &client{t: t, conn: conn}
}

func (c *client) send(b []byte) {
	c.t.Helper()
	if _, err := c.conn.Write(b); err != nil {
		c.t.Fatalf("client send: %v", err)
	}
}

func (c *client) read(within time.Duration) []byte {
	c.t.Helper()
	c.conn.SetReadDeadline(time.Now().Add(within))
	buf := make([]byte, 4096)
	n, err := c.conn.Read(buf)
	if err != nil {
		return nil
	}
	return append([]byte(nil), buf[:n]...)
}

// mustChallenge reads a reply and requires it to be an S2C_CHALLENGE.
func (c *client) mustChallenge() []byte {
	c.t.Helper()
	b := c.read(2 * time.Second)
	ch, ok := isChallenge(b)
	if !ok {
		c.t.Fatalf("wanted a challenge, got % x", b)
	}
	return ch
}

// queryInfo runs the full client dance: bare query, challenge, retry. It
// retries the challenged query for a while because the first one races the
// cache's own upstream fetch, exactly as a real browser's retry does.
func (c *client) queryInfo() []byte {
	c.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c.send(infoRequest(nil))
		ch := c.mustChallenge()
		c.send(infoRequest(ch))
		if b := c.read(200 * time.Millisecond); b != nil {
			return b
		}
	}
	c.t.Fatalf("no payload before the deadline")
	return nil
}

// A source that has not completed a challenge is never served a payload, and
// the challenge it gets back is smaller than the query that provoked it.
// Both halves are the anti-spoofing property: a spoofed source cannot answer
// a challenge it never sees, and the exchange amplifies nothing, so the
// cache cannot be pointed at a victim the way a bare A2S responder can.
func TestUnchallengedQueryGetsASmallerChallengeNeverAPayload(t *testing.T) {
	u := newFakeUpstream(t)
	_, addr, _ := startCacher(t, u, nil)
	c := newClient(t, addr)

	q := infoRequest(nil)
	c.send(q)
	reply := c.read(2 * time.Second)
	if _, ok := isChallenge(reply); !ok {
		t.Fatalf("bare INFO got % x, want a challenge", reply)
	}
	if len(reply) >= len(q) {
		t.Errorf("challenge reply is %d bytes to the query's %d; amplification", len(reply), len(q))
	}

	// A guessed challenge is a spoofer's only other move, and it earns
	// another challenge, not a payload.
	c.send(infoRequest([]byte{9, 9, 9, 9}))
	if _, ok := isChallenge(c.read(2 * time.Second)); !ok {
		t.Fatalf("a wrong challenge was not answered with a fresh challenge")
	}

	// The bare PLAYER and RULES queries are the sharp edge of the
	// no-amplification claim: at 9 bytes they exactly equal the challenge
	// reply, so the property there is "never larger", not "smaller" - a
	// spoofed flood of them is reflected 1:1, which is the floor any UDP
	// responder has. Pinned as <=, deliberately: a reply one byte larger
	// than the query would make the cache an amplifier.
	for _, q := range [][]byte{playerRequest(nil), rulesRequest(nil)} {
		c.send(q)
		reply := c.read(2 * time.Second)
		if _, ok := isChallenge(reply); !ok {
			t.Fatalf("bare query % x got % x, want a challenge", q, reply)
		}
		if len(reply) > len(q) {
			t.Errorf("challenge reply is %d bytes to the query's %d; amplification", len(reply), len(q))
		}
	}
	// And the spoofer drove no upstream traffic either. Nothing above
	// completed a challenge, so no demand was stamped and the refresher must
	// not have polled: demand is what keeps the refresh stream running down
	// the billed tunnel, and a source that cannot echo a challenge back must
	// not be able to keep it running - a trickle of bare queries costing the
	// sender nothing would otherwise bill upstream polling through an LTE
	// failover indefinitely. The sleep covers several 40ms refresh intervals,
	// so a stamped demand could not hide in the window.
	time.Sleep(200 * time.Millisecond)
	if got := u.fetches.Load(); got != 0 {
		t.Errorf("the upstream was fetched %d times on unverified queries alone; a spoofer can drive the refresh stream", got)
	}
}

// The caching property itself: many client queries, few upstream fetches.
// Without the cache every query crosses to the server; with it the upstream
// sees the refresh cadence and nothing else, whatever the query rate.
func TestManyQueriesCostFewUpstreamFetches(t *testing.T) {
	u := newFakeUpstream(t)
	_, addr, _ := startCacher(t, u, nil)
	c := newClient(t, addr)

	first := c.queryInfo()
	if !bytes.Equal(first, u.infoBody) {
		t.Fatalf("served % x, want the upstream's INFO % x", first, u.infoBody)
	}
	for range 50 {
		if b := c.queryInfo(); !bytes.Equal(b, u.infoBody) {
			t.Fatalf("served % x mid-run", b)
		}
	}
	// 51 served queries in well under a second. The refresher polls every
	// 40ms here, so allow its cadence with slack; the point is the order of
	// magnitude, not the exact count.
	if got := u.fetches.Load(); got > 30 {
		t.Errorf("upstream was fetched %d times for 51 client queries; the cache is not caching", got)
	}
}

// A2S_RULES is cached like the other two, and it has to be rather than
// nice-to-have: the redirect is a NAT verdict, NAT verdicts bind to the
// conntrack flow, and a server browser sends INFO, PLAYER and RULES from one
// socket - so a RULES packet on a tuple that queried INFO first arrives here
// whatever the ruleset's type-byte match says. A cache that could not answer
// it would be silently dropping it.
func TestRulesQueriesAreCachedToo(t *testing.T) {
	u := newFakeUpstream(t)
	_, addr, _ := startCacher(t, u, nil)
	c := newClient(t, addr)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c.send(rulesRequest(nil))
		ch := c.mustChallenge()
		c.send(rulesRequest(ch))
		if b := c.read(200 * time.Millisecond); b != nil {
			if !bytes.Equal(b, u.rulesBody()) {
				t.Fatalf("served % x, want the upstream's RULES % x", b, u.rulesBody())
			}
			return
		}
	}
	t.Fatalf("no RULES payload before the deadline")
}

// A port nobody queries costs nothing upstream: the refresh is demand-driven,
// which is what makes a backend full of Source servers affordable to cache.
func TestIdlePortNeverPollsUpstream(t *testing.T) {
	u := newFakeUpstream(t)
	startCacher(t, u, nil)
	time.Sleep(300 * time.Millisecond)
	if got := u.fetches.Load(); got != 0 {
		t.Errorf("upstream fetched %d times with no client demand", got)
	}
}

// A multi-packet upstream reply is replayed to the client verbatim, fragment
// for fragment, because the cache stores datagrams rather than reassembling
// payloads it has no need to parse.
func TestMultipacketRepliesAreReplayedVerbatim(t *testing.T) {
	frag := func(index byte, body string) []byte {
		b := append([]byte{}, headerMulti...)
		b = append(b, 0xAA, 0xBB, 0xCC, 0x0C) // ID, high bit clear
		b = append(b, 2, index)
		return append(b, body...)
	}
	u := newFakeUpstream(t, func(u *fakeUpstream) {
		u.multi = [][]byte{frag(0, "first"), frag(1, "second")}
	})

	_, addr, _ := startCacher(t, u, nil)
	c := newClient(t, addr)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c.send(infoRequest(nil))
		ch := c.mustChallenge()
		c.send(infoRequest(ch))
		one := c.read(200 * time.Millisecond)
		if one == nil {
			continue
		}
		two := c.read(2 * time.Second)
		if !bytes.Equal(one, u.multi[0]) || !bytes.Equal(two, u.multi[1]) {
			t.Fatalf("fragments not replayed verbatim:\n% x\n% x", one, two)
		}
		return
	}
	t.Fatalf("no multipacket payload before the deadline")
}

// A cache past its staleness bound answers nothing rather than advertising a
// server that may be gone: the client is still challenged, because the
// challenge costs nothing and keeps the source classified, but no payload
// follows. Serving stale forever would keep a dead server listed in every
// browser for as long as the frontend ran.
func TestStaleCacheAnswersNothing(t *testing.T) {
	u := newFakeUpstream(t)
	cacher, addr, _ := startCacher(t, u, func(c *Config) {
		c.StaleAfter = 150 * time.Millisecond
	})
	c := newClient(t, addr)
	c.queryInfo() // warm the cache

	// Take the upstream away and let the cache pass its bound. The refresher
	// keeps failing in the background, which is the deployed shape of a
	// tunnel outage.
	u.conn.Close()
	time.Sleep(300 * time.Millisecond)

	c.send(infoRequest(nil))
	ch := c.mustChallenge()
	c.send(infoRequest(ch))
	if b := c.read(300 * time.Millisecond); b != nil {
		t.Fatalf("a stale cache served % x", b)
	}
	// And the state says so, which is what the portal renders: the counter
	// moved and the age is past the bound.
	st := cacher.Snapshot()
	if len(st) != 1 || st[0].Unanswered == 0 {
		t.Errorf("unanswered query not counted: %+v", st)
	}
}

// A port whose upstream never answers says so: the failure lands in the
// snapshot the portal renders. Without it, "never fetched" beside climbing
// counters cannot distinguish a down game server from a port only scanners
// query, which is a dashboard that reports a question. This is also the
// first failure the port ever has, which pins the logging edge case the
// same state feeds: fetchOK must start true or the first failure is not an
// edge and stays silent everywhere.
func TestAnUnreachableUpstreamIsNamedInTheSnapshot(t *testing.T) {
	u := newFakeUpstream(t)
	u.conn.Close() // nothing will ever answer
	cacher, addr, _ := startCacher(t, u, func(c *Config) {
		c.UpstreamTimeout = 200 * time.Millisecond
	})
	c := newClient(t, addr)

	// A real client's dance: the challenge works, the payload never comes.
	c.send(infoRequest(nil))
	ch := c.mustChallenge()
	c.send(infoRequest(ch))
	if b := c.read(100 * time.Millisecond); b != nil {
		t.Fatalf("an empty cache served % x", b)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		st := cacher.Snapshot()
		if len(st) == 1 && st[0].RefreshError != "" {
			if st[0].InfoAgeSec != -1 {
				t.Errorf("info age = %v, want -1 for never fetched", st[0].InfoAgeSec)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("refresh error never surfaced: %+v", st)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Cancellation tears the whole thing down promptly. The read loops sit on
// sockets with no deadline, so this is invariant 17: the context watcher
// must close the socket, or every settings save would stall on a read that
// nothing will ever complete.
func TestCancelStopsPromptly(t *testing.T) {
	u := newFakeUpstream(t)
	c := New(Config{
		Ports: []Port{{Port: 0, Target: "127.0.0.1", TargetPort: u.port(), Service: "test"}},
		Bind:  "127.0.0.1",
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); c.Run(ctx) }()
	<-c.bound
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("Run did not return within 2s of cancellation")
	}
}

// A port something else already holds is reported and skipped, and the ports
// beside it still serve: one lost bind must not take the other fifteen down.
func TestBindFailureIsReportedAndDoesNotSinkTheRest(t *testing.T) {
	u := newFakeUpstream(t)
	taken, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("holding a port: %v", err)
	}
	defer taken.Close()
	takenPort := taken.LocalAddr().(*net.UDPAddr).Port

	c := New(Config{
		Ports: []Port{
			{Port: takenPort, Target: "127.0.0.1", TargetPort: u.port(), Service: "held"},
			{Port: 0, Target: "127.0.0.1", TargetPort: u.port(), Service: "free"},
		},
		Bind:            "127.0.0.1",
		RefreshEvery:    40 * time.Millisecond,
		IdleAfter:       5 * time.Second,
		StaleAfter:      5 * time.Second,
		UpstreamTimeout: time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); c.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	<-c.bound

	var held, free *portCache
	for _, p := range c.ports {
		if p.cfg.Service == "held" {
			held = p
		} else {
			free = p
		}
	}
	if held.bindErrString() == "" {
		t.Errorf("the held port reports no bind error")
	}
	if free.conn == nil {
		t.Fatalf("the free port did not bind")
	}
	cl := newClient(t, free.conn.LocalAddr())
	if b := cl.queryInfo(); !bytes.Equal(b, u.infoBody) {
		t.Errorf("the free port served % x", b)
	}
}

// A failed fetch is retried at the refresh cadence, not the ticker's
// quarter-interval. The refresher ticks at RefreshEvery/4 so a nudge or a due
// fetch lands promptly, but due is measured from the last attempt: measured
// from the last *success*, a failure never advanced the clock, so a crashed
// game server whose port refused or stayed silent was polled at four times
// the configured rate, down the active tunnel, for as long as it stayed down
// - billed during exactly the outages the metering exists for.
func TestFailingUpstreamIsRetriedAtTheRefreshCadence(t *testing.T) {
	// An upstream that hears every query and never answers, so every fetch
	// fails on its own timeout and the datagrams heard count the attempts.
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("silent upstream: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	var heard atomic.Int64
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, _, err := conn.ReadFromUDP(buf); err != nil {
				return
			}
			heard.Add(1)
		}
	}()

	c := New(Config{
		Ports:           []Port{{Port: 0, Target: "127.0.0.1", TargetPort: conn.LocalAddr().(*net.UDPAddr).Port, Service: "test"}},
		Bind:            "127.0.0.1",
		RefreshEvery:    200 * time.Millisecond,
		IdleAfter:       5 * time.Second,
		StaleAfter:      5 * time.Second,
		UpstreamTimeout: 20 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); c.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	<-c.bound
	if c.ports[0].conn == nil {
		t.Fatalf("cacher did not bind: %v", c.ports[0].bindErrString())
	}

	// Stamp demand for INFO the only way a client can: complete the
	// challenge dance. The payload never comes, which is the point.
	cl := newClient(t, c.ports[0].conn.LocalAddr())
	cl.send(infoRequest(nil))
	ch := cl.mustChallenge()
	cl.send(infoRequest(ch))

	// A second of failures at a 200ms cadence is about six attempts counting
	// the nudged first one. The unpaced retry made it about twenty, so the
	// bound separates the two with slack for scheduling on either side.
	time.Sleep(time.Second)
	got := heard.Load()
	if got > 8 {
		t.Errorf("a failing upstream heard %d fetch attempts in a second at a 200ms cadence; retries are not paced", got)
	}
	if got < 2 {
		t.Errorf("a failing upstream heard only %d fetch attempts; it is not being retried at all", got)
	}
}

// The shipped staleness bound must cover at least three shipped refresh
// intervals, the same floor validate and the engine hold for configured
// values: between polls every answer is served from the staleness window,
// and one failed fetch has to be retryable inside it, or a healthy port
// goes dark between refreshes out of the box.
func TestShippedStalenessCoversThreeRefreshIntervals(t *testing.T) {
	if DefaultStaleAfter < 3*DefaultRefreshEvery {
		t.Fatalf("DefaultStaleAfter %v is under three DefaultRefreshEvery %v; a fresh install would go dark between refreshes",
			DefaultStaleAfter, DefaultRefreshEvery)
	}
}
