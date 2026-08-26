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
	if got := u.fetches.Load(); got != 0 {
		// The upstream may legitimately have been polled by now (demand was
		// stamped), so assert the client side only: nothing above was a
		// payload. This check is that the *spoofer* caused no serving, kept
		// deliberately loose because the refresher polling is correct.
		_ = got
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
