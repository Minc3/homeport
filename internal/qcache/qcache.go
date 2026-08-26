package qcache

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quinlan102/homeport/internal/model"
)

// Port is one cached port and the overlay address of the host really
// answering it - the backend, or a linker where the service targets one.
type Port struct {
	Port    int
	Target  string
	Service string

	// TargetPort is the upstream's port where it differs from Port. Zero,
	// the deployed case, queries the same port this cache serves: the DNAT
	// beside the redirect forwards the port unchanged, so the real server is
	// listening on it. Non-zero exists for the tests, which serve on an
	// ephemeral port and answer upstream on another.
	TargetPort int
}

// Config sizes a Cacher. The zero value of every knob takes the shipped
// default; the knobs exist for the tests, which cannot wait ten seconds to
// watch a cache go stale.
type Config struct {
	Ports []Port

	// Bind is the listen address, all interfaces when empty. The redirect
	// rewrites a query's destination to the arriving interface's own address,
	// so the responder cannot know a single address to bind; binding the
	// service port wide is safe because published traffic to it is DNAT'd to
	// the backend before local delivery ever comes into question - only
	// redirected queries reach these sockets.
	Bind string

	// RefreshEvery is the upstream poll interval while a port is being
	// queried, and it is the staleness a browser normally sees. The refresh
	// stream rides the active tunnel, so it is billed during an LTE failover:
	// at the shipped 3s an actively queried port costs about 25 MB a month,
	// and an idle port costs nothing at all, which is what IdleAfter is for.
	RefreshEvery time.Duration

	// IdleAfter stops refreshing a port this long after its last query. The
	// cache is demand-driven so that "loads of Source servers on the backend"
	// costs only what is actually being asked about.
	IdleAfter time.Duration

	// StaleAfter stops serving a cached reply older than this. It is the
	// whole of the trade the operator makes in the portal (QueryCache.
	// StaleMs): longer rides out a longer refresh outage before the port
	// goes quiet, shorter drops a server that has really crashed out of
	// browsers sooner. It must cover at least three refresh intervals,
	// because between polls every answer is served from this window and one
	// failed fetch has to be retryable inside it, or a healthy port goes
	// dark between refreshes; the engine holds that floor.
	StaleAfter time.Duration

	// UpstreamTimeout bounds one refresh round trip.
	UpstreamTimeout time.Duration

	Log *slog.Logger
}

// DefaultRefreshEvery and DefaultStaleAfter are exported because web.validate
// and the engine's clamp key their bounds on them: a default written out
// again in either place is a second definition the next tuning change can
// move apart, silently loosening the floor the staleness bound holds.
const (
	DefaultRefreshEvery    = 3 * time.Second
	DefaultStaleAfter      = 10 * time.Second
	defaultIdleAfter       = 60 * time.Second
	defaultUpstreamTimeout = 2 * time.Second
)

// Cacher runs one responder and one refresher per port. Build with New, run
// with Run, which returns only when the context is cancelled and every
// goroutine is gone - the caller's stop-and-wait discipline is the same as
// the probers', and for the same reason.
type Cacher struct {
	cfg    Config
	log    *slog.Logger
	secret []byte
	ports  []*portCache

	// bound closes once Run has finished binding, so a test that starts Run
	// on a goroutine can read the ephemeral addresses without racing it.
	bound chan struct{}
}

func New(cfg Config) *Cacher {
	if cfg.RefreshEvery <= 0 {
		cfg.RefreshEvery = DefaultRefreshEvery
	}
	if cfg.IdleAfter <= 0 {
		cfg.IdleAfter = defaultIdleAfter
	}
	if cfg.StaleAfter <= 0 {
		cfg.StaleAfter = DefaultStaleAfter
	}
	if cfg.UpstreamTimeout <= 0 {
		cfg.UpstreamTimeout = defaultUpstreamTimeout
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		// crypto/rand failing is a broken host; the challenge only has to be
		// unguessable to an off-path spoofer, so degrading to a fixed key is
		// wrong but starting anyway would hide it. Panic like the stdlib does.
		panic("qcache: crypto/rand: " + err.Error())
	}
	c := &Cacher{cfg: cfg, log: log, secret: secret, bound: make(chan struct{})}
	for _, p := range cfg.Ports {
		pc := &portCache{cfg: p, c: c, nudge: make(chan struct{}, 1)}
		pc.info.fetchOK = true
		pc.player.fetchOK = true
		pc.rules.fetchOK = true
		c.ports = append(c.ports, pc)
	}
	return c
}

// Run binds every port and serves until ctx is cancelled. A port that cannot
// be bound is reported loudly and skipped rather than failing the rest: its
// queries are being redirected to a closed port, which the portal says out
// loud via Snapshot, but one port already held by something else must not
// take the other fifteen down with it.
func (c *Cacher) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, p := range c.ports {
		conn, err := net.ListenPacket("udp4", net.JoinHostPort(c.cfg.Bind, strconv.Itoa(p.cfg.Port)))
		if err != nil {
			p.setBindErr(err)
			c.log.Error("query cache cannot bind its port",
				"port", p.cfg.Port, "service", p.cfg.Service, "err", err,
				"hint", "something else on the frontend holds this port; its A2S queries are being redirected to nothing")
			continue
		}
		p.conn = conn
		// Invariant 17: the read loop sits on the socket with nothing but the
		// close to interrupt it.
		context.AfterFunc(ctx, func() { conn.Close() })
		wg.Add(2)
		go func() { defer wg.Done(); p.serve(ctx) }()
		go func() { defer wg.Done(); p.refresh(ctx) }()
	}
	close(c.bound)
	<-ctx.Done()
	wg.Wait()
}

// Snapshot renders every port for the portal, in port order.
func (c *Cacher) Snapshot() []model.QueryCacheState {
	now := time.Now()
	out := make([]model.QueryCacheState, 0, len(c.ports))
	for _, p := range c.ports {
		st := model.QueryCacheState{
			Port:         p.cfg.Port,
			Service:      p.cfg.Service,
			Target:       p.cfg.Target,
			Answered:     p.answered.Load(),
			Challenged:   p.challenged.Load(),
			Unanswered:   p.unanswered.Load(),
			InfoAgeSec:   p.info.ageSec(now),
			PlayerAgeSec: p.player.ageSec(now),
			RulesAgeSec:  p.rules.ageSec(now),
			Error:        p.bindErrString(),
		}
		if st.RefreshError = p.info.lastErr(); st.RefreshError == "" {
			if st.RefreshError = p.player.lastErr(); st.RefreshError == "" {
				st.RefreshError = p.rules.lastErr()
			}
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

// cacheEntry is one cached reply (INFO or PLAYER) for one port. The
// datagrams are stored exactly as the upstream sent them, multi-packet
// fragments included, and replayed verbatim: the cache never parses a
// payload it serves, so there is no reassembly of its own to get wrong.
type cacheEntry struct {
	mu        sync.Mutex
	datagrams [][]byte
	fetched   time.Time // zero = never
	demand    time.Time // last valid client query of this type

	// fetchOK drives the edge-triggered logging and must start true, or the
	// first failure is not an edge and the one case an operator most needs
	// told about - a cache that has never reached its server at all - is the
	// one case the journal stays silent on. fetchErr is that failure kept
	// for the portal, because "never fetched" on the dashboard without the
	// reason is a question, not a report.
	fetchOK  bool
	fetchErr string
}

func (e *cacheEntry) lastErr() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.fetchErr
}

func (e *cacheEntry) stampDemand(now time.Time) {
	e.mu.Lock()
	e.demand = now
	e.mu.Unlock()
}

func (e *cacheEntry) ageSec(now time.Time) float64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fetched.IsZero() {
		return -1
	}
	return now.Sub(e.fetched).Seconds()
}

// fresh returns the cached datagrams if they are young enough to serve.
func (e *cacheEntry) fresh(now time.Time, staleAfter time.Duration) [][]byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fetched.IsZero() || now.Sub(e.fetched) > staleAfter {
		return nil
	}
	return e.datagrams
}

type portCache struct {
	cfg  Port
	c    *Cacher
	conn net.PacketConn

	mu      sync.Mutex
	bindErr error

	answered   atomic.Uint64
	challenged atomic.Uint64
	unanswered atomic.Uint64

	// nudge wakes the refresher the moment a query finds the cache cold, so
	// the client's retry after its challenge usually finds it warm. Buffered
	// one deep: a nudge that is already pending is the same nudge.
	nudge chan struct{}

	info   cacheEntry
	player cacheEntry
	rules  cacheEntry
}

func (p *portCache) setBindErr(err error) {
	p.mu.Lock()
	p.bindErr = err
	p.mu.Unlock()
}

func (p *portCache) bindErrString() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.bindErr == nil {
		return ""
	}
	return p.bindErr.Error()
}

func (p *portCache) maybeNudge() {
	select {
	case p.nudge <- struct{}{}:
	default:
	}
}

// serve is the responder: one datagram in, at most one challenge or one
// cached reply out. Nothing here blocks on anything but the socket, and
// nothing here ever talks upstream - a flood is answered entirely from
// memory, which is the point.
func (p *portCache) serve(ctx context.Context) {
	buf := make([]byte, 4096)
	for {
		n, addr, err := p.conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		src, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		now := time.Now()
		kind, ch := classify(buf[:n])
		switch kind {
		case queryInfoBare:
			p.info.stampDemand(now)
			p.maybeNudge()
			p.sendChallenge(src, now)
		case queryInfoChallenged:
			p.info.stampDemand(now)
			p.answerOrChallenge(&p.info, src, ch, now)
		case queryPlayerBare:
			p.player.stampDemand(now)
			p.maybeNudge()
			p.sendChallenge(src, now)
		case queryPlayerChallenged:
			p.player.stampDemand(now)
			p.answerOrChallenge(&p.player, src, ch, now)
		case queryRulesBare:
			p.rules.stampDemand(now)
			p.maybeNudge()
			p.sendChallenge(src, now)
		case queryRulesChallenged:
			p.rules.stampDemand(now)
			p.answerOrChallenge(&p.rules, src, ch, now)
		}
	}
}

func (p *portCache) sendChallenge(src *net.UDPAddr, now time.Time) {
	ch := challengeFor(p.c.secret, src.IP.To16(), src.Port, p.cfg.Port, now.Unix()/challengeBucketSecs)
	p.conn.WriteTo(challengeReply(ch), src)
	p.challenged.Add(1)
}

func (p *portCache) verify(src *net.UDPAddr, got []byte, now time.Time) bool {
	bucket := now.Unix() / challengeBucketSecs
	for _, b := range []int64{bucket, bucket - 1} {
		want := challengeFor(p.c.secret, src.IP.To16(), src.Port, p.cfg.Port, b)
		if hmacEqual(want, got) {
			return true
		}
	}
	return false
}

func (p *portCache) answerOrChallenge(e *cacheEntry, src *net.UDPAddr, ch []byte, now time.Time) {
	if !p.verify(src, ch, now) {
		// A wrong challenge is an expired one, or a spoofer guessing. Either
		// way the answer is a fresh challenge, never a payload.
		p.sendChallenge(src, now)
		return
	}
	datagrams := e.fresh(now, p.c.cfg.StaleAfter)
	if datagrams == nil {
		// Correctly challenged and nothing fresh to say. Dropping is the
		// honest answer - a stale reply advertises a server that may be gone -
		// and the nudge means the client's next retry usually lands warm.
		p.maybeNudge()
		p.unanswered.Add(1)
		return
	}
	for _, d := range datagrams {
		p.conn.WriteTo(d, src)
	}
	p.answered.Add(1)
}

// refresh polls the upstream for whichever entries are in demand and due.
// One goroutine per port, so a port's fetches are serialised and a slow
// upstream delays only its own port.
func (p *portCache) refresh(ctx context.Context) {
	t := time.NewTicker(p.c.cfg.RefreshEvery / 4)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.nudge:
		case <-t.C:
		}
		now := time.Now()
		p.refreshEntry(ctx, &p.info, "info", infoRequest, now)
		p.refreshEntry(ctx, &p.player, "players", playerRequest, now)
		p.refreshEntry(ctx, &p.rules, "rules", rulesRequest, now)
	}
}

func (p *portCache) refreshEntry(ctx context.Context, e *cacheEntry, what string, build func([]byte) []byte, now time.Time) {
	e.mu.Lock()
	wanted := !e.demand.IsZero() && now.Sub(e.demand) <= p.c.cfg.IdleAfter
	due := e.fetched.IsZero() || now.Sub(e.fetched) >= p.c.cfg.RefreshEvery
	e.mu.Unlock()
	if !wanted || !due {
		return
	}
	datagrams, err := p.fetch(ctx, build)
	e.mu.Lock()
	wasOK := e.fetchOK
	if err == nil {
		e.datagrams = datagrams
		e.fetched = time.Now()
		e.fetchOK = true
		e.fetchErr = ""
	} else {
		e.fetchOK = false
		e.fetchErr = err.Error()
	}
	e.mu.Unlock()
	// Edge-triggered, because a refresh failure repeats every interval for as
	// long as the upstream is unreachable, and a failover is exactly that: a
	// line per tick would be the throttle problem the control server's
	// reporting was rebuilt to avoid.
	if err != nil && wasOK {
		p.c.log.Warn("query cache cannot refresh from the game server",
			"port", p.cfg.Port, "what", what, "target", p.cfg.Target, "err", err,
			"note", "serving the cached reply until it goes stale, then answering nothing")
	} else if err == nil && !wasOK {
		p.c.log.Info("query cache refreshing again", "port", p.cfg.Port, "what", what)
	}
}

// fetch runs one upstream round trip: query, answer the server's challenge if
// it issues one, and collect the reply's datagrams, fragments included.
func (p *portCache) fetch(ctx context.Context, build func([]byte) []byte) ([][]byte, error) {
	port := p.cfg.TargetPort
	if port == 0 {
		port = p.cfg.Port
	}
	d := net.Dialer{Timeout: p.c.cfg.UpstreamTimeout}
	conn, err := d.DialContext(ctx, "udp4", net.JoinHostPort(p.cfg.Target, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	conn.SetDeadline(time.Now().Add(p.c.cfg.UpstreamTimeout))

	var challenge []byte
	buf := make([]byte, 4096)
	// Two challenge rounds at most: one is the normal dance, a second covers
	// a server rotating its challenge mid-exchange, and a server that only
	// ever answers with challenges is not going to stop on the third.
	for attempt := 0; attempt < 3; attempt++ {
		if _, err := conn.Write(build(challenge)); err != nil {
			return nil, err
		}
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if ch, ok := isChallenge(buf[:n]); ok {
			challenge = append([]byte(nil), ch...)
			continue
		}
		return p.collect(conn, buf[:n])
	}
	return nil, errors.New("upstream answered every attempt with a challenge")
}

// collect gathers the complete reply starting from its first datagram. A
// single-packet reply is itself; a multi-packet one is read until every
// fragment announced by the header has arrived. Fragments are stored in
// index order and replayed verbatim - the client reassembles them exactly as
// it would from the real server.
func (p *portCache) collect(conn net.Conn, first []byte) ([][]byte, error) {
	if len(first) >= 5 && bytes.Equal(first[:4], headerSingle) {
		return [][]byte{clone(first)}, nil
	}
	total, index, ok := fragmentMeta(first)
	if !ok {
		return nil, errors.New("unrecognised reply from upstream")
	}
	frags := make([][]byte, total)
	frags[index] = clone(first)
	got := 1
	buf := make([]byte, 4096)
	for got < total {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		t, i, ok := fragmentMeta(buf[:n])
		if !ok || t != total || frags[i] != nil {
			continue
		}
		frags[i] = clone(buf[:n])
		got++
	}
	return frags, nil
}

func clone(b []byte) []byte {
	return append([]byte(nil), b...)
}
