package engine

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/proto"
	"github.com/quinlan102/homeport/internal/sysx"
)

// ControlServer accepts the backend's control connection.
//
// The backend always dials, never the other way round: the LTE services are
// behind CGNAT, so the home side is the only end that can initiate anything.
//
// This channel carries configuration down and usage accounting up. It
// deliberately does not carry the routing decision - that rides on every probe
// packet instead, because a decision sent over TCP would have to travel across
// the path that just failed.
type ControlServer struct {
	eng  *Engine
	log  *slog.Logger
	psk  []byte
	addr string

	// slots bounds how many connections are being served at once. See
	// maxControlConns.
	slots chan struct{}

	// perSource bounds how many of those one address may hold. See
	// maxPerSource; empty entries are deleted so a churn of addresses cannot
	// grow this map.
	srcMu     sync.Mutex
	perSource map[string]int

	// The throttles for the reports a peer can drive the rate of. They are
	// fields rather than locals because listen is re-entered after a failed
	// bind, and counters that reset there would forget a burst in progress.
	rejected   throttle // dropped before authentication
	refused    throttle // no slot in the pool
	oversubbed throttle // one address holding its share
	// One per reason, not one per family. A shared window means the first
	// report wins it and every other reason is folded into a generic count for
	// thirty seconds, so an operator with two faults at once is told about one
	// of them - which is the opposite of what these are for.
	notBackend throttle // claimed the backend role from another address
	unknownIP  throttle // a linker address that is not configured
	wrongIP    throttle // a linker connecting from an address it does not claim
	clamped    throttle // a usage delta outside the bounds a meter can produce
	badPath    throttle // a usage delta naming a path id no configuration holds
	badSeq     throttle // a usage delta whose sequence would poison the watermark
	oversized  throttle // a usage batch with more deltas than one frame applies

	// usageMu serialises applyUsage across connections.
	//
	// A batch is applied on the connection's own goroutine, and more than one
	// connection from the backend is the normal case rather than the exotic
	// one: a silently dead session sits on its read deadline while its
	// replacement dials in, which is what backendConns and maxPerSource are
	// both written for, and the connection dies at every failover. The
	// replacement resends everything unacked, so two goroutines can be applying
	// the same deltas at once - and the batch is exactly when that happens,
	// because the old goroutine may be several hundred transactions into one.
	//
	// Without this the per-batch watermark memo below is read once per path and
	// never sees the other goroutine's commits, so a whole resent batch is
	// billed twice. The per-delta Meta read it replaced had the same race
	// across one delta; this closes it rather than narrowing it back.
	usageMu sync.Mutex
}

// throttleWindow is how often any one of those reports may reach the journal.
//
// Thirty seconds still surfaces the case they exist for: a genuinely
// misconfigured backend redials on a backoff that tops out at exactly that, so
// an operator with a mismatched secret sees it about as often as it happens.
const throttleWindow = 30 * time.Second

// throttle collapses a burst of one kind of report into a bounded number of
// journal entries. The first event is reported at once and everything counted
// behind it is reported when the window closes.
//
// That second half is what both hand-rolled copies of this got wrong. Each
// counted an event, reported when the window had passed *since the last
// report*, and reset the counter - so a burst that stopped inside the window
// was never reported at all. Five hundred failed authentications over five
// seconds produced one line saying "1", and the other four hundred and
// ninety-nine were counted into a window that never emitted, because the peer
// driving it had stopped. A throttle on this log exists to bound how loud a
// flood can be, not to hide that one happened.
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
// has closed. This is the trailing edge: it is what makes a burst that stops
// get reported rather than swallowed, and it returns zero when there is
// nothing owing, so a quiet server logs nothing at all.
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

// warnRejected reports connections dropped before authentication, at a rate
// that cannot flood the journal.
//
// Every other noise report in this system is throttled - the responder's three
// counters, the accept loop's refusals - and this was the exception. A peer
// that cannot authenticate is a peer that redials, so an attacker churning
// connections produced one Warn per attempt, unbounded: the connection limit
// caps how many are open at once and says nothing about how fast they can be
// cycled. Pushing real entries out of the journal is a cheap way to hide
// something, and journald's own rate limiting would be the thing deciding what
// survived.
//
// See throttle for the window and for why a burst that stops is still counted.
func (s *ControlServer) warnRejected(remote, why string, err error) {
	if seen := s.rejected.take(); seen > 0 {
		s.log.Warn("control connection rejected before authentication",
			"reason", why, "attempts", seen, "remote", remote, "err", err,
			"hint", "is the shared secret identical, and is that host running this build?")
	}
}

// reports pairs every throttle with the line its trailing edge emits.
//
// A table rather than a run of near-identical blocks, because adding a reason
// used to take three coordinated edits - a field, a take() site, and a flush
// block - and omitting the third compiled, passed every test, and produced
// exactly the defect the trailing edge exists to fix: a burst that stops inside
// the window is counted and never reported. Here the field and its line are one
// entry, so there is no third edit to forget.
func (s *ControlServer) reports() []throttleReport {
	return []throttleReport{
		{&s.rejected, slog.LevelWarn, "further control connections rejected before authentication", "attempts",
			[]any{"hint", "is the shared secret identical, and is that host running this build?"}},
		{&s.refused, slog.LevelWarn, "further control connections refused; the concurrency limit was full", "refused",
			[]any{"limit", maxControlConns}},
		{&s.oversubbed, slog.LevelWarn, "further control connections refused; one address held its whole share", "refused",
			[]any{"per_source", maxPerSource}},
		{&s.notBackend, slog.LevelWarn, "further control connections refused; a peer claimed the backend role from another address", "refused", nil},
		{&s.unknownIP, slog.LevelWarn, "further linker connections refused; the address claimed is not configured", "refused", nil},
		{&s.wrongIP, slog.LevelWarn, "further linker connections refused; the address claimed is not the one connecting", "refused", nil},
		{&s.clamped, slog.LevelError, "further usage deltas were outside the bounds a meter can produce and were clamped", "clamped", nil},
		{&s.badPath, slog.LevelError, "further usage deltas named path ids that are neither configured nor in range", "dropped", nil},
		{&s.badSeq, slog.LevelError, "further usage deltas carried sequences that would have ended a path's accounting", "dropped",
			[]any{"hint", "check meter-state.json on the backend"}},
		{&s.oversized, slog.LevelError, "further usage batches were larger than one frame applies", "batches",
			[]any{"limit", maxDeltasPerFrame}},
	}
}

// throttleReport is one throttle and the line it emits when its window closes.
type throttleReport struct {
	t        *throttle
	level    slog.Level
	msg      string
	countKey string
	extra    []any
}

// flushThrottles reports what each throttle has counted since it last spoke.
// Run on a ticker for as long as the listener lives, because otherwise a burst
// that ends inside a window is never reported - see throttle.
func (s *ControlServer) flushThrottles() {
	for _, r := range s.reports() {
		n := r.t.flush()
		if n == 0 {
			continue
		}
		args := append([]any{r.countKey, n, "since", throttleWindow}, r.extra...)
		s.log.Log(context.Background(), r.level, r.msg, args...)
	}
}

// warnUnsendable reports a frame this end refused to send, and exists because
// every writer here treats a failed write as an ordinary disconnect.
//
// That is right for a broken connection and silent in the one case that is not
// one. proto.ErrFrameTooLarge means the frame this host built is past the wire
// limit, so no amount of reconnecting will deliver it: the session counter does
// not advance over a refused write, so the next connection builds the identical
// frame and refuses it again. Left unlogged, the sender-side check turns a
// wordless reconnect loop at the far end into a wordless reconnect loop at this
// one, which is the fault it was added to prevent rather than a fix for it.
//
// Error rather than Warn: nothing here recovers on its own, and the
// configuration has to shrink before this peer is ever configured again.
func (s *ControlServer) warnUnsendable(typ, peer string, err error) {
	if !errors.Is(err, proto.ErrFrameTooLarge) {
		return // an ordinary disconnect; the redial is the whole story
	}
	s.log.Error("cannot send a control frame: it is past the wire size limit",
		"type", typ, "peer", peer, "limit", proto.MaxFrameBytes, "err", err,
		"hint", "this peer reconnects and fails the same way until whatever grew the frame is reduced; the egress source list is the part of the pushed configuration that can grow without bound")
}

// maxControlConns bounds concurrent control connections, authenticated or not.
//
// A frame is bounded by proto.MaxFrameBytes, which settles what one connection
// can cost; this settles how many of them there can be. Without it every accept
// started a goroutine with a reader behind it and nothing said no, so the
// per-frame limit would have been a limit on one multiplier of a product.
//
// The legitimate population is one backend plus one connection per linker, and
// a session whose TCP connection died silently stays parked until
// proto.ControlDeadline retires it - so a reconnect can briefly double the
// count. Sixty-four is far above any real deployment and far below a number
// that costs the frontend anything.
const maxControlConns = 64

// maxPerSource bounds how many of those one address may hold.
//
// The total on its own is a pool with nothing reserved in it, and every
// connection claims from it before proving anything - so sixty-four sockets
// from one machine, opened and left silent or churned as their ten-second
// handshake deadlines expire, hold the whole pool indefinitely and the
// backend's redial is closed on sight. The position that can do it is the one
// proto.Session was written for: a linker reaches this listener as an ordinary
// LAN neighbour routed through the backend, so the first hop is plaintext TCP
// on somebody's office network, and the backend forwards the overlay range in
// both directions.
//
// The cost of losing that race is not a portal that looks wrong. No usage
// delta reaches the ledger, so LTE billing under-counts during exactly the
// window quota enforcement exists for, and no configuration reaches the
// backend. The honest peer is the one that loses, because nothing distinguished
// an authenticated session's slot from a socket that had said nothing.
//
// Four is above anything honest: one backend or one linker holds a single
// connection, and a silently dead session parked on its read deadline while its
// replacement dials in briefly doubles that. It bounds one address, not an
// attacker with a subnet to spend - that is what the total is still for - but
// it is what keeps a flood from one place out of every other peer's way.
const maxPerSource = 4

// sourceIP is the key perSource counts against: the address without the
// ephemeral port, since a flood is one host opening many sockets.
func sourceIP(conn net.Conn) string {
	remote := conn.RemoteAddr().String()
	if host, _, err := net.SplitHostPort(remote); err == nil {
		return host
	}
	return remote
}

// claimSource reserves one of an address's connections, or reports that it
// already holds its share.
func (s *ControlServer) claimSource(ip string) bool {
	s.srcMu.Lock()
	defer s.srcMu.Unlock()
	if s.perSource == nil {
		s.perSource = make(map[string]int)
	}
	if s.perSource[ip] >= maxPerSource {
		return false
	}
	s.perSource[ip]++
	return true
}

// releaseSource gives one back. The entry is deleted rather than left at zero,
// because the addresses this counts are chosen by whoever dials: a map that
// only ever grew would be a second unbounded resource behind the limit meant
// to bound the first.
func (s *ControlServer) releaseSource(ip string) {
	s.srcMu.Lock()
	defer s.srcMu.Unlock()
	if s.perSource[ip] <= 1 {
		delete(s.perSource, ip)
		return
	}
	s.perSource[ip]--
}

// NewControlServer builds the server.
func NewControlServer(eng *Engine, psk []byte) *ControlServer {
	cfg := eng.Config()
	return &ControlServer{
		eng:   eng,
		log:   eng.Logger().With("component", "control"),
		psk:   psk,
		addr:  net.JoinHostPort(cfg.Overlay.FrontendIP, strconv.Itoa(cfg.Overlay.ControlPort)),
		slots: make(chan struct{}, maxControlConns),
	}
}

// Run listens until the context is cancelled.
//
// A failed listen is retried rather than fatal, the same way the backend's
// probe responder handles it. The address being bound lives on dummy0, which
// the engine creates as the first thing it does - so on a fresh host it does
// not exist yet for the first moments of the process's life. Returning an
// error here kills the process, which cancels the context the engine is using
// to run "ip addr add", so the address is never finished. The restart loses
// the same race, and the host never comes up at all.
func (s *ControlServer) Run(ctx context.Context) error {
	for ctx.Err() == nil {
		if err := s.listen(ctx); err != nil {
			if ctx.Err() != nil {
				break
			}
			s.log.Warn("control listen failed, retrying", "addr", s.addr, "err", err)
			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
			}
		}
	}
	return ctx.Err()
}

func (s *ControlServer) listen(ctx context.Context) error {
	// First, before the bind, and that ordering is deliberate rather than
	// tidy: it makes the limit exist whether or not this attempt gets a
	// listener, so there is no state of this server in which the accept loop
	// could be reached without one.
	//
	// A nil channel would not degrade the limit, it would invert it: a send on
	// one never proceeds, so the select below takes `default` every time and
	// this server refuses every connection it is ever offered, silently and
	// for good. NewControlServer fills it in, but three tests build this
	// struct literally, and the day one of them reaches for listen is not the
	// day to discover that. Safe without a lock because Run is the only caller
	// and calls this one at a time.
	if s.slots == nil {
		s.slots = make(chan struct{}, maxControlConns)
	}

	// The listener carries the control mark, which routes its packets - the
	// SYN-ACK included, and every accepted connection inherits it - through
	// the control table rather than the frontend's public interface.
	lc := net.ListenConfig{Control: sysx.MarkControl(sysx.ControlMark)}
	ln, err := lc.Listen(ctx, "tcp", s.addr)
	if err != nil {
		return fmt.Errorf("control listen on %s: %w", s.addr, err)
	}
	defer ln.Close()
	s.log.Info("control channel listening", "addr", s.addr)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	// The trailing edge of every throttle. Without it a burst that stops
	// inside a window is counted and never reported, which is the half of a
	// throttle that says a flood happened at all.
	flush := time.NewTicker(throttleWindow)
	defer flush.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-flush.C:
				s.flushThrottles()
			}
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.log.Warn("control accept failed", "err", err)
			continue
		}
		// Both limits are claimed here rather than inside serve, because a
		// goroutine that has already started is the thing being bounded.
		// Refusing is a close, not a queue: a caller made to wait for a slot is
		// holding one of this host's sockets either way, and the honest peers
		// all redial.
		//
		// The per-address share is claimed first, so a flood is turned away
		// before it can take a slot out of the pool even momentarily.
		ip := sourceIP(conn)
		if !s.claimSource(ip) {
			_ = conn.Close()
			if n := s.oversubbed.take(); n > 0 {
				s.log.Warn("refusing control connections; one address is holding its whole share",
					"remote", ip, "refused", n, "per_source", maxPerSource,
					"hint", "one connection per peer is normal; several from one address that never authenticate is somebody knocking")
			}
			continue
		}
		select {
		case s.slots <- struct{}{}:
			go func() {
				defer func() {
					<-s.slots
					s.releaseSource(ip)
				}()
				s.serve(ctx, conn)
			}()
		default:
			s.releaseSource(ip)
			_ = conn.Close()
			if n := s.refused.take(); n > 0 {
				s.log.Warn("refusing control connections; the concurrency limit is full",
					"refused", n, "limit", maxControlConns,
					"hint", "one backend and one connection per linker is normal; anything else is somebody knocking")
			}
		}
	}
}

func (s *ControlServer) serve(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()

	nonce := proto.RandomNonce()
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := proto.WriteFrame(conn, proto.MsgChallenge, proto.Challenge{Nonce: nonce}); err != nil {
		return
	}

	r := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	env, err := proto.ReadFrame(r)
	if err != nil {
		// Said out loud rather than dropped in silence, which is what this did
		// before. An oversized frame is the one rejection here that is not a
		// peer failing to prove itself: proto.ErrFrameTooLarge means somebody
		// sent something no honest agent sends, and separating it from an
		// authentication failure is the whole reason it is its own error.
		why := "unreadable first frame"
		if errors.Is(err, proto.ErrFrameTooLarge) {
			why = "first frame over the size limit"
		}
		s.warnRejected(remote, why, err)
		return
	}
	var auth proto.Auth
	if env.Type != proto.MsgAuth || proto.DecodeInto(env, &auth) != nil ||
		!proto.VerifyAuth(s.psk, nonce, auth.Nonce, auth.MAC) {
		s.warnRejected(remote, "the peer could not prove it holds the shared secret", nil)
		return
	}

	// And now prove who we are, before the peer is asked to believe anything.
	//
	// The dialling agent will not send its hello until this arrives, and will
	// not apply a pushed configuration without it. That matters most for a
	// linker: its connection reaches us by routing through the backend as a LAN
	// neighbour, so its first hop is plaintext TCP on a network this system does
	// not own, and what an impostor in that position would be believed about is
	// the egress networks - which the linker loads into nftables as root.
	proof, err := proto.SignAuthAck(s.psk, nonce, auth.Nonce)
	if err != nil {
		s.warnRejected(remote, "cannot sign this end's proof", err)
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := proto.WriteFrame(conn, proto.MsgAuthAck, proto.AuthAck{MAC: proof}); err != nil {
		return
	}

	// From here on every frame carries its own MAC under a key derived from
	// both nonces. Proving who the peer is settles who it is, not who is
	// writing down the socket afterwards, and a relay on the wire can let both
	// ends authenticate and then inject its own frames. See proto.Session.
	sess, err := proto.NewSession(s.psk, nonce, auth.Nonce, false)
	if err != nil {
		s.warnRejected(remote, "cannot establish a session", err)
		return
	}

	// Who is this? The first frame after auth says. A backend from before
	// linkers existed sends a Hello with no role, and an empty role means
	// backend - so an older backend is understood exactly as it always was.
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	first, err := sess.ReadFrame(r)
	if err != nil {
		return
	}
	var hello proto.Hello
	if first.Type == proto.MsgHello {
		_ = proto.DecodeInto(first, &hello)
	}

	if hello.Role == model.RoleLinker {
		s.serveLinker(ctx, conn, r, sess, hello, remote)
		return
	}

	// The peer says it is the backend, and saying so is not evidence.
	//
	// The linker branch above holds a claimed address against the configured
	// list, for the reason stated there: the shared secret proves a peer
	// belongs to this deployment, not that it is entitled to a particular
	// address. This branch applied no such test, so a peer that simply left
	// the role field out walked past the one check into the branch that writes
	// the usage ledger - and an empty role is not an exotic frame, it is what
	// a backend from before linkers existed sends.
	//
	// Every host in the deployment holds the identical key: Bootstrap.Key is
	// sha256 of the psk whatever the role, and install-linker.sh takes the
	// frontend's psk verbatim. A linker is the least trusted of the three by
	// this system's own reasoning - it sits on somebody's game server and
	// reaches this listener over a plaintext LAN hop - so leaving the backend
	// role unchecked handed it the ledger, which is authoritative for quota
	// enforcement.
	//
	// The address is the check because the backend's connection is sourced
	// from the overlay address by construction: Agent.controlSession binds
	// LocalAddr to it, and the frontend's WireGuard peer only admits that
	// range in the first place. It costs one comparison and needs no wire
	// change.
	if peer := sourceIP(conn); !s.eng.KnownBackend(peer) {
		// Throttled like every other refusal here, and for the same reason: a
		// refused peer redials on a backoff, so one line per attempt is
		// journal volume driven by whoever is dialling.
		if n := s.notBackend.take(); n > 0 {
			s.log.Warn("a peer claimed to be the backend from an address that is not the backend's; refusing",
				"remote", remote, "expected", s.eng.BackendOverlayIP(), "attempts", n,
				"hint", "overlay.backend_ip must be identical in both hosts' bootstrap files; "+
					"any other host holding the shared secret is refused here on purpose")
		}
		return
	}

	s.log.Info("backend connected", "remote", remote, "version", hello.Version)
	if first.Type == proto.MsgHello {
		s.eng.SetBackendInfo(hello.Version, hello.Hostname)
	}
	s.eng.SetBackendUp(true)
	defer s.eng.SetBackendUp(false)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Unblock the read loop below on shutdown. It is harmless here today only
	// because nothing waits on these goroutines - the listener closes, Run
	// returns and the process exits out from under them. The identical omission
	// on the backend, where Agent.Run does wait, cost every restart a SIGKILL,
	// so it does not get to stay here as a trap for whoever makes shutdown
	// wait on connections.
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	// Push config immediately, then whenever it changes.
	go s.pushLoop(ctx, conn, sess)

	for {
		_ = conn.SetReadDeadline(time.Now().Add(proto.ControlDeadline))
		env, err := sess.ReadFrame(r)
		if err != nil {
			s.log.Info("backend disconnected", "remote", remote, "err", err)
			return
		}
		switch env.Type {
		case proto.MsgHello:
			var h proto.Hello
			if proto.DecodeInto(env, &h) == nil {
				s.log.Info("backend hello", "host", h.Hostname, "version", h.Version)
				s.eng.SetBackendInfo(h.Version, h.Hostname)
			}
		case proto.MsgUsage:
			var u proto.Usage
			if proto.DecodeInto(env, &u) == nil {
				ack := s.applyUsage(u)
				// The ack is what lets the backend drop its buffered copy. Sent
				// from this goroutine, beside the pong, while pushLoop writes
				// from another: Session.WriteFrame serialises them, which it has
				// to now that each frame carries a sequence number.
				if len(ack.Seqs) > 0 {
					_ = sess.WriteFrame(conn, proto.MsgUsageAck, ack)
				}
			}
		case proto.MsgLink:
			var l proto.Link
			if proto.DecodeInto(env, &l) == nil {
				ages := map[int]float64{}
				for _, li := range l.Links {
					ages[li.PathID] = li.HandshakeAgeSec
				}
				s.eng.SetHandshakeAges(ages)
			}
		case proto.MsgPing:
			_ = sess.WriteFrame(conn, proto.MsgPong, nil)
		}
	}
}

// The bounds one usage delta has to fall inside before it reaches the ledger.
//
// Every other value that arrives on this channel is re-parsed at the boundary
// before it is used - the egress networks through EgressNetworks, the overlay
// address through AddressLiteral, the subnet through NetworkLiteral - and the
// numbers in a usage frame went through nothing at all. They are not inert
// data: the ledger is authoritative for quota enforcement, so a large one
// takes every metered path out of the selector while the links themselves read
// perfectly healthy, and a negative one erases the record the data cap depends
// on. The second is the worse direction, because over-billing is at least
// visible in the portal and has an approve button beside it.
const (
	// maxDeltaBytes and maxDeltaPackets are sanity ceilings rather than tight
	// bounds, and the difference decides what they can be. A delta is not one
	// sample interval of traffic: Meter persists its per-interface baseline
	// across restarts, deliberately, so that usage accrued while the agent was
	// stopped is still accounted for - which means the first sample after an
	// outage emits a single delta covering the whole of it. There is no
	// interval here to multiply a line rate by, so a bound derived from one
	// would refuse exactly the delta that exists to survive a long outage.
	//
	// What these do catch is the value no counter difference on a home
	// internet service ever produces. 16 TiB is a saturated gigabit line, both
	// directions, for about twenty hours, which is already well past any
	// outage this system is meant to survive on a metered link.
	//
	// Be clear about what this does not do, because the paragraph above is
	// easy to read as more than it is: a delta clamped to these ceilings still
	// exhausts any real quota several thousand times over. That is deliberate
	// rather than an oversight. The two directions are not symmetric in what
	// they cost, and the asymmetry is the whole design. Over-billing is
	// visible: the portal shows the path blocked by quota, says which, and
	// puts an approve button beside it. Under-billing is silent, and the first
	// anybody hears of it is the carrier's invoice. So the negative direction
	// is refused outright and this one is only kept from reaching a number
	// that would overflow the arithmetic downstream. What keeps a hostile peer
	// away from the ledger is KnownBackend, not this.
	maxDeltaBytes   = 1 << 44
	maxDeltaPackets = 1 << 40

	// maxDeltaSequence bounds the field that does the most damage per byte
	// sent, and it was the last one left unbounded.
	//
	// The sequence is a per-path dedupe watermark: applyUsage skips anything
	// not strictly newer, writes the accepted value into `meta`, and acks it
	// so the backend may drop its buffered copy. All three of those are
	// permanent. One delta carrying a sequence near MaxUint64 therefore parks
	// the watermark where no honest delta can ever exceed it, so every later
	// delta for that path is skipped in silence, the ack tells the backend its
	// entire buffer is applied, and the `meta` row survives every restart.
	// That path is never billed again, the quota never trips, all three paths
	// go on measuring perfectly, and only editing the database clears it. It
	// is the one direction that is both silent and unrecoverable.
	//
	// A sequence counts samples, one per path per interval, and is persisted
	// across restarts. At the ten-second cadence this is roughly three hundred
	// thousand years of continuous sampling, so nothing that has ever run can
	// approach it, and a corrupted meter-state.json cannot quietly walk past
	// it either.
	maxDeltaSequence = 1 << 40

	// maxSequenceJump bounds how far past the recorded watermark one delta may
	// carry the sequence, and it is the half of that bound which does the work.
	//
	// maxDeltaSequence is absolute, so it rules out only the top of the range.
	// Anything between the honest counter, which is a few million after years
	// of running, and 1<<40 is admitted and parks the watermark exactly as
	// effectively: every later delta for the path is skipped in silence, the
	// ack tells the backend its whole buffer is applied, and the meta row
	// survives every restart. The damage is not a function of how large the
	// number is. It is a function of how far ahead of the real one it is, so
	// that is what has to be bounded.
	//
	// The slack has to survive a long frontend outage. The backend goes on
	// sampling while the frontend is unreachable and the sequence keeps
	// advancing even after maxBuffered drops the oldest deltas off the front,
	// so a legitimate jump equals elapsed samples rather than buffered ones. At
	// the ten-second cadence this is about forty years of continuous sampling
	// with nothing acked, which no outage reaches, while still being four
	// orders of magnitude tighter than the absolute bound beside it.
	//
	// It applies to every delta, the first one a path ever sends included,
	// where the base is zero and the ceiling is this value outright. The first
	// version guarded it with `last > 0`, reasoning that the unanchored case had
	// nothing to measure from and that refusing it would refuse the delta that
	// starts a path's accounting. That handed a fresh database maxDeltaSequence
	// as its only protection, which is the poisoned state itself. Zero is a
	// perfectly good base: it says a path may arrive already forty years of
	// sampling deep and no further, which is not a restriction any real backend
	// notices. Do not put that guard back.
	//
	// What it bounds is one frame. base is re-read from the database at the top
	// of every batch, so a peer sending frame after frame may advance the
	// watermark by this much each time and reach maxDeltaSequence in about
	// eight thousand of them. That is deliberate rather than overlooked, and it
	// is the same line CLAUDE.md already draws for maxDeltaBytes: what keeps a
	// hostile peer away from the ledger is KnownBackend, not these. These exist
	// for a meter that has lost its state, and a corrupted meter-state.json
	// emits one wrong sequence, not eight thousand escalating frames. Closing
	// the cross-frame direction means anchoring to elapsed monotonic time the
	// way plausibleDecisionSeq does on the backend, with the re-anchoring
	// hazard that carries; it is not free and it is not what this is for.
	maxSequenceJump = 1 << 27

	// maxDeltaSkew is how far ahead of this host's clock a delta may be
	// stamped, and maxDeltaAge how far behind. AddUsage picks the billing
	// period from this stamp, so a stamp outside the window is not cosmetic:
	// the bytes are written to a period nothing reads, the current period
	// stays where it was, and the quota never trips.
	//
	// The two are wildly different sizes and both are chosen, not inherited.
	// What the window has to protect is which *period* a delta lands in, and a
	// period is a month, so an hour either side of the truth changes nothing
	// except within an hour of a boundary. An hour ahead is therefore generous
	// where five minutes was not: the premise of the past-side bound is that
	// the backend may have no route to NTP, and a host that has been up for
	// months without it drifts minutes. At five minutes every honest delta
	// from such a backend tripped the check and was reported at Error with a
	// hint saying no working backend emits this, which trains an operator to
	// ignore the one line that means the ledger was written wrong.
	//
	// Both ends are needed and only one was there at first. The future side is
	// the obvious one. The past side is the one that happens by accident, and
	// invariant 11 describes the exact route: the house loses power, comes back
	// with every link down, so there is no route to NTP, so the backend's clock
	// is stale - and it is the backend's clock that stamps every delta
	// (agent/meter.go). Left unbounded, such a host bills a month of metered
	// LTE into 1970 while the portal shows the period empty. An extreme value
	// is worse still, because time.Unix overflows: MinInt64 seconds is not far
	// in the past, it is the year 292277026596.
	//
	// A week, which is chosen from the backlog rather than picked round. The
	// backend's buffer holds at most maxBuffered deltas at one per path per
	// ten seconds, so the oldest an honest delta can be is 5.8 days on a
	// single-path site and under two on a three-path one. A month, the first
	// value here, was five times that, and the slack was not free: a backend
	// whose clock is stale by a week - an ordinary amount for an RTC after the
	// power cut invariant 11 describes - stamps current traffic a week back,
	// which lands in the previous billing period whenever the outage straddles
	// a reset day, is never reported because it is inside the window, and
	// leaves the current period reading empty while the cap is spent.
	//
	// Those two figures do not both fit inside seven days and are not meant to.
	// A single-path site draining a 5.8 day backlog from a host whose clock is
	// also days behind has its oldest deltas outside the window, and they are
	// restamped to now rather than refused. That is the intended answer, not a
	// gap: the two candidate periods are the one the stale clock names, which is
	// wrong and may be closed, and the current one, which is where the traffic
	// is actually being spent. Billing to the current period over-attributes at
	// worst and is visible in the portal; billing to a dead one is the silent
	// direction this bound exists to close. The Error beside it is not crying
	// wolf either, because it names the clock as the ordinary cause - a host
	// whose clock is days out is a real fault whether or not this delta was
	// stamped in good faith.
	maxDeltaSkew = time.Hour
	maxDeltaAge  = 7 * 24 * time.Hour

	// maxDeltaPathID bounds the one field of a delta that reaches the database
	// whatever else it says. An unknown path id is not dropped - AddUsage acks
	// it deliberately, so that deltas for a path an operator has just removed
	// stop being resent - and the ack is a row in `meta`, which has no
	// retention. Unbounded ids are therefore unbounded rows. web.validate
	// keeps real ids below sysx.ProbeDenyBandSize, so nothing legitimate is
	// anywhere near this.
	maxDeltaPathID = sysx.ProbeDenyBandSize

	// maxDeltasPerFrame bounds how many deltas one frame may apply. The
	// backend batches at most 500; twice that leaves room for a change to that
	// number without this becoming the thing that breaks, while keeping one
	// frame's worth of database work bounded. See applyUsage.
	maxDeltasPerFrame = 1000
)

// clampCounts brings a delta's two counts inside the bounds above and names
// what it moved.
//
// One definition, called from checkDelta and from Engine.AddUsage. It was
// written out twice, and the two agreed only because they happened to name the
// same constants: a change to the shape of the rule, a floor other than zero or
// a different answer for one of the four cases, had two places to be found and
// nothing to make the second one fail.
func clampCounts(bytes, packets int64) (int64, int64, []string) {
	var why []string
	if bytes < 0 {
		bytes, why = 0, append(why, "negative bytes")
	} else if bytes > maxDeltaBytes {
		bytes, why = maxDeltaBytes, append(why, "implausible byte count")
	}
	if packets < 0 {
		packets, why = 0, append(why, "negative packets")
	} else if packets > maxDeltaPackets {
		packets, why = maxDeltaPackets, append(why, "implausible packet count")
	}
	return bytes, packets, why
}

// checkDelta brings one usage delta inside those bounds.
//
// It clamps rather than refuses, and that is the important half. Refusing
// would leave the watermark where it was, so the backend would resend the same
// delta on every tick and have it refused every time: this path's accounting
// would stall for good, which is a worse outcome than billing a bounded wrong
// number and saying so. Clamping keeps the channel moving and leaves the fault
// in the journal at Error, where nothing here recovers on its own.
//
// Nothing an honest backend sends reaches any of these: Meter.sample refuses
// to emit a negative delta at all, rebaselining instead, and stamps every one
// with its own clock at the moment it is taken.
//
// Every reason is collected, not just the last one. A delta is quite capable of
// tripping two bounds at once, and a line naming one clamp beside values that
// show another sends whoever reads it after the wrong half.
func (s *ControlServer) checkDelta(d proto.UsageDelta, now time.Time) proto.UsageDelta {
	out := d
	var why []string
	out.Bytes, out.Packets, why = clampCounts(out.Bytes, out.Packets)
	// Both directions, compared as raw seconds against raw bounds rather than
	// as time.Time values, and that is the correct way round rather than the
	// obvious one.
	//
	// time.Unix overflows at both extremes, and it overflows to the same place:
	// MinInt64 and MaxInt64 both render as the year 292277026596, and both
	// compare as *before* now. So a time.Time comparison misses MaxInt64 in the
	// future branch entirely and catches it in the past branch, which then
	// reports a stamp tens of billions of years ahead as one too far in the
	// past to bill, sending whoever reads the journal after the wrong fault.
	// Seconds do not wrap, so comparing them classifies both extremes
	// correctly and needs no reasoning about the wrap at all.
	newest, oldest := now.Add(maxDeltaSkew).Unix(), now.Add(-maxDeltaAge).Unix()
	if out.AtUnix > newest {
		out.AtUnix, why = now.Unix(), append(why, "a timestamp in the future")
	} else if out.AtUnix < oldest {
		out.AtUnix, why = now.Unix(), append(why, "a timestamp too far in the past to bill")
	}
	if len(why) == 0 {
		return out
	}
	// Throttled, because the count is chosen by the peer: a batch is hundreds
	// of deltas and every one of them can trip a bound, so an unthrottled line
	// each is peer-driven journal volume - the thing ControlServer.throttle was
	// added for. The first is reported in full and the rest are counted behind
	// it.
	if seen := s.clamped.take(); seen > 0 {
		s.log.Error("usage delta outside the bounds a meter can produce, clamping it",
			"reason", strings.Join(why, ", "), "clamped", seen,
			"path_id", d.PathID, "seq", d.Sequence,
			"bytes", d.Bytes, "packets", d.Packets, "at", d.AtUnix,
			"clamped_bytes", out.Bytes, "clamped_packets", out.Packets,
			"hint", "the ledger is what quotas are enforced against. A count outside its bounds means the meter, not the link; a stamp outside them usually means the backend's clock, which has no route to NTP while every path is down")
	}
	return out
}

// applyUsage folds buffered metering deltas into the ledger and returns, per
// path in the batch, the highest sequence now safely recorded - which is what
// the backend needs in order to drop its buffered copies and nothing more.
//
// The backend resends anything it has not seen acked, so deltas arrive more
// than once. Each is stamped with a per-path sequence number and anything not
// strictly newer than what was already applied is dropped, which keeps
// resends from double-counting LTE data.
func (s *ControlServer) applyUsage(u proto.Usage) proto.UsageAck {
	// One batch at a time across every connection. See usageMu: the watermarks
	// below are database reads held for the length of the batch, and two
	// backend sessions at once is what a failover produces.
	s.usageMu.Lock()
	defer s.usageMu.Unlock()

	st := s.eng.Store()
	now := time.Now()
	ack := proto.UsageAck{Seqs: map[int]uint64{}}

	// Two watermarks per path, and the distinction is the whole of the sequence
	// bound.
	//
	// base is what the database held when this batch started and never moves.
	// It is what maxSequenceJump is measured against, because measuring against
	// a value the batch itself advances is not a bound at all: with the running
	// watermark as the reference, a thousand deltas each exactly at the limit
	// are each accepted, and one frame walks the watermark a thousand times the
	// stated distance. Eight such frames reach maxDeltaSequence, and the path is
	// then unbillable for good - which is the outcome the bound exists to
	// refuse, reached through the bound itself.
	//
	// seen is the running high-water mark, which is what deduplicates resends
	// inside one frame. It only moves for a delta that was accepted for
	// billing, and it is committed to the database once per path at the end.
	base := map[int]uint64{}
	seen := map[int]uint64{}
	// The deltas accepted for each path, the key their watermark lives under,
	// and the sequence that watermark becomes. Written once per path rather
	// than once per delta: see store.AddUsageBatch for what five hundred
	// separate transactions cost every other reader in this process.
	pending := map[int][]usageSample{}
	keys := map[int]string{}
	// First-seen order, so the ledger is written in the order the backend sent
	// rather than in map order.
	order := []int{}

	// Bounded in count as well as in value. The backend batches at most 500
	// (agent.reportLoop), and nothing here enforced that: a frame is bounded
	// only by proto.MaxFrameBytes, and a delta serialises to about a hundred
	// bytes, so an accepted frame can carry ten thousand of them. Logged rather
	// than silent, for the reason warnUnsendable exists: if the sender's 500 is
	// ever raised past this, the excess is resent forever and truncating it
	// quietly would be the only symptom.
	deltas := u.Deltas
	if len(deltas) > maxDeltasPerFrame {
		// Throttled like every other peer-driven line here, and this one needs
		// it most: the excess is never acked, so the sender resends the
		// identical frame on every tick and the report repeats with it.
		if n := s.oversized.take(); n > 0 {
			s.log.Error("usage batch is larger than this frontend will apply in one frame; ignoring the excess",
				"deltas", len(deltas), "limit", maxDeltasPerFrame, "batches", n,
				"hint", "a backend batches at most 500; anything past this limit is resent until it fits")
		}
		deltas = deltas[:maxDeltasPerFrame]
	}

	for _, d := range deltas {
		// Before anything is read or written for this id, because the write is
		// the problem. An id no configuration can hold is not merely unknown -
		// AddUsage acks an unknown id deliberately, so that deltas for a path
		// an operator has just removed stop being resent, and that ack is a row
		// in `meta`, which has no retention. Acking a garbage id is therefore a
		// permanent row per id, chosen by whoever is sending. Nothing honest
		// reaches this: web.validate keeps real ids below the same bound, and
		// the backend only meters paths it was pushed.
		//
		// An id this configuration actually holds is billed whatever its value.
		// The range is the fallback for one it does not, and checking the
		// configuration first is what keeps this from breaking a site the
		// portal itself accepted: web.validate has only bounded ids below
		// ProbeDenyBandSize since 2026-08-22, nothing re-validates a stored
		// blob on load, and Normalise does not touch ids - so a config saved
		// before that carries a legal path at, say, 200. Dropping its deltas
		// without an ack would leave the backend resending them forever and
		// that path's ledger at zero, which is the silent under-billing this
		// whole check exists to prevent, reintroduced from the other side.
		if !s.eng.HasPath(d.PathID) && (d.PathID <= 0 || d.PathID >= maxDeltaPathID) {
			if n := s.badPath.take(); n > 0 {
				s.log.Error("usage delta names a path id that is neither configured nor in range; dropping it",
					"path_id", d.PathID, "seq", d.Sequence, "limit", maxDeltaPathID, "dropped", n)
			}
			continue
		}
		// The absolute sequence bound, applied before the watermark is read
		// rather than because it is the real check. It is a pre-filter that
		// saves a database read for a value no bound could accept; the bound
		// that does the work is maxSequenceJump below, which applies to every
		// delta including the first one a path ever sends.
		if d.Sequence > maxDeltaSequence {
			if n := s.badSeq.take(); n > 0 {
				s.log.Error("usage delta carries an implausible sequence; refusing it rather than making it the watermark",
					"path_id", d.PathID, "seq", d.Sequence, "limit", uint64(maxDeltaSequence), "dropped", n,
					"hint", "accepting this would silently end this path's accounting for good; check meter-state.json on the backend")
			}
			continue
		}
		if _, ok := base[d.PathID]; !ok {
			key := "usage_seq:" + strconv.Itoa(d.PathID)
			last, _ := strconv.ParseUint(st.Meta(key), 10, 64)
			base[d.PathID] = last
			seen[d.PathID] = last
			keys[d.PathID] = key
			order = append(order, d.PathID)
			// A duplicate of something already applied is covered by the
			// existing watermark, so the ack starts there: a batch of pure
			// resends still tells the backend it may stop resending them.
			ack.Seqs[d.PathID] = last
		}
		if d.Sequence <= seen[d.PathID] {
			continue
		}
		// The sequence bound that does the work, measured against the watermark
		// this batch began with. Tested after the duplicate check, so the
		// subtraction has a sequence strictly above `seen`, and `base` is never
		// above `seen`, so it cannot wrap.
		//
		// It applies with no watermark too, where base is zero and the ceiling
		// is maxSequenceJump outright. The first version guarded this with
		// `last > 0` on the grounds that the unanchored case had nothing to
		// measure from, which handed a fresh database the absolute bound as its
		// only protection: one first-contact delta at 1<<40 was billed, became
		// the watermark, and left the path unbillable for good. Zero is a
		// perfectly good base. A sequence counts samples, so it says this path
		// may arrive already forty years of sampling deep and no further.
		//
		// Dropped without an ack, exactly as the absolute bound is: a sender
		// that has jumped this far has lost its meter state, so there is no
		// correct value to clamp to. It shares badSeq because it shares a
		// remediation - both send whoever reads it to meter-state.json on the
		// backend - which is the line these counters are split on.
		if d.Sequence-base[d.PathID] > maxSequenceJump {
			if n := s.badSeq.take(); n > 0 {
				s.log.Error("usage delta jumps implausibly far past this path's watermark; refusing it rather than making it the watermark",
					"path_id", d.PathID, "seq", d.Sequence, "watermark", base[d.PathID],
					"limit", uint64(maxSequenceJump), "dropped", n,
					"hint", "accepting this would silently end this path's accounting for good; check meter-state.json on the backend")
			}
			continue
		}
		// Bounded before it is billed, not after. See checkDelta.
		d = s.checkDelta(d, now)
		seen[d.PathID] = d.Sequence
		pending[d.PathID] = append(pending[d.PathID], usageSample{
			Bytes: d.Bytes, Packets: d.Packets, At: time.Unix(d.AtUnix, 0),
		})
	}

	// One transaction per path, and the ack moves only once it has committed.
	// Acking regardless would discard metered LTE usage for good: the backend
	// drops its buffered copy on the strength of this number. The ledger rows
	// and the watermark go in together, so there is no crash window in which
	// they disagree - written separately, a crash between them had the resent
	// batch pass a stale watermark and bill twice.
	//
	// All or nothing per path is what the old per-delta `stalled` map was for:
	// if one delta failed, every later one for that path had to be held back
	// too, or the next success would advance the watermark past the failed one
	// and the ack would tell the backend to drop it. A single transaction gives
	// that for free.
	for _, id := range order {
		if len(pending[id]) == 0 {
			continue
		}
		// seen[id] is the watermark this batch reached, which for a path with
		// anything in `pending` is the last sequence it accepted. It was
		// carried in a second map for a while, assigned the identical value on
		// the line below its own: two maps that can only ever differ if a
		// future edit advances one on a path the other does not take, and the
		// direction that loses metered bytes is the silent one.
		if err := s.eng.addUsageBatch(id, pending[id], keys[id], strconv.FormatUint(seen[id], 10)); err != nil {
			s.log.Warn("usage batch not recorded, holding back this path's watermark",
				"path_id", id, "deltas", len(pending[id]), "seq", seen[id], "err", err)
			continue
		}
		ack.Seqs[id] = seen[id]
	}
	return ack
}

func (s *ControlServer) pushLoop(ctx context.Context, conn net.Conn, sess *proto.Session) {
	var pushed uint64
	first := true
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	ka := time.NewTicker(proto.KeepaliveInterval)
	defer ka.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			v := s.eng.ConfigVersion()
			if !first && v == pushed {
				continue
			}
			pushed, first = v, false
			if err := sess.WriteFrame(conn, proto.MsgConfig, backendConfig(s.eng.Config())); err != nil {
				s.warnUnsendable(proto.MsgConfig, conn.RemoteAddr().String(), err)
				return
			}
		case <-ka.C:
			if err := sess.WriteFrame(conn, proto.MsgPing, nil); err != nil {
				return
			}
		}
	}
}

func backendConfig(cfg model.Config) proto.BackendConfig {
	bc := proto.BackendConfig{
		Overlay: proto.OverlayInfo{
			FrontendIP: cfg.Overlay.FrontendIP,
			BackendIP:  cfg.Overlay.BackendIP,
			Device:     cfg.Overlay.Device,
			Subnet:     cfg.Overlay.Subnet,
		},
		Mode:     cfg.Mode,
		SampleMs: 10000,
	}
	for _, p := range cfg.Paths {
		bc.Paths = append(bc.Paths, proto.PathInfo{
			ID: p.ID, Name: p.Name, Iface: p.Iface,
			Table: p.Table, Mark: p.Mark, Metered: p.Metered,
			ShapeMbit: p.Shape.ToFrontendMbit,
		})
	}
	// Only enabled ones. Unticking a linker is how an operator takes a host out
	// of service, and leaving its route installed would keep the frontend's
	// DNAT pointing at a machine nobody expects traffic to reach.
	for _, l := range cfg.Linkers {
		if !l.Enabled {
			continue
		}
		bc.Linkers = append(bc.Linkers, proto.LinkerRoute{
			OverlayIP: l.OverlayIP,
			LanIP:     l.LanIP,
		})
	}
	// Only sent when the frontend is prepared to translate them. Pulling a
	// network onto the tunnel without the source NAT waiting at the other end
	// sends its traffic somewhere it cannot be answered - worse than leaving it
	// on the house's own service, because it fails silently.
	if cfg.Frontend.BackendEgress {
		// Only this agent's own networks. A row belongs to exactly one host,
		// because Docker hands out the same bridge subnets on every machine -
		// 172.17.0.0/16 is the default everywhere - so a global list would have
		// each agent pulling containers onto the tunnel that belong to a
		// different box entirely, and paying for them out of the LTE quota.
		for _, s := range cfg.Egress.Sources {
			if s.Enabled && s.CIDR != "" && s.HostOr(cfg.Overlay.BackendIP) == cfg.Overlay.BackendIP {
				bc.EgressCIDRs = append(bc.EgressCIDRs, s.CIDR)
			}
		}
	}
	return bc
}

// serveLinker handles a control connection from an extra host.
//
// Far smaller than the backend's session, because a linker is far smaller: it
// reports nothing but its own liveness and receives nothing but the networks it
// should pull onto the overlay. It sends no usage, because it meters nothing,
// and it is told no path, because it makes no decisions - the backend already
// tracks which tunnel is carrying traffic, and a second thing that had to agree
// with the frontend about the active path is exactly the failure mode pfSense
// demonstrates.
func (s *ControlServer) serveLinker(ctx context.Context, conn net.Conn, r *bufio.Reader, sess *proto.Session, hello proto.Hello, remote string) {
	// The shared secret proves the peer belongs to this deployment. It does not
	// prove it is entitled to a particular overlay address, and a linker that
	// could name itself could be handed another linker's networks - so the
	// address is checked against the configured list rather than trusted.
	if !s.eng.KnownLinker(hello.OverlayIP) {
		if n := s.unknownIP.take(); n > 0 {
			s.log.Warn("linker claimed an address that is not configured; refusing",
				"remote", remote, "claimed", hello.OverlayIP, "attempts", n,
				"hint", "add it under Linkers in the portal, or correct linker.overlay_ip on that host")
		}
		return
	}
	// And it has to be connecting from the address it claims, which the check
	// above does not establish. Being on the configured list only says the
	// address belongs to some linker; every linker holds the same key, so
	// without this one of them could name another and be handed that host's
	// egress networks - rules it loads into nftables as root, for a machine it
	// is not. Its socket is bound to its own overlay address (linker.client
	// sets LocalAddr, which is also what puts the channel on the tunnel), so
	// the claim and the source agree on any correctly configured host.
	if peer := sourceIP(conn); peer != hello.OverlayIP {
		if n := s.wrongIP.take(); n > 0 {
			s.log.Warn("linker claimed an address it is not connecting from; refusing",
				"remote", remote, "claimed", hello.OverlayIP, "connected_from", peer, "attempts", n,
				"hint", "linker.overlay_ip on that host must be the address it holds on dummy0")
		}
		return
	}

	s.log.Info("linker connected", "remote", remote,
		"overlay", hello.OverlayIP, "host", hello.Hostname, "version", hello.Version)
	session := s.eng.SetLinkerUp(hello.OverlayIP, hello.Version, hello.Hostname, hello.Table)
	defer s.eng.SetLinkerDown(hello.OverlayIP, session)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// A context does not interrupt a read in progress, and silence is the
	// normal healthy case here - the frontend speaks only when the
	// configuration changes. Without this the goroutine parks until the
	// deadline expires.
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	go s.pushLinkerLoop(ctx, conn, sess, hello.OverlayIP)

	for {
		_ = conn.SetReadDeadline(time.Now().Add(proto.ControlDeadline))
		env, err := sess.ReadFrame(r)
		if err != nil {
			s.log.Info("linker disconnected", "remote", remote, "overlay", hello.OverlayIP, "err", err)
			return
		}
		// Every frame, not just the ones worth acting on: a pong answering our
		// keepalive is the only thing a healthy linker ever says, and it is
		// exactly the evidence that the host is still there.
		s.eng.MarkLinkerSeen(hello.OverlayIP)
		if env.Type == proto.MsgPing {
			_ = sess.WriteFrame(conn, proto.MsgPong, nil)
		}
	}
}

// pushLinkerLoop sends the linker its configuration, and again whenever it
// changes. Mirrors pushLoop, keyed on the same version counter.
func (s *ControlServer) pushLinkerLoop(ctx context.Context, conn net.Conn, sess *proto.Session, overlayIP string) {
	// `first` rather than comparing against a zero value: the version counter
	// starts at zero, so a linker connecting to a frontend whose configuration
	// has never changed would match on the first pass and never be sent
	// anything at all.
	var pushed uint64
	first := true

	push := func() bool {
		v := s.eng.ConfigVersion()
		if !first && v == pushed {
			return true
		}
		pushed, first = v, false
		cfg := s.eng.LinkerConfigFor(overlayIP)
		if err := sess.WriteFrame(conn, proto.MsgLinkerConfig, cfg); err != nil {
			s.warnUnsendable(proto.MsgLinkerConfig, overlayIP, err)
			return false
		}
		s.log.Info("pushed configuration to linker",
			"overlay", overlayIP, "networks", len(cfg.EgressCIDRs))
		return true
	}

	// Immediately, so a reconnecting linker is configured without waiting a
	// tick, and then on change.
	if !push() {
		return
	}

	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	ka := time.NewTicker(proto.KeepaliveInterval)
	defer ka.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if !push() {
				return
			}
		case <-ka.C:
			// The read side of this session has a deadline, and a healthy
			// linker has nothing to say - so without something to answer, an
			// idle but perfectly well host would be dropped every 45 seconds.
			if err := sess.WriteFrame(conn, proto.MsgPing, nil); err != nil {
				return
			}
		}
	}
}
