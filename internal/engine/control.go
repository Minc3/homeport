package engine

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
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

	// The throttles for the three reports a peer can drive the rate of. They
	// are fields rather than locals because listen is re-entered after a failed
	// bind, and counters that reset there would forget a burst in progress.
	rejected   throttle // dropped before authentication
	refused    throttle // no slot in the pool
	oversubbed throttle // one address holding its share
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

// flushThrottles reports what each throttle has counted since it last spoke.
// Run on a ticker for as long as the listener lives, because otherwise a burst
// that ends inside a window is never reported - see throttle.
func (s *ControlServer) flushThrottles() {
	if n := s.rejected.flush(); n > 0 {
		s.log.Warn("further control connections rejected before authentication",
			"attempts", n, "since", throttleWindow,
			"hint", "is the shared secret identical, and is that host running this build?")
	}
	if n := s.refused.flush(); n > 0 {
		s.log.Warn("further control connections refused; the concurrency limit was full",
			"refused", n, "limit", maxControlConns, "since", throttleWindow)
	}
	if n := s.oversubbed.flush(); n > 0 {
		s.log.Warn("further control connections refused; one address held its whole share",
			"refused", n, "per_source", maxPerSource, "since", throttleWindow)
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

	// The trailing edge of the three throttles. Without it a burst that stops
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

// applyUsage folds buffered metering deltas into the ledger and returns, per
// path in the batch, the highest sequence now safely recorded - which is what
// the backend needs in order to drop its buffered copies and nothing more.
//
// The backend resends anything it has not seen acked, so deltas arrive more
// than once. Each is stamped with a per-path sequence number and anything not
// strictly newer than what was already applied is dropped, which keeps
// resends from double-counting LTE data.
func (s *ControlServer) applyUsage(u proto.Usage) proto.UsageAck {
	st := s.eng.Store()
	ack := proto.UsageAck{Seqs: map[int]uint64{}}
	// Deltas for one path arrive in sequence order, and the watermark is a
	// single high-water mark. If one write fails, every later delta for that
	// path must be held back too - otherwise the next success would advance the
	// watermark past the failed one, the ack would tell the backend to drop it,
	// and those metered bytes are gone for good.
	stalled := map[int]bool{}
	for _, d := range u.Deltas {
		if stalled[d.PathID] {
			continue
		}
		key := "usage_seq:" + strconv.Itoa(d.PathID)
		last, _ := strconv.ParseUint(st.Meta(key), 10, 64)
		// A duplicate of something already applied is covered by the existing
		// watermark, so the ack starts there: a batch of pure resends still
		// tells the backend it may stop resending them.
		if _, seen := ack.Seqs[d.PathID]; !seen {
			ack.Seqs[d.PathID] = last
		}
		if d.Sequence <= last {
			continue
		}
		// Only advance the watermark - and the ack - once the bytes are in the
		// ledger. Acking regardless would discard metered LTE usage for good:
		// the backend drops its buffered copy on the strength of this number.
		// AddUsage writes the ledger and the watermark in one transaction; two
		// separate writes left a crash window between them, and a crash there
		// had the resent batch pass the stale watermark and bill twice.
		if err := s.eng.AddUsage(d.PathID, d.Bytes, d.Packets, time.Unix(d.AtUnix, 0),
			key, strconv.FormatUint(d.Sequence, 10)); err != nil {
			s.log.Warn("usage delta not recorded, holding back this path's watermark",
				"path_id", d.PathID, "seq", d.Sequence, "err", err)
			stalled[d.PathID] = true
			continue
		}
		ack.Seqs[d.PathID] = d.Sequence
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
		s.log.Warn("linker claimed an address that is not configured; refusing",
			"remote", remote, "claimed", hello.OverlayIP,
			"hint", "add it under Linkers in the portal, or correct linker.overlay_ip on that host")
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
