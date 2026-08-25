package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/proto"
	"github.com/quinlan102/homeport/internal/store"
)

// dialSession drives one control connection against serve() over a real socket
// pair, doing the whole handshake the way an agent would: both proofs, then a
// session whose key comes from both nonces, under which every later frame is
// authenticated.
// fromAddr gives a net.Pipe connection a remote address.
//
// serve checks where a peer connected from as well as what it claims to be, so
// a pipe reporting "pipe" as its address is refused like any other stranger.
// Stamping the address the real agent would dial from is what keeps these
// tests exercising the same path a deployment does.
type fromAddr struct {
	net.Conn
	remote net.Addr
}

func (c fromAddr) RemoteAddr() net.Addr { return c.remote }

func dialSession(t *testing.T, e *Engine, psk []byte, hello proto.Hello) (net.Conn, *bufio.Reader, *proto.Session, func()) {
	t.Helper()
	// A linker dials from the address it claims and the backend from the
	// overlay address, both because their sockets are bound to them - which is
	// also what puts the channel on the tunnel.
	from := e.Config().Overlay.BackendIP
	if hello.OverlayIP != "" {
		from = hello.OverlayIP
	}
	return dialSessionFrom(t, e, psk, hello, from)
}

// dialSessionFrom is dialSession with the peer address chosen, for the tests
// that are about that address rather than about what travels over the channel.
func dialSessionFrom(t *testing.T, e *Engine, psk []byte, hello proto.Hello, from string) (net.Conn, *bufio.Reader, *proto.Session, func()) {
	t.Helper()
	rawSrv, cliConn := net.Pipe()
	srvConn := fromAddr{Conn: rawSrv, remote: &net.TCPAddr{IP: net.ParseIP(from), Port: 40000}}

	s := &ControlServer{eng: e, log: slog.New(slog.NewTextHandler(io.Discard, nil)), psk: psk}
	ctx, cancel := context.WithCancel(context.Background())
	go s.serve(ctx, srvConn)

	r := bufio.NewReader(cliConn)
	_ = cliConn.SetDeadline(time.Now().Add(5 * time.Second))

	line, err := r.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	var env proto.Envelope
	if err := json.Unmarshal(line, &env); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	var ch proto.Challenge
	if err := proto.DecodeInto(env, &ch); err != nil {
		t.Fatalf("challenge payload: %v", err)
	}
	// Both halves of the handshake, as a real agent does it: the frontend has
	// to prove itself too before this end says who it is.
	mine := proto.RandomNonce()
	mac, err := proto.SignAuth(psk, ch.Nonce, mine)
	if err != nil {
		t.Fatalf("sign auth: %v", err)
	}
	if err := proto.WriteFrame(cliConn, proto.MsgAuth, proto.Auth{MAC: mac, Nonce: mine}); err != nil {
		t.Fatalf("auth: %v", err)
	}
	if line, err = r.ReadBytes('\n'); err != nil {
		t.Fatalf("read auth ack: %v", err)
	}
	if err := json.Unmarshal(line, &env); err != nil {
		t.Fatalf("decode auth ack: %v", err)
	}
	var ack proto.AuthAck
	if env.Type != proto.MsgAuthAck || proto.DecodeInto(env, &ack) != nil ||
		!proto.VerifyAuthAck(psk, ch.Nonce, mine, ack.MAC) {
		t.Fatalf("the frontend did not prove itself: %q", env.Type)
	}
	sess, err := proto.NewSession(psk, ch.Nonce, mine, true)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	if err := sess.WriteFrame(cliConn, proto.MsgHello, hello); err != nil {
		t.Fatalf("hello: %v", err)
	}
	return cliConn, r, sess, func() { cancel(); cliConn.Close() }
}

// The whole point of the channel: a linker connects and is handed the networks
// belonging to its address, over a real socket with real authentication.
func TestLinkerReceivesItsNetworksOverTheChannel(t *testing.T) {
	psk := []byte("shared-secret")
	e := newTestEngine(linkerCfg(), nil)

	conn, r, sess, done := dialSession(t, e, psk, proto.Hello{
		Role: model.RoleLinker, OverlayIP: "10.99.0.3",
		Version: "test-build", Hostname: "gs1host",
	})
	defer done()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	env, err := sess.ReadFrame(r)
	if err != nil {
		t.Fatalf("read push: %v", err)
	}
	if env.Type != proto.MsgLinkerConfig {
		t.Fatalf("first frame was %q, want a linker config", env.Type)
	}
	var cfg proto.LinkerConfig
	if err := proto.DecodeInto(env, &cfg); err != nil {
		t.Fatalf("config payload: %v", err)
	}
	if len(cfg.EgressCIDRs) != 1 || cfg.EgressCIDRs[0] != "172.18.0.0/16" {
		t.Errorf("linker was sent %v", cfg.EgressCIDRs)
	}
}

// Liveness has to appear in the portal, because a linker being down is
// otherwise completely invisible: the tunnels are all fine.
func TestConnectingRegistersLiveness(t *testing.T) {
	psk := []byte("shared-secret")
	e := newTestEngine(linkerCfg(), nil)

	conn, r, sess, done := dialSession(t, e, psk, proto.Hello{
		Role: model.RoleLinker, OverlayIP: "10.99.0.3",
		Version: "test-build", Hostname: "gs1host",
	})
	defer done()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := sess.ReadFrame(r); err != nil { // wait for the push, so the session is up
		t.Fatalf("read push: %v", err)
	}

	var found bool
	for _, l := range e.Status().LinkerStates {
		if l.OverlayIP == "10.99.0.3" && l.Up {
			found = true
			if l.Version != "test-build" || l.Hostname != "gs1host" {
				t.Errorf("registered as %+v", l)
			}
		}
	}
	if !found {
		t.Error("a connected linker is not reported up")
	}
}

// Knowing the shared secret proves a peer belongs to this deployment, not that
// it may have any address it names. A host that could claim another's address
// would be handed that host's networks, and the frontend publishes to the
// address rather than to the machine - so this is the check that stops one box
// taking over another's traffic.
func TestALinkerCannotClaimAnUnconfiguredAddress(t *testing.T) {
	psk := []byte("shared-secret")
	e := newTestEngine(linkerCfg(), nil)

	conn, r, sess, done := dialSession(t, e, psk, proto.Hello{
		Role: model.RoleLinker, OverlayIP: "10.99.0.9", // never configured
		Version: "test-build", Hostname: "impostor",
	})
	defer done()

	// The session is refused, so the connection closes with nothing pushed.
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := sess.ReadFrame(r); err == nil {
		t.Fatal("an unconfigured linker was sent configuration")
	}
	for _, l := range e.Status().LinkerStates {
		if l.Up {
			t.Errorf("an unconfigured linker registered liveness: %+v", l)
		}
	}
}

// A backend from before linkers existed sends a Hello with no role at all, and
// must still be understood exactly as it always was.
func TestAHelloWithNoRoleIsStillTheBackend(t *testing.T) {
	psk := []byte("shared-secret")
	e := newTestEngine(linkerCfg(), nil)
	// The backend path records an event on connect, so this one needs a store
	// where the linker tests do not.
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	e.st = st

	_, _, _, done := dialSession(t, e, psk, proto.Hello{
		Version: "old-backend", Hostname: "debian",
	})
	defer done()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if st := e.Status(); st.BackendVersion == "old-backend" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("a roleless hello was not treated as the backend")
}

// The frontend will not read a frame that is not authenticated to the session,
// which is what makes the handshake worth doing.
//
// Without this the handshake proves who connected and nothing more: a relay on
// the wire can pass the whole handshake through to the real frontend and then
// send frames of its own down a connection both ends believe in. This end of
// that property is that a bare frame - which is all a relay can produce, having
// no pre-shared key - gets nowhere.
func TestTheFrontendRefusesAnUnauthenticatedFrame(t *testing.T) {
	psk := []byte("shared-secret")
	e := newTestEngine(linkerCfg(), nil)

	srvConn, cliConn := net.Pipe()
	defer cliConn.Close()
	s := &ControlServer{eng: e, log: slog.New(slog.NewTextHandler(io.Discard, nil)), psk: psk}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.serve(ctx, srvConn)

	r := bufio.NewReader(cliConn)
	_ = cliConn.SetDeadline(time.Now().Add(5 * time.Second))

	line, err := r.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	var env proto.Envelope
	if err := json.Unmarshal(line, &env); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	var ch proto.Challenge
	if err := proto.DecodeInto(env, &ch); err != nil {
		t.Fatalf("challenge payload: %v", err)
	}
	mine := proto.RandomNonce()
	mac, err := proto.SignAuth(psk, ch.Nonce, mine)
	if err != nil {
		t.Fatalf("sign auth: %v", err)
	}
	if err := proto.WriteFrame(cliConn, proto.MsgAuth, proto.Auth{MAC: mac, Nonce: mine}); err != nil {
		t.Fatalf("auth: %v", err)
	}
	if _, err := r.ReadBytes('\n'); err != nil { // the frontend's proof
		t.Fatalf("read auth ack: %v", err)
	}

	// The handshake is complete and this end still cannot say anything: the
	// hello goes out with no session MAC on it, as a relay's would.
	if err := proto.WriteFrame(cliConn, proto.MsgHello, proto.Hello{
		Role: model.RoleLinker, OverlayIP: "10.99.0.3", Hostname: "relay",
	}); err != nil {
		t.Fatalf("hello: %v", err)
	}

	_ = cliConn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := r.ReadBytes('\n'); err == nil {
		t.Fatal("the frontend answered a frame it had not authenticated")
	}
	for _, l := range e.Status().LinkerStates {
		if l.Up {
			t.Errorf("an unauthenticated frame registered liveness: %+v", l)
		}
	}
}

// Every frame the frontend sends goes through the session, not just the ones
// somebody remembered.
//
// This is a guard against the shape of edit that is easy to get wrong rather
// than against an attacker: the writes are spread over four functions and two
// goroutines, and one left on the bare proto.WriteFrame is invisible from the
// frontend's side - it is the peer that fails to authenticate it, seconds or
// minutes later, and the symptom is a channel that drops for no stated reason.
// The usage ack is the one that was missed.
func TestEveryFrontendReplyIsAuthenticated(t *testing.T) {
	psk := []byte("shared-secret")
	e := newTestEngine(linkerCfg(), nil)
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	e.st = st

	conn, r, sess, done := dialSession(t, e, psk, proto.Hello{Version: "test", Hostname: "debian"})
	defer done()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := sess.WriteFrame(conn, proto.MsgUsage, proto.Usage{
		Deltas: []proto.UsageDelta{{PathID: 2, Bytes: 1024, Packets: 8, AtUnix: time.Now().Unix(), Sequence: 1}},
	}); err != nil {
		t.Fatalf("send usage: %v", err)
	}

	// Read until the ack turns up. The config push and the keepalive share this
	// connection, and every one of them has to authenticate on the way past.
	for {
		env, err := sess.ReadFrame(r)
		if err != nil {
			t.Fatalf("a frame from the frontend did not authenticate: %v", err)
		}
		if env.Type == proto.MsgUsageAck {
			var ack proto.UsageAck
			if err := proto.DecodeInto(env, &ack); err != nil {
				t.Fatalf("ack payload: %v", err)
			}
			if ack.Seqs[2] != 1 {
				t.Errorf("ack did not cover the delta: %+v", ack.Seqs)
			}
			return
		}
	}
}
