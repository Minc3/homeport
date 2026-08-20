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
// pair, doing the challenge/response the way an agent would.
func dialSession(t *testing.T, e *Engine, psk []byte, hello proto.Hello) (net.Conn, *bufio.Reader, func()) {
	t.Helper()
	srvConn, cliConn := net.Pipe()

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
	if err := proto.WriteFrame(cliConn, proto.MsgAuth,
		proto.Auth{MAC: proto.SignChallenge(psk, ch.Nonce)}); err != nil {
		t.Fatalf("auth: %v", err)
	}
	if err := proto.WriteFrame(cliConn, proto.MsgHello, hello); err != nil {
		t.Fatalf("hello: %v", err)
	}
	return cliConn, r, func() { cancel(); cliConn.Close() }
}

// The whole point of the channel: a linker connects and is handed the networks
// belonging to its address, over a real socket with real authentication.
func TestLinkerReceivesItsNetworksOverTheChannel(t *testing.T) {
	psk := []byte("shared-secret")
	e := newTestEngine(linkerCfg(), nil)

	conn, r, done := dialSession(t, e, psk, proto.Hello{
		Role: model.RoleLinker, OverlayIP: "10.99.0.3",
		Version: "test-build", Hostname: "gs1host",
	})
	defer done()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	line, err := r.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read push: %v", err)
	}
	var env proto.Envelope
	if err := json.Unmarshal(line, &env); err != nil {
		t.Fatalf("decode push: %v", err)
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

	conn, r, done := dialSession(t, e, psk, proto.Hello{
		Role: model.RoleLinker, OverlayIP: "10.99.0.3",
		Version: "test-build", Hostname: "gs1host",
	})
	defer done()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := r.ReadBytes('\n'); err != nil { // wait for the push, so the session is up
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

	conn, r, done := dialSession(t, e, psk, proto.Hello{
		Role: model.RoleLinker, OverlayIP: "10.99.0.9", // never configured
		Version: "test-build", Hostname: "impostor",
	})
	defer done()

	// The session is refused, so the connection closes with nothing pushed.
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := r.ReadBytes('\n'); err == nil {
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

	_, _, done := dialSession(t, e, psk, proto.Hello{
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
