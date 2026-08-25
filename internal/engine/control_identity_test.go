package engine

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/quinlan102/homeport/internal/proto"
	"github.com/quinlan102/homeport/internal/store"
)

// identityEngine is an engine with a store, which the backend branch needs
// because it records an event on connect.
func identityEngine(t *testing.T) *Engine {
	t.Helper()
	e := newTestEngine(linkerCfg(), nil)
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	e.st = st
	// A store without a logger is the one combination that panics: a linker
	// disconnecting persists its last-contact stamp, and that path logs.
	e.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	return e
}

// mustBeRefused asserts that serve dropped the connection instead of serving
// it, and insists on a closed socket rather than merely a read that did not
// finish.
//
// The distinction is the test. A refused peer has its connection closed at
// once; a served backend is sent nothing until pushLoop's ticker fires two
// seconds later, because that loop has no immediate push the way
// pushLinkerLoop does. A plain "the read failed" assertion with a deadline
// anywhere near two seconds therefore passes against unguarded code on a busy
// machine, which is the one way a test like this is worse than no test at all.
// A timeout is treated as inconclusive and fails.
func mustBeRefused(t *testing.T, conn net.Conn, read func() (proto.Envelope, error)) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	env, err := read()
	if err == nil {
		t.Fatalf("the peer was served: it received a %q frame", env.Type)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("inconclusive: the read timed out rather than the connection being closed (%v)", err)
	}
}

// A peer's role arrives in its own Hello, and every host in the deployment
// holds the identical key: Bootstrap.Key is sha256 of the psk whatever the
// role. The linker branch was checked against the configured list and the
// backend branch was not, so omitting one JSON field was enough to be served
// as the backend - and what that branch does is write the usage ledger, which
// is authoritative for quota enforcement.
func TestAPeerFromAnotherAddressCannotBeServedAsTheBackend(t *testing.T) {
	psk := []byte("shared-secret")
	e := identityEngine(t)

	// A configured linker, holding the same secret, saying nothing about its
	// role. Before the check this was served as the backend.
	conn, r, sess, done := dialSessionFrom(t, e, psk,
		proto.Hello{Version: "impostor", Hostname: "gs1host"}, "10.99.0.3")
	defer done()

	mustBeRefused(t, conn, func() (proto.Envelope, error) { return sess.ReadFrame(r) })
	if v := e.Status().BackendVersion; v == "impostor" {
		t.Errorf("the impostor was recorded as the backend, version %q", v)
	}
}

// The property the check above must not break: the real backend dials from the
// overlay address, because Agent.controlSession binds its socket to it, and it
// still sends a Hello with no role at all when it is an older build.
func TestTheBackendFromTheOverlayAddressIsStillServed(t *testing.T) {
	psk := []byte("shared-secret")
	e := identityEngine(t)

	_, _, _, done := dialSessionFrom(t, e, psk,
		proto.Hello{Version: "old-backend", Hostname: "debian"}, e.Config().Overlay.BackendIP)
	defer done()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if e.Status().BackendVersion == "old-backend" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("the backend dialling from the overlay address was refused")
}

// KnownLinker says the claimed address belongs to some linker. It does not say
// it belongs to this one, and every linker holds the same key - so without the
// source check one of them could name another and be handed that host's egress
// networks, which it loads into nftables as root for a machine it is not.
func TestALinkerCannotClaimAnotherLinkersAddress(t *testing.T) {
	psk := []byte("shared-secret")
	e := identityEngine(t)

	// The linker at 10.99.0.4 claiming to be the one at 10.99.0.3. Both are
	// configured, so KnownLinker alone admits it.
	if !e.KnownLinker("10.99.0.3") || !e.KnownLinker("10.99.0.4") {
		t.Fatal("this test needs both linkers configured")
	}
	conn, r, sess, done := dialSessionFrom(t, e, psk,
		proto.Hello{Role: "linker", OverlayIP: "10.99.0.3", Hostname: "web"}, "10.99.0.4")
	defer done()

	mustBeRefused(t, conn, func() (proto.Envelope, error) { return sess.ReadFrame(r) })
	for _, l := range e.Status().LinkerStates {
		if l.OverlayIP == "10.99.0.3" && l.Up {
			t.Error("the impostor registered as the linker it named")
		}
	}
}

// The unit behind both, so a future caller cannot reach a wildcard by accident.
// Empty cannot happen on a loaded configuration - LoadBootstrap defaults the
// field and then parses it - but it must not read as "any address" if it does.
func TestKnownBackendIsExactAndRefusesEmpty(t *testing.T) {
	e := newTestEngine(linkerCfg(), nil)
	if !e.KnownBackend(e.Config().Overlay.BackendIP) {
		t.Error("the configured backend address was not recognised")
	}
	for _, other := range []string{"", "10.99.0.3", "10.99.0.20", "pipe"} {
		if e.KnownBackend(other) {
			t.Errorf("KnownBackend(%q) admitted a peer that is not the backend", other)
		}
	}

	blank := newTestEngine(linkerCfg(), nil)
	blank.cfg.Overlay.BackendIP = ""
	if blank.KnownBackend("") {
		t.Error("an unset backend address behaved as a wildcard")
	}
}
