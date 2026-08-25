package agent

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"

	"github.com/quinlan102/homeport/internal/proto"
)

// The control session has to return when the context is cancelled.
//
// It spends nearly all its life blocked reading the socket, and a channel that
// is silent but healthy is the normal case - the frontend only speaks when it
// has something to say. With nothing but ControlDeadline (45s) behind that
// read, a SIGTERM arriving mid-session left the goroutine parked while the
// unit's TimeoutStopSec (10s) elapsed, so Agent.Run never returned and every
// restart ended in SIGKILL instead of a clean exit.
func TestControlSessionReturnsPromptlyWhenCancelled(t *testing.T) {
	a, _ := testAgent(t, true)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Stand in for the frontend: complete the handshake, then say nothing at
	// all, which is exactly what a healthy idle channel looks like.
	greeted := make(chan struct{})
	go func() {
		defer close(greeted)
		nonce := proto.RandomNonce()
		if err := proto.WriteFrame(server, proto.MsgChallenge, proto.Challenge{Nonce: nonce}); err != nil {
			return
		}
		r := bufio.NewReader(server)
		env, err := proto.ReadFrame(r)
		if err != nil {
			return
		}
		// The backend will not send its hello until this end has proved itself
		// too, so a stand-in frontend has to do the whole handshake.
		var auth proto.Auth
		if proto.DecodeInto(env, &auth) != nil {
			return
		}
		ack, err := proto.SignAuthAck(a.psk, nonce, auth.Nonce)
		if err != nil {
			return
		}
		if err := proto.WriteFrame(server, proto.MsgAuthAck, proto.AuthAck{MAC: ack}); err != nil {
			return
		}
		_, _ = proto.ReadFrame(r) // hello
	}()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.runSession(ctx, client, "test") }()

	select {
	case <-greeted:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("handshake never completed")
	}

	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("control session did not return on cancellation; " +
			"systemd would SIGKILL the process instead of it exiting")
	}
}

// The same property at the level that actually matters: Agent.Run waits on
// every goroutine it started, so one of them ignoring cancellation is enough to
// hang the whole shutdown.
func TestAgentRunReturnsOnCancellation(t *testing.T) {
	a, _ := testAgent(t, true)

	// Nothing to dial and no interfaces to touch; the point is only that every
	// loop notices the context and stops.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	cancel()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("Agent.Run did not return on cancellation")
	}
}

// The dialling agent will not act on a peer that cannot prove it holds the
// shared secret, and will not even tell it who this host is.
//
// The handshake used to be one-sided: the frontend challenged the dialler and
// the dialler never challenged back. That is survivable for a backend, whose
// connection enters WireGuard on its own host, and it is not survivable for a
// linker - it reaches the frontend by routing through the backend as an
// ordinary LAN neighbour, so the first hop is plaintext TCP that anything on
// that segment can answer. Both agents run the same handshake, so this is
// pinned on the one with a seam to test it through.
func TestSessionRefusesAFrontendThatCannotProveItself(t *testing.T) {
	for _, tc := range []struct {
		what string
		ack  func(psk []byte, nonce, clientNonce string) (string, bool)
	}{
		{"no proof at all", func([]byte, string, string) (string, bool) { return "", false }},
		{"a made-up MAC", func([]byte, string, string) (string, bool) {
			return "00000000000000000000000000000000", true
		}},
		{"a proof under the wrong key", func(_ []byte, n, cn string) (string, bool) {
			mac, err := proto.SignAuthAck([]byte("not the secret"), n, cn)
			return mac, err == nil
		}},
		{"the dialler's own proof reflected back", func(psk []byte, n, cn string) (string, bool) {
			mac, err := proto.SignAuth(psk, n, cn)
			return mac, err == nil
		}},
	} {
		t.Run(tc.what, func(t *testing.T) {
			a, _ := testAgent(t, true)

			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()

			sawHello := make(chan struct{})
			go func() {
				nonce := proto.RandomNonce()
				if err := proto.WriteFrame(server, proto.MsgChallenge, proto.Challenge{Nonce: nonce}); err != nil {
					return
				}
				r := bufio.NewReader(server)
				env, err := proto.ReadFrame(r)
				if err != nil {
					return
				}
				var auth proto.Auth
				if proto.DecodeInto(env, &auth) != nil {
					return
				}
				mac, send := tc.ack(a.psk, nonce, auth.Nonce)
				if !send {
					// What an impostor that gives up looks like. Staying silent
					// instead only means waiting out the read deadline, which
					// is the same refusal an hour later.
					_ = server.Close()
					return
				}
				if err := proto.WriteFrame(server, proto.MsgAuthAck, proto.AuthAck{MAC: mac}); err != nil {
					return
				}
				// Anything at all arriving here means this end was told
				// something before it had proved itself.
				if _, err := proto.ReadFrame(r); err == nil {
					close(sawHello)
				}
			}()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- a.runSession(ctx, client, "test") }()

			select {
			case err := <-done:
				if err == nil {
					t.Fatal("the session was accepted from a peer that never proved itself")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the session neither completed nor was refused")
			}
			select {
			case <-sawHello:
				t.Error("the hello went out before the frontend had proved itself")
			default:
			}
		})
	}
}
