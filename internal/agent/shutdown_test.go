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
		if err := proto.WriteFrame(server, proto.MsgChallenge, proto.Challenge{Nonce: "test-nonce"}); err != nil {
			return
		}
		r := bufio.NewReader(server)
		_, _ = readFrame(r) // auth
		_, _ = readFrame(r) // hello
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
