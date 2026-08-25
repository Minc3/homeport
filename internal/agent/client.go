package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/quinlan102/homeport/internal/proto"
	"github.com/quinlan102/homeport/internal/sysx"
)

// Version is stamped into the hello message.
var Version = "dev"

// runControlClient keeps a connection to the frontend, reconnecting forever.
//
// The backend always dials. The LTE services sit behind CGNAT, so the frontend
// can never initiate anything toward home - which is also why the tunnels
// themselves must be brought up from this side with a persistent keepalive.
func (a *Agent) runControlClient(ctx context.Context) {
	// Zero, not the floor, and the wait is chosen before it is served rather
	// than after. Deciding afterwards spends the *previous* session's wait
	// before the reset can apply, so a backend that had climbed to the ceiling
	// on a run of failovers still sat out thirty seconds after the next session
	// that worked - which is the one case this backoff exists to get right.
	// nextDialBackoff clamps up, so starting from zero still gives 1s, 2s, 4s.
	var backoff time.Duration
	for ctx.Err() == nil {
		started := time.Now()
		err := a.controlSession(ctx)
		if ctx.Err() != nil {
			return
		}
		lasted := time.Since(started)
		backoff = nextDialBackoff(backoff, lasted)
		if err != nil {
			a.log.Warn("control channel down", "err", err,
				"session", lasted.Round(time.Second), "retry_in", backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

// Bounds on the wait between control-channel dials.
const (
	dialBackoffMin = time.Second
	dialBackoffMax = 30 * time.Second

	// sessionSettled is how long a session must last to count as one that
	// worked. Authentication and the first push are done inside a second, so
	// anything past a minute is a channel that was up and then went, rather
	// than one that never came up.
	sessionSettled = time.Minute
)

// nextDialBackoff is the wait after a session that lasted this long, given the
// wait that preceded it.
//
// A session that stayed up resets it. Without that the backoff only ever grows,
// and it has nothing to do with whether the frontend is reachable: every
// failover drops the TCP connection, so after five or six of them the backend
// waits the full thirty seconds before redialling for the rest of the process's
// life. Nothing is lost while it waits, usage buffers to disk and the routing
// decision rides on the probes, but the portal reports the backend unreachable
// for half a minute after each switch and a mode change takes that much longer
// to reach it.
func nextDialBackoff(previous, sessionFor time.Duration) time.Duration {
	if sessionFor >= sessionSettled {
		return dialBackoffMin
	}
	next := previous * 2
	if next > dialBackoffMax {
		next = dialBackoffMax
	}
	if next < dialBackoffMin {
		next = dialBackoffMin
	}
	return next
}

func (a *Agent) controlSession(ctx context.Context) error {
	ov := a.Overlay()
	addr := net.JoinHostPort(ov.FrontendIP, strconv.Itoa(ov.ControlPort))

	d := net.Dialer{Timeout: 10 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(ov.BackendIP)}}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial frontend %s: %w", addr, err)
	}
	defer conn.Close()
	return a.runSession(ctx, conn, addr)
}

// runSession is the session on an established connection, split out from the
// dial so that its shutdown behaviour can be tested over a pipe.
// warnUnsendable reports a frame this end refused to send. The reporting loop
// treats every write error as an ordinary disconnect and redials, which is
// right for a broken connection and silent in the one case that is not one:
// proto.ErrFrameTooLarge means this host built a frame past the wire limit, and
// since the session counter does not advance over a refused write, the next
// connection builds the identical frame and refuses it again. The usage batch
// is capped at 500 deltas so nothing reaches it today; it is here for the
// change that raises that number, which is precisely the change that would
// otherwise present as a reconnect loop with no cause anywhere in the journal.
func (a *Agent) warnUnsendable(typ string, err error) {
	if !errors.Is(err, proto.ErrFrameTooLarge) {
		return // an ordinary disconnect; the redial is the whole story
	}
	a.log.Error("cannot send a control frame: it is past the wire size limit",
		"type", typ, "limit", proto.MaxFrameBytes, "err", err,
		"hint", "this agent reconnects and fails the same way until whatever grew the frame is reduced")
}

func (a *Agent) runSession(ctx context.Context, conn net.Conn, addr string) error {
	// Closing the connection is the only thing that unblocks a read, and that
	// has to be true from the first one, not from the end of the handshake.
	//
	// proto.ReadFrame sits on the socket with nothing but a deadline behind it, and a
	// silent-but-healthy channel is normal - the frontend only speaks when it
	// has something to say. So a SIGTERM arriving mid-session left this
	// goroutine parked for up to 45 seconds while systemd's TimeoutStopSec of
	// 10 elapsed, and every restart ended in SIGKILL rather than a clean exit.
	//
	// The handshake is two reads of 15 seconds now that the frontend proves
	// itself too, so installed after it this watcher left half a minute of the
	// session's life uncovered - the same fault in the window where a redial
	// loop makes it most likely. The linker's client has always done it here.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	r := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	env, err := proto.ReadFrame(r)
	if err != nil {
		return err
	}
	var ch proto.Challenge
	if env.Type != proto.MsgChallenge || proto.DecodeInto(env, &ch) != nil {
		return fmt.Errorf("unexpected first frame %q", env.Type)
	}
	// Both ends prove themselves. Ours first, then the frontend's, and nothing
	// it sends is acted on until its half has been checked - see proto.Auth for
	// why a one-sided handshake was not enough.
	mine := proto.RandomNonce()
	mac, err := proto.SignAuth(a.psk, ch.Nonce, mine)
	if err != nil {
		return fmt.Errorf("frontend sent an unusable challenge: %w", err)
	}
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := proto.WriteFrame(conn, proto.MsgAuth, proto.Auth{MAC: mac, Nonce: mine}); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	env, err = proto.ReadFrame(r)
	if err != nil {
		return err
	}
	var ack proto.AuthAck
	if env.Type != proto.MsgAuthAck || proto.DecodeInto(env, &ack) != nil ||
		!proto.VerifyAuthAck(a.psk, ch.Nonce, mine, ack.MAC) {
		return fmt.Errorf("the peer at %s did not prove it holds the shared secret; "+
			"refusing to take configuration from it", addr)
	}

	// Every frame from here carries its own MAC. The handshake settles who the
	// peer is and nothing about who writes down the socket afterwards; see
	// proto.Session.
	sess, err := proto.NewSession(a.psk, ch.Nonce, mine, true)
	if err != nil {
		return fmt.Errorf("cannot establish a session with %s: %w", addr, err)
	}

	host, _ := os.Hostname()
	// The deadline for this and every later frame is set inside WriteFrame:
	// the one taken before the auth write above may have been spent waiting
	// for the frontend's proof, and on a slow link that failed the hello
	// instantly and redialled forever.
	if err := sess.WriteFrame(conn, proto.MsgHello, proto.Hello{Version: Version, Hostname: host}); err != nil {
		return err
	}
	a.log.Info("control channel connected", "frontend", addr)

	go a.reportLoop(ctx, conn, sess)

	for {
		_ = conn.SetReadDeadline(time.Now().Add(proto.ControlDeadline))
		env, err := sess.ReadFrame(r)
		if err != nil {
			return err
		}
		switch env.Type {
		case proto.MsgConfig:
			var cfg proto.BackendConfig
			if err := proto.DecodeInto(env, &cfg); err != nil {
				a.log.Warn("bad config frame", "err", err)
				continue
			}
			a.ApplyConfig(ctx, cfg)
		case proto.MsgUsageAck:
			var ack proto.UsageAck
			if err := proto.DecodeInto(env, &ack); err != nil {
				a.log.Warn("bad usage ack frame", "err", err)
				continue
			}
			a.meter.AckApplied(ack.Seqs)
		case proto.MsgPing:
			_ = sess.WriteFrame(conn, proto.MsgPong, nil)
		}
	}
}

// reportLoop ships buffered usage and tunnel state upward.
func (a *Agent) reportLoop(ctx context.Context, conn net.Conn, sess *proto.Session) {
	usage := time.NewTicker(10 * time.Second)
	defer usage.Stop()
	link := time.NewTicker(15 * time.Second)
	defer link.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-usage.C:
			// At most a few hundred at a time so a long offline backlog drains
			// steadily instead of in one oversized frame - and only that many
			// copied, rather than the whole backlog for the sake of its front.
			batch := a.meter.PendingBatch(500)
			if len(batch) == 0 {
				continue
			}
			if err := sess.WriteFrame(conn, proto.MsgUsage, proto.Usage{Deltas: batch}); err != nil {
				a.warnUnsendable(proto.MsgUsage, err)
				return
			}
			// Deliberately not dropped here. A successful write is not delivery
			// - the bytes can die in the send buffer with the connection, which
			// is what a failover does to it - so the buffer holds every delta
			// until the frontend's usage_ack says it is in the ledger. Until
			// then each tick resends the oldest batch; the frontend dedupes on
			// the per-path sequence, so the overlap costs nothing. (A frontend
			// too old to ack never drains this buffer; it caps at maxBuffered
			// and drops oldest-first, which by then is long since applied.)

		case <-link.C:
			cfg, ok := a.Config()
			if !ok {
				continue
			}
			a.mu.RLock()
			runner := a.runner
			a.mu.RUnlock()
			ages := sysx.HandshakeAges(ctx, runner)
			var report proto.Link
			for _, p := range cfg.Paths {
				age, seen := ages[p.Iface]
				report.Links = append(report.Links, proto.LinkInfo{
					PathID:          p.ID,
					HandshakeAgeSec: age,
					Exists:          seen || sysx.IfaceExists(p.Iface),
				})
			}
			if err := sess.WriteFrame(conn, proto.MsgLink, report); err != nil {
				a.warnUnsendable(proto.MsgLink, err)
				return
			}
		}
	}
}
