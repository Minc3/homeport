package agent

import (
	"bufio"
	"context"
	"encoding/json"
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
func (a *Agent) runSession(ctx context.Context, conn net.Conn, addr string) error {
	r := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	env, err := readFrame(r)
	if err != nil {
		return err
	}
	var ch proto.Challenge
	if env.Type != proto.MsgChallenge || proto.DecodeInto(env, &ch) != nil {
		return fmt.Errorf("unexpected first frame %q", env.Type)
	}
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := proto.WriteFrame(conn, proto.MsgAuth, proto.Auth{MAC: proto.SignChallenge(a.psk, ch.Nonce)}); err != nil {
		return err
	}
	host, _ := os.Hostname()
	if err := proto.WriteFrame(conn, proto.MsgHello, proto.Hello{Version: Version, Hostname: host}); err != nil {
		return err
	}
	a.log.Info("control channel connected", "frontend", addr)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Closing the connection is the only thing that unblocks the read below.
	//
	// readFrame sits on the socket with nothing but ControlDeadline behind it,
	// and a silent-but-healthy channel is normal - the frontend only speaks
	// when it has something to say. So a SIGTERM arriving mid-session left this
	// goroutine parked for up to 45 seconds while systemd's TimeoutStopSec of
	// 10 elapsed, and every restart ended in SIGKILL rather than a clean exit.
	// The probe responder already does this; the control client did not.
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	go a.reportLoop(ctx, conn)

	for {
		_ = conn.SetReadDeadline(time.Now().Add(proto.ControlDeadline))
		env, err := readFrame(r)
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
		case proto.MsgPing:
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_ = proto.WriteFrame(conn, proto.MsgPong, nil)
		}
	}
}

// reportLoop ships buffered usage and tunnel state upward.
func (a *Agent) reportLoop(ctx context.Context, conn net.Conn) {
	usage := time.NewTicker(10 * time.Second)
	defer usage.Stop()
	link := time.NewTicker(15 * time.Second)
	defer link.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-usage.C:
			pending := a.meter.Pending()
			if len(pending) == 0 {
				continue
			}
			// Send at most a few hundred at a time so a long offline backlog
			// drains steadily instead of in one oversized frame.
			batch := pending
			if len(batch) > 500 {
				batch = batch[:500]
			}
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := proto.WriteFrame(conn, proto.MsgUsage, proto.Usage{Deltas: batch}); err != nil {
				return
			}
			// The frontend dedupes on the per-path sequence number, so a batch
			// that is sent but never applied is safe to resend.
			a.meter.Ack(len(batch))

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
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := proto.WriteFrame(conn, proto.MsgLink, report); err != nil {
				return
			}
		}
	}
}

func readFrame(r *bufio.Reader) (proto.Envelope, error) {
	line, err := r.ReadBytes('\n')
	if err != nil {
		return proto.Envelope{}, err
	}
	var env proto.Envelope
	if err := json.Unmarshal(line, &env); err != nil {
		return proto.Envelope{}, fmt.Errorf("bad control frame: %w", err)
	}
	return env, nil
}
