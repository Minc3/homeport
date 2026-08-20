package linker

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/proto"
)

// Version is stamped into the hello message.
var Version = "dev"

// runControlClient keeps a connection to the frontend, reconnecting forever.
//
// The linker dials, like the backend does, and for a reason of its own: it sits
// behind the backend on a private network the frontend has no route back into
// except the one this connection travels over.
//
// The route it travels is worth being precise about. The socket is bound to the
// overlay address, which is what puts it on the `from <overlay> lookup 200` rule
// and therefore onto the backend, which puts it on whichever tunnel is active.
// So the control channel follows failover for free, exactly like everything else
// this host sends - and unbound, it would leave by the LAN default route and
// never arrive.
func (l *Linker) runControlClient(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		if err := l.session(ctx); err != nil && ctx.Err() == nil {
			l.log.Warn("control channel down, retrying", "err", err, "in", backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (l *Linker) session(ctx context.Context) error {
	ov := l.boot.Overlay
	addr := net.JoinHostPort(ov.FrontendIP, strconv.Itoa(ov.ControlPort))

	// Bound to the overlay address on purpose - see runControlClient.
	d := net.Dialer{
		Timeout:   10 * time.Second,
		LocalAddr: &net.TCPAddr{IP: net.ParseIP(l.boot.Linker.OverlayIP)},
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()

	// A context does not interrupt a read in progress, and silence is the
	// normal healthy case: the frontend speaks only when the configuration
	// changes. Without this the read loop parks until the deadline expires,
	// and a shutdown that waits on it waits the same.
	sessCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-sessCtx.Done()
		_ = conn.Close()
	}()

	r := bufio.NewReader(conn)

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	env, err := readFrame(r)
	if err != nil {
		return fmt.Errorf("read challenge: %w", err)
	}
	var ch proto.Challenge
	if env.Type != proto.MsgChallenge || proto.DecodeInto(env, &ch) != nil {
		return fmt.Errorf("expected a challenge, got %q", env.Type)
	}

	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := proto.WriteFrame(conn, proto.MsgAuth,
		proto.Auth{MAC: proto.SignChallenge(l.boot.Key(), ch.Nonce)}); err != nil {
		return fmt.Errorf("send auth: %w", err)
	}

	host, _ := os.Hostname()
	if err := proto.WriteFrame(conn, proto.MsgHello, proto.Hello{
		Version:   Version,
		Hostname:  host,
		Role:      model.RoleLinker,
		OverlayIP: l.boot.Linker.OverlayIP,
		Table:     l.table(),
	}); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}

	l.log.Info("control channel connected", "frontend", addr)

	for {
		_ = conn.SetReadDeadline(time.Now().Add(proto.ControlDeadline))
		env, err := readFrame(r)
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		if env.Type == proto.MsgPing {
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_ = proto.WriteFrame(conn, proto.MsgPong, nil)
			continue
		}
		if env.Type != proto.MsgLinkerConfig {
			continue
		}
		var cfg proto.LinkerConfig
		if proto.DecodeInto(env, &cfg) != nil {
			continue
		}
		l.applyEgress(sessCtx, cfg.EgressCIDRs)
	}
}

func readFrame(r *bufio.Reader) (proto.Envelope, error) {
	line, err := r.ReadBytes('\n')
	if err != nil {
		return proto.Envelope{}, err
	}
	var env proto.Envelope
	if err := json.Unmarshal(line, &env); err != nil {
		return proto.Envelope{}, err
	}
	return env, nil
}
