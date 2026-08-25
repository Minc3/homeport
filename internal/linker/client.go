package linker

import (
	"bufio"
	"context"
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
	env, err := proto.ReadFrame(r)
	if err != nil {
		return fmt.Errorf("read challenge: %w", err)
	}
	var ch proto.Challenge
	if env.Type != proto.MsgChallenge || proto.DecodeInto(env, &ch) != nil {
		return fmt.Errorf("expected a challenge, got %q", env.Type)
	}

	// Both ends prove themselves, and this end has the most to lose by not
	// insisting on it. The frame above arrived over a first hop that is
	// plaintext TCP on the local network - this host reaches the frontend by
	// routing through the backend as a neighbour, and only enters WireGuard
	// there - so anything on that segment can answer in the frontend's place.
	// What it would then be believed about is applyEgress, which loads what it
	// is told into nftables as root.
	mine := proto.RandomNonce()
	mac, err := proto.SignAuth(l.boot.Key(), ch.Nonce, mine)
	if err != nil {
		return fmt.Errorf("unusable challenge from %s: %w", addr, err)
	}
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := proto.WriteFrame(conn, proto.MsgAuth, proto.Auth{MAC: mac, Nonce: mine}); err != nil {
		return fmt.Errorf("send auth: %w", err)
	}

	// Checked before the hello goes out, so a peer that cannot prove itself is
	// not even told which overlay address this host holds.
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	env, err = proto.ReadFrame(r)
	if err != nil {
		return fmt.Errorf("read auth ack: %w", err)
	}
	var ack proto.AuthAck
	if env.Type != proto.MsgAuthAck || proto.DecodeInto(env, &ack) != nil ||
		!proto.VerifyAuthAck(l.boot.Key(), ch.Nonce, mine, ack.MAC) {
		return fmt.Errorf("the peer at %s did not prove it holds the shared secret; "+
			"refusing to take egress networks from it", addr)
	}

	// And every frame after it carries its own MAC. Proving who answered the
	// handshake is not the same as knowing who is writing down the socket
	// afterwards: the neighbour who could have impersonated the frontend on
	// this hop could equally have relayed the handshake to the real one and
	// then sent frames of its own. See proto.Session.
	sess, err := proto.NewSession(l.boot.Key(), ch.Nonce, mine, true)
	if err != nil {
		return fmt.Errorf("cannot establish a session with %s: %w", addr, err)
	}

	host, _ := os.Hostname()
	// The deadline for this and every later frame is set inside WriteFrame:
	// the one taken before the auth write above may have been spent waiting
	// for the frontend's proof, and on a slow link that failed the hello
	// instantly and redialled forever.
	if err := sess.WriteFrame(conn, proto.MsgHello, proto.Hello{
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
		env, err := sess.ReadFrame(r)
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		if env.Type == proto.MsgPing {
			_ = sess.WriteFrame(conn, proto.MsgPong, nil)
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
