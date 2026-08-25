package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/quinlan102/homeport/internal/proto"
	"github.com/quinlan102/homeport/internal/sysx"
)

// Responder answers path probes.
//
// Each reply goes out through the same tunnel its request arrived on. That is
// not a detail: if replies took whichever tunnel the routing table happened to
// prefer, every measurement would be a mix of one path outbound and another
// inbound, and a failed link could still look healthy because its replies were
// riding a working one.
//
// The path is identified by the authenticated path id in the probe itself, and
// the reply is sent from a socket carrying that path's fwmark, which selects
// the matching routing table.
type Responder struct {
	agent *Agent
	log   *slog.Logger

	mu      sync.Mutex
	replies map[int]*net.UDPConn // path id -> marked reply socket
	reload  chan struct{}
}

// NewResponder builds the probe responder.
func NewResponder(a *Agent, log *slog.Logger) *Responder {
	return &Responder{
		agent:   a,
		log:     log.With("component", "responder"),
		replies: map[int]*net.UDPConn{},
		reload:  make(chan struct{}, 1),
	}
}

// Reload asks the responder to rebuild its reply sockets after a config change.
func (r *Responder) Reload() {
	select {
	case r.reload <- struct{}{}:
	default:
	}
}

// Run listens for probes until the context is cancelled.
func (r *Responder) Run(ctx context.Context) {
	// Started once, not per listen attempt. Spawning it inside listen() leaked
	// a goroutine on every socket retry, and left several watchers racing to
	// close the same reply sockets.
	go r.watchReloads(ctx)

	for ctx.Err() == nil {
		if err := r.listen(ctx); err != nil {
			r.log.Warn("probe listener failed, retrying", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
		}
	}
}

func (r *Responder) listen(ctx context.Context) error {
	ov := r.agent.Overlay()
	addr := net.JoinHostPort(ov.BackendIP, strconv.Itoa(ov.ProbePort))

	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp", addr)
	if err != nil {
		return err
	}
	conn := pc.(*net.UDPConn)
	defer conn.Close()
	r.log.Info("probe responder listening", "addr", addr)

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	buf := make([]byte, 512)

	// Unauthenticated packets are dropped silently by design - on a public
	// overlay they are indistinguishable from noise. But the single most
	// likely cause is a shared secret that does not match the frontend's, and
	// with no log at all that looks exactly like a dead tunnel. Report it at a
	// rate that cannot flood the journal.
	var lastNoise time.Time
	var noise int
	var lastVersion time.Time
	var wrongVersion int
	var lastFail time.Time
	failed := map[int]int{}

	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		msg, err := proto.Unmarshal(buf[:n], r.agent.psk)
		if err != nil {
			// Two different things to go and look at, so they are not reported
			// as one. A packet from another wire version is a host part-way
			// through an upgrade, and the hosts have to move together: the
			// MACs are domain separated by version, so an older frontend's
			// probes will not authenticate here and this one's replies will
			// not authenticate there. Told it was a secret mismatch, an
			// operator goes and checks the one thing that is fine.
			if errors.Is(err, proto.ErrProbeVersion) {
				wrongVersion++
				if time.Since(lastVersion) > 30*time.Second {
					r.log.Warn("dropping probes from a different wire version; upgrade both hosts to the same build",
						"packets", wrongVersion, "from", src.String())
					lastVersion = time.Now()
					wrongVersion = 0
				}
				continue
			}
			noise++
			if time.Since(lastNoise) > 30*time.Second {
				r.log.Warn("dropping unauthenticated probe packets; check that the shared secret is identical on both hosts",
					"packets", noise, "from", src.String(), "err", err)
				lastNoise = time.Now()
				noise = 0
			}
			continue
		}
		if msg.Type != proto.TypeProbe {
			continue
		}

		// The frontend's routing decision rides on every probe, so it reaches
		// the backend over whichever tunnel is still delivering packets. Sending
		// it over the control channel instead would mean sending it across the
		// path that just failed.
		r.agent.SetActivePath(ctx, int(msg.ActivePath), msg.DecisionSeq)

		reply := (&proto.Probe{
			Type:        proto.TypeReply,
			PathID:      msg.PathID,
			Seq:         msg.Seq,
			TxNanos:     msg.TxNanos,
			EchoNanos:   time.Now().UnixNano(),
			ActivePath:  msg.ActivePath,
			DecisionSeq: msg.DecisionSeq,
			Nonce:       msg.Nonce,
		}).Marshal(r.agent.psk)

		out := r.replyConn(ctx, int(msg.PathID))
		if out == nil {
			out = conn // best effort before configuration arrives
		}
		_ = out.SetWriteDeadline(time.Now().Add(time.Second))
		if _, err := out.WriteToUDP(reply, src); err != nil {
			// A reply that cannot be sent looks identical to a dead tunnel from
			// the frontend's side, so this cannot stay at debug level. The
			// usual cause is a missing route in the path's table, which makes
			// a perfectly healthy link probe as 100% loss.
			failed[int(msg.PathID)]++
			if time.Since(lastFail) > 30*time.Second {
				r.log.Warn("probe replies could not be sent; the path's reply route is probably missing",
					"failures_by_path", fmt.Sprint(failed), "err", err)
				lastFail = time.Now()
				failed = map[int]int{}
			}
		}
	}
}

func (r *Responder) watchReloads(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.reload:
			r.mu.Lock()
			for _, c := range r.replies {
				_ = c.Close()
			}
			r.replies = map[int]*net.UDPConn{}
			r.mu.Unlock()
		}
	}
}

// replyConn returns the marked socket for a path, creating it on demand.
func (r *Responder) replyConn(ctx context.Context, pathID int) *net.UDPConn {
	r.mu.Lock()
	if c, ok := r.replies[pathID]; ok {
		r.mu.Unlock()
		return c
	}
	r.mu.Unlock()

	cfg, ok := r.agent.Config()
	if !ok {
		return nil
	}
	var mark int
	for _, p := range cfg.Paths {
		if p.ID == pathID {
			mark = p.Mark
		}
	}
	if mark == 0 {
		return nil
	}

	ov := r.agent.Overlay()
	lc := net.ListenConfig{Control: sysx.MarkControl(mark)}
	pc, err := lc.ListenPacket(ctx, "udp", net.JoinHostPort(ov.BackendIP, "0"))
	if err != nil {
		r.log.Warn("cannot open reply socket", "path_id", pathID, "err", err)
		return nil
	}
	conn := pc.(*net.UDPConn)

	r.mu.Lock()
	if existing, ok := r.replies[pathID]; ok {
		r.mu.Unlock()
		_ = conn.Close()
		return existing
	}
	r.replies[pathID] = conn
	r.mu.Unlock()
	return conn
}
