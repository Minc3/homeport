package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/proto"
	"github.com/quinlan102/homeport/internal/sysx"
)

// ControlServer accepts the backend's control connection.
//
// The backend always dials, never the other way round: the LTE services are
// behind CGNAT, so the home side is the only end that can initiate anything.
//
// This channel carries configuration down and usage accounting up. It
// deliberately does not carry the routing decision - that rides on every probe
// packet instead, because a decision sent over TCP would have to travel across
// the path that just failed.
type ControlServer struct {
	eng  *Engine
	log  *slog.Logger
	psk  []byte
	addr string
}

// NewControlServer builds the server.
func NewControlServer(eng *Engine, psk []byte) *ControlServer {
	cfg := eng.Config()
	return &ControlServer{
		eng:  eng,
		log:  eng.Logger().With("component", "control"),
		psk:  psk,
		addr: net.JoinHostPort(cfg.Overlay.FrontendIP, strconv.Itoa(cfg.Overlay.ControlPort)),
	}
}

// Run listens until the context is cancelled.
//
// A failed listen is retried rather than fatal, the same way the backend's
// probe responder handles it. The address being bound lives on dummy0, which
// the engine creates as the first thing it does - so on a fresh host it does
// not exist yet for the first moments of the process's life. Returning an
// error here kills the process, which cancels the context the engine is using
// to run "ip addr add", so the address is never finished. The restart loses
// the same race, and the host never comes up at all.
func (s *ControlServer) Run(ctx context.Context) error {
	for ctx.Err() == nil {
		if err := s.listen(ctx); err != nil {
			if ctx.Err() != nil {
				break
			}
			s.log.Warn("control listen failed, retrying", "addr", s.addr, "err", err)
			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
			}
		}
	}
	return ctx.Err()
}

func (s *ControlServer) listen(ctx context.Context) error {
	// The listener carries the control mark, which routes its packets - the
	// SYN-ACK included, and every accepted connection inherits it - through
	// the control table rather than the frontend's public interface.
	lc := net.ListenConfig{Control: sysx.MarkControl(sysx.ControlMark)}
	ln, err := lc.Listen(ctx, "tcp", s.addr)
	if err != nil {
		return fmt.Errorf("control listen on %s: %w", s.addr, err)
	}
	defer ln.Close()
	s.log.Info("control channel listening", "addr", s.addr)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.log.Warn("control accept failed", "err", err)
			continue
		}
		go s.serve(ctx, conn)
	}
}

func (s *ControlServer) serve(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()

	nonce := proto.RandomNonce()
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := proto.WriteFrame(conn, proto.MsgChallenge, proto.Challenge{Nonce: nonce}); err != nil {
		return
	}

	r := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	env, err := readFrame(r)
	if err != nil {
		return
	}
	var auth proto.Auth
	if env.Type != proto.MsgAuth || proto.DecodeInto(env, &auth) != nil ||
		!proto.VerifyChallenge(s.psk, nonce, auth.MAC) {
		s.log.Warn("control authentication failed", "remote", remote)
		return
	}

	// Who is this? The first frame after auth says. A backend from before
	// linkers existed sends a Hello with no role, and an empty role means
	// backend - so an older backend is understood exactly as it always was.
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	first, err := readFrame(r)
	if err != nil {
		return
	}
	var hello proto.Hello
	if first.Type == proto.MsgHello {
		_ = proto.DecodeInto(first, &hello)
	}

	if hello.Role == model.RoleLinker {
		s.serveLinker(ctx, conn, r, hello, remote)
		return
	}

	s.log.Info("backend connected", "remote", remote, "version", hello.Version)
	if first.Type == proto.MsgHello {
		s.eng.SetBackendInfo(hello.Version, hello.Hostname)
	}
	s.eng.SetBackendUp(true)
	defer s.eng.SetBackendUp(false)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Unblock the read loop below on shutdown. It is harmless here today only
	// because nothing waits on these goroutines - the listener closes, Run
	// returns and the process exits out from under them. The identical omission
	// on the backend, where Agent.Run does wait, cost every restart a SIGKILL,
	// so it does not get to stay here as a trap for whoever makes shutdown
	// wait on connections.
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	// Push config immediately, then whenever it changes.
	go s.pushLoop(ctx, conn)

	for {
		_ = conn.SetReadDeadline(time.Now().Add(proto.ControlDeadline))
		env, err := readFrame(r)
		if err != nil {
			s.log.Info("backend disconnected", "remote", remote, "err", err)
			return
		}
		switch env.Type {
		case proto.MsgHello:
			var h proto.Hello
			if proto.DecodeInto(env, &h) == nil {
				s.log.Info("backend hello", "host", h.Hostname, "version", h.Version)
				s.eng.SetBackendInfo(h.Version, h.Hostname)
			}
		case proto.MsgUsage:
			var u proto.Usage
			if proto.DecodeInto(env, &u) == nil {
				s.applyUsage(u)
			}
		case proto.MsgLink:
			var l proto.Link
			if proto.DecodeInto(env, &l) == nil {
				ages := map[int]float64{}
				for _, li := range l.Links {
					ages[li.PathID] = li.HandshakeAgeSec
				}
				s.eng.SetHandshakeAges(ages)
			}
		case proto.MsgPing:
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_ = proto.WriteFrame(conn, proto.MsgPong, nil)
		}
	}
}

// applyUsage folds buffered metering deltas into the ledger.
//
// The backend replays anything it could not deliver while the control channel
// was down, so deltas arrive more than once. Each is stamped with a per-path
// sequence number and anything not strictly newer than what was already
// applied is dropped, which keeps replays from double-counting LTE data.
func (s *ControlServer) applyUsage(u proto.Usage) {
	st := s.eng.Store()
	// Deltas for one path arrive in sequence order, and the watermark is a
	// single high-water mark. If one write fails, every later delta for that
	// path must be held back too - otherwise the next success would advance the
	// watermark past the failed one and those metered bytes are gone for good,
	// since the backend has already dropped its buffered copy.
	stalled := map[int]bool{}
	for _, d := range u.Deltas {
		if stalled[d.PathID] {
			continue
		}
		key := "usage_seq:" + strconv.Itoa(d.PathID)
		last, _ := strconv.ParseUint(st.Meta(key), 10, 64)
		if d.Sequence <= last {
			continue
		}
		// Only advance the watermark once the bytes are in the ledger.
		// Advancing regardless would let a failed write discard metered LTE
		// usage for good: the backend has already dropped its buffered copy.
		if err := s.eng.AddUsage(d.PathID, d.Bytes, d.Packets, time.Unix(d.AtUnix, 0)); err != nil {
			s.log.Warn("usage delta not recorded, holding back this path's watermark",
				"path_id", d.PathID, "seq", d.Sequence, "err", err)
			stalled[d.PathID] = true
			continue
		}
		_ = st.SetMeta(key, strconv.FormatUint(d.Sequence, 10))
	}
}

func (s *ControlServer) pushLoop(ctx context.Context, conn net.Conn) {
	var pushed uint64
	first := true
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	ka := time.NewTicker(proto.KeepaliveInterval)
	defer ka.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			v := s.eng.ConfigVersion()
			if !first && v == pushed {
				continue
			}
			pushed, first = v, false
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := proto.WriteFrame(conn, proto.MsgConfig, backendConfig(s.eng.Config())); err != nil {
				return
			}
		case <-ka.C:
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := proto.WriteFrame(conn, proto.MsgPing, nil); err != nil {
				return
			}
		}
	}
}

func backendConfig(cfg model.Config) proto.BackendConfig {
	bc := proto.BackendConfig{
		Overlay: proto.OverlayInfo{
			FrontendIP: cfg.Overlay.FrontendIP,
			BackendIP:  cfg.Overlay.BackendIP,
			Device:     cfg.Overlay.Device,
			Subnet:     cfg.Overlay.Subnet,
		},
		Mode:     cfg.Mode,
		SampleMs: 10000,
	}
	for _, p := range cfg.Paths {
		bc.Paths = append(bc.Paths, proto.PathInfo{
			ID: p.ID, Name: p.Name, Iface: p.Iface,
			Table: p.Table, Mark: p.Mark, Metered: p.Metered,
			ShapeMbit: p.Shape.ToFrontendMbit,
		})
	}
	// Only enabled ones. Unticking a linker is how an operator takes a host out
	// of service, and leaving its route installed would keep the frontend's
	// DNAT pointing at a machine nobody expects traffic to reach.
	for _, l := range cfg.Linkers {
		if !l.Enabled {
			continue
		}
		bc.Linkers = append(bc.Linkers, proto.LinkerRoute{
			OverlayIP: l.OverlayIP,
			LanIP:     l.LanIP,
		})
	}
	// Only sent when the frontend is prepared to translate them. Pulling a
	// network onto the tunnel without the source NAT waiting at the other end
	// sends its traffic somewhere it cannot be answered - worse than leaving it
	// on the house's own service, because it fails silently.
	if cfg.Frontend.BackendEgress {
		// Only this agent's own networks. A row belongs to exactly one host,
		// because Docker hands out the same bridge subnets on every machine -
		// 172.17.0.0/16 is the default everywhere - so a global list would have
		// each agent pulling containers onto the tunnel that belong to a
		// different box entirely, and paying for them out of the LTE quota.
		for _, s := range cfg.Egress.Sources {
			if s.Enabled && s.CIDR != "" && s.HostOr(cfg.Overlay.BackendIP) == cfg.Overlay.BackendIP {
				bc.EgressCIDRs = append(bc.EgressCIDRs, s.CIDR)
			}
		}
	}
	return bc
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

// serveLinker handles a control connection from an extra host.
//
// Far smaller than the backend's session, because a linker is far smaller: it
// reports nothing but its own liveness and receives nothing but the networks it
// should pull onto the overlay. It sends no usage, because it meters nothing,
// and it is told no path, because it makes no decisions - the backend already
// tracks which tunnel is carrying traffic, and a second thing that had to agree
// with the frontend about the active path is exactly the failure mode pfSense
// demonstrates.
func (s *ControlServer) serveLinker(ctx context.Context, conn net.Conn, r *bufio.Reader, hello proto.Hello, remote string) {
	// The shared secret proves the peer belongs to this deployment. It does not
	// prove it is entitled to a particular overlay address, and a linker that
	// could name itself could be handed another linker's networks - so the
	// address is checked against the configured list rather than trusted.
	if !s.eng.KnownLinker(hello.OverlayIP) {
		s.log.Warn("linker claimed an address that is not configured; refusing",
			"remote", remote, "claimed", hello.OverlayIP,
			"hint", "add it under Linkers in the portal, or correct linker.overlay_ip on that host")
		return
	}

	s.log.Info("linker connected", "remote", remote,
		"overlay", hello.OverlayIP, "host", hello.Hostname, "version", hello.Version)
	session := s.eng.SetLinkerUp(hello.OverlayIP, hello.Version, hello.Hostname, hello.Table)
	defer s.eng.SetLinkerDown(hello.OverlayIP, session)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// A context does not interrupt a read in progress, and silence is the
	// normal healthy case here - the frontend speaks only when the
	// configuration changes. Without this the goroutine parks until the
	// deadline expires.
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	go s.pushLinkerLoop(ctx, conn, hello.OverlayIP)

	for {
		_ = conn.SetReadDeadline(time.Now().Add(proto.ControlDeadline))
		env, err := readFrame(r)
		if err != nil {
			s.log.Info("linker disconnected", "remote", remote, "overlay", hello.OverlayIP, "err", err)
			return
		}
		// Every frame, not just the ones worth acting on: a pong answering our
		// keepalive is the only thing a healthy linker ever says, and it is
		// exactly the evidence that the host is still there.
		s.eng.MarkLinkerSeen(hello.OverlayIP)
		if env.Type == proto.MsgPing {
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_ = proto.WriteFrame(conn, proto.MsgPong, nil)
		}
	}
}

// pushLinkerLoop sends the linker its configuration, and again whenever it
// changes. Mirrors pushLoop, keyed on the same version counter.
func (s *ControlServer) pushLinkerLoop(ctx context.Context, conn net.Conn, overlayIP string) {
	// `first` rather than comparing against a zero value: the version counter
	// starts at zero, so a linker connecting to a frontend whose configuration
	// has never changed would match on the first pass and never be sent
	// anything at all.
	var pushed uint64
	first := true

	push := func() bool {
		v := s.eng.ConfigVersion()
		if !first && v == pushed {
			return true
		}
		pushed, first = v, false
		cfg := s.eng.LinkerConfigFor(overlayIP)
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := proto.WriteFrame(conn, proto.MsgLinkerConfig, cfg); err != nil {
			return false
		}
		s.log.Info("pushed configuration to linker",
			"overlay", overlayIP, "networks", len(cfg.EgressCIDRs))
		return true
	}

	// Immediately, so a reconnecting linker is configured without waiting a
	// tick, and then on change.
	if !push() {
		return
	}

	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	ka := time.NewTicker(proto.KeepaliveInterval)
	defer ka.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if !push() {
				return
			}
		case <-ka.C:
			// The read side of this session has a deadline, and a healthy
			// linker has nothing to say - so without something to answer, an
			// idle but perfectly well host would be dropped every 45 seconds.
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := proto.WriteFrame(conn, proto.MsgPing, nil); err != nil {
				return
			}
		}
	}
}
