package engine

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/proto"
	"github.com/quinlan102/homeport/internal/sysx"
)

// Result is one resolved probe: either a reply with a round-trip time, or a
// probe that timed out.
type Result struct {
	PathID int
	Seq    uint64
	RTT    time.Duration
	Lost   bool
	At     time.Time
}

// Prober measures one path end-to-end.
//
// The socket is stamped with the path's fwmark, which sends it into that
// path's own routing table. Without that every probe would follow the single
// active route and the standby tunnels would never be tested at all. It also
// means the question being answered is "can I reach the backend through this
// tunnel", not "is this WireGuard interface up" - an interface stays up long
// after the link beneath it has died.
type Prober struct {
	path     model.PathConfig
	probeCfg model.ProbeConfig
	psk      []byte
	localIP  string
	remote   *net.UDPAddr
	log      *slog.Logger

	// decision supplies the frontend's current choice, piggybacked on every
	// probe so the backend learns it over whichever tunnel still works.
	decision func() (uint16, uint64)

	results chan<- Result

	mu       sync.Mutex
	conn     *net.UDPConn
	seq      uint64
	pending  map[uint64]time.Time
	resolved map[uint64]Result
	deliver  uint64 // next sequence number to emit, keeps results in order
	active   bool
}

// NewProber builds a prober for one path.
func NewProber(p model.PathConfig, probeCfg model.ProbeConfig, ov model.OverlayConfig,
	psk []byte, results chan<- Result, decision func() (uint16, uint64), log *slog.Logger) (*Prober, error) {

	remote, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ov.BackendIP, fmt.Sprint(ov.ProbePort)))
	if err != nil {
		return nil, fmt.Errorf("resolve backend probe address: %w", err)
	}
	return &Prober{
		path:     p,
		probeCfg: probeCfg,
		psk:      psk,
		localIP:  ov.FrontendIP,
		remote:   remote,
		log:      log.With("path", p.Name),
		decision: decision,
		results:  results,
		pending:  map[uint64]time.Time{},
		resolved: map[uint64]Result{},
		deliver:  1,
	}, nil
}

// SetActive switches between the fast cadence used for the path currently
// carrying traffic and the slower cadence for standby paths. Standby paths
// only need to be known-good, not instantly good, and on metered LTE the
// difference is the bulk of the monthly probe cost.
func (p *Prober) SetActive(active bool) {
	p.mu.Lock()
	p.active = active
	p.mu.Unlock()
}

func (p *Prober) interval() time.Duration {
	p.mu.Lock()
	active := p.active
	p.mu.Unlock()
	if active {
		return time.Duration(p.probeCfg.ActiveIntervalMs) * time.Millisecond
	}
	return time.Duration(p.probeCfg.StandbyIntervalMs) * time.Millisecond
}

// Run probes until the context is cancelled.
func (p *Prober) Run(ctx context.Context) {
	for ctx.Err() == nil {
		if err := p.dial(ctx); err != nil {
			p.log.Warn("probe socket unavailable, retrying", "err", err)
			// The tunnel may not exist yet. Report losses so the path reads
			// as down rather than silently stalling.
			p.reportUnreachable(ctx)
			continue
		}
		p.loop(ctx)
	}
}

// dial opens the marked probe socket.
//
// The socket is deliberately unconnected. The backend answers from a socket
// marked for the same path so that the reply leaves through the same tunnel
// the request arrived on, which means it answers from an ephemeral port rather
// than the probe port. A connected socket would reject that reply. Nothing is
// lost by accepting from any source: every packet is HMAC-authenticated and
// matched against an outstanding sequence number.
func (p *Prober) dial(ctx context.Context) error {
	lc := net.ListenConfig{Control: sysx.MarkControl(p.path.Mark)}
	c, err := lc.ListenPacket(ctx, "udp", net.JoinHostPort(p.localIP, "0"))
	if err != nil {
		return err
	}
	conn, ok := c.(*net.UDPConn)
	if !ok {
		_ = c.Close()
		return fmt.Errorf("unexpected connection type %T", c)
	}
	p.mu.Lock()
	p.conn = conn
	p.mu.Unlock()
	return nil
}

func (p *Prober) reportUnreachable(ctx context.Context) {
	t := time.NewTimer(p.interval())
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
		p.mu.Lock()
		p.seq++
		seq := p.seq
		p.resolved[seq] = Result{PathID: p.path.ID, Seq: seq, Lost: true, At: time.Now()}
		p.mu.Unlock()
		p.flush(ctx)
	}
}

func (p *Prober) loop(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	conn := p.currentConn()
	if conn == nil {
		return
	}
	defer func() {
		_ = conn.Close()
		p.mu.Lock()
		p.conn = nil
		p.mu.Unlock()
	}()

	// A context does not interrupt a read in progress. This was the one read
	// loop here without the watcher, relying on its one-second read deadline
	// instead, and while nothing waited on it that cost nothing. stopProbers
	// waits now - it has to, or a replaced generation goes on probing the same
	// path as its replacement - so the deadline became a second of latency on
	// every settings save. Closing the socket unblocks the read at once.
	//
	// It is safe to close from here: net.UDPConn is safe for concurrent use,
	// and closing during a read is the documented way to end one. The deferred
	// close above may get there first, in which case this is a second close on
	// an already-closed socket, which is an error nobody reads.
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.readLoop(ctx, conn)
		cancel() // a dead socket must restart the send loop too
	}()

	// stop must cancel before waiting. The read loop only returns once the
	// context is done, so waiting first would deadlock - and the path that
	// hits it is the common one: when a tunnel goes down the next send fails
	// with ENETUNREACH, which is precisely when probing must keep going.
	stop := func() {
		cancel()
		wg.Wait()
	}

	send := time.NewTicker(p.interval())
	defer send.Stop()
	sweep := time.NewTicker(50 * time.Millisecond)
	defer sweep.Stop()

	current := p.interval()
	for {
		select {
		case <-ctx.Done():
			stop()
			return
		case <-send.C:
			if err := p.send(conn); err != nil {
				p.log.Debug("probe send failed", "err", err)
				stop()
				return
			}
			if iv := p.interval(); iv != current {
				current = iv
				send.Reset(iv)
			}
		case <-sweep.C:
			p.expire()
			p.flush(ctx)
		}
	}
}

func (p *Prober) currentConn() *net.UDPConn {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.conn
}

func (p *Prober) send(conn *net.UDPConn) error {
	activePath, decisionSeq := p.decision()

	p.mu.Lock()
	p.seq++
	seq := p.seq
	p.pending[seq] = time.Now()
	p.mu.Unlock()

	pkt := (&proto.Probe{
		Type:        proto.TypeProbe,
		PathID:      uint16(p.path.ID),
		Seq:         seq,
		TxNanos:     time.Now().UnixNano(),
		ActivePath:  activePath,
		DecisionSeq: decisionSeq,
		Nonce:       proto.NewNonce(),
	}).Marshal(p.psk)

	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	_, err := conn.WriteToUDP(pkt, p.remote)
	return err
}

func (p *Prober) readLoop(ctx context.Context, conn *net.UDPConn) {
	buf := make([]byte, 256)
	for ctx.Err() == nil {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		msg, err := proto.Unmarshal(buf[:n], p.psk)
		if err != nil || msg.Type != proto.TypeReply {
			continue // unauthenticated noise; nobody can forge path health
		}
		now := time.Now()
		p.mu.Lock()
		sent, ok := p.pending[msg.Seq]
		if ok {
			delete(p.pending, msg.Seq)
			p.resolved[msg.Seq] = Result{
				PathID: p.path.ID,
				Seq:    msg.Seq,
				RTT:    now.Sub(sent),
				At:     now,
			}
		}
		p.mu.Unlock()
	}
}

// expire resolves probes that have been outstanding past the timeout.
func (p *Prober) expire() {
	timeout := time.Duration(p.probeCfg.TimeoutMs) * time.Millisecond
	cutoff := time.Now().Add(-timeout)
	p.mu.Lock()
	defer p.mu.Unlock()
	for seq, sent := range p.pending {
		if sent.Before(cutoff) {
			delete(p.pending, seq)
			p.resolved[seq] = Result{PathID: p.path.ID, Seq: seq, Lost: true, At: time.Now()}
		}
	}
}

// flush emits resolved probes in sequence order.
//
// Ordering is not cosmetic: consecutive-loss counting is what condemns a path,
// and a lost probe only resolves after the timeout, by which time later probes
// may already have replied. Delivering out of order would scramble the streak
// counts and either delay a failover or trigger a spurious one.
func (p *Prober) flush(ctx context.Context) {
	for {
		p.mu.Lock()
		r, ok := p.resolved[p.deliver]
		if !ok {
			// Skip past any sequence that is still outstanding only if it has
			// no pending entry either, which happens after a socket restart.
			if _, stillPending := p.pending[p.deliver]; !stillPending && p.deliver < p.seq {
				p.deliver++
				p.mu.Unlock()
				continue
			}
			p.mu.Unlock()
			return
		}
		delete(p.resolved, p.deliver)
		p.deliver++
		p.mu.Unlock()

		select {
		case p.results <- r:
		case <-ctx.Done():
			return
		}
	}
}

// Window is a small fixed-size ring of recent probe outcomes, used for loss,
// mean RTT and jitter.
type Window struct {
	size    int
	entries []Result
}

// NewWindow builds a window of the given size.
func NewWindow(size int) *Window {
	if size < 5 {
		size = 5
	}
	return &Window{size: size}
}

// Add records one result.
func (w *Window) Add(r Result) {
	w.entries = append(w.entries, r)
	if len(w.entries) > w.size {
		w.entries = w.entries[len(w.entries)-w.size:]
	}
}

// Stats returns loss percentage, mean RTT and jitter in milliseconds.
//
// Jitter is the median absolute deviation of RTT rather than the standard
// deviation, so one satellite-grade outlier does not make an otherwise steady
// link look unusable.
func (w *Window) Stats() (lossPct, rttMs, jitterMs float64) {
	if len(w.entries) == 0 {
		return 0, 0, 0
	}
	var lost int
	var rtts []float64
	for _, e := range w.entries {
		if e.Lost {
			lost++
			continue
		}
		rtts = append(rtts, float64(e.RTT.Microseconds())/1000.0)
	}
	lossPct = float64(lost) / float64(len(w.entries)) * 100
	if len(rtts) == 0 {
		return lossPct, 0, 0
	}
	var sum float64
	for _, v := range rtts {
		sum += v
	}
	rttMs = sum / float64(len(rtts))

	dev := make([]float64, len(rtts))
	for i, v := range rtts {
		d := v - rttMs
		if d < 0 {
			d = -d
		}
		dev[i] = d
	}
	sort.Float64s(dev)
	jitterMs = dev[len(dev)/2]
	return lossPct, rttMs, jitterMs
}
