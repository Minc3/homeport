package engine

import (
	"context"
	"crypto/rand"
	"encoding/binary"
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
	pending  map[uint64]pendingProbe
	resolved map[uint64]Result
	deliver  uint64 // next sequence number to emit, keeps results in order
	active   bool

	// nudge asks the send loop for a probe now, outside its ticker. See Nudge.
	nudge chan struct{}
}

// pendingProbe is one probe in flight: when it left, and the nonce it carried.
//
// The nonce is what a reply has to echo before it is believed. The MAC proves
// a reply was made by somebody holding the key, and the sequence says which
// probe it claims to answer, but neither says it was made for *this* probe:
// an authentic reply captured off the wire is still authentic later. Matching
// on the sequence alone let one such capture answer a probe again the next
// time this path was at that sequence, which every generation used to reach
// because it counted from zero. See resolve.
type pendingProbe struct {
	sent  time.Time
	nonce uint64
}

// seqSeedBits is how much of the sequence space a generation's starting point
// is drawn from. Sixty-two bits leaves two bits of headroom above the seed,
// which at four probes a second is longer than the age of the universe before
// the counter could wrap.
const seqSeedBits = 62

// seedSeq draws a generation's starting sequence number at random.
//
// Every generation used to count from zero, so the sequences a replaced
// generation had used were exactly the ones its replacement would use next,
// and a reply captured against one was addressed, as far as the sequence
// could tell, to the other. The nonce check in resolve is what actually
// refuses that reply; the random start is the second lock on the same door,
// so a captured reply does not even name a probe the new generation will send.
// The clock would be a worse seed than it looks: two generations started
// within its granularity - a settings save landing beside a mode change - draw
// the same number.
func seedSeq() uint64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint64(b[:]) & (1<<seqSeedBits - 1)
}

// NewProber builds a prober for one path.
func NewProber(p model.PathConfig, probeCfg model.ProbeConfig, ov model.OverlayConfig,
	psk []byte, results chan<- Result, decision func() (uint16, uint64), log *slog.Logger) (*Prober, error) {

	remote, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ov.BackendIP, fmt.Sprint(ov.ProbePort)))
	if err != nil {
		return nil, fmt.Errorf("resolve backend probe address: %w", err)
	}
	// deliver is the next sequence flush will emit, so it starts one past the
	// seed: the first send takes seq+1, and flush only skips a sequence that
	// is below seq, so a deliver left at 1 would sit behind a seed nothing
	// ever resolves and no result would leave this prober.
	seq := seedSeq()
	return &Prober{
		path:     p,
		probeCfg: probeCfg,
		psk:      psk,
		localIP:  ov.FrontendIP,
		remote:   remote,
		log:      log.With("path", p.Name),
		decision: decision,
		results:  results,
		seq:      seq,
		pending:  map[uint64]pendingProbe{},
		resolved: map[uint64]Result{},
		deliver:  seq + 1,
		nudge:    make(chan struct{}, 1),
	}, nil
}

// Nudge sends a probe at once and restarts the cadence from now.
//
// The routing decision travels on probes and nowhere else, so the backend
// learns about a switch when the next probe reaches it, and a standby path's
// next probe was wherever its 5s ticker happened to be. SetActive changed the
// interval, but the loop only picks that up after the ticker it is already
// waiting on fires. Until a probe lands the backend's replies still leave by
// the tunnel that just died: the frontend had switched, and the players were
// still frozen for up to five seconds more. That wait was the largest and
// least visible part of a failover, and it was not in any setting.
//
// The loop also nudges itself on entry, so a fresh generation (startup, a
// settings save, a redial after the tunnel came back) measures and carries
// the decision at once rather than after a full interval of silence.
//
// Non-blocking and coalescing: a nudge that arrives while one is already
// queued is the same request.
func (p *Prober) Nudge() {
	select {
	case p.nudge <- struct{}{}:
	default:
	}
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
		if err := p.loop(ctx); err != nil {
			// The send failed synchronously, and the failed probe has already
			// been booked as a loss. Hold one interval before the socket is
			// rebuilt: see loop for what happens without the wait.
			p.hold(ctx)
		}
	}
}

// hold pauses for one interval, or until the context ends, and reports which.
// Before returning it runs the sweep the loop is not there to run.
//
// It is the throttle on the two synchronous failures, a socket that will not
// open and a send the kernel refuses. Either fails again at once if retried at
// once, and one attempt per interval is the cadence the path would have been
// measured at anyway.
//
// The sweep is not optional. Results leave in sequence order, and the common
// way into this path is a link dying with a probe outstanding: sent fine,
// never answered, still in pending when the next send is refused. Only expire
// resolves it, and only the loop's sweep ticker called expire - a loop the
// entry nudge now ends before its first tick. Without a sweep here every
// later probe was booked as lost and none was ever delivered, because deliver
// was parked behind a probe that could never time out. That is the symptom
// the hold exists to prevent, reached a second way.
func (p *Prober) hold(ctx context.Context) bool {
	t := time.NewTimer(p.interval())
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		p.expire()
		p.flush(ctx)
		return true
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
	if !p.hold(ctx) {
		return
	}
	p.mu.Lock()
	p.seq++
	p.markLost(p.seq)
	p.mu.Unlock()
	p.flush(ctx)
}

// markLost resolves one probe as lost, whether or not it was ever pending.
// Called with p.mu held.
func (p *Prober) markLost(seq uint64) {
	delete(p.pending, seq)
	p.resolved[seq] = Result{PathID: p.path.ID, Seq: seq, Lost: true, At: time.Now()}
}

// loop probes on one socket until the context ends or a send fails. It returns
// the send error, nil otherwise, so Run can hold before opening another socket.
func (p *Prober) loop(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	conn := p.currentConn()
	if conn == nil {
		return nil
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

	// A send the kernel refuses outright - ENETUNREACH while the tunnel's
	// table is empty, a prohibit route covering the overlay range, an output
	// firewall - ends this socket, and Run opens another. That cycle used to
	// be throttled by accident: the first send waited a full interval on the
	// ticker, so it ran at one attempt per interval, and the sweeps in between
	// expired each failed probe into the loss that condemned the path. The
	// entry nudge below took away that wait, and with it the only delay in
	// the cycle: dial, nudge, fail, return, dial, a core spinning, the sweep
	// never reached, no loss ever delivered so the path was never condemned
	// by this route, and pending growing without bound until the sends came
	// back and the whole backlog was expired at once as a streak of losses
	// against a path that by then was working. So the failed probe is booked
	// as lost here, deterministically rather than by a sweep that may not
	// run, and the error is returned so Run holds one interval first.
	sendFailed := func(seq uint64, err error) error {
		p.log.Debug("probe send failed", "err", err)
		p.mu.Lock()
		p.markLost(seq)
		p.mu.Unlock()
		p.flush(ctx) // before stop: flush gives up on a cancelled context
		stop()
		return err
	}

	send := time.NewTicker(p.interval())
	defer send.Stop()
	sweep := time.NewTicker(50 * time.Millisecond)
	defer sweep.Stop()

	// First probe now, not one interval from now. On a standby path that
	// interval is 5s of measuring nothing and carrying no decision, and a
	// generation starts at exactly the moments that matters: a frontend
	// restart mid-outage, a settings save, a tunnel coming back.
	p.Nudge()

	current := p.interval()
	for {
		select {
		case <-ctx.Done():
			stop()
			return nil
		case <-send.C:
			if seq, err := p.send(conn); err != nil {
				return sendFailed(seq, err)
			}
			if iv := p.interval(); iv != current {
				current = iv
				send.Reset(iv)
			}
		case <-p.nudge:
			if seq, err := p.send(conn); err != nil {
				return sendFailed(seq, err)
			}
			// Restart the cadence from this send, at whatever interval the
			// decision that prompted it has left us on. A path that has just
			// become active goes from a 5s ticker to 250ms here and now.
			current = p.interval()
			send.Reset(current)
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

// send transmits one probe and returns its sequence number, which is already
// outstanding in pending whether or not the write succeeded.
func (p *Prober) send(conn *net.UDPConn) (uint64, error) {
	activePath, decisionSeq := p.decision()
	nonce := proto.NewNonce()

	p.mu.Lock()
	p.seq++
	seq := p.seq
	p.pending[seq] = pendingProbe{sent: time.Now(), nonce: nonce}
	p.mu.Unlock()

	pkt := (&proto.Probe{
		Type:        proto.TypeProbe,
		PathID:      uint16(p.path.ID),
		Seq:         seq,
		TxNanos:     time.Now().UnixNano(),
		ActivePath:  activePath,
		DecisionSeq: decisionSeq,
		Nonce:       nonce,
	}).Marshal(p.psk)

	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	_, err := conn.WriteToUDP(pkt, p.remote)
	return seq, err
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
		if err != nil {
			continue // unauthenticated noise; nobody can forge path health
		}
		p.resolve(msg, time.Now())
	}
}

// resolve matches one authenticated reply to the probe it answers and books
// the round trip. It reports whether anything was resolved.
//
// A reply counts only if it names a sequence still outstanding, echoes the
// nonce that probe carried, and is for this path. The MAC has already proved
// that somebody holding the key made it; these three say it was made for the
// probe it is being matched to. Sequence alone was not enough for two reasons.
// The backend echoes the nonce and the frontend used to throw it away, so a
// reply captured off the wire - which the MAC makes no less authentic a
// minute later - answered again on any later probe that reused its sequence,
// and every generation reused all of them because each counted from zero.
// Injecting that at the frontend's overlay address takes no key at all,
// only a position the backend forwards for, and what it buys is a condemned
// tunnel that keeps resolving its probes as answered. The path id closes the
// other half: a reply is stamped with this prober's own path whatever it
// carries, so one captured on a working tunnel could be replayed at a dead
// one. Anything else is dropped as the noise an unauthenticated packet
// already is. There is no log line here, because this runs per packet on a
// socket anybody in that position can write to.
func (p *Prober) resolve(msg *proto.Probe, now time.Time) bool {
	if msg.Type != proto.TypeReply || msg.PathID != uint16(p.path.ID) {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	entry, ok := p.pending[msg.Seq]
	if !ok || entry.nonce != msg.Nonce {
		return false
	}
	delete(p.pending, msg.Seq)
	p.resolved[msg.Seq] = Result{
		PathID: p.path.ID,
		Seq:    msg.Seq,
		RTT:    now.Sub(entry.sent),
		At:     now,
	}
	return true
}

// expire resolves probes that have been outstanding past the timeout.
func (p *Prober) expire() {
	timeout := time.Duration(p.probeCfg.TimeoutMs) * time.Millisecond
	cutoff := time.Now().Add(-timeout)
	p.mu.Lock()
	defer p.mu.Unlock()
	for seq, entry := range p.pending {
		if entry.sent.Before(cutoff) {
			p.markLost(seq)
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
