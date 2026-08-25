package agent

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/quinlan102/homeport/internal/proto"
	"github.com/quinlan102/homeport/internal/sysx"
)

// maxBuffered caps the offline backlog. At one sample every ten seconds this
// is several days of accounting, far longer than any plausible outage.
const maxBuffered = 50_000

// Meter turns raw interface counters into usage deltas for the frontend's
// ledger.
//
// Two details matter more than they look:
//
// Packets are counted alongside bytes, because the carrier meters the
// encapsulated datagram on the WAN rather than the payload inside the tunnel.
// The frontend reconstructs the billed figure from both.
//
// Deltas are buffered on disk when the control channel is down. That is
// precisely the window in which LTE data is being burned - a failover to LTE
// often coincides with the frontend being unreachable - so dropping the
// accounting then would lose exactly the usage that matters most.
type Meter struct {
	log        *slog.Logger
	bufferPath string
	statePath  string

	mu      sync.Mutex
	last    map[string]sysx.Counters
	nextSeq map[int]uint64
	pending []proto.UsageDelta

	// persistMu serialises persist against itself. It is called from two
	// goroutines - the sample ticker and, via AckApplied, the control read
	// loop - and both write the same tmp file before renaming it over the
	// buffer. Unserialised, one rename can land mid-write of the other and
	// publish a torn file. It is a separate lock from mu, held across the
	// snapshot as well as the write, so the last writer to finish is also the
	// one holding the newest snapshot and the file never goes backwards.
	persistMu sync.Mutex
}

type meterState struct {
	Last    map[string]sysx.Counters `json:"last"`
	NextSeq map[int]uint64           `json:"next_seq"`
}

// NewMeter builds a meter backed by an on-disk buffer.
func NewMeter(log *slog.Logger, bufferPath string) *Meter {
	m := &Meter{
		log:        log.With("component", "meter"),
		bufferPath: bufferPath,
		statePath:  filepath.Join(filepath.Dir(bufferPath), "meter-state.json"),
		last:       map[string]sysx.Counters{},
		nextSeq:    map[int]uint64{},
	}
	m.load()
	return m
}

// Run samples counters until the context is cancelled.
func (m *Meter) Run(ctx context.Context, a *Agent) {
	interval := 10 * time.Second
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			m.save()
			return
		case <-t.C:
			m.sample(a)
			if cfg, ok := a.Config(); ok && cfg.SampleMs > 0 {
				if d := time.Duration(cfg.SampleMs) * time.Millisecond; d != interval {
					interval = d
					t.Reset(interval)
				}
			}
		}
	}
}

func (m *Meter) sample(a *Agent) {
	cfg, ok := a.Config()
	if !ok {
		return
	}
	now := time.Now()
	var fresh []proto.UsageDelta

	m.mu.Lock()
	for _, p := range cfg.Paths {
		if !p.Metered {
			continue
		}
		cur, err := sysx.ReadCounters(p.Iface)
		if err != nil {
			continue // interface absent; nothing to account for
		}
		prev, seen := m.last[p.Iface]
		m.last[p.Iface] = cur
		if !seen {
			continue // first sample only establishes the baseline
		}

		dBytes := cur.Bytes() - prev.Bytes()
		dPackets := cur.Packets() - prev.Packets()
		if dBytes < 0 || dPackets < 0 {
			// The interface was recreated or the machine rebooted. Treat the
			// current reading as a new baseline rather than logging a negative
			// or absurd delta, which would corrupt the month's ledger.
			m.log.Info("counter reset detected, rebaselining", "iface", p.Iface)
			continue
		}
		if dBytes == 0 && dPackets == 0 {
			continue
		}
		seq := m.nextSeq[p.ID] + 1
		m.nextSeq[p.ID] = seq
		fresh = append(fresh, proto.UsageDelta{
			PathID:   p.ID,
			Bytes:    dBytes,
			Packets:  dPackets,
			AtUnix:   now.Unix(),
			Sequence: seq,
		})
	}
	if len(fresh) > 0 {
		m.pending = append(m.pending, fresh...)
		if len(m.pending) > maxBuffered {
			dropped := len(m.pending) - maxBuffered
			m.pending = m.pending[dropped:]
			m.log.Warn("usage buffer full, oldest deltas dropped", "dropped", dropped)
		}
	}
	m.mu.Unlock()

	if len(fresh) > 0 {
		m.persist()
	}
	m.save()
}

// Pending returns a copy of the buffered deltas awaiting delivery.
func (m *Meter) Pending() []proto.UsageDelta {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]proto.UsageDelta, len(m.pending))
	copy(out, m.pending)
	return out
}

// PendingBatch returns a copy of at most n buffered deltas, with no one path
// allowed more than its share of them.
//
// Order is preserved *within* a path, which is what the frontend's watermark
// requires: applyUsage takes a per-path high-water mark and skips anything not
// strictly newer. The slice as a whole is not in buffer order, because the
// share is taken per path - do not read it as a chronological stream. It used
// to say "oldest first" and that is no longer the guarantee.
//
// The share is the whole point and a flat prefix of the buffer was the bug.
// `pending` is one FIFO across every path, so a path whose deltas the frontend
// will not accept - a sequence it refuses, a path id it drops, anything that is
// never acked - accumulates at the front of it at one per sample interval.
// After about five hundred samples the oldest n are all that path's, every
// batch from then on consists solely of deltas that will be refused again, and
// no delta for *any* path reaches the ledger until maxBuffered evicts them days
// later. Every metered byte in that window is lost and no quota can trip.
//
// The frontend's refusals are per-path and deliberate: a stalled path with an
// Error beside it is meant to be recoverable. This is what keeps that stall
// from being deployment-wide.
func (m *Meter) PendingBatch(n int) []proto.UsageDelta {
	m.mu.Lock()
	defer m.mu.Unlock()
	if n > len(m.pending) {
		n = len(m.pending)
	}
	// <= rather than ==, because the multi-path branch below reaches
	// make([]proto.UsageDelta, 0, n), and a negative capacity panics on the
	// report goroutine. The only caller passes a constant today; a guard that
	// reads as covering this and stops one notch short is worse than no guard.
	if n <= 0 {
		return nil
	}

	// What this costs, stated once and plainly, because three earlier versions
	// of this comment each got it wrong in the optimistic direction.
	//
	// Three passes over the buffer at worst: one to learn which paths are in it,
	// then the share pass and the fill pass, each of which stops once it has n.
	// At maxBuffered that is 150,000 iterations of an integer compare every ten
	// seconds, under a lock sample and AckApplied also want, which measures in
	// the low hundreds of microseconds. It could be made O(1) by carrying a
	// live per-path count on the Meter, and that is not worth another invariant
	// for sample, AckApplied and load to keep in step - the same trade
	// quota.EvaluateIn was deleted over, at a similar size.
	//
	// The single-path branch is the rare case, not the ordinary one. The shipped
	// configuration meters two paths and Meter.sample emits a delta for every
	// metered path with traffic in the same pass, so an ordinary deployment
	// always has at least two ids buffered and always takes the shared branch.
	// The branch is for a site with one metered link, or a backlog that has
	// drained to one path.
	paths := map[int]bool{}
	for _, d := range m.pending {
		paths[d.PathID] = true
	}
	if len(paths) == 1 {
		out := make([]proto.UsageDelta, n)
		copy(out, m.pending[:n])
		return out
	}
	share := n / len(paths)
	if share < 1 {
		share = 1
	}

	// Two passes. The first takes up to an equal share from each path, in
	// buffer order, which is what guarantees a stuck path cannot crowd the
	// others out. The second fills whatever is left from the front, so a
	// backlog that is mostly one path still drains at close to the full rate.
	//
	// Pass one always takes a contiguous prefix of each path's subsequence, so
	// "already taken" is one index per path rather than a bitmap over the whole
	// buffer: pass two skips an entry when its path's counter has not yet
	// reached it.
	out := make([]proto.UsageDelta, 0, n)
	taken := make(map[int]int, len(paths))
	for _, d := range m.pending {
		if len(out) == n {
			break
		}
		if taken[d.PathID] >= share {
			continue
		}
		taken[d.PathID]++
		out = append(out, d)
	}
	seen := make(map[int]int, len(paths))
	for _, d := range m.pending {
		if len(out) == n {
			break
		}
		seen[d.PathID]++
		if seen[d.PathID] <= taken[d.PathID] {
			continue
		}
		out = append(out, d)
	}
	return out
}

// AckApplied drops every buffered delta the frontend's ack covers: for each
// path named, everything at or below the acked sequence.
//
// Driven by the frontend's usage_ack frame rather than by the send succeeding,
// because a successful write only means the bytes reached the local send
// buffer. The connection dying right there - which is what a failover does to
// it - would lose the batch in flight, and it used to: the buffered copy was
// dropped the moment the write returned, so every disconnect silently lost the
// usage it coincided with, always in the direction of undercounting a metered
// path. A delta the ack does not cover stays buffered and is resent.
func (m *Meter) AckApplied(seqs map[int]uint64) {
	m.mu.Lock()
	kept := m.pending[:0]
	for _, d := range m.pending {
		if upTo, ok := seqs[d.PathID]; ok && d.Sequence <= upTo {
			continue
		}
		kept = append(kept, d)
	}
	changed := len(kept) != len(m.pending)
	m.pending = kept
	m.mu.Unlock()
	if changed {
		m.persist()
	}
}

// persist writes the pending deltas out as JSON lines, one delta per line -
// which is both what the file's name promises and the format that stays
// readable when somebody opens it mid-incident to see what has not been
// delivered yet.
func (m *Meter) persist() {
	m.persistMu.Lock()
	defer m.persistMu.Unlock()

	m.mu.Lock()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	var err error
	for _, d := range m.pending {
		if err = enc.Encode(d); err != nil {
			break
		}
	}
	m.mu.Unlock()
	if err != nil {
		return
	}
	writeAtomic(m.log, m.bufferPath, buf.Bytes())
}

func (m *Meter) save() {
	m.mu.Lock()
	st := meterState{Last: map[string]sysx.Counters{}, NextSeq: map[int]uint64{}}
	for k, v := range m.last {
		st.Last[k] = v
	}
	for k, v := range m.nextSeq {
		st.NextSeq[k] = v
	}
	m.mu.Unlock()

	raw, err := json.Marshal(st)
	if err != nil {
		return
	}
	writeAtomic(m.log, m.statePath, raw)
}

func (m *Meter) load() {
	if raw, err := os.ReadFile(m.bufferPath); err == nil {
		pending, err := decodeBuffer(raw)
		if err != nil {
			// Whatever decoded ahead of the bad line is kept. Discarding the
			// lot because the tail was torn threw away exactly the usage this
			// buffer exists to protect - the deltas accrued while the frontend
			// was unreachable.
			m.log.Warn("usage buffer damaged, keeping the deltas that decoded",
				"kept", len(pending), "err", err)
		}
		if len(pending) > 0 {
			m.pending = pending
			m.log.Info("restored buffered usage deltas", "count", len(pending))
		}
	}
	if raw, err := os.ReadFile(m.statePath); err == nil {
		var st meterState
		if err := json.Unmarshal(raw, &st); err == nil {
			if st.Last != nil {
				m.last = st.Last
			}
			if st.NextSeq != nil {
				m.nextSeq = st.NextSeq
			}
		}
	}
}

// decodeBuffer reads a buffer file in either format it has ever had: JSON
// lines, or the single JSON array older builds wrote despite the .jsonl name.
// The legacy branch exists so an upgrade does not discard deltas buffered by
// the build it replaced - which would lose usage at exactly the moment the
// buffer was doing its job.
//
// On a decode error it returns the deltas that decoded cleanly ahead of it,
// alongside the error. A torn final line - a crash mid-write is enough - must
// not cost the whole file: everything before it is intact and is the usage the
// buffer was keeping safe.
func decodeBuffer(raw []byte) ([]proto.UsageDelta, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, nil
	}
	if trimmed[0] == '[' {
		var pending []proto.UsageDelta
		err := json.Unmarshal(trimmed, &pending)
		return pending, err
	}
	var pending []proto.UsageDelta
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	for dec.More() {
		var d proto.UsageDelta
		if err := dec.Decode(&d); err != nil {
			return pending, err
		}
		pending = append(pending, d)
	}
	return pending, nil
}

func writeAtomic(log *slog.Logger, path string, data []byte) {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		log.Warn("cannot write state file", "path", path, "err", err)
		return
	}
	_, werr := f.Write(data)
	// Synced before the rename. The rename is metadata and can survive a power
	// loss that the data behind it did not, replacing the last good file with a
	// truncated one - the one corruption "atomic" was supposed to rule out.
	serr := f.Sync()
	if cerr := f.Close(); werr == nil && serr == nil {
		werr = cerr
	}
	if werr != nil || serr != nil {
		log.Warn("cannot write state file", "path", path, "err", cmp.Or(werr, serr))
		_ = os.Remove(tmp)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Warn("cannot replace state file", "path", path, "err", err)
	}
}
