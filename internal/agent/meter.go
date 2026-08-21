package agent

import (
	"bytes"
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
		if err == nil && len(pending) > 0 {
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
			return nil, err
		}
		pending = append(pending, d)
	}
	return pending, nil
}

func writeAtomic(log *slog.Logger, path string, data []byte) {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		log.Warn("cannot write state file", "path", path, "err", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Warn("cannot replace state file", "path", path, "err", err)
	}
}
