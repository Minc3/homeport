// Package proto defines the wire formats spoken between the frontend and
// backend agents: an authenticated UDP probe used to measure each path
// end-to-end, and a JSON control channel for config push and usage reporting.
package proto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"time"
)

// Probe packet layout. Fixed size so there is nothing to parse defensively.
const (
	ProbeSize = 66

	offMagic       = 0  // 4 bytes
	offVersion     = 4  // 1
	offType        = 5  // 1
	offPathID      = 6  // 2
	offSeq         = 8  // 8
	offTxNanos     = 16 // 8
	offEchoNanos   = 24 // 8
	offActivePath  = 32 // 2
	offDecisionSeq = 34 // 8
	offNonce       = 42 // 8
	offMAC         = 50 // 16
)

// Message types carried in the probe packet.
const (
	TypeProbe uint8 = 1
	TypeReply uint8 = 2
)

// Version is bumped only on incompatible wire changes.
const Version uint8 = 1

var magic = [4]byte{'F', 'O', 'V', 'R'}

// ErrBadProbe covers every rejection reason. Callers only ever drop the
// packet, so distinguishing them would only help an attacker.
var ErrBadProbe = errors.New("proto: malformed or unauthenticated probe")

// Probe is one path measurement packet. The frontend piggybacks its current
// routing decision on every probe, which is what lets the backend learn the
// active path over whichever tunnel is still delivering packets. The TCP
// control channel would have to travel over the path that just died.
type Probe struct {
	Type        uint8
	PathID      uint16
	Seq         uint64
	TxNanos     int64  // frontend send time, echoed unchanged
	EchoNanos   int64  // backend receive time, for one-way delay estimates
	ActivePath  uint16 // frontend's current decision
	DecisionSeq uint64 // monotonic, so reordered probes cannot rewind the decision
	Nonce       uint64
}

// Marshal serialises and authenticates the probe with the pre-shared key.
func (p *Probe) Marshal(psk []byte) []byte {
	b := make([]byte, ProbeSize)
	copy(b[offMagic:], magic[:])
	b[offVersion] = Version
	b[offType] = p.Type
	binary.BigEndian.PutUint16(b[offPathID:], p.PathID)
	binary.BigEndian.PutUint64(b[offSeq:], p.Seq)
	binary.BigEndian.PutUint64(b[offTxNanos:], uint64(p.TxNanos))
	binary.BigEndian.PutUint64(b[offEchoNanos:], uint64(p.EchoNanos))
	binary.BigEndian.PutUint16(b[offActivePath:], p.ActivePath)
	binary.BigEndian.PutUint64(b[offDecisionSeq:], p.DecisionSeq)
	binary.BigEndian.PutUint64(b[offNonce:], p.Nonce)
	mac := hmac.New(sha256.New, psk)
	mac.Write(b[:offMAC])
	copy(b[offMAC:], mac.Sum(nil)[:16])
	return b
}

// Unmarshal verifies and decodes a probe. Anything that fails authentication
// is indistinguishable from noise, so nobody can forge path health.
func Unmarshal(b []byte, psk []byte) (*Probe, error) {
	if len(b) != ProbeSize {
		return nil, ErrBadProbe
	}
	if string(b[offMagic:offMagic+4]) != string(magic[:]) || b[offVersion] != Version {
		return nil, ErrBadProbe
	}
	mac := hmac.New(sha256.New, psk)
	mac.Write(b[:offMAC])
	if !hmac.Equal(mac.Sum(nil)[:16], b[offMAC:ProbeSize]) {
		return nil, ErrBadProbe
	}
	return &Probe{
		Type:        b[offType],
		PathID:      binary.BigEndian.Uint16(b[offPathID:]),
		Seq:         binary.BigEndian.Uint64(b[offSeq:]),
		TxNanos:     int64(binary.BigEndian.Uint64(b[offTxNanos:])),
		EchoNanos:   int64(binary.BigEndian.Uint64(b[offEchoNanos:])),
		ActivePath:  binary.BigEndian.Uint16(b[offActivePath:]),
		DecisionSeq: binary.BigEndian.Uint64(b[offDecisionSeq:]),
		Nonce:       binary.BigEndian.Uint64(b[offNonce:]),
	}, nil
}

// NewNonce returns a random nonce for a probe.
func NewNonce() uint64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint64(b[:])
}

// ---------------------------------------------------------------------------
// Control channel
// ---------------------------------------------------------------------------

// Control message types. The backend dials the frontend, because CGNAT means
// the backend is the only side that can initiate anything.
const (
	MsgChallenge = "challenge" // frontend -> backend
	MsgAuth      = "auth"      // backend  -> frontend
	MsgHello     = "hello"     // backend  -> frontend, after auth
	MsgConfig    = "config"    // frontend -> backend, the pushed configuration
	MsgUsage     = "usage"     // backend  -> frontend, buffered counter deltas
	MsgUsageAck  = "usage_ack" // frontend -> backend, sequences safely in the ledger
	MsgLink      = "link"      // backend  -> frontend, WireGuard handshake ages
	MsgPing      = "ping"
	MsgPong      = "pong"

	// MsgLinkerConfig is the frontend's push to a linker. A linker's subset is
	// far smaller than the backend's: it makes no decisions and terminates no
	// tunnels, so it needs no paths, no mode and no sample interval.
	MsgLinkerConfig = "linker_config" // frontend -> linker
)

// Envelope wraps every control message. Frames are newline-delimited JSON;
// the channel already runs inside WireGuard, so there is no second layer of
// encryption, only authentication of the peer.
type Envelope struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

// Challenge is sent by the frontend as soon as a connection is accepted.
type Challenge struct {
	Nonce string `json:"nonce"`
}

// Auth is the backend's HMAC of the challenge nonce under the pre-shared key.
type Auth struct {
	MAC string `json:"mac"`
}

// Hello identifies a connecting agent and its build.
//
// Role and OverlayIP are empty from a backend, which is the only thing that
// connected before linkers existed - so an older backend is still understood
// exactly as it was, and an empty role means "backend".
type Hello struct {
	Version  string `json:"version"`
	Hostname string `json:"hostname"`

	// Role is "linker" from a linker. The frontend uses it to decide which
	// half of the control protocol this connection speaks.
	Role string `json:"role,omitempty"`

	// OverlayIP is which linker this is. It is checked against the configured
	// list rather than trusted: the shared secret proves the peer belongs to
	// this deployment, not that it is entitled to any particular address, and
	// a linker that could name itself could take over another's traffic.
	OverlayIP string `json:"overlay_ip,omitempty"`

	// Table is the routing table the linker actually used. It has to come from
	// that host's own bootstrap file, because it names the rule carrying this
	// connection - so it is the one setting that can silently disagree with the
	// portal, and reporting it is what makes the disagreement visible.
	Table int `json:"table,omitempty"`
}

// LinkerConfig is everything a linker is told.
//
// Only the networks it should pull onto the tunnel. It is deliberately not
// sent the active path, the tunnels or the mode: a linker makes no decisions,
// and the backend already tracks which tunnel is carrying traffic.
type LinkerConfig struct {
	// EgressCIDRs are the container networks on this host whose traffic should
	// leave by the frontend's public address rather than the local one.
	EgressCIDRs []string `json:"egress_cidrs,omitempty"`
}

// LinkerRoute tells the backend how to reach one extra host: the overlay
// address the frontend publishes to, and the neighbour on the backend's own
// network that holds it.
//
// This travels down rather than being discovered because the linker agent has
// no control channel to announce itself with. It is the frontend's job to know
// the topology, and the backend's only to install what it is told.
type LinkerRoute struct {
	OverlayIP string `json:"overlay_ip"`
	LanIP     string `json:"lan_ip"`
}

// UsageDelta is one metering sample for one path. The backend buffers these
// on disk when the control channel is down, so an outage does not silently
// lose the LTE usage it caused.
type UsageDelta struct {
	PathID   int    `json:"path_id"`
	Bytes    int64  `json:"bytes"`   // inner payload bytes, both directions
	Packets  int64  `json:"packets"` // used to add encapsulation overhead
	AtUnix   int64  `json:"at"`
	Sequence uint64 `json:"seq"` // dedupe on replay after reconnect
}

// Usage is a batch of deltas.
type Usage struct {
	Deltas []UsageDelta `json:"deltas"`
}

// UsageAck reports, per path, the highest delta sequence the frontend has
// durably recorded. The backend keeps a delta buffered until an ack covers it.
//
// It exists because a successful TCP write is not delivery: the bytes sit in
// the local send buffer, and the connection dying right there - which is what
// a failover does to it - loses them. The backend used to drop its buffered
// copy the moment the write returned, so the batch in flight at every
// disconnect was silently gone from the ledger, and the loss always fell on
// exactly the usage a failover causes. Acking what was *applied* rather than
// what was sent closes that: anything unacked is resent on the next tick, and
// the per-path sequence dedupe makes the overlap free.
type UsageAck struct {
	Seqs map[int]uint64 `json:"seqs"`
}

// LinkInfo is the backend's local view of a tunnel. This is a corroborating
// signal for the portal only; the routing decision is always made from
// end-to-end probe results.
type LinkInfo struct {
	PathID          int     `json:"path_id"`
	HandshakeAgeSec float64 `json:"handshake_age_sec"`
	Exists          bool    `json:"exists"`
}

// Link is a batch of link reports.
type Link struct {
	Links []LinkInfo `json:"links"`
}

// BackendConfig is the subset of configuration the backend needs. It is
// cached to disk so the backend keeps working correctly if the frontend
// becomes unreachable.
type BackendConfig struct {
	Overlay  OverlayInfo `json:"overlay"`
	Paths    []PathInfo  `json:"paths"`
	Mode     string      `json:"mode"`
	SampleMs int         `json:"sample_ms"`

	// Linkers are the extra hosts the backend must forward to. Empty on a
	// site with none, which is what keeps that site's routing identical to a
	// build that never had the feature.
	Linkers []LinkerRoute `json:"linkers,omitempty"`

	// EgressCIDRs are the backend-side networks whose outbound traffic leaves
	// through the frontend. Only the enabled ones are sent; the backend has no
	// opinion about them beyond generating rules.
	EgressCIDRs []string `json:"egress_cidrs,omitempty"`
}

// OverlayInfo mirrors the overlay addressing.
type OverlayInfo struct {
	FrontendIP string `json:"frontend_ip"`
	BackendIP  string `json:"backend_ip"`
	Device     string `json:"device"`

	// Subnet is the overlay range, sent only where a site runs linker agents.
	// Empty is the ordinary case and means the backend is the only host at this
	// end, exactly as before this field existed.
	Subnet string `json:"subnet,omitempty"`
}

// PathInfo is what the backend needs to know about one tunnel: which
// interface it is, and the table and mark used to steer probe replies back
// out the same tunnel the probe arrived on.
type PathInfo struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Iface   string `json:"iface"`
	Table   int    `json:"table"`
	Mark    int    `json:"mark"`
	Metered bool   `json:"metered"`

	// ShapeMbit is the rate the backend may put into this tunnel - the house's
	// upload figure. Only this direction is sent: the other one governs the
	// frontend's own queue and is none of the backend's business. Zero, the
	// value every existing site has, means no shaping and no tc command.
	ShapeMbit float64 `json:"shape_mbit,omitempty"`
}

// SignChallenge computes the expected auth MAC for a challenge nonce.
func SignChallenge(psk []byte, nonce string) string {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(nonce))
	return hexEncode(mac.Sum(nil))
}

// VerifyChallenge is a constant-time comparison of a received auth MAC.
func VerifyChallenge(psk []byte, nonce, got string) bool {
	want := SignChallenge(psk, nonce)
	return hmac.Equal([]byte(want), []byte(got))
}

// RandomNonce returns a hex nonce for the auth challenge.
func RandomNonce() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hexEncode(b[:])
}

const hexDigits = "0123456789abcdef"

func hexEncode(b []byte) string {
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexDigits[c>>4]
		out[i*2+1] = hexDigits[c&0x0f]
	}
	return string(out)
}

// WriteFrame writes one newline-delimited JSON envelope.
func WriteFrame(w io.Writer, typ string, payload any) error {
	env := Envelope{Type: typ}
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		env.Data = raw
	}
	line, err := json.Marshal(env)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	_, err = w.Write(line)
	return err
}

// DecodeInto unmarshals an envelope's payload.
func DecodeInto(env Envelope, out any) error {
	if len(env.Data) == 0 {
		return nil
	}
	return json.Unmarshal(env.Data, out)
}

// KeepaliveInterval is how often the control channel exchanges ping/pong.
const KeepaliveInterval = 15 * time.Second

// ControlDeadline is how long a silent control channel is tolerated.
const ControlDeadline = 45 * time.Second
