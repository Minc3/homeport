// Package proto defines the wire formats spoken between the frontend and
// backend agents: an authenticated UDP probe used to measure each path
// end-to-end, and a JSON control channel for config push and usage reporting.
package proto

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
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
//
// 2 carries the domain-separated MACs. Before it, the probe MAC and the
// control channel's challenge response were both a bare HMAC of the message
// under the same key, with nothing to say which was which - so anything that
// would sign a challenge would also sign a probe body, and the challenge
// nonce is chosen by the peer. See probeLabel.
const Version uint8 = 2

var magic = [4]byte{'F', 'O', 'V', 'R'}

// ErrBadProbe covers every rejection reason bar one. Callers only ever drop
// the packet, so distinguishing them would only help an attacker.
var ErrBadProbe = errors.New("proto: malformed or unauthenticated probe")

// ErrProbeVersion is the exception, and it is separated for the operator
// rather than for the code: a version byte is checked before the MAC and tells
// an attacker nothing they did not already choose, while a host part-way
// through an upgrade otherwise reports "check that the shared secret is
// identical", which is the wrong thing to go and look at.
var ErrProbeVersion = errors.New("proto: probe from a different wire version")

// probeLabel and the two control labels are the domain separation between
// everything this key authenticates. They are the fix for a concrete forgery:
// the probe MAC covers the first 50 bytes of the packet, the control handshake
// MAC covered a nonce string the peer supplied, and neither said which it was
// - so a peer that could get a challenge answered could ask for a MAC over a
// probe body instead and be handed a valid probe. Every byte of a probe body
// is reachable from a JSON string, the decision sequence included, so the
// forged probe could pin the backend's reply path for good.
//
// Any new use of this key gets its own label, and no label is ever a prefix of
// another.
const (
	probeLabel      = "homeport-probe-v2"
	controlLabel    = "homeport-control-client-v2"
	controlAckLabel = "homeport-control-server-v2"
	sessionLabel    = "homeport-control-session-v2"
	frameToServer   = "homeport-frame-to-server-v2"
	frameToClient   = "homeport-frame-to-client-v2"
)

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
	copy(b[offMAC:], probeMAC(psk, b[:offMAC]))
	return b
}

// probeMAC authenticates a probe body, truncated to the 16 bytes the packet
// carries. The label is what stops the control handshake signing one; see
// probeLabel.
func probeMAC(psk, body []byte) []byte {
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(probeLabel))
	mac.Write(body)
	return mac.Sum(nil)[:16]
}

// Unmarshal verifies and decodes a probe. Anything that fails authentication
// is indistinguishable from noise, so nobody can forge path health.
func Unmarshal(b []byte, psk []byte) (*Probe, error) {
	if len(b) != ProbeSize {
		return nil, ErrBadProbe
	}
	if string(b[offMagic:offMagic+4]) != string(magic[:]) {
		return nil, ErrBadProbe
	}
	if b[offVersion] != Version {
		return nil, ErrProbeVersion
	}
	if !hmac.Equal(probeMAC(psk, b[:offMAC]), b[offMAC:ProbeSize]) {
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
	MsgAuthAck   = "auth_ack"  // frontend -> backend, the frontend's half of the proof
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

// Envelope wraps every control message. Frames are newline-delimited JSON.
//
// There is no second layer of encryption, deliberately: nothing on this channel
// is a secret, and for the backend it runs inside WireGuard anyway. There is a
// second layer of *authentication*, on every frame after the handshake, and
// that is not the same thing. Proving who the peer is at connect time settles
// nothing about who is sending the frames afterwards - an attacker positioned
// on the wire can let both ends authenticate each other and then write down the
// same socket. That position is real for a linker, whose first hop to the
// frontend is plaintext TCP on a LAN. See Session.
type Envelope struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`

	// Seq and MAC are set on every frame after the handshake and on none of
	// the frames within it, which have their own proofs and no session key to
	// use yet.
	Seq uint64 `json:"seq,omitempty"`
	MAC string `json:"mac,omitempty"`
}

// Challenge is sent by the frontend as soon as a connection is accepted.
type Challenge struct {
	Nonce string `json:"nonce"`
}

// Auth is the dialling agent's half of the handshake: a MAC over both nonces,
// and its own nonce for the frontend to answer in turn.
//
// The handshake authenticates both ends. It used to authenticate only the
// dialler, on the reasoning that the channel runs inside WireGuard - which
// holds for the backend, whose connection enters the tunnel on its own host,
// and does not hold for a linker. A linker reaches the frontend by routing
// through the backend as an ordinary LAN neighbour, so the first hop is
// plaintext TCP on somebody's office network. Anything on that segment could
// answer in the frontend's place, and what it would then be believed about is
// the egress networks: rules this agent loads into nftables as root.
//
// This settles who the peer is and nothing more. Who is writing frames once the
// handshake is done is a separate question with a separate answer, because the
// same position that allows impersonation also allows relaying: see Session,
// which is what the two nonces here are ultimately for.
type Auth struct {
	MAC   string `json:"mac"`
	Nonce string `json:"nonce,omitempty"`
}

// AuthAck is the frontend's half: a MAC over the same two nonces under a
// different label, so neither side's proof can be replayed as the other's.
type AuthAck struct {
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

// SignAuth computes the dialling agent's proof: a MAC over both nonces.
//
// Both, so that neither end can steer the whole preimage. The frontend picks
// the first and the dialler the second, so a MAC obtained from either side is
// bound to a transcript the other contributed to and cannot be replayed into a
// session it did not take part in.
func SignAuth(psk []byte, serverNonce, clientNonce string) (string, error) {
	return controlMAC(psk, controlLabel, serverNonce, clientNonce)
}

// VerifyAuth is a constant-time check of a dialling agent's proof.
func VerifyAuth(psk []byte, serverNonce, clientNonce, got string) bool {
	return verifyControl(psk, controlLabel, serverNonce, clientNonce, got)
}

// SignAuthAck computes the frontend's proof, under its own label.
func SignAuthAck(psk []byte, serverNonce, clientNonce string) (string, error) {
	return controlMAC(psk, controlAckLabel, serverNonce, clientNonce)
}

// VerifyAuthAck is a constant-time check of the frontend's proof. A dialling
// agent calls this before it will act on anything the peer sends it.
func VerifyAuthAck(psk []byte, serverNonce, clientNonce, got string) bool {
	return verifyControl(psk, controlAckLabel, serverNonce, clientNonce, got)
}

// controlMAC authenticates one direction of the handshake.
//
// Both nonces are checked for shape before either goes near the key, which is
// belt and braces beside the label above: with the labels in place a control
// MAC can no longer be a probe MAC whatever the nonce says, and refusing a
// preimage the peer composed freely means there is no oracle to reason about
// in the first place. The nonces are also length-prefixed by being fixed
// length, so no pair of them can be concatenated two ways.
func controlMAC(psk []byte, label, serverNonce, clientNonce string) (string, error) {
	if !validNonce(serverNonce) || !validNonce(clientNonce) {
		return "", ErrBadNonce
	}
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(label))
	mac.Write([]byte(serverNonce))
	mac.Write([]byte(clientNonce))
	return hexEncode(mac.Sum(nil)), nil
}

func verifyControl(psk []byte, label, serverNonce, clientNonce, got string) bool {
	want, err := controlMAC(psk, label, serverNonce, clientNonce)
	if err != nil {
		return false
	}
	return hmac.Equal([]byte(want), []byte(got))
}

// ErrBadNonce is returned when a nonce is not the shape RandomNonce produces.
var ErrBadNonce = errors.New("proto: challenge nonce is not " +
	"a 32-character lowercase hex string")

// nonceLen is the length of the hex string RandomNonce returns.
const nonceLen = 32

// validNonce reports whether a nonce is exactly what RandomNonce produces.
func validNonce(s string) bool {
	if len(s) != nonceLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// RandomNonce returns a hex nonce for the auth handshake. Both ends send one.
func RandomNonce() string {
	var b [nonceLen / 2]byte
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

// ---------------------------------------------------------------------------
// Session-authenticated frames
// ---------------------------------------------------------------------------

// Session authenticates every frame exchanged after the handshake.
//
// The handshake proves who the peer is. On its own that settles nothing about
// who is sending the frames that follow, and the difference is the whole
// attack: someone on the wire between the two ends can relay the handshake
// untouched, let both sides satisfy each other, and then write frames of their
// own down a connection both ends believe is authenticated. Relaying is exactly
// what an ARP-spoofing neighbour can do, and a linker's first hop to the
// frontend is plaintext TCP on a LAN, so this is not a theoretical position.
//
// The key is derived from the pre-shared key and *both* nonces. A relay cannot
// change either one without breaking the handshake MACs, so it is forced to
// pass the same transcript to both ends - which means both ends derive the same
// session key and the relay, holding no pre-shared key, derives nothing. It is
// reduced to passing frames through or dropping them, and dropping them is what
// cutting the cable already did.
//
// Each direction has its own label and its own counter, so a frame cannot be
// reflected back at its sender, replayed, or reordered. The counter is checked
// exactly rather than as a floor: the transport is TCP, so a gap is not late
// delivery, it is a frame that somebody removed.
type Session struct {
	mu  sync.Mutex
	key []byte

	txLabel string
	rxLabel string
	tx      uint64
	rx      uint64
}

// NewSession derives the session key from the completed handshake. dialler
// picks which direction this end writes in: the backend and a linker dial, the
// frontend accepts.
func NewSession(psk []byte, serverNonce, clientNonce string, dialler bool) (*Session, error) {
	if !validNonce(serverNonce) || !validNonce(clientNonce) {
		return nil, ErrBadNonce
	}
	mac := hmac.New(sha256.New, psk)
	mac.Write([]byte(sessionLabel))
	mac.Write([]byte(serverNonce))
	mac.Write([]byte(clientNonce))
	s := &Session{key: mac.Sum(nil), txLabel: frameToClient, rxLabel: frameToServer}
	if dialler {
		s.txLabel, s.rxLabel = frameToServer, frameToClient
	}
	return s, nil
}

// WriteDeadline is how long one control frame gets to reach the wire.
const WriteDeadline = 10 * time.Second

// deadlineWriter is a connection that can bound a write. Session.WriteFrame
// sets the deadline itself when handed one, which is why it takes an interface
// rather than a net.Conn: the tests write into a buffer.
type deadlineWriter interface {
	SetWriteDeadline(time.Time) error
}

// WriteFrame writes one authenticated envelope.
//
// Safe to call from several goroutines: both ends do, and the lock is held
// across the counter and the write together, because a sequence number that
// reached the wire out of order would be rejected as tampering by a peer that
// is checking it exactly.
//
// The write deadline is set here, under that lock, rather than by the caller
// before it. Serialising the writes made caller-side deadlines wrong in two
// ways at once: a goroutine that set its deadline and then waited out another's
// stalled write arrived at the socket with the time already spent and failed
// instantly, and two goroutines setting a deadline on one connection were
// overwriting each other's anyway, because a deadline belongs to the connection
// and not to the write. Neither is worth asking every call site to remember.
func (s *Session) WriteFrame(w io.Writer, typ string, payload any) error {
	env := Envelope{Type: typ}
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		env.Data = raw
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	env.Seq = s.tx
	env.MAC = frameMAC(s.key, s.txLabel, env.Seq, env.Type, env.Data)
	line, err := json.Marshal(env)
	if err != nil {
		return err
	}
	if c, ok := w.(deadlineWriter); ok {
		_ = c.SetWriteDeadline(time.Now().Add(WriteDeadline))
	}
	if _, err := w.Write(append(line, '\n')); err != nil {
		return err
	}
	s.tx++
	return nil
}

// ErrBadFrame is what an unauthenticated, replayed or reordered frame gets.
// Like ErrBadProbe it does not say which, because the caller only ever drops
// the connection.
var ErrBadFrame = errors.New("proto: unauthenticated control frame")

// ReadFrame reads one envelope and authenticates it against this session.
func (s *Session) ReadFrame(r *bufio.Reader) (Envelope, error) {
	line, err := r.ReadBytes('\n')
	if err != nil {
		return Envelope{}, err
	}
	var env Envelope
	if err := json.Unmarshal(line, &env); err != nil {
		return Envelope{}, fmt.Errorf("bad control frame: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if env.Seq != s.rx {
		return Envelope{}, ErrBadFrame
	}
	want := frameMAC(s.key, s.rxLabel, env.Seq, env.Type, env.Data)
	if !hmac.Equal([]byte(want), []byte(env.MAC)) {
		return Envelope{}, ErrBadFrame
	}
	s.rx++
	return env, nil
}

// frameMAC authenticates one frame's direction, position, type and payload.
//
// Every variable-length part is length-prefixed, so no two different frames can
// present the same bytes to the MAC - without that, a type and a payload could
// be shifted across the boundary between them.
func frameMAC(key []byte, label string, seq uint64, typ string, data []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(label))
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], seq)
	mac.Write(n[:])
	binary.BigEndian.PutUint64(n[:], uint64(len(typ)))
	mac.Write(n[:])
	mac.Write([]byte(typ))
	binary.BigEndian.PutUint64(n[:], uint64(len(data)))
	mac.Write(n[:])
	mac.Write(data)
	return hexEncode(mac.Sum(nil)[:16])
}
