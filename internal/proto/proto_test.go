package proto

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

var psk = []byte("a shared secret that is exactly long enough")

func TestProbeRoundTrip(t *testing.T) {
	in := &Probe{
		Type: TypeProbe, PathID: 2, Seq: 12345,
		TxNanos: 1700000000000000000, EchoNanos: 1700000000000000001,
		ActivePath: 3, DecisionSeq: 99, Nonce: NewNonce(),
	}
	out, err := Unmarshal(in.Marshal(psk), psk)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if *out != *in {
		t.Errorf("round trip changed the probe:\n got %+v\nwant %+v", out, in)
	}
}

func TestProbeRejectsWrongKey(t *testing.T) {
	pkt := (&Probe{Type: TypeProbe, PathID: 1, Seq: 1}).Marshal(psk)
	if _, err := Unmarshal(pkt, []byte("a different secret")); err == nil {
		t.Error("a probe signed with another key must not authenticate")
	}
}

func TestProbeRejectsTampering(t *testing.T) {
	// Path health drives routing, so a forged probe would be a way to steer
	// traffic. Every field is covered by the MAC.
	pkt := (&Probe{Type: TypeProbe, PathID: 1, Seq: 1, ActivePath: 1, DecisionSeq: 5}).Marshal(psk)
	for _, off := range []int{offPathID, offSeq, offActivePath, offDecisionSeq} {
		tampered := bytes.Clone(pkt)
		tampered[off] ^= 0xff
		if _, err := Unmarshal(tampered, psk); err == nil {
			t.Errorf("tampering at offset %d was not detected", off)
		}
	}
}

func TestProbeRejectsWrongSize(t *testing.T) {
	pkt := (&Probe{Type: TypeProbe}).Marshal(psk)
	if _, err := Unmarshal(pkt[:len(pkt)-1], psk); err == nil {
		t.Error("a truncated probe must be rejected")
	}
	if _, err := Unmarshal(append(pkt, 0), psk); err == nil {
		t.Error("an over-long probe must be rejected")
	}
}

func TestProbeRejectsGarbage(t *testing.T) {
	if _, err := Unmarshal(make([]byte, ProbeSize), psk); err == nil {
		t.Error("zeroed noise must not authenticate")
	}
}

func TestChallengeResponse(t *testing.T) {
	sn, cn := RandomNonce(), RandomNonce()

	mac := sign(t, sn, cn)
	if !VerifyAuth(psk, sn, cn, mac) {
		t.Error("a correctly signed challenge should verify")
	}
	if VerifyAuth([]byte("wrong"), sn, cn, mac) {
		t.Error("a challenge signed with the wrong key must not verify")
	}
	if VerifyAuth(psk, RandomNonce(), cn, mac) {
		t.Error("a response to a different challenge must not verify, or replays would work")
	}

	// Both nonces are in the transcript, so neither end can pin the preimage on
	// its own. Without the dialler's half, a peer posing as the frontend could
	// choose the whole thing.
	if VerifyAuth(psk, sn, RandomNonce(), mac) {
		t.Error("the dialler's own nonce must be part of what it signs")
	}
}

// Both ends of the control channel prove themselves, and their proofs are not
// interchangeable.
//
// The frontend used to be the only end that checked anything. That is safe for
// the backend, whose connection enters WireGuard on its own host, and is not
// safe for a linker: it reaches the frontend by routing through the backend as
// an ordinary LAN neighbour, so the first hop is plaintext TCP that anything on
// that segment can answer. What an impostor there would be believed about is
// the egress networks, which the linker loads into nftables as root.
//
// The two labels are what stop the cheapest attack on a two-sided handshake:
// reflecting the dialler's own proof back at it as the frontend's.
func TestHandshakeProofsAreNotInterchangeable(t *testing.T) {
	sn, cn := RandomNonce(), RandomNonce()
	client := sign(t, sn, cn)
	server := signAck(t, sn, cn)

	if client == server {
		t.Fatal("the two directions must not produce the same MAC")
	}
	if VerifyAuthAck(psk, sn, cn, client) {
		t.Error("reflecting the dialler's proof back must not pass as the frontend's")
	}
	if VerifyAuth(psk, sn, cn, server) {
		t.Error("the frontend's proof must not pass as a dialler's")
	}
	if !VerifyAuthAck(psk, sn, cn, server) {
		t.Error("the frontend's own proof should verify")
	}
}

// The handshake cannot be talked into signing a probe.
//
// Both MACs are taken under the same key. The control side used to sign a
// string the peer supplied, with no label to say what it was, and the probe MAC
// covers the first 50 bytes of the packet - every one of which is reachable
// from a JSON string, because a probe body can be composed entirely of bytes
// below 0x80, the decision sequence included. So a peer that could get a
// challenge answered could ask for a MAC over a probe body instead and be
// handed a valid probe, then use it to pin the backend's reply path to a tunnel
// of its choosing for good.
//
// Two things close it and this pins both, because either one alone would be
// enough and neither should be the one that gets removed.
func TestTheHandshakeCannotSignAProbe(t *testing.T) {
	body := (&Probe{
		Type: TypeProbe, PathID: 1, ActivePath: 2,
		DecisionSeq: 0x7f7f7f7f7f7f7f7f, // the highest a JSON string can carry
	}).Marshal(psk)[:offMAC]

	// One: a nonce that is not a nonce is refused before the key is touched, so
	// there is no chosen preimage to reason about at all.
	if _, err := SignAuth(psk, RandomNonce(), string(body)); !errors.Is(err, ErrBadNonce) {
		t.Fatalf("a probe body offered as a nonce must be refused, got %v", err)
	}

	// Two: the labels, so the two MACs are different functions whatever they are
	// asked to cover. Compared against the unlabelled HMAC this used to be.
	unlabelled := hmac.New(sha256.New, psk)
	unlabelled.Write(body)
	if hmac.Equal(probeMAC(psk, body), unlabelled.Sum(nil)[:16]) {
		t.Error("the probe MAC must not be a bare HMAC of the probe body")
	}

	sn, cn := RandomNonce(), RandomNonce()
	bare := hmac.New(sha256.New, psk)
	bare.Write([]byte(sn))
	bare.Write([]byte(cn))
	if sign(t, sn, cn) == hexEncode(bare.Sum(nil)) {
		t.Error("the handshake MAC must not be a bare HMAC of its transcript")
	}
}

// A nonce is refused unless it is exactly the shape RandomNonce produces.
func TestNonceShapeIsChecked(t *testing.T) {
	good := RandomNonce()
	for _, bad := range []string{"", "test-nonce", good[:31], good + "0", "ABCDEF0123456789abcdef0123456789"} {
		if _, err := SignAuth(psk, good, bad); !errors.Is(err, ErrBadNonce) {
			t.Errorf("nonce %q should have been refused, got %v", bad, err)
		}
		if _, err := SignAuth(psk, bad, good); !errors.Is(err, ErrBadNonce) {
			t.Errorf("challenge %q should have been refused, got %v", bad, err)
		}
		if VerifyAuth(psk, good, bad, "") || VerifyAuth(psk, bad, good, "") {
			t.Errorf("a MAC over the malformed nonce %q must never verify", bad)
		}
	}
}

// A probe from another wire version is told apart from an unauthenticated one,
// because the operator is sent to look at two different things: a staged
// upgrade against a mismatched shared secret.
func TestProbeVersionIsDistinguishable(t *testing.T) {
	pkt := (&Probe{Type: TypeProbe, PathID: 1}).Marshal(psk)
	pkt[offVersion] = Version + 1
	if _, err := Unmarshal(pkt, psk); !errors.Is(err, ErrProbeVersion) {
		t.Errorf("a version mismatch should say so, got %v", err)
	}
	if _, err := Unmarshal((&Probe{Type: TypeProbe}).Marshal([]byte("wrong")), psk); !errors.Is(err, ErrBadProbe) {
		t.Errorf("a bad MAC should stay indistinguishable noise, got %v", err)
	}
}

func sign(t *testing.T, serverNonce, clientNonce string) string {
	t.Helper()
	mac, err := SignAuth(psk, serverNonce, clientNonce)
	if err != nil {
		t.Fatalf("SignAuth: %v", err)
	}
	return mac
}

func signAck(t *testing.T, serverNonce, clientNonce string) string {
	t.Helper()
	mac, err := SignAuthAck(psk, serverNonce, clientNonce)
	if err != nil {
		t.Fatalf("SignAuthAck: %v", err)
	}
	return mac
}

func TestNonceIsRandom(t *testing.T) {
	if RandomNonce() == RandomNonce() {
		t.Error("challenge nonces must not repeat")
	}
}

// pair returns the two ends of one completed handshake.
func pair(t *testing.T, key []byte) (client, server *Session, sn, cn string) {
	t.Helper()
	sn, cn = RandomNonce(), RandomNonce()
	c, err := NewSession(key, sn, cn, true)
	if err != nil {
		t.Fatalf("client session: %v", err)
	}
	srv, err := NewSession(key, sn, cn, false)
	if err != nil {
		t.Fatalf("server session: %v", err)
	}
	return c, srv, sn, cn
}

func frame(t *testing.T, s *Session, typ string, payload any) *bufio.Reader {
	t.Helper()
	var buf bytes.Buffer
	if err := s.WriteFrame(&buf, typ, payload); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	return bufio.NewReader(&buf)
}

// The ordinary case, so the negatives below mean something.
func TestSessionFramesRoundTrip(t *testing.T) {
	client, server, _, _ := pair(t, psk)
	env, err := server.ReadFrame(frame(t, client, MsgHello, Hello{Hostname: "gs1"}))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	var h Hello
	if DecodeInto(env, &h) != nil || h.Hostname != "gs1" {
		t.Errorf("payload did not survive: %+v", h)
	}
}

// The attack the session key exists for.
//
// Proving who the peer is at connect time settles nothing about who is writing
// down the socket afterwards. Someone on the wire - and a linker's first hop to
// the frontend is plaintext TCP on a LAN, so this is a real position - can relay
// the handshake untouched, let both ends satisfy each other, and then send
// frames of their own. Relaying means they see both nonces. What they do not
// have is the pre-shared key, and the session key is derived from all three.
func TestARelayedHandshakeDoesNotLetTheRelayWriteFrames(t *testing.T) {
	client, server, sn, cn := pair(t, psk)

	// Everything the relay learned by passing the handshake through.
	relay, err := NewSession([]byte("not the pre-shared key"), sn, cn, true)
	if err != nil {
		t.Fatalf("relay session: %v", err)
	}
	if _, err := server.ReadFrame(frame(t, relay, MsgUsage, Usage{})); !errors.Is(err, ErrBadFrame) {
		t.Errorf("the frontend accepted a frame from a relay, got %v", err)
	}

	other, _, _, _ := pair(t, psk)
	if _, err := client.ReadFrame(frame(t, other, MsgLinkerConfig,
		LinkerConfig{EgressCIDRs: []string{"0.0.0.0/0"}})); !errors.Is(err, ErrBadFrame) {
		t.Errorf("a linker accepted a config from another session, got %v", err)
	}
}

// A frame cannot be turned round and sent back at the end that wrote it, which
// is the cheapest thing to try when both directions share a key.
func TestSessionFramesCannotBeReflected(t *testing.T) {
	client, _, _, _ := pair(t, psk)
	if _, err := client.ReadFrame(frame(t, client, MsgPing, nil)); !errors.Is(err, ErrBadFrame) {
		t.Errorf("a frame was accepted back at its own sender, got %v", err)
	}
}

// Replay and reorder, which the counter is what stops. It is checked exactly
// rather than as a floor: the transport is TCP, so a gap is not late delivery,
// it is a frame somebody removed.
func TestSessionFramesCannotBeReplayedOrReordered(t *testing.T) {
	client, server, _, _ := pair(t, psk)

	var first, second bytes.Buffer
	if err := client.WriteFrame(&first, MsgPing, nil); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := client.WriteFrame(&second, MsgUsage, Usage{}); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The second frame ahead of the first: a dropped frame is not tolerated.
	if _, err := server.ReadFrame(bufio.NewReader(bytes.NewReader(second.Bytes()))); !errors.Is(err, ErrBadFrame) {
		t.Errorf("a frame out of order was accepted, got %v", err)
	}
	if _, err := server.ReadFrame(bufio.NewReader(bytes.NewReader(first.Bytes()))); err != nil {
		t.Fatalf("the frame actually next was refused: %v", err)
	}
	// And the same frame again.
	if _, err := server.ReadFrame(bufio.NewReader(bytes.NewReader(first.Bytes()))); !errors.Is(err, ErrBadFrame) {
		t.Errorf("a replayed frame was accepted, got %v", err)
	}
}

// The type is authenticated along with the payload, so a frame cannot be
// relabelled into one the peer handles differently.
func TestSessionFrameTypeIsAuthenticated(t *testing.T) {
	client, server, _, _ := pair(t, psk)
	var buf bytes.Buffer
	if err := client.WriteFrame(&buf, MsgPing, nil); err != nil {
		t.Fatalf("write: %v", err)
	}
	tampered := bytes.Replace(buf.Bytes(), []byte(`"type":"ping"`), []byte(`"type":"pong"`), 1)
	if bytes.Equal(tampered, buf.Bytes()) {
		t.Fatal("the frame was not in the shape this test edits")
	}
	if _, err := server.ReadFrame(bufio.NewReader(bytes.NewReader(tampered))); !errors.Is(err, ErrBadFrame) {
		t.Errorf("a relabelled frame was accepted, got %v", err)
	}
}

// An unauthenticated frame is refused outright, which is what stops a peer
// simply leaving the MAC off.
func TestSessionRefusesAnUnauthenticatedFrame(t *testing.T) {
	_, server, _, _ := pair(t, psk)
	var buf bytes.Buffer
	if err := WriteFrame(&buf, MsgHello, Hello{Hostname: "impostor"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := server.ReadFrame(bufio.NewReader(bytes.NewReader(buf.Bytes()))); !errors.Is(err, ErrBadFrame) {
		t.Errorf("a bare frame was accepted into a session, got %v", err)
	}
}

// deadlineRecorder is a writer that remembers the deadlines it was given.
type deadlineRecorder struct {
	bytes.Buffer
	deadlines []time.Time
}

func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	d.deadlines = append(d.deadlines, t)
	return nil
}

// Each frame gets its own write deadline, set inside the lock that serialises
// the writes.
//
// Set by the caller instead, it was taken before that caller queued behind
// somebody else's stalled write - so it could arrive at the socket already
// spent and fail instantly. Both ends write from two goroutines, so the queue
// is not hypothetical. It also stops two goroutines overwriting each other's
// deadline, which is a connection-wide setting rather than a per-write one.
func TestEachFrameGetsItsOwnWriteDeadline(t *testing.T) {
	client, _, _, _ := pair(t, psk)
	w := &deadlineRecorder{}

	before := time.Now()
	if err := client.WriteFrame(w, MsgPing, nil); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := client.WriteFrame(w, MsgUsage, Usage{}); err != nil {
		t.Fatalf("write: %v", err)
	}

	if len(w.deadlines) != 2 {
		t.Fatalf("got %d deadlines for two frames, want 2", len(w.deadlines))
	}
	for i, d := range w.deadlines {
		if !d.After(before) {
			t.Errorf("deadline %d was already spent when it was set", i)
		}
	}
	if !w.deadlines[1].After(w.deadlines[0]) && !w.deadlines[1].Equal(w.deadlines[0]) {
		t.Error("the second frame reused a deadline older than the first's")
	}

	// A writer that cannot take one is written to anyway, which is what lets
	// the rest of these tests use a plain buffer.
	var plain bytes.Buffer
	if err := client.WriteFrame(&plain, MsgPing, nil); err != nil {
		t.Fatalf("a plain writer should still work: %v", err)
	}
}
