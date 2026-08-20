package proto

import (
	"bytes"
	"testing"
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
	nonce := RandomNonce()
	if !VerifyChallenge(psk, nonce, SignChallenge(psk, nonce)) {
		t.Error("a correctly signed challenge should verify")
	}
	if VerifyChallenge(psk, nonce, SignChallenge([]byte("wrong"), nonce)) {
		t.Error("a challenge signed with the wrong key must not verify")
	}
	if VerifyChallenge(psk, nonce, SignChallenge(psk, RandomNonce())) {
		t.Error("a response to a different nonce must not verify, or replays would work")
	}
}

func TestNonceIsRandom(t *testing.T) {
	if RandomNonce() == RandomNonce() {
		t.Error("challenge nonces must not repeat")
	}
}
