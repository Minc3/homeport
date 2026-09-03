package engine

import (
	"net"
	"testing"
	"time"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/proto"
)

// replayProber builds a prober for the first shipped path, pointed at a
// loopback listener that never answers, and a plain loopback socket to send
// from. Nothing here needs an fwmark: send takes the socket it is given, and
// the listener is only there so a real probe can be captured off the wire
// exactly as an attacker in a forwarding position would capture its reply.
func replayProber(t *testing.T, psk []byte) (*Prober, *net.UDPConn, net.PacketConn) {
	t.Helper()
	silent, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = silent.Close() })

	cfg := model.Defaults()
	cfg.Overlay.FrontendIP = "127.0.0.1"
	cfg.Overlay.BackendIP = "127.0.0.1"
	cfg.Overlay.ProbePort = silent.LocalAddr().(*net.UDPAddr).Port

	pr, err := NewProber(cfg.Paths[0], cfg.Probe, cfg.Overlay, psk, make(chan Result, 64),
		func() (uint16, uint64) { return 1, 1 }, quietLogger())
	if err != nil {
		t.Fatalf("new prober: %v", err)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return pr, conn, silent
}

// captureProbe sends one probe through the prober and returns it as the
// backend would have parsed it, which is everything a reply is built from.
func captureProbe(t *testing.T, pr *Prober, conn *net.UDPConn, silent net.PacketConn, psk []byte) *proto.Probe {
	t.Helper()
	if _, err := pr.send(conn); err != nil {
		t.Fatalf("send: %v", err)
	}
	buf := make([]byte, 256)
	_ = silent.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := silent.ReadFrom(buf)
	if err != nil {
		t.Fatalf("probe never arrived: %v", err)
	}
	msg, err := proto.Unmarshal(buf[:n], psk)
	if err != nil {
		t.Fatalf("the probe on the wire does not authenticate: %v", err)
	}
	return msg
}

// replyTo is the reply the backend's responder builds: every field echoed,
// the type flipped, authenticated under the shared key. It is what a capture
// holds, and it stays authentic for as long as the key does.
func replyTo(msg *proto.Probe) *proto.Probe {
	r := *msg
	r.Type = proto.TypeReply
	r.EchoNanos = time.Now().UnixNano()
	return &r
}

// pendingEntry reads one outstanding probe under the lock.
func pendingEntry(pr *Prober, seq uint64) (pendingProbe, bool) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	e, ok := pr.pending[seq]
	return e, ok
}

// An honest reply still resolves, with the round trip taken from when the
// probe left. This is the case every failover decision is made from, so it is
// pinned beside the refusals rather than assumed.
func TestAnHonestReplyResolvesWithAnRTT(t *testing.T) {
	psk := []byte("secret")
	pr, conn, silent := replayProber(t, psk)
	msg := captureProbe(t, pr, conn, silent, psk)

	sent, ok := pendingEntry(pr, msg.Seq)
	if !ok {
		t.Fatalf("sequence %d not pending after send", msg.Seq)
	}
	if sent.nonce != msg.Nonce {
		t.Fatalf("the nonce on the wire (%x) is not the one recorded against the probe (%x)", msg.Nonce, sent.nonce)
	}

	now := sent.sent.Add(20 * time.Millisecond)
	if !pr.resolve(replyTo(msg), now) {
		t.Fatal("the backend's own reply was refused")
	}
	if _, still := pendingEntry(pr, msg.Seq); still {
		t.Fatal("a resolved probe is still pending")
	}
	pr.mu.Lock()
	r, ok := pr.resolved[msg.Seq]
	pr.mu.Unlock()
	if !ok || r.Lost || r.RTT != 20*time.Millisecond || r.PathID != pr.path.ID {
		t.Fatalf("resolved result wrong: %+v (want a 20ms reply on path %d)", r, pr.path.ID)
	}
}

// The nonce is generated from crypto/rand, echoed by the backend, and used to
// be thrown away on the way back in. A reply that names the right sequence
// with any other nonce is not an answer to this probe, whatever key it was
// made under: the MAC proves who made it, the nonce proves what for.
func TestAReplyWithTheWrongNonceIsNotResolved(t *testing.T) {
	psk := []byte("secret")
	pr, conn, silent := replayProber(t, psk)
	msg := captureProbe(t, pr, conn, silent, psk)

	forged := replyTo(msg)
	forged.Nonce = msg.Nonce ^ 1
	if pr.resolve(forged, time.Now()) {
		t.Fatal("a reply carrying a nonce this probe never sent was accepted as its answer")
	}
	if _, still := pendingEntry(pr, msg.Seq); !still {
		t.Fatal("the refused reply took the probe out of pending; the honest reply behind it would now be dropped")
	}
	// The honest one is still welcome.
	if !pr.resolve(replyTo(msg), time.Now()) {
		t.Fatal("the honest reply was refused after a forged one")
	}
}

// A reply is stamped with this prober's own path id whatever it carries, so
// one captured on a working tunnel could stand in for an answer on a dead
// one. The path id is checked with the sequence and the nonce so that a reply
// only ever answers the prober that asked.
func TestAReplyForAnotherPathIsNotResolved(t *testing.T) {
	psk := []byte("secret")
	pr, conn, silent := replayProber(t, psk)
	msg := captureProbe(t, pr, conn, silent, psk)

	other := replyTo(msg)
	other.PathID = msg.PathID + 1
	if pr.resolve(other, time.Now()) {
		t.Fatal("a reply addressed to another path was booked against this one")
	}
	if _, still := pendingEntry(pr, msg.Seq); !still {
		t.Fatal("the refused reply took the probe out of pending")
	}
}

// The attack this closes: capture an authentic reply for (path, seq N), wait
// for a new prober generation - a settings save, a mode change, a restart -
// and inject it when that generation reaches N. Every generation used to
// count from zero, so N always came round again, and the reply matched on
// sequence alone. This test forces the new generation onto the captured
// sequence, which is the pre-seeding world exactly, and the nonce check has
// to refuse it on its own; the seed is pinned separately below.
func TestAReplyCapturedFromAPreviousGenerationDoesNotResolveInTheNext(t *testing.T) {
	psk := []byte("secret")
	old, oldConn, silent := replayProber(t, psk)
	captured := replyTo(captureProbe(t, old, oldConn, silent, psk))

	next, nextConn, silent2 := replayProber(t, psk)
	next.mu.Lock()
	next.seq = captured.Seq - 1
	next.deliver = captured.Seq
	next.mu.Unlock()
	live := captureProbe(t, next, nextConn, silent2, psk)
	if live.Seq != captured.Seq {
		t.Fatalf("test setup: the new generation sent seq %d, wanted the captured %d", live.Seq, captured.Seq)
	}
	if live.Nonce == captured.Nonce {
		t.Fatal("two probes drew the same nonce; the replay check has nothing to work with")
	}

	if next.resolve(captured, time.Now()) {
		t.Fatal("a reply captured from the previous generation answered the new generation's probe on the same sequence; a dead path can be kept eligible by replaying old replies")
	}
	if _, still := pendingEntry(next, live.Seq); !still {
		t.Fatal("the replayed reply took the live probe out of pending")
	}
	if !next.resolve(replyTo(live), time.Now()) {
		t.Fatal("the live probe's own reply was refused")
	}
}

// Each generation starts its sequence from its own random seed rather than
// from zero, so the sequences a replaced generation used are not the ones its
// replacement is about to use, and a captured reply does not even name a
// probe the new generation will send. Two fresh probers drawing the same
// start is the failure, and the clock could produce it.
func TestEachProberGenerationStartsFromItsOwnSequence(t *testing.T) {
	cfg := model.Defaults()
	seen := map[uint64]bool{}
	for i := 0; i < 8; i++ {
		pr, err := NewProber(cfg.Paths[0], cfg.Probe, cfg.Overlay, []byte("secret"), make(chan Result),
			func() (uint16, uint64) { return 0, 0 }, quietLogger())
		if err != nil {
			t.Fatalf("new prober: %v", err)
		}
		if pr.seq == 0 {
			t.Fatal("a generation started its sequence at zero, which is the value every earlier generation started at too")
		}
		if pr.seq>>seqSeedBits != 0 {
			t.Fatalf("seed %x uses more than %d bits; the counter needs the headroom above it", pr.seq, seqSeedBits)
		}
		if pr.deliver != pr.seq+1 {
			t.Fatalf("deliver %d is not one past the seed %d; flush would wait forever on a sequence nothing sends", pr.deliver, pr.seq)
		}
		if seen[pr.seq] {
			t.Fatalf("two generations drew the same starting sequence %d", pr.seq)
		}
		seen[pr.seq] = true
	}
}

// Seeding moves the sequence away from zero, and flush, expire and the loss
// bookkeeping all reason about sequence order from wherever it starts. Two
// probes answered in reverse order must still leave in sequence order, and a
// loss booked between them must be delivered in its place: the ordering
// invariant (invariant 4) does not care what the first number was, and this
// pins that the seeded start did not leave deliver behind.
func TestASeededSequenceStillDeliversResultsInOrder(t *testing.T) {
	psk := []byte("secret")
	pr, conn, silent := replayProber(t, psk)
	results := make(chan Result, 8)
	pr.results = results

	first := captureProbe(t, pr, conn, silent, psk)
	second := captureProbe(t, pr, conn, silent, psk)
	third := captureProbe(t, pr, conn, silent, psk)

	ctx := t.Context()
	if !pr.resolve(replyTo(third), time.Now()) {
		t.Fatal("third reply refused")
	}
	pr.flush(ctx)
	select {
	case r := <-results:
		t.Fatalf("result %+v delivered ahead of the two probes before it", r)
	default:
	}

	pr.mu.Lock()
	pr.markLost(second.Seq)
	pr.mu.Unlock()
	if !pr.resolve(replyTo(first), time.Now()) {
		t.Fatal("first reply refused")
	}
	pr.flush(ctx)

	want := []struct {
		seq  uint64
		lost bool
	}{{first.Seq, false}, {second.Seq, true}, {third.Seq, false}}
	for i, w := range want {
		select {
		case r := <-results:
			if r.Seq != w.seq || r.Lost != w.lost {
				t.Fatalf("result %d: got seq %d lost=%v, want seq %d lost=%v", i, r.Seq, r.Lost, w.seq, w.lost)
			}
		default:
			t.Fatalf("result %d (seq %d) was never delivered", i, w.seq)
		}
	}
}
