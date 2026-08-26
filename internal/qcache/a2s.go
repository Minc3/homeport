// Package qcache answers Source-engine A2S_INFO and A2S_PLAYER queries from
// the frontend, out of a cache refreshed from the real server.
//
// It exists for the flood the per-source limits cannot touch: spoofed source
// addresses. The limits key on an address being real - a hundred real bots
// trip them and are parked - but a flood that randomises its source never
// trips a per-source limit, lands on the service-wide ceiling, and the
// ceiling drops legitimate browser queries along with the flood. The cache
// closes that by doing what a modern Source server itself does: every source
// is challenged before it is served a payload, a spoofed sender never sees
// the challenge and so never gets an answer, and the challenge reply is
// smaller than the query that provoked it, so the exchange amplifies
// nothing. Legitimate clients complete the challenge and are answered from
// cache, at the datacentre, with nothing crossing a tunnel.
//
// Only INFO and PLAYER are cached, matching the reference implementations:
// A2S_RULES is rarer, larger, and passes through to the real server like any
// other packet, where the per-source query limit still covers it.
package qcache

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// The A2S type bytes this cache speaks. A query datagram is the single-packet
// header 0xFFFFFFFF followed by one of these.
const (
	typeInfoRequest   = 0x54 // 'T', A2S_INFO
	typePlayerRequest = 0x55 // 'U', A2S_PLAYER
	typeChallenge     = 0x41 // 'A', S2C_CHALLENGE, both directions
)

var (
	headerSingle = []byte{0xff, 0xff, 0xff, 0xff}
	headerMulti  = []byte{0xfe, 0xff, 0xff, 0xff}

	// infoPayload is the fixed string every A2S_INFO query carries. Anything
	// else after a 'T' is not a query a real client sends, and is ignored
	// rather than challenged - replying to arbitrary bytes would answer
	// traffic this cache has no business answering.
	infoPayload = []byte("Source Engine Query\x00")

	// noChallenge is the -1 a client sends to ask for a challenge.
	noChallenge = []byte{0xff, 0xff, 0xff, 0xff}
)

// maxFragments bounds a multi-packet response. The largest honest reply this
// protocol produces is a full player list or a long rules dump, a handful of
// fragments; a count read off the wire is a peer-chosen number and must not
// size an allocation unbounded.
const maxFragments = 16

// queryKind classifies a client datagram.
type queryKind int

const (
	queryNone queryKind = iota
	queryInfoBare
	queryInfoChallenged
	queryPlayerBare
	queryPlayerChallenged
)

// classify reads a client datagram. The returned challenge is meaningful only
// for the two challenged kinds.
func classify(b []byte) (queryKind, []byte) {
	if len(b) < 5 || !bytes.Equal(b[:4], headerSingle) {
		return queryNone, nil
	}
	body := b[5:]
	switch b[4] {
	case typeInfoRequest:
		if !bytes.HasPrefix(body, infoPayload) {
			return queryNone, nil
		}
		rest := body[len(infoPayload):]
		switch len(rest) {
		case 0:
			return queryInfoBare, nil
		case 4:
			if bytes.Equal(rest, noChallenge) {
				return queryInfoBare, nil
			}
			return queryInfoChallenged, rest
		}
		return queryNone, nil
	case typePlayerRequest:
		if len(body) != 4 {
			return queryNone, nil
		}
		if bytes.Equal(body, noChallenge) {
			return queryPlayerBare, nil
		}
		return queryPlayerChallenged, body
	}
	return queryNone, nil
}

// challengeReply builds the 9-byte S2C_CHALLENGE datagram. Deliberately
// smaller than either query that can provoke it (25 bytes for the shortest
// INFO), which is what makes challenging every unknown source safe: a spoofed
// flood gets back less traffic than it sent, aimed at an address that never
// asked for it.
func challengeReply(ch []byte) []byte {
	out := make([]byte, 0, 9)
	out = append(out, headerSingle...)
	out = append(out, typeChallenge)
	return append(out, ch...)
}

// infoRequest builds an upstream A2S_INFO query, with the server's challenge
// appended once it has issued one.
func infoRequest(challenge []byte) []byte {
	out := make([]byte, 0, len(headerSingle)+1+len(infoPayload)+4)
	out = append(out, headerSingle...)
	out = append(out, typeInfoRequest)
	out = append(out, infoPayload...)
	return append(out, challenge...)
}

// playerRequest builds an upstream A2S_PLAYER query. With no challenge yet it
// carries -1, which is the protocol's "give me one".
func playerRequest(challenge []byte) []byte {
	if challenge == nil {
		challenge = noChallenge
	}
	out := make([]byte, 0, len(headerSingle)+1+4)
	out = append(out, headerSingle...)
	out = append(out, typePlayerRequest)
	return append(out, challenge...)
}

// isChallenge reports an upstream S2C_CHALLENGE and hands back its value.
func isChallenge(b []byte) ([]byte, bool) {
	if len(b) == 9 && bytes.Equal(b[:4], headerSingle) && b[4] == typeChallenge {
		return b[5:9], true
	}
	return nil, false
}

// fragmentMeta reads the total and index from a multi-packet fragment. The
// Source multi-packet header is 4 bytes 0xFFFFFFFE, 4 bytes of ID, then one
// byte of total and one of index, and those offsets hold for the compressed
// variant too. GoldSrc's older format differs and is not spoken here: the
// cache is Source-only, like the tick box that opts a service in.
func fragmentMeta(b []byte) (total, index int, ok bool) {
	if len(b) < 10 || !bytes.Equal(b[:4], headerMulti) {
		return 0, 0, false
	}
	total, index = int(b[8]), int(b[9])
	if total < 1 || total > maxFragments || index >= total {
		return 0, 0, false
	}
	return total, index, true
}

// hmacEqual compares in constant time; a challenge is a MAC.
func hmacEqual(a, b []byte) bool { return hmac.Equal(a, b) }

// challengeBucket is the coarse time window a challenge lives in. Verifying
// against the current and previous bucket gives a client between 30 and 60
// seconds to echo one back, which is thousands of times what a real retry
// takes.
const challengeBucketSecs = 30

// challengeFor derives the 4-byte challenge for one source talking to one
// port. HMAC over the source and the time bucket, keyed by a per-generation
// random secret, so there is no table of outstanding challenges for a
// spoofed flood to fill: the same source gets the same answer for the life
// of the bucket, computed fresh each time, and state per client is zero.
func challengeFor(secret []byte, srcIP []byte, srcPort, dstPort int, bucket int64) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(srcIP)
	var scratch [8]byte
	binary.BigEndian.PutUint16(scratch[:2], uint16(srcPort))
	mac.Write(scratch[:2])
	binary.BigEndian.PutUint16(scratch[:2], uint16(dstPort))
	mac.Write(scratch[:2])
	binary.BigEndian.PutUint64(scratch[:], uint64(bucket))
	mac.Write(scratch[:])
	sum := mac.Sum(nil)[:4]
	if bytes.Equal(sum, noChallenge) {
		// -1 is the protocol's "no challenge yet" and cannot be issued as
		// one: a client echoing it would be indistinguishable from a client
		// asking for one.
		sum = append([]byte(nil), 0xff, 0xff, 0xff, 0xfe)
	}
	return sum
}
