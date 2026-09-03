package qcache

import (
	"container/list"
	"net"
	"sync"
	"time"
)

// The challenge stops a spoofed source being served at all, and that is the
// whole of the anti-amplification argument in a2s.go. It says nothing about
// a source that is real: one address completes one challenge per 30 second
// bucket and can then send the 9-byte PLAYER or RULES query at line rate,
// each drawing the entire cached reply, up to maxFragments datagrams of 4 KB,
// off the frontend's public uplink. That is not reflection, since the bytes
// go back to whoever sent the query, but it is the cache handing a real
// address several thousand times what it sent, paced by nothing but the
// optional nft per-source limiter, and a real address is the one kind a
// per-source limiter cannot tell from a player.
//
// The pacer is a token bucket of reply bytes per source address per port. A
// bucket starts full at paceBurstBytes and refills at paceRefillPerSec, which
// a browser refreshing INFO, PLAYER and RULES every few seconds never
// notices, while an abuser is held to the refill rate however fast it asks.
// A reply the bucket cannot cover is dropped whole: not a partial reply,
// which a browser would wait on and reassemble wrongly, and not a challenge,
// which would be a fresh round trip for a source that has already proved
// itself and has simply been served enough.
//
// The key is the address alone, never address and port. One host with many
// sockets is one host, and a socket per query is the cheapest thing an
// abuser can do.
const (
	// paceBurstBytes is eight times the largest reply this cache can hold
	// (maxFragments datagrams of 4 KB), so the burst covers a browser's
	// first look at a full server with room for its retries, and a reply
	// can never be larger than a fresh bucket.
	paceBurstBytes = 512 << 10

	// paceRefillPerSec is a full RULES reply every second, sustained. A
	// server browser asks for that once every few seconds at most.
	paceRefillPerSec = 64 << 10

	// paceIdleAfter drops a source's bucket once it has been quiet this
	// long. Nothing is lost by it: at the refill rate a bucket is full again
	// eight seconds after it was emptied, so an idle entry holds no
	// information and only costs memory.
	paceIdleAfter = 2 * time.Minute

	// paceMaxSources bounds the table per port. Past it the least recently
	// seen source is evicted, which is the right failure: refusing new
	// sources instead would let a few thousand addresses lock real players
	// out. What it means is that the bound is per address, and an abuser
	// with more real addresses than this cycling through them is a botnet,
	// which is the service ceiling's problem rather than the pacer's.
	paceMaxSources = 4096
)

type paceKey [16]byte

type paceEntry struct {
	key    paceKey
	tokens float64
	last   time.Time
}

// pacer is one port's table of buckets. Only the port's serve goroutine
// touches it, but the lock is kept so that stays a fact about today's callers
// rather than a rule the next one has to know.
type pacer struct {
	burst  float64
	refill float64 // bytes per second
	idle   time.Duration
	max    int

	mu  sync.Mutex
	by  map[paceKey]*list.Element
	lru *list.List // front is most recently seen
}

func newPacer(burst, refillPerSec int, idle time.Duration, max int) *pacer {
	return &pacer{
		burst:  float64(burst),
		refill: float64(refillPerSec),
		idle:   idle,
		max:    max,
		by:     make(map[paceKey]*list.Element),
		lru:    list.New(),
	}
}

// allow reports whether a reply of n bytes to ip may be sent now, and charges
// the bucket if so. A refusal charges nothing, so a source that is over its
// budget is served again exactly when the refill covers the reply, never
// later.
func (p *pacer) allow(ip net.IP, n int, now time.Time) bool {
	var k paceKey
	copy(k[:], ip.To16())

	p.mu.Lock()
	defer p.mu.Unlock()
	p.prune(now)

	var e *paceEntry
	if el, ok := p.by[k]; ok {
		e = el.Value.(*paceEntry)
		if elapsed := now.Sub(e.last); elapsed > 0 {
			e.tokens = min(p.burst, e.tokens+elapsed.Seconds()*p.refill)
			e.last = now
		}
		p.lru.MoveToFront(el)
	} else {
		if p.lru.Len() >= p.max {
			p.evict(p.lru.Back())
		}
		e = &paceEntry{key: k, tokens: p.burst, last: now}
		p.by[k] = p.lru.PushFront(e)
	}
	if float64(n) > e.tokens {
		return false
	}
	e.tokens -= float64(n)
	return true
}

// prune drops sources idle past the bound, from the least recently seen end,
// so the table is kept small by ordinary traffic rather than only by the cap.
func (p *pacer) prune(now time.Time) {
	for el := p.lru.Back(); el != nil; el = p.lru.Back() {
		if now.Sub(el.Value.(*paceEntry).last) <= p.idle {
			return
		}
		p.evict(el)
	}
}

func (p *pacer) evict(el *list.Element) {
	delete(p.by, el.Value.(*paceEntry).key)
	p.lru.Remove(el)
}

// sources is the number of addresses currently tracked, for the tests.
func (p *pacer) sources() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lru.Len()
}
