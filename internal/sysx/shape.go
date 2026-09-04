package sysx

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// Tunnel shaping
// --------------
// One queue discipline per tunnel interface, at each end, at a rate the
// operator measured. Everything here is off unless a rate was configured, and a
// site that configures none never runs `tc` at all.
//
// Why a queue helps at all, given the link is the same speed either way: the
// packets have to wait somewhere, and where they wait decides what the latency
// looks like. Left alone they wait in the carrier's buffer, which is large, has
// no idea which flow is which, and adds seconds of delay to a game packet
// stuck behind a file transfer. Shaping slightly *below* the real line rate
// moves that queue into this host, where CAKE keeps it short and hands each
// flow its own share - so a download stops being something everybody else can
// feel.
//
// The direction matters and is easy to get backwards. A queue only controls
// what the host it lives on is sending. The frontend's queue on wg-lte1 is the
// house's download; the backend's queue on the same tunnel is the house's
// upload. Being able to shape the download side at all is unusual and is a
// property of owning both ends: an ordinary home router can only drop traffic
// that has already crossed the bottleneck.

// ShapeOverheadBytes is what CAKE is told to add to every packet.
//
// The shaper counts the payload it is handed, but the carrier bills what
// leaves the WAN: WireGuard's header, the UDP and IP headers around it, and the
// ethernet framing beneath. Around 80 bytes, and it matters most where packets
// are small and numerous - which is exactly what a game server sends. Without
// it a link shaped to its measured rate still overruns and the queue drifts
// back out to the carrier.
const ShapeOverheadBytes = 80

// ShapeQdisc is the discipline installed. CAKE is chosen over fq_codel because
// it does the rate limiting itself - fq_codel needs an htb or tbf parent to be
// told a rate - and because its flow isolation gives sparse flows priority,
// which is what keeps a 66-byte probe every 250ms out from behind a download
// without any classification to maintain.
const ShapeQdisc = "cake"

// EnsureQdisc installs or corrects the shaper on one interface.
//
// Reports whether it changed anything, so a reconciler can say when it repaired
// something rather than logging every ten seconds. A rate of zero removes any
// shaper this agent installed and leaves an interface it never shaped alone -
// which is what makes turning the feature off in the portal actually take
// effect, rather than leaving the last rate in place with nothing in the
// configuration to explain it.
func EnsureQdisc(ctx context.Context, r Runner, iface string, mbit float64) (bool, error) {
	if iface == "" {
		return false, fmt.Errorf("no interface")
	}
	have, kind, ours, err := qdiscInfo(ctx, r, iface)
	if err != nil {
		return false, err
	}
	if mbit <= 0 {
		// Only a shaper carrying this agent's own signature. This branch is
		// reached with zero for every unshaped path on every settings save
		// and every config push, so "any cake" here removed a CAKE the
		// operator had put on a tunnel by hand, on a site that never set a
		// rate in the portal, with a "changed" line as the only trace.
		// Invariant 8: never touch what the agent did not install.
		if kind != ShapeQdisc || !ours {
			return false, nil // nothing of ours to take down
		}
		RemoveQdisc(ctx, r, iface)
		return true, nil
	}
	// Compared loosely: tc rounds to its own units on the way in and prints
	// them back rounded, so an exact match would reinstall the same shaper
	// forever and blow away the queue's state every ten seconds. A cake
	// without the signature is replaced: a configured rate is the operator
	// asking for this shaper on this interface.
	if kind == ShapeQdisc && ours && sameRate(have, mbit) {
		return false, nil
	}
	if _, err := r.Run(ctx, "tc", "qdisc", "replace", "dev", iface, "root", ShapeQdisc,
		"bandwidth", formatRate(mbit), "overhead", strconv.Itoa(ShapeOverheadBytes), "besteffort"); err != nil {
		return false, fmt.Errorf("shape %s at %s: %w", iface, formatRate(mbit), err)
	}
	return true, nil
}

// RemoveQdisc takes the shaper off, returning the interface to the kernel's
// default. Errors are ignored: an interface with no qdisc of its own, or no
// longer present at all, is the state this is trying to reach.
func RemoveQdisc(ctx context.Context, r Runner, iface string) {
	_, _ = r.Run(ctx, "tc", "qdisc", "del", "dev", iface, "root")
}

// QdiscRate reads back what is actually installed, in Mbit, along with the
// discipline's name.
//
// A readback rather than a memory of what was installed, for the reason every
// other readback here exists: `wg-quick down` deletes the interface and the
// queue discipline goes with it, and the agent's own belief about it survives
// the loss perfectly intact.
//
// It also reports whether the shaper is recognisably this agent's. EnsureQdisc installs exactly `cake bandwidth X overhead 80
// besteffort`, and tc prints the overhead and the priority mode back, so a
// cake carrying both is treated as ours and one carrying neither is somebody
// else's shaping that happens to use the same discipline.
func qdiscInfo(ctx context.Context, r Runner, iface string) (rate float64, kind string, ours bool, err error) {
	out, err := r.Run(ctx, "tc", "qdisc", "show", "dev", iface)
	if err != nil {
		return 0, "", false, fmt.Errorf("read qdisc on %s: %w", iface, err)
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "qdisc" {
			continue
		}
		kind := fields[1]
		if kind != ShapeQdisc {
			// Something else owns this interface - the kernel default, or an
			// operator's own shaping. Reported, never overwritten silently.
			return 0, kind, false, nil
		}
		overhead, besteffort := false, false
		for i, f := range fields {
			switch {
			case f == "bandwidth" && i+1 < len(fields):
				rate = parseRate(fields[i+1])
			case f == "overhead" && i+1 < len(fields):
				overhead = fields[i+1] == strconv.Itoa(ShapeOverheadBytes)
			case f == "besteffort":
				besteffort = true
			}
		}
		return rate, kind, overhead && besteffort, nil
	}
	return 0, "", false, nil
}

// formatRate renders a rate the way tc accepts it. %g so a whole number stays
// whole: "18mbit", not "18.000000mbit".
func formatRate(mbit float64) string { return fmt.Sprintf("%gmbit", mbit) }

// sameRate tolerates the rounding tc does on the way in and out. A tenth of a
// megabit either way is far below anything an operator can measure.
func sameRate(a, b float64) bool {
	d := a - b
	return d < 0.1 && d > -0.1
}

// parseRate turns tc's printed bandwidth back into Mbit. It prints "18Mbit",
// "2500Kbit", "1Gbit" or "unlimited" depending on the value it was given.
func parseRate(s string) float64 {
	lower := strings.ToLower(s)
	mult := 0.0
	switch {
	case strings.HasSuffix(lower, "gbit"):
		lower, mult = strings.TrimSuffix(lower, "gbit"), 1000
	case strings.HasSuffix(lower, "mbit"):
		lower, mult = strings.TrimSuffix(lower, "mbit"), 1
	case strings.HasSuffix(lower, "kbit"):
		lower, mult = strings.TrimSuffix(lower, "kbit"), 0.001
	case strings.HasSuffix(lower, "bit"):
		lower, mult = strings.TrimSuffix(lower, "bit"), 0.000001
	default:
		return 0 // "unlimited", or something this does not understand
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(lower), 64)
	if err != nil {
		return 0
	}
	return v * mult
}
