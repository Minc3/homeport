// Package quota turns raw interface counters into billed data usage, works
// out which billing period a moment falls in, and decides whether a path is
// allowed to carry traffic.
//
// Quota exhaustion is a policy block, never a health verdict. An over-quota
// path stays fully healthy in the portal; it is simply not selectable. That
// distinction matters because it is the reason the system can offer to use it
// anyway when there is nothing else left.
package quota

import (
	"fmt"
	"math"
	"time"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/store"
)

// The ceilings on the two configuration values Metered multiplies every byte
// by. Exported because web.validate refuses the same values with a message an
// operator can act on, and two hand-kept copies of a bound is that promise
// drifting apart waiting to happen: raise one alone and the portal accepts a
// figure this silently clamps, which under-bills every metered byte with
// nothing anywhere saying so.
//
// MaxOverheadPerPacket is a per-packet figure. WireGuard, UDP and IP together
// come to about sixty bytes, so a kilobyte is already absurd and 65535 is past
// anything a single datagram can carry.
//
// The calibration is a percentage correction for what the carrier counts
// against what the interface does, and it is bounded on both sides because a
// factor of ten either way is a typo rather than a calibration. Only the upper
// bound existed at first, which left the whole of the silent direction open:
// 100 typed as 10 bills a gigabyte of LTE as a hundred megabytes, the ledger
// never approaches the cap, the quota never trips, the portal shows the path
// healthy and under quota, and the first anybody hears of it is the carrier's
// invoice. That is the same failure the negative byte count is refused for,
// reached through the multiplier instead of the operand.
const (
	MaxOverheadPerPacket = 65535
	MaxCalibration       = 1000.0
	MinCalibration       = 10.0
)

// Metered converts inner tunnel payload into what the carrier will bill.
//
// The carrier meters the encapsulated datagram on the WAN, not the payload
// inside the tunnel, so every packet carries WireGuard, UDP and IP headers
// that the interface counters never see. Counting raw payload alone
// undercounts by roughly 5-15% depending on packet size, which would mean
// hitting the real cap while the ledger still thinks there is headroom.
func Metered(bytes, packets int64, q model.Quota) int64 {
	// Every input here is bounded before the arithmetic, because this function
	// sits between a socket and the ledger and an int64 that wraps does not
	// announce itself: it produces a plausible number, or a negative one that
	// silently credits the month back. The engine bounds the two counts at the
	// frame boundary (see checkDelta); these bound the two configuration
	// values beside them, which the portal accepts with no ceiling of their
	// own.
	overhead := int64(q.OverheadPerPacket)
	if overhead < 0 {
		overhead = 0
	} else if overhead > MaxOverheadPerPacket {
		overhead = MaxOverheadPerPacket
	}
	if bytes < 0 {
		bytes = 0
	}
	if packets < 0 {
		packets = 0
	}
	// NaN before the ordered comparisons, because both of them are false for
	// it: a NaN would sail past `cal <= 0` and `cal > MaxCalibration` alike,
	// stay NaN through the multiply, and reach int64(NaN), which on the
	// deployment platform is MinInt64. That is a large negative number added
	// to the ledger, which is the one outcome this function is here to
	// prevent. JSON cannot carry NaN so nothing produces it today, and that is
	// not the point: this is written as the boundary for a value stored by an
	// older build or arriving from a socket, so it has to be total.
	// A calibration outside the range validate accepts is not a calibration, so
	// it falls back to 100 rather than to the nearest edge. Clamping up to
	// MinCalibration was worse than useless in the one case the floor exists
	// for: a stored 1, a fraction typed where a percent was wanted, became 10
	// and went on under-billing by a factor of ten, while a stored 0 took this
	// branch and billed correctly. Neutral is the only fail-safe answer, and it
	// errs toward the visible direction.
	cal := q.Calibration
	if math.IsNaN(cal) || cal < MinCalibration || cal > MaxCalibration {
		cal = 100
	}
	// Saturating rather than wrapping. With the bounds above nothing reaches
	// this on a configuration the portal accepted, and that is exactly why it
	// is here: the case it covers is a stored blob or a pushed value nobody
	// checked, which is the case the rest of this system's boundary parsing
	// exists for.
	total := saturatingAdd(bytes, saturatingMul(packets, overhead))
	scaled := float64(total) * cal / 100.0
	if scaled >= math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(scaled)
}

// saturatingMul and saturatingAdd clamp at the int64 limits instead of
// wrapping, for any operands rather than only for the non-negative ones the
// call site happens to guarantee.
//
// The first version relied on that guarantee and stated it in a comment, which
// is not the same as holding it: `math.MaxInt64 - b` itself wraps for a
// negative b, so saturatingAdd(5, -3) returned MaxInt64 rather than 2. Nothing
// reached it, because Metered pre-clamps both operands, and a helper named for
// general saturation sitting one call away from the ledger is not the place to
// leave a trap for whoever adds the second caller.
func saturatingMul(a, b int64) int64 {
	if a == 0 || b == 0 {
		return 0
	}
	c := a * b
	// Division recovers the operand exactly unless the multiply overflowed.
	// MinInt64 * -1 is the one case it cannot see, because the overflow is
	// exactly the value it started from.
	if c/b != a || (a == math.MinInt64 && b == -1) {
		if (a > 0) == (b > 0) {
			return math.MaxInt64
		}
		return math.MinInt64
	}
	return c
}

func saturatingAdd(a, b int64) int64 {
	if b > 0 && a > math.MaxInt64-b {
		return math.MaxInt64
	}
	if b < 0 && a < math.MinInt64-b {
		return math.MinInt64
	}
	return a + b
}

// Location resolves the quota's timezone, falling back to UTC.
func Location(q model.Quota) *time.Location {
	if q.Timezone == "" {
		return time.UTC
	}
	loc, err := time.LoadLocation(q.Timezone)
	if err != nil {
		return time.UTC
	}
	return loc
}

// PeriodBounds returns the billing period containing now.
//
// ResetDay is clamped to the length of the month, so a carrier that resets on
// the 31st still gets a sane boundary in February.
func PeriodBounds(q model.Quota, now time.Time) (start, end time.Time) {
	loc := Location(q)
	n := now.In(loc)

	day := q.ResetDay
	if day < 1 {
		day = 1
	}
	if day > 31 {
		day = 31
	}

	boundary := func(year int, month time.Month) time.Time {
		d := day
		if last := daysIn(year, month); d > last {
			d = last
		}
		return time.Date(year, month, d, 0, 0, 0, 0, loc)
	}

	start = boundary(n.Year(), n.Month())
	if n.Before(start) {
		y, m := n.Year(), n.Month()
		if m == time.January {
			y, m = y-1, time.December
		} else {
			m--
		}
		start = boundary(y, m)
	}

	y, m := start.Year(), start.Month()
	if m == time.December {
		y, m = y+1, time.January
	} else {
		m++
	}
	end = boundary(y, m)
	return start, end
}

func daysIn(year int, month time.Month) int {
	return time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

// Decision is the outcome of evaluating a path's quota.
type Decision struct {
	Blocked     bool
	Reason      string
	Used        int64
	Limit       int64
	PeriodStart time.Time
	PeriodEnd   time.Time
	GrantUntil  time.Time
	GrantBytes  int64
	// OverQuota reports that the path is past its limit, whether or not an
	// approval is currently letting it through. The portal uses this to show
	// the approve button.
	OverQuota bool
}

// Evaluate decides whether a metered path may be used right now.
//
// A path over its limit is blocked unless a live approval covers it. The
// absolute ceiling, if set, overrides even an approval: it exists so that a
// runaway cannot cost unbounded money no matter what was clicked at 2am.
func Evaluate(p model.PathConfig, used int64, grant store.Grant, hasGrant bool, now time.Time) Decision {
	start, end := PeriodBounds(p.Quota, now)
	d := Decision{
		Used:        used,
		Limit:       p.Quota.LimitBytes,
		PeriodStart: start,
		PeriodEnd:   end,
	}
	if !p.Metered || p.Quota.LimitBytes <= 0 {
		return d
	}

	d.OverQuota = used >= p.Quota.LimitBytes

	if ceiling := p.Quota.CeilingBytes; ceiling > 0 && used >= ceiling {
		d.Blocked = true
		d.Reason = fmt.Sprintf("absolute ceiling reached (%s of %s)",
			HumanBytes(used), HumanBytes(ceiling))
		return d
	}

	if !d.OverQuota {
		return d
	}

	if hasGrant {
		until := time.Unix(grant.Until, 0)
		d.GrantUntil = until
		d.GrantBytes = grant.ExtraBytes
		expired := !now.Before(until)
		exhausted := grant.ExtraBytes > 0 && used >= grant.StartBytes+grant.ExtraBytes
		if !expired && !exhausted {
			return d // approved overage, allowed through
		}
	}

	d.Blocked = true
	d.Reason = fmt.Sprintf("over monthly quota (%s of %s), resets %s",
		HumanBytes(used), HumanBytes(p.Quota.LimitBytes), end.Format("2 Jan 15:04"))
	return d
}

// HumanBytes formats a byte count for display and log messages.
func HumanBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit && exp < 4; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTP"[exp])
}
