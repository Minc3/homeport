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
	"time"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/store"
)

// Metered converts inner tunnel payload into what the carrier will bill.
//
// The carrier meters the encapsulated datagram on the WAN, not the payload
// inside the tunnel, so every packet carries WireGuard, UDP and IP headers
// that the interface counters never see. Counting raw payload alone
// undercounts by roughly 5-15% depending on packet size, which would mean
// hitting the real cap while the ledger still thinks there is headroom.
func Metered(bytes, packets int64, q model.Quota) int64 {
	overhead := int64(q.OverheadPerPacket)
	if overhead < 0 {
		overhead = 0
	}
	total := bytes + packets*overhead
	cal := q.Calibration
	if cal <= 0 {
		cal = 100
	}
	return int64(float64(total) * cal / 100.0)
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
