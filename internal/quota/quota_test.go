package quota

import (
	"testing"
	"time"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/store"
)

func syd(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("Australia/Sydney")
	if err != nil {
		t.Skipf("tzdata unavailable: %v", err)
	}
	return loc
}

func TestPeriodBoundsFirstOfMonth(t *testing.T) {
	loc := syd(t)
	q := model.Quota{ResetDay: 1, Timezone: "Australia/Sydney"}

	// Mid-month falls in the period that began on the 1st.
	start, end := PeriodBounds(q, time.Date(2026, time.March, 17, 9, 30, 0, 0, loc))
	if want := time.Date(2026, time.March, 1, 0, 0, 0, 0, loc); !start.Equal(want) {
		t.Errorf("start = %v, want %v", start, want)
	}
	if want := time.Date(2026, time.April, 1, 0, 0, 0, 0, loc); !end.Equal(want) {
		t.Errorf("end = %v, want %v", end, want)
	}

	// The instant the month rolls over belongs to the new period, which is
	// what makes an over-quota path become usable again on the 1st.
	start, _ = PeriodBounds(q, time.Date(2026, time.April, 1, 0, 0, 1, 0, loc))
	if want := time.Date(2026, time.April, 1, 0, 0, 0, 0, loc); !start.Equal(want) {
		t.Errorf("start after rollover = %v, want %v", start, want)
	}
}

func TestPeriodBoundsClampsShortMonths(t *testing.T) {
	loc := syd(t)
	q := model.Quota{ResetDay: 31, Timezone: "Australia/Sydney"}

	// February has no 31st; the boundary must clamp rather than roll into March.
	start, end := PeriodBounds(q, time.Date(2026, time.February, 15, 12, 0, 0, 0, loc))
	if want := time.Date(2026, time.January, 31, 0, 0, 0, 0, loc); !start.Equal(want) {
		t.Errorf("start = %v, want %v", start, want)
	}
	if want := time.Date(2026, time.February, 28, 0, 0, 0, 0, loc); !end.Equal(want) {
		t.Errorf("end = %v, want %v", end, want)
	}
}

func TestPeriodBoundsBeforeResetDay(t *testing.T) {
	loc := syd(t)
	q := model.Quota{ResetDay: 14, Timezone: "Australia/Sydney"}

	start, end := PeriodBounds(q, time.Date(2026, time.March, 3, 0, 0, 0, 0, loc))
	if want := time.Date(2026, time.February, 14, 0, 0, 0, 0, loc); !start.Equal(want) {
		t.Errorf("start = %v, want %v", start, want)
	}
	if want := time.Date(2026, time.March, 14, 0, 0, 0, 0, loc); !end.Equal(want) {
		t.Errorf("end = %v, want %v", end, want)
	}
}

func TestMeteredAddsEncapsulationOverhead(t *testing.T) {
	q := model.Quota{OverheadPerPacket: 60, Calibration: 100}
	// 1000 packets of 1000 bytes payload each: the carrier sees the 60 bytes
	// of WireGuard, UDP and IP headers per packet that the interface counter
	// never reports.
	if got, want := Metered(1_000_000, 1000, q), int64(1_060_000); got != want {
		t.Errorf("Metered = %d, want %d", got, want)
	}
}

func TestMeteredCalibration(t *testing.T) {
	q := model.Quota{OverheadPerPacket: 0, Calibration: 110}
	if got, want := Metered(1000, 0, q), int64(1100); got != want {
		t.Errorf("Metered with calibration = %d, want %d", got, want)
	}
	// A zero or missing calibration must not silently zero the ledger.
	q.Calibration = 0
	if got, want := Metered(1000, 0, q), int64(1000); got != want {
		t.Errorf("Metered with unset calibration = %d, want %d", got, want)
	}
}

func meteredPath(limit, ceiling int64) model.PathConfig {
	return model.PathConfig{
		ID: 2, Name: "lte1", Metered: true,
		Quota: model.Quota{
			LimitBytes: limit, CeilingBytes: ceiling,
			ResetDay: 1, Timezone: "UTC", Calibration: 100, OverheadPerPacket: 60,
		},
	}
}

func TestEvaluateUnderQuota(t *testing.T) {
	d := Evaluate(meteredPath(60<<30, 0), 10<<30, store.Grant{}, false, time.Now())
	if d.Blocked || d.OverQuota {
		t.Errorf("path under quota should not be blocked: %+v", d)
	}
}

func TestEvaluateBlocksOverQuota(t *testing.T) {
	d := Evaluate(meteredPath(60<<30, 0), 61<<30, store.Grant{}, false, time.Now())
	if !d.Blocked || !d.OverQuota {
		t.Errorf("path over quota should be blocked: %+v", d)
	}
	if d.Reason == "" {
		t.Error("a blocked path should explain itself")
	}
}

func TestEvaluateGrantAllowsOverage(t *testing.T) {
	now := time.Now()
	g := store.Grant{PathID: 2, Until: now.Add(time.Hour).Unix(), ExtraBytes: 5 << 30, StartBytes: 61 << 30}
	d := Evaluate(meteredPath(60<<30, 0), 62<<30, g, true, now)
	if d.Blocked {
		t.Errorf("a live approval should let traffic through: %+v", d)
	}
	if !d.OverQuota {
		t.Error("the path is still over quota even while approved")
	}
}

func TestEvaluateGrantExpires(t *testing.T) {
	now := time.Now()
	g := store.Grant{PathID: 2, Until: now.Add(-time.Minute).Unix(), StartBytes: 61 << 30}
	d := Evaluate(meteredPath(60<<30, 0), 62<<30, g, true, now)
	if !d.Blocked {
		t.Error("an expired approval must stop allowing overage")
	}
}

func TestEvaluateGrantExhaustsByBytes(t *testing.T) {
	now := time.Now()
	g := store.Grant{PathID: 2, Until: now.Add(time.Hour).Unix(), ExtraBytes: 1 << 30, StartBytes: 61 << 30}
	d := Evaluate(meteredPath(60<<30, 0), 63<<30, g, true, now)
	if !d.Blocked {
		t.Error("an approval capped in bytes must stop once those bytes are spent")
	}
}

func TestEvaluateCeilingOverridesGrant(t *testing.T) {
	now := time.Now()
	g := store.Grant{PathID: 2, Until: now.Add(24 * time.Hour).Unix(), StartBytes: 61 << 30}
	d := Evaluate(meteredPath(60<<30, 70<<30), 71<<30, g, true, now)
	if !d.Blocked {
		t.Error("the absolute ceiling must override even a live approval")
	}
}

func TestEvaluateUnmeteredPathNeverBlocks(t *testing.T) {
	p := model.PathConfig{ID: 1, Name: "nbn"}
	d := Evaluate(p, 1<<40, store.Grant{}, false, time.Now())
	if d.Blocked {
		t.Error("an unmetered path has no quota to exceed")
	}
}
