package engine

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/quota"
)

// The gap between the two places these bounds are enforced.
//
// web.validate rejects an out-of-range multiplier with a message an operator
// can act on, and it runs only on PUT /api/config. quota.Metered clamps
// whatever it is handed, silently, because there is nobody at a socket to tell.
// Between them sits the stored blob: store.LoadConfig unmarshals it,
// model.Normalise does not touch Quota, and nothing re-validates it - so a
// value written by an older build is seen by neither.
//
// That is not cosmetic, because MinCalibration is newer than the field it
// bounds. A site that saved 5 under a build whose only rule was "above zero"
// billed at 5% before this change and bills at 100% after it, a factor of
// twenty, from one restart to the next. Saying so at load is the only notice
// that reaches an operator who has not opened the settings form.
func TestAnOutOfRangeStoredCalibrationIsReportedAtLoad(t *testing.T) {
	for _, tc := range []struct {
		name string
		cal  float64
	}{
		// The silent direction: a percent typed as a fraction under-bills
		// twentyfold and the quota never trips.
		{"below the floor", 5},
		{"above the ceiling", quota.MaxCalibration + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.Paths[1].Quota.Calibration = tc.cal

			var buf bytes.Buffer
			reportQuotaSubstitutions(slog.New(slog.NewTextHandler(&buf, nil)), cfg)

			out := buf.String()
			if !strings.Contains(out, "calibration") {
				t.Fatalf("a stored calibration of %v was substituted with nothing said; the journal held:\n%s", tc.cal, out)
			}
			if !strings.Contains(out, cfg.Paths[1].Name) {
				t.Errorf("the report does not name the path, so an operator cannot tell which one to correct:\n%s", out)
			}
		})
	}
}

// A configuration the portal accepted must produce no line at all, or the one
// that means the ledger is being written differently than it was is buried
// among lines that mean nothing.
//
// Zero is the case worth pinning: validate has always read it as "unset" and
// filled in 100, so it is a value nobody chose rather than one being ignored,
// and reporting it would fire on every path of any deployment predating the
// field.
func TestAnAcceptableStoredCalibrationIsNotReported(t *testing.T) {
	for _, tc := range []struct {
		name string
		q    model.Quota
	}{
		{"the shipped values", model.Quota{Calibration: 100, OverheadPerPacket: 60}},
		{"unset, which validate reads as 100", model.Quota{Calibration: 0, OverheadPerPacket: 60}},
		// validate runs `if Calibration <= 0 { = 100 }` before its range check,
		// so a negative value saves cleanly and means 100 everywhere, exactly
		// as an unset one does. The first version of this report fired on it
		// with a hint saying the settings form would refuse to save, which is
		// the one thing that is not true of it.
		{"negative, which validate also reads as 100", model.Quota{Calibration: -5, OverheadPerPacket: 60}},
		{"no overhead, which is a real setting", model.Quota{Calibration: 100, OverheadPerPacket: 0}},
		{"both boundaries", model.Quota{Calibration: quota.MinCalibration, OverheadPerPacket: quota.MaxOverheadPerPacket}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			for i := range cfg.Paths {
				cfg.Paths[i].Quota = tc.q
			}
			var buf bytes.Buffer
			reportQuotaSubstitutions(slog.New(slog.NewTextHandler(&buf, nil)), cfg)
			if buf.Len() != 0 {
				t.Errorf("a configuration the portal accepts produced a report:\n%s", buf.String())
			}
		})
	}
}
