package engine

import (
	"bytes"
	"log/slog"
	"math"
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
		// Every ordered comparison against NaN is false, so a guard written as
		// `cal > 0 && (math.IsNaN(cal) || ...)` short-circuits before the IsNaN
		// branch is ever reached and this case goes silent. That is how
		// tightening the zero guard broke it once already, and Metered turns a
		// NaN into 100 without a word.
		{"not a number at all", math.NaN()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			// A resolvable zone on every path, so the only thing this case can
			// report is the calibration. The shared fixture leaves Timezone
			// blank, which no real configuration does - Defaults sets it and
			// validate fills it - and which is itself reported, below.
			// Metered, because the report covers only paths that bill: nothing
			// it looks at is read for a path that does not. And a resolvable
			// zone on every one, so the only thing this case can report is the
			// calibration.
			for i := range cfg.Paths {
				cfg.Paths[i].Metered = true
				cfg.Paths[i].Quota.Timezone = "UTC"
			}
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
				cfg.Paths[i].Metered = true
				cfg.Paths[i].Quota = tc.q
				cfg.Paths[i].Quota.Timezone = "UTC"
			}
			var buf bytes.Buffer
			reportQuotaSubstitutions(slog.New(slog.NewTextHandler(&buf, nil)), cfg)
			if buf.Len() != 0 {
				t.Errorf("a configuration the portal accepts produced a report:\n%s", buf.String())
			}
		})
	}
}

// The timezone is the third value reportQuotaSubstitutions covers, and the one
// with the worst outcome of the three. quota.Location answers a zone it cannot
// resolve with time.UTC and says nothing, and that decides which billing period
// every metered byte lands in: eleven hours out for this deployment, so the rows
// land under a period_start the quota read never asks for, the current period
// reads empty, and the cap never trips.
//
// Embedding tzdata removes one of the three routes here, a host with no database
// at all. These are the other two, and both are a stored blob nothing
// re-validates on load.
func TestAnUnresolvableStoredTimezoneIsReportedAtLoad(t *testing.T) {
	for _, tc := range []struct {
		name string
		tz   string
	}{
		// A rename between tzdata releases, or a typo saved before validate
		// checked the zone.
		{"a zone this build cannot resolve", "Mars/Olympus_Mons"},
		// validate fills a blank with the deployment's own zone on save, so a
		// stored blank predates that - and Location reads it as UTC, not as the
		// default, which is a ten hour difference nobody is told about.
		{"blank, which Location reads as UTC rather than the default", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			for i := range cfg.Paths {
				cfg.Paths[i].Metered = true
				cfg.Paths[i].Quota.Timezone = "UTC"
			}
			cfg.Paths[1].Quota.Timezone = tc.tz

			var buf bytes.Buffer
			reportQuotaSubstitutions(slog.New(slog.NewTextHandler(&buf, nil)), cfg)
			out := buf.String()
			if !strings.Contains(out, "timezone") {
				t.Fatalf("a stored timezone of %q was substituted with nothing said; the journal held:\n%s", tc.tz, out)
			}
			if !strings.Contains(out, cfg.Paths[1].Name) {
				t.Errorf("the report does not name the path, so an operator cannot tell which one to correct:\n%s", out)
			}
			if strings.Count(out, "timezone") != 1 {
				t.Errorf("want exactly one path reported, got:\n%s", out)
			}
		})
	}
}

// The shipped configuration reports nothing at all, and that is the property
// deciding whether any of the lines above are worth reading.
//
// model.Defaults() ships `main` unmetered with a zero-valued Quota, so its
// timezone is blank: not a stored value being ignored, a value nobody chose.
// Reporting it put a Warn on every fresh install, on every start until somebody
// saved settings, telling the operator to install a tzdata package this binary
// now embeds. That is how an operator learns to ignore the one occurrence that
// means the ledger was written wrong.
func TestTheShippedConfigurationReportsNothing(t *testing.T) {
	var buf bytes.Buffer
	reportQuotaSubstitutions(slog.New(slog.NewTextHandler(&buf, nil)), model.Defaults())
	if buf.Len() != 0 {
		t.Errorf("a fresh install produced a report, and it would do so on every start:\n%s", buf.String())
	}
}

// And an unmetered path is not reported however wrong its values are, because
// nothing is billed for it: addUsageBatch returns before quota.Metered and
// PeriodBounds are ever reached.
func TestAnUnmeteredPathIsNotReported(t *testing.T) {
	cfg := testConfig()
	for i := range cfg.Paths {
		cfg.Paths[i].Metered = false
		cfg.Paths[i].Quota.Timezone = "Mars/Olympus_Mons"
		cfg.Paths[i].Quota.Calibration = 5
		cfg.Paths[i].Quota.OverheadPerPacket = -1
	}
	var buf bytes.Buffer
	reportQuotaSubstitutions(slog.New(slog.NewTextHandler(&buf, nil)), cfg)
	if buf.Len() != 0 {
		t.Errorf("an unmetered path was reported, and nothing is billed for one:\n%s", buf.String())
	}
}
