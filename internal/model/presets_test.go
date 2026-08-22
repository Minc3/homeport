package model

import (
	"fmt"
	"strings"
	"testing"
)

// The standard preset is the shipped tuning. If the two drift, a fresh install
// opens the portal showing "Custom" for numbers nobody chose, and the preset a
// site picks to go back to the default would change its behaviour.
func TestStandardPresetIsTheShippedTuning(t *testing.T) {
	std := presetByName(t, PresetStandard)
	if !std.Matches(Defaults().Probe) {
		t.Errorf("standard preset %+v does not match Defaults().Probe %+v", std, Defaults().Probe)
	}
}

// The presets exist to trade detection time against false failovers, so they
// must actually be ordered by detection time, and the figure quoted in each
// note must be the one the numbers give, because the note is the only place
// the trade-off is explained.
func TestPresetsAreOrderedByDetectionTimeAndTheNotesQuoteIt(t *testing.T) {
	presets := DetectionPresets()
	var prev float64
	for i, d := range presets {
		var p ProbeConfig
		d.Apply(&p)
		secs := p.DetectSeconds()
		if i > 0 && secs <= prev {
			t.Errorf("preset %s detects in %.2fs, not slower than the one before it (%.2fs)", d.Name, secs, prev)
		}
		prev = secs
		// Rounded half up in integer milliseconds: 2550ms is "2.6s", and a
		// float %.1f would print 2.5 because 2.55 is not exact in binary.
		tenths := ((d.FailThreshold-1)*d.ActiveIntervalMs + d.TimeoutMs + 50) / 100
		quoted := "about " + strings.TrimSuffix(fmt.Sprintf("%d.%d", tenths/10, tenths%10), ".0") + "s"
		if !strings.Contains(d.Note, quoted) {
			t.Errorf("preset %s note does not quote its own detection time %q:\n%s", d.Name, quoted, d.Note)
		}
		if d.Note == "" {
			t.Errorf("preset %s has no note; the trade-off has to be stated where it is chosen", d.Name)
		}
	}
}

// Every preset has to pass the portal's own validation, or choosing one would
// produce a form that cannot be saved. The bounds are repeated here rather than
// imported because model cannot depend on web.
func TestPresetsAreWithinTheValidatedBounds(t *testing.T) {
	standby := Defaults().Probe.StandbyIntervalMs
	for _, d := range DetectionPresets() {
		if d.ActiveIntervalMs < 50 || d.TimeoutMs < 50 || d.FailThreshold < 1 || d.WindowSize < 5 {
			t.Errorf("preset %s = %+v is outside the validated bounds", d.Name, d)
		}
		if d.ActiveIntervalMs > standby {
			t.Errorf("preset %s probes the active path slower than the shipped standby cadence (%dms)", d.Name, standby)
		}
	}
}

// DetectSeconds is the floor under the lag spike: the first lost probe, the
// rest of the streak at the active interval, and the last one's timeout.
func TestDetectSecondsCountsTheStreakAndTheLastTimeout(t *testing.T) {
	p := ProbeConfig{ActiveIntervalMs: 250, TimeoutMs: 800, FailThreshold: 8}
	if got := p.DetectSeconds(); got != 2.55 {
		t.Errorf("DetectSeconds = %v, want 2.55", got)
	}
	one := ProbeConfig{ActiveIntervalMs: 250, TimeoutMs: 800, FailThreshold: 1}
	if got := one.DetectSeconds(); got != 0.8 {
		t.Errorf("a single-loss threshold should be just the timeout, got %v", got)
	}
}

func presetByName(t *testing.T, name string) DetectionPreset {
	t.Helper()
	for _, d := range DetectionPresets() {
		if d.Name == name {
			return d
		}
	}
	t.Fatalf("no preset named %q", name)
	return DetectionPreset{}
}
