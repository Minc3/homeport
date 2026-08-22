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
	want := Defaults().Probe
	got := want
	std.Apply(&got)
	if got != want {
		t.Errorf("standard preset applied to the defaults changes them: %+v, want %+v", got, want)
	}
}

// The presets exist to trade detection time against false failovers, so they
// must actually be ordered by detection time, and the figure quoted in each
// note must be the one DetectMs gives for its numbers, because the note is the
// only place the trade-off is explained. Whether every preset also survives
// validation is web's question, and web/validate_test.go asks it.
func TestPresetsAreOrderedByDetectionTimeAndTheNotesQuoteIt(t *testing.T) {
	presets := DetectionPresets()
	prev := -1
	for _, d := range presets {
		var p ProbeConfig
		d.Apply(&p)
		ms := p.DetectMs()
		if ms <= prev {
			t.Errorf("preset %s detects in %dms, not slower than the one before it (%dms)", d.Name, ms, prev)
		}
		prev = ms
		// Rounded half up in integer milliseconds: 2550ms is "2.6s", and a
		// float %.1f would print 2.5 because 2.55 is not exact in binary.
		tenths := (ms + 50) / 100
		quoted := "about " + strings.TrimSuffix(fmt.Sprintf("%d.%d", tenths/10, tenths%10), ".0") + "s"
		if !strings.Contains(d.Note, quoted) {
			t.Errorf("preset %s note does not quote its own detection time %q:\n%s", d.Name, quoted, d.Note)
		}
	}
}

// Validation refuses a standby cadence faster than the active one. A preset
// that raised the active interval past a site's standby interval would hand
// the operator a form that cannot be saved, with the error naming a field the
// dropdown never mentioned, so Apply lifts the standby interval with it.
func TestApplyLiftsAShortStandbyIntervalWithTheActiveOne(t *testing.T) {
	p := Defaults().Probe
	p.StandbyIntervalMs = 250
	presetByName(t, PresetRelaxed).Apply(&p)
	if p.StandbyIntervalMs != p.ActiveIntervalMs {
		t.Errorf("standby = %d after applying relaxed (active %d); it must be lifted to at least the active interval",
			p.StandbyIntervalMs, p.ActiveIntervalMs)
	}
	p = Defaults().Probe
	presetByName(t, PresetRelaxed).Apply(&p)
	if p.StandbyIntervalMs != Defaults().Probe.StandbyIntervalMs {
		t.Errorf("a standby interval already slower than the new active one was changed to %d", p.StandbyIntervalMs)
	}
}

// DetectMs is the floor under the lag spike: the first lost probe, the rest of
// the streak at the active interval, and the last one's timeout.
func TestDetectMsCountsTheStreakAndTheLastTimeout(t *testing.T) {
	p := ProbeConfig{ActiveIntervalMs: 250, TimeoutMs: 800, FailThreshold: 8}
	if got := p.DetectMs(); got != 2550 {
		t.Errorf("DetectMs = %v, want 2550", got)
	}
	one := ProbeConfig{ActiveIntervalMs: 250, TimeoutMs: 800, FailThreshold: 1}
	if got := one.DetectMs(); got != 800 {
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
