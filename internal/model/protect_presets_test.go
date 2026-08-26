package model

import (
	"reflect"
	"testing"
)

// The Off preset must be exactly the shipped state: every limit at zero. A
// fresh install's protection section then reads "Off" rather than "Custom",
// which matters because all-zero is the state nobody chose and the dropdown
// must say so, and choosing Off must actually turn every limit off rather
// than leaving one behind.
func TestOffPresetIsTheShippedProtectState(t *testing.T) {
	off := protectPresetByName(t, ProtectPresetOff)
	want := Defaults().Protect
	got := want
	off.Apply(&got)
	if got.NewConnsPerSec != 0 || got.MaxConnsPerSource != 0 || got.PacketsPerSec != 0 ||
		got.QueriesPerSec != 0 || got.BlockSeconds != 0 {
		t.Errorf("Off preset leaves a limit set: %+v", got)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Off preset applied to the shipped config changes it: %+v, want %+v", got, want)
	}
}

// The presets exist to trade protection against room for clients sharing an
// address, so after Off they must actually be ordered from tightest to most
// generous in every limit. Block seconds is deliberately excluded: the most
// generous preset parks for the shortest time, because on a carrier NAT one
// parked address is every household behind it.
func TestProtectPresetsAreOrderedTightestFirstAfterOff(t *testing.T) {
	presets := ProtectPresets()
	if len(presets) < 2 || presets[0].Name != ProtectPresetOff {
		t.Fatalf("the first preset must be Off, got %+v", presets)
	}
	for i := 2; i < len(presets); i++ {
		prev, cur := presets[i-1], presets[i]
		for _, v := range []struct {
			what     string
			from, to int
		}{
			{"new connections per second", prev.NewConnsPerSec, cur.NewConnsPerSec},
			{"concurrent connections", prev.MaxConnsPerSource, cur.MaxConnsPerSource},
			{"packets per second", prev.PacketsPerSec, cur.PacketsPerSec},
			{"queries per second", prev.QueriesPerSec, cur.QueriesPerSec},
		} {
			if v.to <= v.from {
				t.Errorf("preset %s has %s = %d, not more generous than %s's %d",
					cur.Name, v.what, v.to, prev.Name, v.from)
			}
		}
		if cur.BlockSeconds > prev.BlockSeconds {
			t.Errorf("preset %s parks for %ds, longer than %s's %ds; the generous preset must park "+
				"for less, not more, because a parked shared address is every household behind it",
				cur.Name, cur.BlockSeconds, prev.Name, prev.BlockSeconds)
		}
	}
}

// Apply fills five boxes and nothing else. The dropdown must never flip the
// master switch, change an edge filtering toggle, or touch the regions: those
// are separate, deliberate acts, and a preset that armed the feature as a
// side effect would drop packets nobody asked it to.
func TestProtectPresetApplyTouchesOnlyTheFiveLimits(t *testing.T) {
	pr := ProtectConfig{
		Enabled:        true,
		DropInvalid:    true,
		DropBogusTCP:   true,
		DropSpoofed:    true,
		GeoLockSeconds: 120,
		Regions:        []GeoRegion{{Name: "oceania", CIDRs: []string{"1.128.0.0/11"}}},
	}
	protectPresetByName(t, ProtectPresetPublic).Apply(&pr)
	if !pr.Enabled || !pr.DropInvalid || !pr.DropBogusTCP || !pr.DropSpoofed {
		t.Errorf("a preset changed a switch it does not own: %+v", pr)
	}
	if pr.GeoLockSeconds != 120 || len(pr.Regions) != 1 {
		t.Errorf("a preset touched the region config: %+v", pr)
	}
}

func protectPresetByName(t *testing.T, name string) ProtectPreset {
	t.Helper()
	for _, p := range ProtectPresets() {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("no protect preset named %q", name)
	return ProtectPreset{}
}
