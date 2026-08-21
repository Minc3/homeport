package web

import (
	"testing"

	"github.com/quinlan102/homeport/internal/model"
)

func TestValidateRejectsBadOverlayPorts(t *testing.T) {
	cfg := model.Defaults()
	cfg.Overlay.ProbePort = 0
	if err := validate(&cfg); err == nil {
		t.Error("an unset probe port should be rejected, not silently bound to a random one")
	}

	cfg = model.Defaults()
	cfg.Overlay.ControlPort = 70000
	if err := validate(&cfg); err == nil {
		t.Error("an out-of-range control port should be rejected")
	}

	cfg = model.Defaults()
	cfg.Overlay.ControlPort = cfg.Overlay.ProbePort
	if err := validate(&cfg); err == nil {
		t.Error("probe and control cannot share a port; one of the two listeners would fail")
	}
}

// A PUT carries the whole config blob, and two fields inside it belong to the
// server rather than the page that sent it. Overlay is bootstrap-owned. Mode
// is dashboard-owned and, worse, invisible on the settings page: a tab left
// open across a revert still holds mode "armed" in its copy, and applying it
// would re-arm the frontend and clear the revert latch on a plain settings
// save. The client's values must be discarded whatever they say.
func TestPutConfigCannotChangeModeOrOverlay(t *testing.T) {
	body := model.Defaults()
	body.Mode = model.ModeArmed
	body.Overlay.BackendIP = "10.99.0.99"

	current := model.Defaults()
	current.Mode = model.ModeObserve

	pinServerOwnedFields(&body, current)
	if body.Mode != model.ModeObserve {
		t.Errorf("mode = %q after pinning, want the engine's %q", body.Mode, model.ModeObserve)
	}
	if body.Overlay.BackendIP != current.Overlay.BackendIP {
		t.Errorf("overlay backend IP = %q after pinning, want the engine's %q", body.Overlay.BackendIP, current.Overlay.BackendIP)
	}
}
