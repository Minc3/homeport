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
