package engine

import (
	"testing"

	"github.com/quinlan102/homeport/internal/model"
)

// The backend installs a route for everything it is sent, so what is sent is
// the whole of the policy.
func TestEnabledLinkersArePushedToTheBackend(t *testing.T) {
	cfg := model.Defaults()
	cfg.Overlay.Subnet = "10.99.0.0/24"
	cfg.Linkers = []model.Linker{
		{Name: "gs1", OverlayIP: "10.99.0.3", LanIP: "10.1.1.4", Enabled: true},
	}

	bc := backendConfig(cfg)

	if len(bc.Linkers) != 1 {
		t.Fatalf("pushed %d linkers, want 1", len(bc.Linkers))
	}
	if bc.Linkers[0].OverlayIP != "10.99.0.3" || bc.Linkers[0].LanIP != "10.1.1.4" {
		t.Errorf("pushed %+v", bc.Linkers[0])
	}
}

// Unticking a linker is how a host is taken out of service. If its route were
// still pushed the backend would go on forwarding to a machine the operator
// has deliberately withdrawn.
func TestDisabledLinkersAreNotPushed(t *testing.T) {
	cfg := model.Defaults()
	cfg.Overlay.Subnet = "10.99.0.0/24"
	cfg.Linkers = []model.Linker{
		{Name: "gs1", OverlayIP: "10.99.0.3", LanIP: "10.1.1.4", Enabled: false},
	}

	bc := backendConfig(cfg)

	if len(bc.Linkers) != 0 {
		t.Errorf("a disabled linker was pushed: %+v", bc.Linkers)
	}
}

// A site with none must send an empty list, so the backend installs nothing and
// its routing stays identical to a build with no linker support at all.
func TestNoLinkersMeansNothingPushed(t *testing.T) {
	cfg := model.Defaults()

	bc := backendConfig(cfg)

	if bc.Linkers != nil {
		t.Errorf("a site with no linkers pushed %+v", bc.Linkers)
	}
}
