package web

import (
	"strings"
	"testing"

	"github.com/quinlan102/homeport/internal/model"
)

func withSubnet() model.Config {
	cfg := model.Defaults()
	cfg.Overlay.Subnet = "10.99.0.0/24"
	return cfg
}

// withLinkers is withSubnet plus the two extra hosts the egress tests assign
// networks to. They have to be declared now: a row naming a host that is not a
// configured linker is rejected rather than delivered nowhere in silence.
func withLinkers() model.Config {
	cfg := withSubnet()
	cfg.BackendLAN = "10.1.1.3"
	cfg.Linkers = []model.Linker{
		{Name: "gs1", OverlayIP: "10.99.0.3", LanIP: "10.1.1.4", Enabled: true},
		{Name: "web", OverlayIP: "10.99.0.4", LanIP: "10.1.1.5", Enabled: true},
	}
	return cfg
}

// Publishing to an address the frontend has no route to would DNAT every
// request into a black hole, and a published port that accepts nothing looks
// exactly like the service being down at the far end. Fail closed instead, and
// say which setting is missing.
func TestServiceTargetNeedsAnOverlaySubnet(t *testing.T) {
	cfg := model.Defaults() // no subnet: this site has no linkers
	cfg.Services[0].Target = "10.99.0.3"

	err := validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "overlay.subnet") {
		t.Fatalf("targeting another host without a subnet should be rejected and name the fix, got %v", err)
	}
}

func TestServiceTargetMustBeInsideTheOverlaySubnet(t *testing.T) {
	cfg := withSubnet()
	cfg.Services[0].Target = "192.168.1.50" // a LAN address, not an overlay one

	err := validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "outside the overlay subnet") {
		t.Fatalf("a target outside the overlay range should be rejected, got %v", err)
	}
}

// Being inside the subnet was once enough on its own. It no longer is, and the
// tightening is deliberate: the subnet only says the *frontend* can route the
// address down the tunnel, while the backend still has to know which neighbour
// holds it - and it learns that solely from the linker list. A target with no
// linker behind it therefore still black-holes, one hop further along than the
// case above, so it is rejected for the same reason.
func TestServiceTargetInsideTheSubnetIsAcceptedWhenALinkerHoldsIt(t *testing.T) {
	cfg := withSubnet()
	cfg.BackendLAN = "10.1.1.3"
	cfg.Linkers = []model.Linker{
		{Name: "gs1", OverlayIP: "10.99.0.3", LanIP: "10.1.1.4", Enabled: true},
	}
	cfg.Services[0].Target = "10.99.0.3"

	if err := validate(&cfg); err != nil {
		t.Fatalf("a target inside the subnet with a linker holding it should be accepted: %v", err)
	}
}

// The backend is always reachable, subnet or not - it is the one host that
// existed before any of this.
func TestServiceMayNameTheBackendWithoutASubnet(t *testing.T) {
	cfg := model.Defaults()
	cfg.Services[0].Target = cfg.Overlay.BackendIP

	if err := validate(&cfg); err != nil {
		t.Fatalf("naming the backend explicitly should always be valid: %v", err)
	}
}

// The distinction that makes the whole host scoping work. Docker's default
// bridge is 172.17.0.0/16 on every machine, so the same CIDR on two hosts is
// ordinary and must stay legal; the same CIDR twice on one host is a mistake
// that would generate the mark and the SNAT twice.
func TestSameEgressNetworkOnTwoHostsIsAllowed(t *testing.T) {
	cfg := withLinkers()
	cfg.Egress.Sources = []model.EgressSource{
		{Name: "gmod box", Host: "10.99.0.3", CIDR: "172.17.0.0/16", Enabled: true},
		{Name: "web box", Host: "10.99.0.4", CIDR: "172.17.0.0/16", Enabled: true},
	}

	if err := validate(&cfg); err != nil {
		t.Fatalf("the same bridge subnet on two different hosts is normal: %v", err)
	}
}

func TestSameEgressNetworkTwiceOnOneHostIsRejected(t *testing.T) {
	cfg := withLinkers()
	cfg.Egress.Sources = []model.EgressSource{
		{Name: "bridge", Host: "10.99.0.3", CIDR: "172.17.0.0/16", Enabled: true},
		{Name: "bridge again", Host: "10.99.0.3", CIDR: "172.17.0.0/16", Enabled: true},
	}

	err := validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "twice for the same host") {
		t.Fatalf("a repeated network on one host should be rejected, got %v", err)
	}
}

// A blank owner means the backend, so a blank row and a row naming the backend
// are the same row and collide with each other.
func TestUnownedAndBackendOwnedRowsCollide(t *testing.T) {
	cfg := withSubnet()
	cfg.Egress.Sources = []model.EgressSource{
		{Name: "bridge", CIDR: "172.17.0.0/16", Enabled: true},
		{Name: "bridge again", Host: cfg.Overlay.BackendIP, CIDR: "172.17.0.0/16", Enabled: true},
	}

	err := validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "twice for the same host") {
		t.Fatalf("a blank owner is the backend, so these are the same row, got %v", err)
	}
}

// An owner nothing can route to would silently own nothing: its rows would be
// filtered out of every push and the operator would see rules they configured
// having no effect anywhere.
func TestEgressOwnerMustBeAnOverlayAddress(t *testing.T) {
	cfg := withSubnet()
	cfg.Egress.Sources = []model.EgressSource{
		{Name: "bridge", Host: "192.168.1.50", CIDR: "172.17.0.0/16", Enabled: true},
	}

	err := validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "not in the overlay range") {
		t.Fatalf("an owner outside the overlay range should be rejected, got %v", err)
	}
}

// Everything above is an addon. The shipped configuration names no targets and
// no owners, and must validate untouched.
func TestDefaultsStillValidateWithNoLinkerSettings(t *testing.T) {
	cfg := model.Defaults()
	if err := validate(&cfg); err != nil {
		t.Fatalf("the shipped defaults must validate unchanged: %v", err)
	}
	if cfg.Overlay.Subnet != "" {
		t.Errorf("defaults must not configure an overlay subnet, got %q", cfg.Overlay.Subnet)
	}
	for _, s := range cfg.Services {
		if s.Target != "" {
			t.Errorf("default service %s must not name a target, got %q", s.Name, s.Target)
		}
	}
}
