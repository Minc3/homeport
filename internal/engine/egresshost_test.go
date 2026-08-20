package engine

import (
	"testing"

	"github.com/quinlan102/homeport/internal/model"
)

func egressCfg(sources ...model.EgressSource) model.Config {
	cfg := model.Defaults()
	cfg.Overlay.Subnet = "10.99.0.0/24"
	cfg.Frontend.PublicIface = "eth0"
	cfg.Frontend.BackendEgress = true
	cfg.Egress.Sources = sources
	return cfg
}

func has(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// The reason the row has an owner at all. Docker's default bridge is
// 172.17.0.0/16 on every machine, and the allocator walks 172.18, 172.19 and so
// on in the same order on each one - so several hosts routinely hold the
// identical subnet. A global list would have the backend pulling a linker's
// containers onto the tunnel, silently and through the LTE quota.
func TestBackendReceivesOnlyItsOwnEgressNetworks(t *testing.T) {
	cfg := egressCfg(
		model.EgressSource{Name: "backend bridge", CIDR: "172.17.0.0/16", Enabled: true},
		model.EgressSource{Name: "gmod box", Host: "10.99.0.3", CIDR: "172.17.0.0/16", Enabled: true},
		model.EgressSource{Name: "web box", Host: "10.99.0.4", CIDR: "172.18.0.0/16", Enabled: true},
	)

	got := backendConfig(cfg).EgressCIDRs
	if len(got) != 1 || got[0] != "172.17.0.0/16" {
		t.Fatalf("backend should receive only its own network, got %v", got)
	}
}

// An unowned row means the backend, because that is what every row meant before
// linkers existed. Upgrading a site must not move its egress configuration.
func TestUnownedEgressRowStillMeansTheBackend(t *testing.T) {
	cfg := egressCfg(model.EgressSource{Name: "bridge", CIDR: "172.20.0.0/24", Enabled: true})
	cfg.Overlay.Subnet = "" // a site that has never heard of linkers

	got := backendConfig(cfg).EgressCIDRs
	if !has(got, "172.20.0.0/24") {
		t.Fatalf("an unowned row must still reach the backend, got %v", got)
	}
}

// Naming the backend explicitly has to mean the same thing as leaving it blank,
// or the portal would offer a choice that quietly changed behaviour.
func TestNamingTheBackendExplicitlyIsTheSameAsLeavingItBlank(t *testing.T) {
	cfg := egressCfg(model.EgressSource{
		Name: "bridge", Host: "10.99.0.2", CIDR: "172.21.0.0/24", Enabled: true,
	})

	got := backendConfig(cfg).EgressCIDRs
	if !has(got, "172.21.0.0/24") {
		t.Fatalf("a row naming the backend must reach it, got %v", got)
	}
}

// The existing guard, still standing: pulling a network onto the tunnel with no
// source NAT waiting at the far end sends its traffic somewhere it cannot be
// answered, which is worse than leaving it alone because it fails silently.
func TestEgressNetworksAreWithheldWhileTheFeatureIsOff(t *testing.T) {
	cfg := egressCfg(model.EgressSource{Name: "bridge", CIDR: "172.22.0.0/24", Enabled: true})
	cfg.Frontend.BackendEgress = false

	if got := backendConfig(cfg).EgressCIDRs; len(got) != 0 {
		t.Fatalf("no networks should be sent while backend egress is off, got %v", got)
	}
}

// A disabled row is configuration somebody kept, not configuration they want.
func TestDisabledEgressRowsAreNotSent(t *testing.T) {
	cfg := egressCfg(model.EgressSource{Name: "bridge", CIDR: "172.23.0.0/24", Enabled: false})

	if got := backendConfig(cfg).EgressCIDRs; len(got) != 0 {
		t.Fatalf("a disabled row should not be sent, got %v", got)
	}
}

// The overlay subnet has to reach the backend, because its return rule needs it:
// a linker's outbound traffic arrives over the LAN as a new connection carrying
// no mark, so the source range is the only thing that identifies it.
func TestBackendIsToldTheOverlaySubnet(t *testing.T) {
	cfg := egressCfg()
	if got := backendConfig(cfg).Overlay.Subnet; got != "10.99.0.0/24" {
		t.Fatalf("backend should be told the overlay subnet, got %q", got)
	}

	cfg.Overlay.Subnet = ""
	if got := backendConfig(cfg).Overlay.Subnet; got != "" {
		t.Fatalf("a site with no linkers should be told no subnet, got %q", got)
	}
}
