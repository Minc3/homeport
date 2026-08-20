package web

import (
	"strings"
	"testing"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/sysx"
)

func linkerConfig() model.Config {
	cfg := model.Defaults()
	cfg.Overlay.Subnet = "10.99.0.0/24"
	cfg.BackendLAN = "10.1.1.3"
	cfg.Linkers = []model.Linker{
		{Name: "gs1", OverlayIP: "10.99.0.3", LanIP: "10.1.1.4", Enabled: true},
	}
	return cfg
}

func TestValidLinkerIsAccepted(t *testing.T) {
	cfg := linkerConfig()
	if err := validate(&cfg); err != nil {
		t.Fatalf("valid linker rejected: %v", err)
	}
}

// Without a subnet the frontend routes only the backend's /32 down the tunnel,
// so a linker address is unroutable. Accepting the row would leave the operator
// with a configured host that silently receives nothing.
func TestLinkerRejectedWithoutAnOverlaySubnet(t *testing.T) {
	cfg := linkerConfig()
	cfg.Overlay.Subnet = ""
	err := validate(&cfg)
	if err == nil {
		t.Fatal("a linker was accepted on a site with no overlay subnet")
	}
	if !strings.Contains(err.Error(), "subnet") {
		t.Errorf("error should name the subnet, got: %v", err)
	}
}

// Two routes for the same destination, where whichever the backend installed
// last silently wins.
func TestTwoLinkersCannotClaimTheSameOverlayAddress(t *testing.T) {
	cfg := linkerConfig()
	cfg.Linkers = append(cfg.Linkers,
		model.Linker{Name: "gs2", OverlayIP: "10.99.0.3", LanIP: "10.1.1.5", Enabled: true})
	if err := validate(&cfg); err == nil {
		t.Fatal("two linkers on one overlay address were accepted")
	}
}

// The frontend would have no route for it, so every request to that service
// would be DNAT'd into a black hole.
func TestLinkerOutsideTheOverlaySubnetIsRejected(t *testing.T) {
	cfg := linkerConfig()
	cfg.Linkers[0].OverlayIP = "10.50.0.3"
	if err := validate(&cfg); err == nil {
		t.Fatal("a linker outside the overlay subnet was accepted")
	}
}

func TestLinkerCannotClaimTheBackendsOverlayAddress(t *testing.T) {
	cfg := linkerConfig()
	cfg.Linkers[0].OverlayIP = cfg.Overlay.BackendIP
	if err := validate(&cfg); err == nil {
		t.Fatal("a linker claiming the backend's overlay address was accepted")
	}
}

// The two addresses are easy to transpose and the mistake produces a route
// pointing at the address it is meant to reach.
func TestLinkerCannotUseOneAddressForBoth(t *testing.T) {
	cfg := linkerConfig()
	cfg.Linkers[0].LanIP = cfg.Linkers[0].OverlayIP
	if err := validate(&cfg); err == nil {
		t.Fatal("a linker with the same overlay and LAN address was accepted")
	}
}

// Its config cannot be generated without it, and the operator would be back to
// assembling the file by hand - which is the thing this replaces.
func TestLinkersRequireTheBackendsLANAddress(t *testing.T) {
	cfg := linkerConfig()
	cfg.BackendLAN = ""
	if err := validate(&cfg); err == nil {
		t.Fatal("linkers were accepted with no backend LAN address")
	}
}

// Being inside the subnet only means the frontend can route it down the tunnel.
// The backend still has to know which neighbour holds it, and it only learns
// that from the linker list - so publishing to an address with no linker behind
// it DNATs every request to a host the backend drops on the floor.
func TestPublishingToAnAddressWithNoLinkerIsRejected(t *testing.T) {
	cfg := linkerConfig()
	cfg.Services = append(cfg.Services, model.Service{
		Name: "gmod2", Proto: "udp", Port: 27016, Target: "10.99.0.9", Enabled: true,
	})
	err := validate(&cfg)
	if err == nil {
		t.Fatal("a service was published to an address with no linker configured")
	}
	if !strings.Contains(err.Error(), "linker") {
		t.Errorf("error should point at the linker list, got: %v", err)
	}
}

func TestPublishingToAConfiguredLinkerIsAccepted(t *testing.T) {
	cfg := linkerConfig()
	cfg.Services = append(cfg.Services, model.Service{
		Name: "gmod2", Proto: "udp", Port: 27016, Target: "10.99.0.3", Enabled: true,
	})
	if err := validate(&cfg); err != nil {
		t.Fatalf("publishing to a configured linker was rejected: %v", err)
	}
}

// Every existing site has no linkers, and its config must keep validating
// exactly as it did - including services published to the backend by default.
func TestASiteWithNoLinkersIsUnaffected(t *testing.T) {
	cfg := model.Defaults()
	if err := validate(&cfg); err != nil {
		t.Fatalf("a site with no linkers no longer validates: %v", err)
	}
}

// The table belongs to that host's own namespace, so the portal cannot know
// what else is using it there - but it can refuse the numbers this system is
// definitely using at the far end, which are the ones an operator reaching for
// a number is most likely to pick.
func TestLinkerTableCannotCollideWithThisSystemsOwn(t *testing.T) {
	for _, tbl := range []int{sysx.ReturnTable, sysx.ControlTable, 101} {
		cfg := linkerConfig()
		cfg.Linkers[0].Table = tbl
		if err := validate(&cfg); err == nil {
			t.Errorf("routing table %d was accepted, but this system already uses it", tbl)
		}
	}
}

// 253-255 are default, main and local. Writing a default route into one of
// those would redirect the whole host.
func TestLinkerTableMustBeInRange(t *testing.T) {
	for _, tbl := range []int{-1, 253, 254, 255, 300} {
		cfg := linkerConfig()
		cfg.Linkers[0].Table = tbl
		if err := validate(&cfg); err == nil {
			t.Errorf("routing table %d was accepted", tbl)
		}
	}
}

// Zero means the default, which is what every existing row unmarshals as.
func TestLinkerTableZeroMeansTheDefault(t *testing.T) {
	cfg := linkerConfig()
	cfg.Linkers[0].Table = 0
	if err := validate(&cfg); err != nil {
		t.Fatalf("an unset table should be accepted: %v", err)
	}
	if got := cfg.Linkers[0].TableOr(sysx.DefaultLinkerTable); got != sysx.DefaultLinkerTable {
		t.Errorf("TableOr resolved to %d", got)
	}
}

// The whole point of making it configurable: a host that already uses 200 for
// its own policy routing must be able to say so.
func TestALinkerMayUseANonDefaultTable(t *testing.T) {
	cfg := linkerConfig()
	cfg.Linkers[0].Table = 220
	if err := validate(&cfg); err != nil {
		t.Fatalf("a non-default table should be accepted: %v", err)
	}
}
