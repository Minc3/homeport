package engine

import (
	"net"
	"testing"
	"time"

	"github.com/quinlan102/homeport/internal/model"
)

// The portal colours the active badge green only while traffic is on the
// preferred path, and plain on any fallback. That rule has to come from the
// engine rather than being reimplemented in JavaScript, because a second
// definition of "preferred" is free to drift from the selector's own.
func TestStatusReportsPreferredPathSoThePortalNeedNotReimplementIt(t *testing.T) {
	cfg := testConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthUp, 2: model.HealthUp, 3: model.HealthUp})

	st := e.Status()
	if st.PreferredPath != 1 {
		t.Errorf("preferred path %d, want main (1)", st.PreferredPath)
	}
}

// The reported preferred path must be the one the selector actually returns to,
// not merely the first in the list. Disabling the top-priority path has to move
// both together or the portal shows green on a path the engine is treating as a
// fallback.
func TestPreferredPathTracksTheSelectorWhenTheTopPathIsDisabled(t *testing.T) {
	cfg := testConfig()
	cfg.Paths[0].Enabled = false
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthUp, 2: model.HealthUp, 3: model.HealthUp})
	e.blocks[1] = model.BlockDisabled

	st := e.Status()
	if st.PreferredPath != 2 {
		t.Errorf("preferred path %d, want lte1 (2) once main is disabled", st.PreferredPath)
	}

	// The selector and the badge must agree about where traffic belongs.
	chosen, held, _ := e.selectPath(cfg, time.Now())
	if held {
		t.Fatal("two healthy paths remain, so the system is not held")
	}
	if chosen != st.PreferredPath {
		t.Errorf("selector chose %d but status reports preferred %d; the badge would be green on a fallback",
			chosen, st.PreferredPath)
	}
}

// Neither host's build was visible from the portal, which is exactly the kind of
// thing that is only missed when a procedure has already been written against
// the wrong assumption.
func TestStatusCarriesBothVersions(t *testing.T) {
	old := Version
	t.Cleanup(func() { Version = old })
	Version = "test-frontend-build"

	cfg := testConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthUp})
	e.SetBackendInfo("test-backend-build", "backend-host")

	st := e.Status()
	if st.FrontendVersion != "test-frontend-build" {
		t.Errorf("frontend version %q, want the stamped build", st.FrontendVersion)
	}
	if st.BackendVersion != "test-backend-build" {
		t.Errorf("backend version %q, want what the backend said in its hello", st.BackendVersion)
	}
	if st.BackendHost != "backend-host" {
		t.Errorf("backend host %q", st.BackendHost)
	}
}

// The backend's reported build deliberately outlives the control channel. A
// blank on disconnect would throw away the more useful answer - which build was
// there a minute ago - and BackendUp already reports liveness separately.
func TestBackendVersionSurvivesTheChannelDropping(t *testing.T) {
	cfg := testConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthUp})
	e.SetBackendInfo("test-backend-build", "backend-host")
	e.backendUp = false

	st := e.Status()
	if st.BackendVersion != "test-backend-build" {
		t.Errorf("backend version %q, want the last reported build to survive a disconnect", st.BackendVersion)
	}
	if st.BackendUp {
		t.Error("backend should still report as down; the version is not a liveness signal")
	}
}

// The WAN badge in the portal header shows the address published services are
// reachable at. A configured public IP must win over anything read from an
// interface, because it is what the DNAT rules actually match: an interface
// holding several addresses would otherwise show one the rules may not cover.
func TestPublicAddressPrefersTheConfiguredIPOverTheInterface(t *testing.T) {
	if got := publicAddress("203.0.113.10", "eth0"); got != "203.0.113.10" {
		t.Errorf("publicAddress = %q, want the configured 203.0.113.10", got)
	}
}

// With nothing configured there is nothing truthful to show, and the portal
// hides the badge on an empty string. An interface the host does not have is
// the same case, not an error: the portal is often opened before the settings
// are right, and a broken read must not take the status endpoint with it.
func TestPublicAddressIsEmptyRatherThanAnErrorWhenUnconfigured(t *testing.T) {
	if got := publicAddress("", ""); got != "" {
		t.Errorf("publicAddress with nothing configured = %q, want empty", got)
	}
	if got := publicAddress("", "no-such-interface-xyz"); got != "" {
		t.Errorf("publicAddress on a missing interface = %q, want empty", got)
	}
}

// The kernel lists an interface's addresses in the order they were added, not
// in order of meaning, and a datacentre NIC often carries a management or
// carrier-NAT address alongside the public one. The badge exists to say where
// services are reachable, so the publicly routable address must win whatever
// position it holds; with only private addresses on the interface the first
// one is shown rather than nothing.
func TestPickWANAddressPrefersPubliclyRoutableOverPrivateAndCGNAT(t *testing.T) {
	mustNet := func(cidr string) net.Addr {
		ip, ipn, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("parse %s: %v", cidr, err)
		}
		ipn.IP = ip
		return ipn
	}

	got := pickWANAddress([]net.Addr{
		mustNet("10.20.30.40/24"),  // management subnet, added first
		mustNet("100.90.1.2/10"),   // carrier-grade NAT space
		mustNet("203.0.113.10/24"), // the actual WAN
	})
	if got != "203.0.113.10" {
		t.Errorf("pickWANAddress = %q, want the public 203.0.113.10 over the private and CGNAT addresses before it", got)
	}

	got = pickWANAddress([]net.Addr{mustNet("10.20.30.40/24"), mustNet("192.168.1.5/24")})
	if got != "10.20.30.40" {
		t.Errorf("pickWANAddress with only private addresses = %q, want the first (10.20.30.40) rather than a blank", got)
	}

	if got = pickWANAddress(nil); got != "" {
		t.Errorf("pickWANAddress with no addresses = %q, want empty", got)
	}
}
