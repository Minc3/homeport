package engine

import (
	"testing"

	"github.com/quinlan102/homeport/internal/model"
)

func linkerCfg() model.Config {
	cfg := testConfig()
	cfg.Overlay.Subnet = "10.99.0.0/24"
	cfg.BackendLAN = "10.1.1.3"
	cfg.Linkers = []model.Linker{
		{Name: "gs1", OverlayIP: "10.99.0.3", LanIP: "10.1.1.4", Enabled: true},
		{Name: "web", OverlayIP: "10.99.0.4", LanIP: "10.1.1.5", Enabled: true},
	}
	cfg.Frontend.BackendEgress = true
	cfg.Egress.Sources = []model.EgressSource{
		{Name: "gs1 bridge", Host: "10.99.0.3", CIDR: "172.18.0.0/16", Enabled: true},
		{Name: "web bridge", Host: "10.99.0.4", CIDR: "172.18.0.0/16", Enabled: true},
		{Name: "backend bridge", CIDR: "172.17.0.0/16", Enabled: true},
	}
	return cfg
}

// Docker hands out the same bridge subnets on every machine, so a host must
// receive only its own rows. Sending the list unfiltered would have each linker
// pull containers onto the tunnel that belong to a different box entirely -
// silently, and through the metered link.
func TestEachLinkerReceivesOnlyItsOwnNetworks(t *testing.T) {
	e := newTestEngine(linkerCfg(), nil)

	got := e.LinkerConfigFor("10.99.0.3")
	if len(got.EgressCIDRs) != 1 || got.EgressCIDRs[0] != "172.18.0.0/16" {
		t.Fatalf("gs1 received %v", got.EgressCIDRs)
	}
	// The identical CIDR on the other host is a different row and must not
	// arrive here twice.
	if len(e.LinkerConfigFor("10.99.0.4").EgressCIDRs) != 1 {
		t.Errorf("web received %v", e.LinkerConfigFor("10.99.0.4").EgressCIDRs)
	}
}

// A row with no owner belongs to the backend, and must never leak to a linker.
func TestAnUnownedNetworkNeverReachesALinker(t *testing.T) {
	e := newTestEngine(linkerCfg(), nil)

	for _, c := range e.LinkerConfigFor("10.99.0.3").EgressCIDRs {
		if c == "172.17.0.0/16" {
			t.Fatal("the backend's own network was sent to a linker")
		}
	}
}

// Pulling a network onto the overlay without the frontend's source NAT waiting
// at the other end sends its traffic somewhere it cannot be answered - worse
// than leaving it on the local service, because it fails silently. Same gate as
// the backend's.
func TestNoNetworksArePushedWhileBackendEgressIsOff(t *testing.T) {
	cfg := linkerCfg()
	cfg.Frontend.BackendEgress = false
	e := newTestEngine(cfg, nil)

	if got := e.LinkerConfigFor("10.99.0.3"); len(got.EgressCIDRs) != 0 {
		t.Errorf("pushed %v with the master switch off", got.EgressCIDRs)
	}
}

// The shared secret proves a peer belongs to this deployment. It does not prove
// it is entitled to a particular overlay address - and a linker that could name
// itself could be handed another linker's networks, or take over the traffic
// published to it.
func TestOnlyConfiguredLinkersAreAccepted(t *testing.T) {
	e := newTestEngine(linkerCfg(), nil)

	if !e.KnownLinker("10.99.0.3") {
		t.Error("a configured, enabled linker should be accepted")
	}
	if e.KnownLinker("10.99.0.9") {
		t.Error("an address nobody configured was accepted")
	}
	if e.KnownLinker("10.99.0.2") {
		t.Error("the backend's own address was accepted as a linker")
	}
}

// Unticking a linker is how a host is taken out of service. It must stop being
// able to connect, not merely stop being published to.
func TestADisabledLinkerIsNotAccepted(t *testing.T) {
	cfg := linkerCfg()
	cfg.Linkers[0].Enabled = false
	e := newTestEngine(cfg, nil)

	if e.KnownLinker("10.99.0.3") {
		t.Error("a disabled linker was still accepted")
	}
}

// A configured linker that has never dialled in must be reported as down rather
// than be absent. A host missing from the portal entirely looks like one nobody
// configured, which is the confusion this whole feature exists to remove.
func TestConfiguredButUnconnectedLinkersAreReportedDown(t *testing.T) {
	e := newTestEngine(linkerCfg(), nil)
	e.SetLinkerUp("10.99.0.3", "v1", "gs1host", 200)

	st := e.Status()
	if len(st.LinkerStates) != 2 {
		t.Fatalf("reported %d linkers, want both configured ones", len(st.LinkerStates))
	}
	byIP := map[string]model.LinkerState{}
	for _, l := range st.LinkerStates {
		byIP[l.OverlayIP] = l
	}
	if !byIP["10.99.0.3"].Up || byIP["10.99.0.3"].Version != "v1" {
		t.Errorf("connected linker reported as %+v", byIP["10.99.0.3"])
	}
	if byIP["10.99.0.4"].Up {
		t.Error("a linker that never connected is reported up")
	}
	if byIP["10.99.0.4"].Name != "web" {
		t.Errorf("an unconnected linker must still carry its configured identity, got %+v", byIP["10.99.0.4"])
	}
}

// Losing the control channel must clear liveness, or a host that has gone away
// goes on reading as healthy.
func TestDisconnectingClearsLiveness(t *testing.T) {
	e := newTestEngine(linkerCfg(), nil)
	session := e.SetLinkerUp("10.99.0.3", "v1", "gs1host", 200)
	e.SetLinkerDown("10.99.0.3", session)

	for _, l := range e.Status().LinkerStates {
		if l.OverlayIP == "10.99.0.3" && l.Up {
			t.Error("a disconnected linker is still reported up")
		}
	}
}

// Liveness answers "is it there now"; last contact answers "how long has it
// been gone", and only the second one is useful once a host has dropped. Losing
// the channel must not take the stamp with it, or a host that has been down for
// a week reports exactly what one that has never connected does.
func TestLastContactSurvivesTheConnectionGoingAway(t *testing.T) {
	e := newTestEngine(linkerCfg(), nil)
	session := e.SetLinkerUp("10.99.0.3", "v1", "gs1host", 200)
	e.MarkLinkerSeen("10.99.0.3")
	e.SetLinkerDown("10.99.0.3", session)

	for _, l := range e.Status().LinkerStates {
		if l.OverlayIP != "10.99.0.3" {
			continue
		}
		if l.Up {
			t.Fatal("a disconnected linker is still reported up")
		}
		if l.LastSeen.IsZero() {
			t.Error("last contact was cleared with the connection")
		}
	}
}

// A host that has never dialled in has no last contact to report, and must not
// borrow one from anywhere. "never" and "a while ago" send an operator to
// different places.
func TestALinkerThatHasNeverConnectedHasNoLastContact(t *testing.T) {
	e := newTestEngine(linkerCfg(), nil)
	e.SetLinkerUp("10.99.0.3", "v1", "gs1host", 200)

	for _, l := range e.Status().LinkerStates {
		if l.OverlayIP == "10.99.0.4" && !l.LastSeen.IsZero() {
			t.Errorf("a linker that never connected reported last contact %v", l.LastSeen)
		}
	}
}

// A linker whose TCP connection dies silently - what a failover looks like from
// up here - redials while the old session is still parked on its read deadline.
// The teardown that follows must not delete the entry the new session made, or
// the portal shows a healthy host as disconnected until it dials again, which
// it has no reason to do.
func TestAStaleTeardownDoesNotUnregisterTheNewSession(t *testing.T) {
	e := newTestEngine(linkerCfg(), nil)
	stale := e.SetLinkerUp("10.99.0.3", "v1", "gs1host", 200)
	e.SetLinkerUp("10.99.0.3", "v2", "gs1host", 200)

	e.SetLinkerDown("10.99.0.3", stale)

	for _, l := range e.Status().LinkerStates {
		if l.OverlayIP != "10.99.0.3" {
			continue
		}
		if !l.Up {
			t.Fatal("the stale session's teardown unregistered the live one")
		}
		if l.Version != "v2" {
			t.Errorf("reporting the old session's details: %+v", l)
		}
	}
}

// A site with no linkers reports none, so the portal shows no section at all
// and nothing about the dashboard changes.
func TestNoLinkersMeansNoLinkerStates(t *testing.T) {
	e := newTestEngine(testConfig(), nil)
	if got := e.Status().LinkerStates; got != nil {
		t.Errorf("a site with no linkers reported %+v", got)
	}
}
