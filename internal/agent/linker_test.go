package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/quinlan102/homeport/internal/proto"
	"github.com/quinlan102/homeport/internal/sysx"
)

// The whole reason the backend learns about linkers over the control channel is
// so nobody has to install this route by hand on a box the agents exist to stop
// people logging into.
func TestApplyInstallsTheRouteToEachLinker(t *testing.T) {
	a, q := agentForReconcile(t, backendKernel())
	cfg := a.cfg
	cfg.Linkers = []proto.LinkerRoute{
		{OverlayIP: "10.99.0.3", LanIP: "10.1.1.4"},
		{OverlayIP: "10.99.0.4", LanIP: "10.1.1.5"},
	}

	a.applyPlumbing(context.Background(), cfg)

	if q.wrote("ip route replace 10.99.0.3/32 via 10.1.1.4") != 1 {
		t.Errorf("first linker route not installed; writes were %v", q.writes())
	}
	if q.wrote("ip route replace 10.99.0.4/32 via 10.1.1.5") != 1 {
		t.Errorf("second linker route not installed; writes were %v", q.writes())
	}
}

// A site with no linkers must issue no linker commands at all. This is the
// multi-host invariant at the point it is easiest to break: an unguarded loop
// over an empty slice is fine, but a helper that installs a subnet route or a
// placeholder would change every existing deployment.
func TestNoLinkersConfiguredInstallsNothingExtra(t *testing.T) {
	a, q := agentForReconcile(t, backendKernel())
	cfg := a.cfg
	cfg.Linkers = nil

	a.applyPlumbing(context.Background(), cfg)

	for _, w := range q.writes() {
		if strings.Contains(w, " via ") {
			t.Errorf("a site with no linkers issued a via route: %q", w)
		}
	}
}

// The route points at a neighbour rather than a device, so the kernel drops it
// when the LAN interface bounces and nothing else would ever put it back. That
// is precisely the failure the manual version had.
func TestReconcileRestoresALinkerRouteLostWithTheLANInterface(t *testing.T) {
	kernel := backendKernel()
	kernel["ip route show 10.99.0.3/32"] = "" // gone with the interface

	a, q := agentForReconcile(t, kernel)
	a.cfg.Linkers = []proto.LinkerRoute{{OverlayIP: "10.99.0.3", LanIP: "10.1.1.4"}}

	a.reconcileRouting(context.Background())

	if q.wrote("ip route replace 10.99.0.3/32 via 10.1.1.4") != 1 {
		t.Errorf("linker route was not restored; writes were %v", q.writes())
	}
}

// An intact linker route must be left completely alone, or every tick rewrites
// routing that was already correct and the log becomes noise nobody reads.
func TestReconcileLeavesAnIntactLinkerRouteAlone(t *testing.T) {
	kernel := backendKernel()
	kernel["ip route show 10.99.0.3/32"] = "10.99.0.3 via 10.1.1.4 dev eth0"

	a, q := agentForReconcile(t, kernel)
	a.cfg.Linkers = []proto.LinkerRoute{{OverlayIP: "10.99.0.3", LanIP: "10.1.1.4"}}

	a.reconcileRouting(context.Background())

	if n := q.wrote("10.99.0.3"); n != 0 {
		t.Errorf("reconcile touched an intact linker route %d times; writes were %v", n, q.writes())
	}
}

// Moving a linker to a different machine has to move the route with it. The
// readback compares the next hop, not merely whether a route exists, because a
// route pointing at the old box is worse than none: it forwards published
// traffic to a machine that is no longer listening.
func TestReconcileCorrectsALinkerRoutePointingAtTheWrongHost(t *testing.T) {
	kernel := backendKernel()
	kernel["ip route show 10.99.0.3/32"] = "10.99.0.3 via 10.1.1.9 dev eth0"

	a, q := agentForReconcile(t, kernel)
	a.cfg.Linkers = []proto.LinkerRoute{{OverlayIP: "10.99.0.3", LanIP: "10.1.1.4"}}

	a.reconcileRouting(context.Background())

	if q.wrote("ip route replace 10.99.0.3/32 via 10.1.1.4") != 1 {
		t.Errorf("stale next hop not corrected; writes were %v", q.writes())
	}
}

// Unticking a linker in the portal is how an operator takes a host out of
// service. Leaving its route behind means the backend still forwards to a
// machine nobody expects traffic to reach, and nothing anywhere says so.
func TestWithdrawRemovesTheRouteForALinkerNoLongerConfigured(t *testing.T) {
	a, q := agentForReconcile(t, backendKernel())

	prev := []proto.LinkerRoute{
		{OverlayIP: "10.99.0.3", LanIP: "10.1.1.4"},
		{OverlayIP: "10.99.0.4", LanIP: "10.1.1.5"},
	}
	now := []proto.LinkerRoute{{OverlayIP: "10.99.0.3", LanIP: "10.1.1.4"}}

	a.withdrawRemovedLinkers(context.Background(), prev, now)

	if q.wrote("ip route del 10.99.0.4/32") != 1 {
		t.Errorf("removed linker's route was not withdrawn; writes were %v", q.writes())
	}
	if q.wrote("ip route del 10.99.0.3/32") != 0 {
		t.Errorf("withdrew a linker that is still configured; writes were %v", q.writes())
	}
}

// The return rule matches on source, and once a subnet is configured that range
// includes the frontend. So a packet the frontend sends to a linker arrives
// here, matches `from <subnet> lookup 100`, and is routed by a table whose
// default points back down the tunnel it just came out of - it never reaches
// the linker.
//
// Published traffic hides this completely: a client's source is a public
// address, so it never matches the return rule and is forwarded normally. The
// only thing bounced is overlay-to-overlay traffic, which in practice is the
// linker's control channel - the frontend's SYN-ACK goes back to the frontend
// and the connection never completes, while everything published keeps working.
func TestOverlayTrafficIsKeptOutOfTheReturnTable(t *testing.T) {
	a, q := agentForReconcile(t, backendKernel())
	cfg := a.cfg
	cfg.Overlay.Subnet = "10.99.0.0/24"

	a.applyPlumbing(context.Background(), cfg)

	if q.wrote("ip rule add to 10.99.0.0/24 lookup main") != 1 {
		t.Errorf("the overlay-local exception was not installed; writes were %v", q.writes())
	}
}

// It must sit ahead of the source rules it is an exception to, or it never gets
// the chance to match.
func TestTheOverlayLocalRuleOutranksTheReturnRules(t *testing.T) {
	if sysx.OverlayLocalRulePref >= sysx.ReturnRulePrefBase {
		t.Fatalf("overlay-local rule at %d does not outrank the return rules at %d",
			sysx.OverlayLocalRulePref, sysx.ReturnRulePrefBase)
	}
}

// Without a subnet the return rule names a single address and cannot match the
// frontend, so there is nothing to except - and a site with no linkers must
// generate exactly what it always did.
func TestNoOverlayLocalRuleWithoutASubnet(t *testing.T) {
	a, q := agentForReconcile(t, backendKernel())
	cfg := a.cfg
	cfg.Overlay.Subnet = ""

	a.applyPlumbing(context.Background(), cfg)

	for _, w := range q.writes() {
		if strings.Contains(w, "lookup main") {
			t.Errorf("a site with no subnet installed an overlay-local rule: %q", w)
		}
	}
}

// The backend forwards for a linker, and a box that runs containers has a
// drop-policy forward chain waiting for it. This is the fault that made a
// perfectly routed linker look dead: every packet crossed the FORWARD hook and
// was dropped there, with nothing in any log and correct routing on every host.
func TestLinkersInstallForwardExceptionsForTheOverlayRange(t *testing.T) {
	kernel := backendKernel()
	kernel["nft -a list chain ip filter DOCKER-USER"] = "table ip filter {\n chain DOCKER-USER {\n }\n}\n"

	a, q := agentForReconcile(t, kernel)
	cfg := a.cfg
	cfg.Overlay.Subnet = "10.99.0.0/24"
	cfg.Linkers = []proto.LinkerRoute{{OverlayIP: "10.99.0.3", LanIP: "10.1.1.4"}}

	a.applyPlumbing(context.Background(), cfg)

	if q.wrote("nft insert rule ip filter DOCKER-USER ip daddr 10.99.0.0/24 accept") != 1 {
		t.Errorf("no forward exception for traffic to a linker; writes were %v", q.writes())
	}
	if q.wrote("nft insert rule ip filter DOCKER-USER ip saddr 10.99.0.0/24 accept") != 1 {
		t.Errorf("no forward exception for traffic from a linker; writes were %v", q.writes())
	}
}

// And a site with no linkers forwards nothing, so it must not touch a chain it
// has no business in - the same invariant as the route above, one layer down.
func TestNoLinkersTouchesNoForwardChain(t *testing.T) {
	kernel := backendKernel()
	kernel["nft -a list chain ip filter DOCKER-USER"] = "table ip filter {\n chain DOCKER-USER {\n }\n}\n"

	a, q := agentForReconcile(t, kernel)
	cfg := a.cfg
	cfg.Linkers = nil

	a.applyPlumbing(context.Background(), cfg)

	for _, w := range q.writes() {
		if strings.Contains(w, "DOCKER-USER") {
			t.Errorf("a site with no linkers wrote to DOCKER-USER: %q", w)
		}
	}
}
