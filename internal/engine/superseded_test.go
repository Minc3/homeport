package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/quinlan102/homeport/internal/model"
)

// Setting overlay.subnet on a site that has been running leaves behind the /32
// the widened route replaced. It is the more specific of the two, so the
// backend would stay pinned to whichever tunnel was active at the moment of the
// change while every failover afterwards moved only the range.
//
// Nothing would report it. Probes and the control channel are steered into
// their own tables by fwmark, so all three paths would go on measuring
// perfectly while published traffic left down a tunnel carrying nothing else.
func TestSupersededHostRouteIsRemovedOnceASubnetIsSet(t *testing.T) {
	kernel := healthyKernel()
	kernel["ip route show 10.99.0.0/24"] = "10.99.0.0/24 dev wg-nbn scope link src 10.99.0.1"
	// The leftover from before the subnet was configured.
	kernel["ip route show 10.99.0.2/32"] = "10.99.0.2 dev wg-nbn scope link src 10.99.0.1"
	// The control table carries the same widening and is cleaned the same way;
	// this test is about the main one, so it starts finished.
	kernel["ip route show 10.99.0.0/24 table 100"] = "10.99.0.0/24 dev wg-nbn scope link src 10.99.0.1"
	kernel["ip route show 10.99.0.2/32 table 100"] = ""

	e, q := engineForReconcile(t, kernel)
	e.cfg.Overlay.Subnet = "10.99.0.0/24"

	e.reconcileRouting(context.Background())

	if q.count("ip route del 10.99.0.2/32") != 1 {
		t.Fatalf("the superseded /32 should be removed; writes were %v", q.writes())
	}
}

// On a site with no subnet the /32 *is* the route. Removing it would blackhole
// every published service on a system that had nothing to do with linkers.
func TestHostRouteIsKeptWhenNoSubnetIsConfigured(t *testing.T) {
	e, q := engineForReconcile(t, healthyKernel())

	e.reconcileRouting(context.Background())

	if q.count("ip route del") != 0 {
		t.Fatalf("the /32 is the real route here and must be kept; writes were %v", q.writes())
	}
}

// Once the leftover is gone the reconciler must fall silent again, or it issues
// a delete for a route that no longer exists on every tick forever.
func TestSupersededRemovalIsNotRepeated(t *testing.T) {
	kernel := healthyKernel()
	kernel["ip route show 10.99.0.0/24"] = "10.99.0.0/24 dev wg-nbn scope link src 10.99.0.1"
	kernel["ip route show 10.99.0.2/32"] = "" // already cleaned
	// The control table is a separate copy of the same widening, and these
	// tests are about the main one, so it starts in its finished state.
	kernel["ip route show 10.99.0.0/24 table 100"] = "10.99.0.0/24 dev wg-nbn scope link src 10.99.0.1"
	kernel["ip route show 10.99.0.2/32 table 100"] = ""

	e, q := engineForReconcile(t, kernel)
	e.cfg.Overlay.Subnet = "10.99.0.0/24"

	e.reconcileRouting(context.Background())

	if got := q.writes(); len(got) != 0 {
		t.Fatalf("nothing left to do, but reconcile wrote %v", got)
	}
}

// Observe mode must not remove it. The installed route is what published
// traffic is still following, and taking it away would be the one thing observe
// mode exists to never do.
func TestSupersededHostRouteSurvivesObserveMode(t *testing.T) {
	kernel := healthyKernel()
	kernel["ip route show 10.99.0.0/24"] = "10.99.0.0/24 dev wg-nbn scope link src 10.99.0.1"
	kernel["ip route show 10.99.0.2/32"] = "10.99.0.2 dev wg-nbn scope link src 10.99.0.1"
	kernel["ip route show 10.99.0.0/24 table 100"] = "10.99.0.0/24 dev wg-nbn scope link src 10.99.0.1"
	kernel["ip route show 10.99.0.2/32 table 100"] = ""

	e, q := engineForReconcile(t, kernel)
	e.cfg.Overlay.Subnet = "10.99.0.0/24"
	e.cfg.Mode = model.ModeObserve
	e.runner = runnerFor(model.ModeObserve, quietLogger())

	e.reconcileRouting(context.Background())

	// The main-table route specifically. The control table is a different
	// matter and is repaired for real in observe mode - it carries only marked
	// control connections, never published traffic - so the /32 it supersedes
	// goes in both modes, which is why this counts the withdrawal that would
	// actually move traffic rather than every delete.
	for _, w := range q.writes() {
		if strings.HasPrefix(w, "ip route del") && !strings.Contains(w, "table") {
			t.Fatalf("observe mode must not withdraw an installed route; writes were %v", q.writes())
		}
	}
}
