package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/proto"
)

// revertKernel is a backend with a subnet, a linker and one shaped tunnel, so
// every branch of the teardown has something to find.
func revertKernel() map[string]string {
	return map[string]string{
		"ip rule show table 100": "29998: from all fwmark 0x200 lookup 100\n" +
			"32499: from all to 10.99.0.0/24 lookup main\n" +
			"32500: from 10.99.0.2 lookup 100\n" +
			"32501: from 10.99.0.0/24 lookup 100\n",
		"ip rule show table 101": "30001: from all fwmark 0x101 lookup 101\n",
		"ip rule show table 102": "30002: from all fwmark 0x102 lookup 102\n",
	}
}

func agentForRevert(t *testing.T) (*Agent, *queryRunner) {
	t.Helper()
	a, q := agentForReconcile(t, revertKernel())
	a.cfg.Overlay.Subnet = "10.99.0.0/24"
	a.cfg.Linkers = []proto.LinkerRoute{{OverlayIP: "10.99.0.3", LanIP: "192.168.1.4"}}
	a.cfg.Paths[1].ShapeMbit = 18 // lte1 is shaped; nbn is not
	return a, q
}

// Revert has to take down everything this agent installed. It used to take down
// nothing at all: the teardown helpers were written and never called from
// anywhere, so `failoverctl revert` reported success while the backend kept its
// reply rules, its table-100 default route, its marking table and its routes to
// every extra host.
func TestBackendRevertRemovesWhatTheAgentInstalled(t *testing.T) {
	a, q := agentForRevert(t)

	a.Revert(context.Background())

	for _, want := range []string{
		"nft delete table ip failover_return",
		"nft delete table ip failover_egress",
		// Both sources, at the priorities they were found at.
		"ip rule del from 10.99.0.2 lookup 100 pref 32500",
		"ip rule del from 10.99.0.0/24 lookup 100 pref 32501",
		"ip rule del fwmark 0x200 lookup 100 pref 29998",
		"ip rule del to 10.99.0.0/24 lookup main",
		"ip route del default table 100",
		// The per-path plumbing, and the main-table route to the frontend.
		"ip rule del fwmark 0x101 lookup 101 pref 30001",
		"ip rule del fwmark 0x102 lookup 102 pref 30002",
		"ip route del 10.99.0.1/32",
		// The route to the extra host, which nothing else would ever remove.
		"ip route del 10.99.0.3/32",
	} {
		if q.wrote(want) == 0 {
			t.Errorf("revert left %q behind; writes were %v", want, q.writes())
		}
	}
}

// A revert that flushes a routing table takes the operator's own routes with
// it. The number belongs to the host, not to this system, and a backend that
// already policy-routes may well keep its own entries in 100.
func TestBackendRevertDeletesTheDefaultRouteRatherThanFlushingTheTable(t *testing.T) {
	a, q := agentForRevert(t)

	a.Revert(context.Background())

	for _, c := range q.writes() {
		if strings.Contains(c, "route flush table 100") {
			t.Errorf("revert flushed the return table, taking any of the host's own routes with it: %s", c)
		}
	}
}

// Only tunnels this agent shaped. An interface it never touched carries
// somebody else's queue discipline, and revert removes what the agent
// installed and nothing else.
func TestBackendRevertRemovesOnlyTheShapersItInstalled(t *testing.T) {
	a, q := agentForRevert(t)

	a.Revert(context.Background())

	if q.wrote("tc qdisc del dev wg-lte1") == 0 {
		t.Errorf("the shaped tunnel kept its queue discipline; writes were %v", q.writes())
	}
	if q.wrote("tc qdisc del dev wg-nbn") != 0 {
		t.Errorf("revert removed a queue discipline this agent never installed; writes were %v", q.writes())
	}
}

// The guard every existing site depends on: with no linkers and no subnet,
// revert must issue nothing that mentions either.
func TestBackendRevertOnASingleHostSiteTouchesNoMultiHostState(t *testing.T) {
	a, q := agentForReconcile(t, revertKernel())

	a.Revert(context.Background())

	for _, c := range q.writes() {
		if strings.Contains(c, "10.99.0.0/24") || strings.Contains(c, "lookup main") {
			t.Errorf("a site with no overlay subnet reverted multi-host state: %s", c)
		}
		if strings.Contains(c, "10.99.0.3") {
			t.Errorf("a site with no linkers withdrew a linker route: %s", c)
		}
		if strings.Contains(c, "tc qdisc") {
			t.Errorf("an unshaped site ran tc during revert: %s", c)
		}
	}
	// It still has to do its own half.
	if q.wrote("ip rule del from 10.99.0.2 lookup 100 pref 32500") == 0 {
		t.Errorf("the backend's own return rule was left behind; writes were %v", q.writes())
	}
}

// Revert acts whatever the mode. Observe mode means the agent installed less,
// not that there is nothing to take down: the measurement plumbing goes in
// either way, and a revert that skipped it would leave the probe tables and
// the overlay route behind on exactly the hosts being trialled.
func TestBackendRevertActsInObserveMode(t *testing.T) {
	a, q := agentForRevert(t)
	a.cfg.Mode = model.ModeObserve
	a.runner = &observeRunner{q}

	a.Revert(context.Background())

	if q.wrote("ip rule del fwmark 0x101 lookup 101 pref 30001") == 0 {
		t.Errorf("observe mode skipped the revert; writes were %v", q.writes())
	}
}
