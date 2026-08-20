package engine

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/notify"
	"github.com/quinlan102/homeport/internal/store"
)

// queryRunner answers `ip ... show` from a canned kernel state and records
// everything else, so a reconcile can be driven without a network stack.
type queryRunner struct {
	mu      sync.Mutex
	calls   []string
	replies map[string]string
}

func (q *queryRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	line := name + " " + strings.Join(args, " ")
	q.mu.Lock()
	defer q.mu.Unlock()
	q.calls = append(q.calls, line)
	return q.replies[line], nil
}

func (q *queryRunner) Applying() bool { return true }

// writes returns the commands that would have changed the system.
func (q *queryRunner) writes() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	var out []string
	for _, c := range q.calls {
		if strings.Contains(c, " show") || strings.HasPrefix(c, "sysctl -n") {
			continue
		}
		out = append(out, c)
	}
	return out
}

func (q *queryRunner) count(substr string) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	n := 0
	for _, c := range q.calls {
		if strings.Contains(c, substr) {
			n++
		}
	}
	return n
}

// healthyKernel is what the frontend sees when every route is where the agent
// put it: nbn active, all three probe tables populated, rules in place.
func healthyKernel() map[string]string {
	return map[string]string{
		"ip rule show": "0: from all lookup local\n" +
			"29999: from all fwmark 0x100 lookup 100\n" +
			"30001: from all fwmark 0x101 lookup 101\n" +
			"30002: from all fwmark 0x102 lookup 102\n" +
			"30003: from all fwmark 0x103 lookup 103\n" +
			"32766: from all lookup main\n",
		// Rules are read back filtered by table, not grepped out of the full
		// listing: `ip rule show` prints a table's *name* wherever rt_tables
		// gives it one. The kernel answers a numbered query either way, which
		// is why every readback asks this way - see listRulesInTable.
		"ip rule show table 100":                    "29999: from all fwmark 0x100 lookup 100\n",
		"ip rule show table 101":                    "30001: from all fwmark 0x101 lookup 101\n",
		"ip rule show table 102":                    "30002: from all fwmark 0x102 lookup 102\n",
		"ip rule show table 103":                    "30003: from all fwmark 0x103 lookup 103\n",
		"sysctl -n net.ipv4.conf.wg-nbn.rp_filter":  "0",
		"sysctl -n net.ipv4.conf.wg-lte1.rp_filter": "0",
		"sysctl -n net.ipv4.conf.wg-lte2.rp_filter": "0",
		"ip route show 10.99.0.2/32 table 101":      "10.99.0.2 dev wg-nbn scope link src 10.99.0.1",
		"ip route show 10.99.0.2/32 table 102":      "10.99.0.2 dev wg-lte1 scope link src 10.99.0.1",
		"ip route show 10.99.0.2/32 table 103":      "10.99.0.2 dev wg-lte2 scope link src 10.99.0.1",
		"ip route show 10.99.0.2/32 table 100":      "10.99.0.2 dev wg-nbn scope link src 10.99.0.1",
		"ip route show 10.99.0.2/32":                "10.99.0.2 dev wg-nbn scope link src 10.99.0.1",
	}
}

// engineForReconcile builds an armed engine whose view of the kernel is the
// supplied canned state and whose interfaces all exist.
func engineForReconcile(t *testing.T, kernel map[string]string) (*Engine, *queryRunner) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg := model.Defaults()
	cfg.Mode = model.ModeArmed
	log := quietLogger()
	e := New(log, st, notify.New(log), cfg, []byte("secret"), t.TempDir())

	q := &queryRunner{replies: kernel}
	e.real = q
	e.runner = q
	e.ifaceExists = func(string) bool { return true }
	e.active = 1 // nbn
	return e, q
}

// A tunnel restart deletes the interface, and the kernel silently drops every
// route that used it. Recreating the interface does not bring them back, so
// without this repair the path's probes have no route out of their own tunnel
// and it reads as down forever - which is exactly what "the come back online
// part doesn't work" looks like from the portal.
func TestReconcileRestoresAProbeRouteLostWhenATunnelWasRecreated(t *testing.T) {
	kernel := healthyKernel()
	kernel["ip route show 10.99.0.2/32 table 101"] = "" // wg-nbn was restarted

	// Traffic already moved to lte1, so that is where the active routes point.
	kernel["ip route show 10.99.0.2/32 table 100"] = "10.99.0.2 dev wg-lte1 scope link src 10.99.0.1"
	kernel["ip route show 10.99.0.2/32"] = "10.99.0.2 dev wg-lte1 scope link src 10.99.0.1"

	e, q := engineForReconcile(t, kernel)
	e.active = 2 // lte1

	e.reconcileRouting(context.Background())

	want := "ip route replace 10.99.0.2/32 dev wg-nbn src 10.99.0.1 table 101"
	if q.count(want) != 1 {
		t.Errorf("probe route for the restarted tunnel was not restored; writes were %v", q.writes())
	}
	// Only the path that lost its route is touched. Reapplying everything
	// would rewrite the active route too, for no reason and on every tick.
	if got := len(q.writes()); got != 1 {
		t.Errorf("reconcile made %d changes, want exactly 1; writes were %v", got, q.writes())
	}
}

// A healthy system must be silent. The reconciler runs every ten seconds
// forever, so anything it writes unconditionally is a route being replaced
// under live traffic several times a minute.
func TestReconcileChangesNothingWhenTheKernelAgrees(t *testing.T) {
	e, q := engineForReconcile(t, healthyKernel())

	e.reconcileRouting(context.Background())

	if got := q.writes(); len(got) != 0 {
		t.Errorf("reconcile touched an intact system: %v", got)
	}
}

// A tunnel that has not come back is a path that is down, not a repair. Trying
// to install a route through a missing interface would fail once per tick and
// bury the real events in the journal.
func TestReconcileSkipsPathsWhoseTunnelIsStillMissing(t *testing.T) {
	kernel := healthyKernel()
	kernel["ip route show 10.99.0.2/32 table 101"] = ""

	e, q := engineForReconcile(t, kernel)
	e.ifaceExists = func(iface string) bool { return iface != "wg-nbn" }
	e.active = 2

	e.reconcileRouting(context.Background())

	if q.count("dev wg-nbn") != 0 {
		t.Errorf("tried to route through a tunnel that does not exist: %v", q.writes())
	}
}

// Observe mode must keep measuring but must not move traffic. The probe table
// is measurement and is repaired; the main-table route to the backend is the
// failover action itself and deliberately does not exist in observe mode, so
// there is nothing there to restore.
func TestReconcileInObserveModeRepairsProbingButNotTheTrafficRoute(t *testing.T) {
	kernel := healthyKernel()
	kernel["ip route show 10.99.0.2/32 table 101"] = ""
	kernel["ip route show 10.99.0.2/32"] = "" // observe mode never installed it

	e, q := engineForReconcile(t, kernel)
	e.mu.Lock()
	e.cfg.Mode = model.ModeObserve
	e.runner = runnerFor(model.ModeObserve, e.log)
	e.mu.Unlock()

	e.reconcileRouting(context.Background())

	repaired := 0
	for _, c := range q.writes() {
		if strings.Contains(c, "table 101") {
			repaired++
		}
	}
	if repaired != 1 {
		t.Errorf("observe mode must still repair measurement plumbing; writes were %v", q.writes())
	}
	for _, c := range q.writes() {
		if strings.Contains(c, "route replace 10.99.0.2/32 dev") && !strings.Contains(c, "table") {
			t.Errorf("observe mode installed the traffic route: %q", c)
		}
	}
}
