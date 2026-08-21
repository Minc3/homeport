package agent

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/proto"
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

func (q *queryRunner) wrote(substr string) int {
	n := 0
	for _, c := range q.writes() {
		if strings.Contains(c, substr) {
			n++
		}
	}
	return n
}

// backendKernel is what the backend sees with lte1 active and every reply
// route where applyPlumbing put it.
func backendKernel() map[string]string {
	return map[string]string{
		"ip rule show": "0: from all lookup local\n" +
			"29998: from all fwmark 0x200 lookup 100\n" +
			"30001: from all fwmark 0x101 lookup 101\n" +
			"30002: from all fwmark 0x102 lookup 102\n" +
			"32500: from 10.99.0.2 lookup 100\n" +
			"32766: from all lookup main\n",
		// The agent reads rules filtered by table, because `ip rule show` prints
		// a table's *name* wherever rt_tables gives it one - see listRulesInTable.
		"ip rule show table 100": "29998: from all fwmark 0x200 lookup 100\n" +
			"32500: from 10.99.0.2 lookup 100",
		"ip rule show table 101":                    "30001: from all fwmark 0x101 lookup 101\n",
		"ip rule show table 102":                    "30002: from all fwmark 0x102 lookup 102\n",
		"sysctl -n net.ipv4.conf.wg-main.rp_filter": "0",
		"sysctl -n net.ipv4.conf.wg-lte1.rp_filter": "0",
		"ip route show 10.99.0.1/32 table 101":      "10.99.0.1 dev wg-main scope link src 10.99.0.2",
		"ip route show 10.99.0.1/32 table 102":      "10.99.0.1 dev wg-lte1 scope link src 10.99.0.2",
		"ip route show 10.99.0.1/32":                "10.99.0.1 dev wg-lte1 scope link src 10.99.0.2",
		"ip route show default table 100":           "default dev wg-lte1 scope link",
	}
}

func agentForReconcile(t *testing.T, kernel map[string]string) (*Agent, *queryRunner) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a := New(log, model.Bootstrap{
		PSK:      "secret",
		StateDir: t.TempDir(),
		Overlay:  model.OverlayConfig{FrontendIP: "10.99.0.1", BackendIP: "10.99.0.2", Device: "dummy0"},
	})
	q := &queryRunner{replies: kernel}
	a.real = q
	a.runner = q
	a.ifaceExists = func(string) bool { return true }
	a.cfg = proto.BackendConfig{
		Mode:    model.ModeArmed,
		Overlay: proto.OverlayInfo{FrontendIP: "10.99.0.1", BackendIP: "10.99.0.2"},
		Paths: []proto.PathInfo{
			{ID: 1, Name: "main", Iface: "wg-main", Table: 101, Mark: 0x101},
			{ID: 2, Name: "lte1", Iface: "wg-lte1", Table: 102, Mark: 0x102},
		},
	}
	a.haveCfg = true
	a.active = 2
	return a, q
}

// Restarting a tunnel deletes the interface, which takes its reply route with
// it. Without that route the backend cannot answer a probe through the tunnel
// the probe arrived on, so the frontend keeps scoring the path as 100% loss
// however healthy the link is - the reason a recovered tunnel never came back.
func TestReconcileRestoresAReplyRouteLostWhenATunnelWasRecreated(t *testing.T) {
	kernel := backendKernel()
	kernel["ip route show 10.99.0.1/32 table 101"] = "" // wg-main was restarted

	a, q := agentForReconcile(t, kernel)

	a.reconcileRouting(context.Background())

	want := "ip route replace 10.99.0.1/32 dev wg-main src 10.99.0.2 table 101"
	if q.wrote(want) != 1 {
		t.Errorf("reply route for the restarted tunnel was not restored; writes were %v", q.writes())
	}
	if got := len(q.writes()); got != 1 {
		t.Errorf("reconcile made %d changes, want exactly 1; writes were %v", got, q.writes())
	}
}

// Restarting the tunnel that is carrying traffic takes the return-path default
// route with it too, and reply traffic then leaves out the LAN to pfSense
// instead of back down the tunnel - which looks like every published service
// hanging rather than like a path being down.
func TestReconcileRestoresTheReturnPathAfterTheActiveTunnelRestarted(t *testing.T) {
	kernel := backendKernel()
	kernel["ip route show default table 100"] = ""
	kernel["ip route show 10.99.0.1/32"] = ""

	a, q := agentForReconcile(t, kernel)

	a.reconcileRouting(context.Background())

	if q.wrote("ip route replace default dev wg-lte1 table 100") != 1 {
		t.Errorf("return path not restored; writes were %v", q.writes())
	}
	if q.wrote("ip route replace 10.99.0.1/32 dev wg-lte1 src 10.99.0.2") != 1 {
		t.Errorf("overlay route to the frontend not restored; writes were %v", q.writes())
	}
}

// A healthy backend must be silent: the reconciler runs forever, and a route
// it replaces unnecessarily is one replaced under live traffic every ten
// seconds.
func TestReconcileChangesNothingWhenTheKernelAgrees(t *testing.T) {
	a, q := agentForReconcile(t, backendKernel())

	a.reconcileRouting(context.Background())

	if got := q.writes(); len(got) != 0 {
		t.Errorf("reconcile touched an intact system: %v", got)
	}
}

// Observe mode must keep answering probes but must not carry published traffic.
// The reply table is measurement and is repaired; the return-path default route
// moves real traffic and deliberately does not exist in observe mode.
func TestReconcileInObserveModeRepairsRepliesButNotTheReturnPath(t *testing.T) {
	kernel := backendKernel()
	kernel["ip route show 10.99.0.1/32 table 101"] = ""
	kernel["ip route show default table 100"] = "" // observe mode never installed it

	a, q := agentForReconcile(t, kernel)
	a.runner = &observeRunner{q}

	a.reconcileRouting(context.Background())

	if q.wrote("table 101") != 1 {
		t.Errorf("observe mode must still repair probe reply routing; writes were %v", q.writes())
	}
	if q.wrote("route replace default") != 0 {
		t.Errorf("observe mode installed the return path; writes were %v", q.writes())
	}
}

// observeRunner is a runner that reports it changes nothing, standing in for
// the DryRunner without swallowing the recorded calls.
type observeRunner struct{ *queryRunner }

func (o *observeRunner) Applying() bool { return false }

// The backend shapes the direction that matters most for a game server: srcds
// sends far more than it receives, and the house's upload is the smaller half
// of every service here. The shaper belongs to the interface, so `wg-quick
// down` takes it away with nothing to report the loss - traffic keeps flowing,
// unshaped, and only the latency under load gets quietly worse.
func TestReconcileRestoresShapingLostWithTheTunnel(t *testing.T) {
	kernel := backendKernel()
	kernel["tc qdisc show dev wg-main"] = "qdisc noqueue 0: root refcnt 2"
	kernel["tc qdisc show dev wg-lte1"] = "qdisc noqueue 0: root refcnt 2"

	a, q := agentForReconcile(t, kernel)
	a.cfg.Paths[0].ShapeMbit = 20

	a.reconcileRouting(context.Background())

	if q.wrote("tc qdisc replace dev wg-main root cake bandwidth 20mbit") != 1 {
		t.Errorf("shaping was not restored; writes were %v", q.writes())
	}
	// The unshaped path is not even asked about.
	if countCalls(q, "tc qdisc show dev wg-lte1") != 0 {
		t.Errorf("ran tc against a path with no shaping configured; calls were %v", q.calls)
	}
}

// The guarantee for every existing site: a backend told no rates never changes
// a queue discipline, so upgrading to a build with shaping in it is felt by
// nobody.
//
// Applying a configuration does read each interface back, because that is how
// clearing a rate in the portal takes the shaper off again - a removal cannot
// be generated from a setting that is no longer there. The ten-second
// reconcile skips unshaped paths entirely, so the steady state is silent.
func TestABackendWithNoShapingChangesNoQdisc(t *testing.T) {
	a, q := agentForReconcile(t, backendKernel())

	a.applyShaping(context.Background(), a.cfg)
	for _, c := range q.writes() {
		if strings.HasPrefix(c, "tc ") {
			t.Errorf("changed a queue discipline on a site with no shaping configured: %q", c)
		}
	}

	before := len(q.calls)
	a.reconcileRouting(context.Background())
	for _, c := range q.calls[before:] {
		if strings.HasPrefix(c, "tc ") {
			t.Errorf("the reconciler ran tc on a site with no shaping configured: %q", c)
		}
	}
}

// countCalls counts every command, readbacks included - the point of some
// assertions is that a readback never happened either.
func countCalls(q *queryRunner, substr string) int {
	n := 0
	for _, c := range q.calls {
		if strings.Contains(c, substr) {
			n++
		}
	}
	return n
}
