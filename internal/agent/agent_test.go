package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/proto"
	"github.com/quinlan102/homeport/internal/sysx"
)

type stubRunner struct {
	mu    sync.Mutex
	calls []string
	fail  bool
}

func (s *stubRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, name+" "+strings.Join(args, " "))
	if s.fail {
		return "", errors.New("RTNETLINK answers: Network is unreachable")
	}
	return "", nil
}

func (s *stubRunner) Applying() bool { return true }

func (s *stubRunner) count(substr string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.calls {
		if strings.Contains(c, substr) {
			n++
		}
	}
	return n
}

func testAgent(t *testing.T, withConfig bool) (*Agent, *stubRunner) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	boot := model.Bootstrap{
		PSK:      "secret",
		StateDir: t.TempDir(),
		Overlay:  model.OverlayConfig{FrontendIP: "10.99.0.1", BackendIP: "10.99.0.2", Device: "dummy0"},
	}
	a := New(log, boot)
	runner := &stubRunner{}
	a.runner = runner
	// The real runner too: these tests must not shell out to `ip` on the
	// development machine, which has none of this plumbing.
	a.real = runner
	a.ifaceExists = func(string) bool { return true }
	if withConfig {
		a.cfg = proto.BackendConfig{
			Overlay: proto.OverlayInfo{FrontendIP: "10.99.0.1", BackendIP: "10.99.0.2"},
			Paths: []proto.PathInfo{
				{ID: 1, Name: "nbn", Iface: "wg-nbn", Table: 101, Mark: 0x101},
				{ID: 2, Name: "lte1", Iface: "wg-lte1", Table: 102, Mark: 0x102},
			},
		}
		a.haveCfg = true
	}
	return a, runner
}

func TestBackendRetriesWhenConfigHasNotArrived(t *testing.T) {
	a, runner := testAgent(t, false)

	// A probe arrives before the frontend has pushed any configuration, so the
	// interface for path 1 cannot be resolved yet.
	a.applyDecision(context.Background(), 1, 100)
	if a.ActivePath() != 0 {
		t.Fatalf("active = %d; nothing should be recorded when the path is unknown", a.ActivePath())
	}
	if runner.count("route replace") != 0 {
		t.Error("no route should have been attempted")
	}

	// Config lands. The very next probe carries the same decision sequence, so
	// it must still be acted on rather than dismissed as already applied.
	a.mu.Lock()
	a.cfg = proto.BackendConfig{Paths: []proto.PathInfo{{ID: 1, Name: "nbn", Iface: "wg-nbn"}}}
	a.haveCfg = true
	a.mu.Unlock()

	a.applyDecision(context.Background(), 1, 100)
	if a.ActivePath() != 1 {
		t.Errorf("active = %d, want 1 once the config arrived", a.ActivePath())
	}
	if runner.count("route replace default dev wg-nbn") != 1 {
		t.Errorf("return path not installed; calls were %v", runner.calls)
	}
}

func TestBackendRetriesAfterAFailedApply(t *testing.T) {
	a, runner := testAgent(t, true)
	runner.fail = true

	a.applyDecision(context.Background(), 2, 50)
	if a.ActivePath() != 0 {
		t.Fatalf("active = %d after a failed apply; reply traffic would be on the wrong tunnel", a.ActivePath())
	}

	runner.fail = false
	a.applyDecision(context.Background(), 2, 50)
	if a.ActivePath() != 2 {
		t.Errorf("active = %d, want 2 on retry", a.ActivePath())
	}
	// Two attempts: the one that failed, and the retry that succeeded. The
	// retry is the point - before this fix the first failure was recorded as
	// applied and no later probe ever tried again.
	if got := runner.count("route replace default dev wg-lte1"); got != 2 {
		t.Errorf("expected a failed attempt then a successful retry, got %d; calls were %v", got, runner.calls)
	}
}

func TestBackendIgnoresReorderedProbes(t *testing.T) {
	a, _ := testAgent(t, true)

	a.applyDecision(context.Background(), 2, 100)
	if a.ActivePath() != 2 {
		t.Fatalf("setup failed, active = %d", a.ActivePath())
	}
	// A probe that was delayed in flight still carries the older decision.
	a.applyDecision(context.Background(), 1, 99)
	if a.ActivePath() != 2 {
		t.Errorf("active = %d; a reordered probe must not rewind the decision", a.ActivePath())
	}
}

func TestBackendIgnoresEmptyDecision(t *testing.T) {
	a, runner := testAgent(t, true)
	a.applyDecision(context.Background(), 0, 10)
	if a.ActivePath() != 0 || runner.count("route") != 0 {
		t.Error("path id zero means the frontend has not chosen yet; nothing should happen")
	}
}

func TestBackendAppliesNewerDecision(t *testing.T) {
	a, _ := testAgent(t, true)
	a.applyDecision(context.Background(), 1, 10)
	a.applyDecision(context.Background(), 2, 11)
	if a.ActivePath() != 2 {
		t.Errorf("active = %d, want 2", a.ActivePath())
	}
}

var _ sysx.Runner = (*stubRunner)(nil)

// Arming the system changes the runner without changing the frontend's choice,
// and applyDecision deliberately short-circuits when the choice is unchanged.
// Without an explicit re-assert when a configuration arrives, the return-path
// default route - the one that actually carries reply traffic - is never
// installed: the portal reports armed, the frontend DNATs, and every published
// connection hangs because replies leave via the LAN instead of the tunnel.
func TestConfigChangeReinstallsTheReturnPath(t *testing.T) {
	a, runner := testAgent(t, true)

	// A decision has already been applied - in observe mode, so nothing real
	// was installed - and the frontend has not changed its mind since.
	a.active = 1
	a.lastSeq = 5

	a.reassertReturnPath(context.Background())

	if runner.count("route replace default dev wg-nbn table 100") != 1 {
		t.Errorf("a configuration change must reinstall the return path, got: %v", runner.calls)
	}
}

// With no decision yet there is nothing to re-assert, and guessing one would
// point reply traffic down a tunnel the frontend has not chosen.
func TestReturnPathIsNotGuessedBeforeAnyDecision(t *testing.T) {
	a, runner := testAgent(t, true)

	a.reassertReturnPath(context.Background())

	if runner.count("route replace default") != 0 {
		t.Errorf("nothing should be installed before the first decision, got: %v", runner.calls)
	}
}
