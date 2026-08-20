package engine

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/notify"
	"github.com/quinlan102/homeport/internal/store"
	"github.com/quinlan102/homeport/internal/sysx"
)

// stubRunner records commands and can be made to fail.
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

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// engineForApply builds an engine with a real store and a stub runner.
func engineForApply(t *testing.T, health map[int]model.Health) (*Engine, *stubRunner) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg := model.Defaults()
	log := quietLogger()
	e := New(log, st, notify.New(log), cfg, []byte("secret"), t.TempDir())

	runner := &stubRunner{}
	e.runner = runner
	// A separate stub for the always-real runner, so these tests never shell
	// out to `ip` on the development machine, and so assertions counting what
	// the mode-gated runner did are not polluted by the measurement plumbing.
	e.real = &stubRunner{}
	e.ifaceExists = func(string) bool { return true }
	for _, p := range cfg.Paths {
		tr := NewTracker(p, cfg.Probe, cfg.Failover)
		tr.health = health[p.ID]
		if tr.health == model.HealthUp {
			tr.cleanSince = time.Now().Add(-time.Hour)
		}
		e.trackers[p.ID] = tr
		e.blocks[p.ID] = model.BlockNone
	}
	return e, runner
}

func TestSwitchIsCommittedOnlyAfterTheRouteInstalls(t *testing.T) {
	e, runner := engineForApply(t, map[int]model.Health{1: model.HealthUp, 2: model.HealthUp, 3: model.HealthUp})
	runner.fail = true

	e.evaluate(context.Background(), time.Now())

	// The kernel rejected the route, so the engine must not claim to have
	// switched - the portal would show a path that traffic is not using.
	if e.active != 0 {
		t.Errorf("active = %d after a failed route install, want it left alone", e.active)
	}
	if runner.count("route replace") != 1 {
		t.Fatalf("expected one route attempt, got %d", runner.count("route replace"))
	}

	// And because nothing was committed, the next pass retries rather than
	// treating the failed choice as already current.
	e.evaluate(context.Background(), time.Now())
	if runner.count("route replace") != 2 {
		t.Errorf("a failed route install was never retried; attempts = %d", runner.count("route replace"))
	}

	runner.fail = false
	e.evaluate(context.Background(), time.Now())
	if e.active != 1 {
		t.Errorf("active = %d once the route installs, want nbn (1)", e.active)
	}
}

func TestSwitchCommitsOnSuccess(t *testing.T) {
	e, runner := engineForApply(t, map[int]model.Health{1: model.HealthDown, 2: model.HealthUp, 3: model.HealthUp})
	e.active = 1

	before := e.decisionSeq
	e.evaluate(context.Background(), time.Now())

	if e.active != 2 {
		t.Errorf("active = %d, want lte1 (2)", e.active)
	}
	if e.decisionSeq <= before {
		t.Error("decision sequence must advance on a switch, or the backend ignores it")
	}
	if runner.count("route replace 10.99.0.2/32 dev wg-lte1") != 1 {
		t.Errorf("route not installed for the chosen path; calls were %v", runner.calls)
	}
}

func TestDecisionSequenceSurvivesARestart(t *testing.T) {
	// The backend remembers the highest sequence it has seen. If a restarted
	// frontend began at zero again, every decision it made would be ignored as
	// stale until it had switched paths as many times as before the restart -
	// leaving reply traffic on the wrong tunnel.
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	log := quietLogger()
	e := New(log, st, notify.New(log), model.Defaults(), []byte("secret"), t.TempDir())
	if e.decisionSeq == 0 {
		t.Fatal("decision sequence starts at zero; a restart would rewind it")
	}
	if e.decisionSeq < uint64(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Unix())<<16 {
		t.Errorf("decision sequence %d is not seeded from the clock", e.decisionSeq)
	}
}

func TestProbePlumbingIsInstalledInObserveMode(t *testing.T) {
	// Observe mode must still measure. Without the per-path tables and fwmark
	// rules every probe follows the single active route, so all three paths
	// would be testing the same tunnel and the observation would be worthless.
	cfg := model.Defaults()
	runner := &stubRunner{}
	err := sysx.EnsureProbeRoutes(context.Background(), runner, cfg.Paths,
		cfg.Overlay.BackendIP, cfg.Overlay.FrontendIP)
	// Interfaces do not exist on the test host, so an error is expected; what
	// matters is that it reports which paths it could not set up rather than
	// skipping them silently.
	if err == nil {
		t.Skip("test host unexpectedly has wg interfaces")
	}
	for _, name := range []string{"nbn", "lte1", "lte2"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error should name the unprobeable path %q, got: %v", name, err)
		}
	}
}

// Arming a system that is already running changes the runner without changing
// the chosen path, and evaluate() installs a route only when the choice
// changes. Without a re-assert when configuration is applied, the DNAT rules
// get published while the main table still has no route to the backend: every
// connection to a published service hangs, because the DNAT'd packets follow
// the default route out the public interface instead.
func TestApplyingConfigReinstallsTheActiveRoute(t *testing.T) {
	e, runner := engineForApply(t, map[int]model.Health{1: model.HealthUp, 2: model.HealthUp, 3: model.HealthUp})

	e.evaluate(context.Background(), time.Now())
	if e.active != 1 {
		t.Fatalf("active = %d, want nbn (1)", e.active)
	}
	before := runner.count("route replace 10.99.0.2/32")

	e.applySystemConfig(context.Background())

	if runner.count("route replace 10.99.0.2/32") != before+1 {
		t.Errorf("applying configuration must reinstall the active route; attempts went %d -> %d",
			before, runner.count("route replace 10.99.0.2/32"))
	}
}
