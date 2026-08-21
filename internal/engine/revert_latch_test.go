package engine

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/notify"
	"github.com/quinlan102/homeport/internal/store"
)

// latchedEngineOn builds an armed engine on an existing store, with a
// recording runner in both seats, so a "restart" can be simulated by building
// a second engine on the same database.
func latchedEngineOn(t *testing.T, st *store.Store) (*Engine, *ctxRunner) {
	t.Helper()
	cfg := model.Defaults()
	cfg.Mode = model.ModeArmed
	log := quietLogger()
	e := New(log, st, notify.New(log), cfg, []byte("secret"), t.TempDir())
	runner := &ctxRunner{}
	e.real = runner
	e.runner = runner
	e.ifaceExists = func(string) bool { return true }
	return e, runner
}

// The frontend's unit runs under Restart=always, so the latch a revert sets
// cannot live only in memory: a crash between `failoverctl revert` and the
// `systemctl stop` that follows it restarts the process, and a startup that
// did not know about the latch reinstalled the probe tables and resumed
// probing - during uninstall, moments before the only binary able to remove
// them was deleted. The latch is persisted, reloaded by New, and honoured by
// Run's startup sequence.
func TestRevertLatchSurvivesARestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	e, _ := latchedEngineOn(t, st)
	e.mu.Lock()
	e.dataPlane = true
	e.mu.Unlock()
	e.Revert(context.Background())
	if !e.Status().Reverted {
		t.Fatal("revert did not latch the engine that served it")
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	// The restart: a fresh process on the same database.
	st, err = store.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	e2, runner := latchedEngineOn(t, st)
	if !e2.Status().Reverted {
		t.Fatal("the latch did not survive the restart")
	}

	// And Run must honour it: a latched startup installs nothing and starts no
	// probers. A pre-cancelled context returns Run immediately after its
	// startup sequence, which is the part under test.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = e2.Run(ctx)
	if n := runner.count(); n != 0 {
		t.Errorf("a latched startup ran %d system commands, want none: %v", n, runner.calls)
	}
	if n := e2.liveProbers.Load(); n != 0 {
		t.Errorf("a latched startup left %d probers running, want none", n)
	}
}

// A settings save is what releases the hold, and the persisted copy has to
// come off with the in-memory flag - or the next restart would start held on
// a latch the operator already released, measuring nothing and saying why
// nowhere.
func TestReconfigureClearsThePersistedLatch(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	e, _ := latchedEngineOn(t, st)
	e.Revert(context.Background())

	cfg := e.Config()
	if err := e.Reconfigure(cfg); err != nil {
		t.Fatalf("reconfigure: %v", err)
	}
	defer e.stopProbers() // Reconfigure starts a real prober generation
	if e.Status().Reverted {
		t.Fatal("reconfigure did not release the hold")
	}

	e2, _ := latchedEngineOn(t, st)
	if e2.Status().Reverted {
		t.Error("a restart after the save came up latched; the persisted copy was not cleared")
	}
}
