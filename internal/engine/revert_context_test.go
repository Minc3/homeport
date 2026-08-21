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

// ctxRunner models ExecRunner's one behaviour that matters here: it builds
// every command with exec.CommandContext, so a cancelled context does not
// abort the work in progress - it makes each command fail on the spot.
type ctxRunner struct {
	mu    sync.Mutex
	calls []string
}

func (r *ctxRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	return "", nil
}

func (r *ctxRunner) Applying() bool { return true }

func (r *ctxRunner) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func engineForRevert(t *testing.T) (*Engine, *ctxRunner) {
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

	runner := &ctxRunner{}
	e.real = runner
	e.runner = runner
	e.ifaceExists = func(string) bool { return true }
	e.mu.Lock()
	e.dataPlane = true
	e.mu.Unlock()
	return e, runner
}

// Revert checks none of its removals for errors and records dataPlane = false
// whatever happened, so handing it a context that is already cancelled produces
// the worst state this system has: every rule still installed, and an engine
// that believes it removed them - so nothing ever tries again.
//
// That is why web.handleRevert detaches the request context with
// context.WithoutCancel. failoverctl gives up after 15s and a browser tab
// closes whenever its owner decides to, and Revert now waits on reconfMu and
// applyMu before it does anything at all - longest when a settings save is
// stuck on a slow nft, which is exactly when somebody reaches for this button.
//
// This pins the hazard rather than the handler, because the hazard is what a
// future edit would have to keep in mind: if Revert ever learns to check its
// errors and refuse, this test is the one that should be revisited.
func TestRevertWithACancelledContextRemovesNothingButClaimsSuccess(t *testing.T) {
	e, runner := engineForRevert(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	e.Revert(ctx)

	if n := runner.count(); n != 0 {
		t.Fatalf("%d commands ran under a cancelled context, want 0 - the premise of this test is gone", n)
	}
	// And yet it reports the system reverted. This is the damage, stated.
	if e.Status().RulesActive {
		t.Fatal("RulesActive is still true; the rest of this test no longer describes the fault")
	}
}

// The same revert with a live context does the work, which is what
// context.WithoutCancel buys the handler.
func TestRevertWithALiveContextRemovesTheRules(t *testing.T) {
	e, runner := engineForRevert(t)

	e.Revert(context.Background())

	if n := runner.count(); n == 0 {
		t.Fatal("no commands ran; revert removed nothing")
	}
	if e.Status().RulesActive {
		t.Error("RulesActive should be false after a revert")
	}
}
