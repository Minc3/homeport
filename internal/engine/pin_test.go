package engine

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/store"
)

// A pin to a path that is down is an operator override and is honoured, held
// and said out loud. A pin to a path that is over quota is different in kind:
// quota is a policy block with a time-boxed approval beside it so that a 2am
// click cannot switch enforcement off for the month, and a pin has no
// expiry, so honouring it was that outcome by another button. Disabled is
// the operator's own instruction, contradicted.
func TestPinRefusesAQuotaOrDisabledPathAndHonoursADownOne(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cfg := testConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthUp, 2: model.HealthUp, 3: model.HealthDown})
	e.st = st
	e.blocks[2] = model.BlockQuota
	if err := e.Pin(2); err == nil || !strings.Contains(err.Error(), "approve") {
		t.Fatalf("a pin to an over-quota path was accepted: %v", err)
	}
	e.blocks[2] = model.BlockDisabled
	if err := e.Pin(2); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("a pin to a disabled path was accepted: %v", err)
	}
	if e.pinned != 0 {
		t.Fatal("a refused pin was recorded")
	}
	if err := e.Pin(3); err != nil {
		t.Fatalf("a pin to a down path was refused: %v", err)
	}
	if got, held, _ := e.selectPath(cfg, time.Now()); got != 3 || !held {
		t.Fatalf("a pin to a down path is not honoured as held: path %d held=%v", got, held)
	}
}
