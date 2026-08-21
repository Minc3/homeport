package engine

import (
	"testing"
	"time"

	"github.com/quinlan102/homeport/internal/model"
)

// The portal colours the active badge green only while traffic is on the
// preferred path, and plain on any fallback. That rule has to come from the
// engine rather than being reimplemented in JavaScript, because a second
// definition of "preferred" is free to drift from the selector's own.
func TestStatusReportsPreferredPathSoThePortalNeedNotReimplementIt(t *testing.T) {
	cfg := testConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthUp, 2: model.HealthUp, 3: model.HealthUp})

	st := e.Status()
	if st.PreferredPath != 1 {
		t.Errorf("preferred path %d, want main (1)", st.PreferredPath)
	}
}

// The reported preferred path must be the one the selector actually returns to,
// not merely the first in the list. Disabling the top-priority path has to move
// both together or the portal shows green on a path the engine is treating as a
// fallback.
func TestPreferredPathTracksTheSelectorWhenTheTopPathIsDisabled(t *testing.T) {
	cfg := testConfig()
	cfg.Paths[0].Enabled = false
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthUp, 2: model.HealthUp, 3: model.HealthUp})
	e.blocks[1] = model.BlockDisabled

	st := e.Status()
	if st.PreferredPath != 2 {
		t.Errorf("preferred path %d, want lte1 (2) once main is disabled", st.PreferredPath)
	}

	// The selector and the badge must agree about where traffic belongs.
	chosen, held, _ := e.selectPath(cfg, time.Now())
	if held {
		t.Fatal("two healthy paths remain, so the system is not held")
	}
	if chosen != st.PreferredPath {
		t.Errorf("selector chose %d but status reports preferred %d; the badge would be green on a fallback",
			chosen, st.PreferredPath)
	}
}

// Neither host's build was visible from the portal, which is exactly the kind of
// thing that is only missed when a procedure has already been written against
// the wrong assumption.
func TestStatusCarriesBothVersions(t *testing.T) {
	old := Version
	t.Cleanup(func() { Version = old })
	Version = "test-frontend-build"

	cfg := testConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthUp})
	e.SetBackendInfo("test-backend-build", "backend-host")

	st := e.Status()
	if st.FrontendVersion != "test-frontend-build" {
		t.Errorf("frontend version %q, want the stamped build", st.FrontendVersion)
	}
	if st.BackendVersion != "test-backend-build" {
		t.Errorf("backend version %q, want what the backend said in its hello", st.BackendVersion)
	}
	if st.BackendHost != "backend-host" {
		t.Errorf("backend host %q", st.BackendHost)
	}
}

// The backend's reported build deliberately outlives the control channel. A
// blank on disconnect would throw away the more useful answer - which build was
// there a minute ago - and BackendUp already reports liveness separately.
func TestBackendVersionSurvivesTheChannelDropping(t *testing.T) {
	cfg := testConfig()
	e := newTestEngine(cfg, map[int]model.Health{1: model.HealthUp})
	e.SetBackendInfo("test-backend-build", "backend-host")
	e.backendUp = false

	st := e.Status()
	if st.BackendVersion != "test-backend-build" {
		t.Errorf("backend version %q, want the last reported build to survive a disconnect", st.BackendVersion)
	}
	if st.BackendUp {
		t.Error("backend should still report as down; the version is not a liveness signal")
	}
}
