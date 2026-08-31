package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/quinlan102/homeport/internal/engine"
	"github.com/quinlan102/homeport/internal/model"
)

// The dashboard reads these three fields straight out of /api/status: two to
// print the running builds, one to decide whether the active-path badge is
// green. Renaming or dropping any of them breaks the page silently - the JSON
// still parses, the values just come back undefined - so the wire names are
// pinned here rather than only in the Go struct.
func TestStatusAPICarriesTheFieldsTheDashboardReads(t *testing.T) {
	oldVersion := engine.Version
	t.Cleanup(func() { engine.Version = oldVersion })
	engine.Version = "frontend-build-under-test"

	srv, eng, _ := portalServer(t, model.Defaults())
	eng.SetBackendInfo("backend-build-under-test", "backend-host")

	rec := httptest.NewRecorder()
	// trusted: this exercises the payload, not the login flow.
	srv.Handler(true).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/status", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}

	var got struct {
		Status struct {
			FrontendVersion string `json:"frontend_version"`
			BackendVersion  string `json:"backend_version"`
			BackendHost     string `json:"backend_host"`
			PreferredPath   int    `json:"preferred_path"`
			ActivePath      int    `json:"active_path"`
		} `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if got.Status.FrontendVersion != "frontend-build-under-test" {
		t.Errorf("frontend_version = %q", got.Status.FrontendVersion)
	}
	if got.Status.BackendVersion != "backend-build-under-test" {
		t.Errorf("backend_version = %q", got.Status.BackendVersion)
	}
	if got.Status.BackendHost != "backend-host" {
		t.Errorf("backend_host = %q", got.Status.BackendHost)
	}
	// The shipped defaults put main at priority 1, so that is where traffic
	// belongs and where the badge should read green.
	if got.Status.PreferredPath != 1 {
		t.Errorf("preferred_path = %d, want 1", got.Status.PreferredPath)
	}
}
