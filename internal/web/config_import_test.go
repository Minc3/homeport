package web

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quinlan102/homeport/internal/engine"
	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/notify"
	"github.com/quinlan102/homeport/internal/store"
)

// portalServer is the package's engine-backed portal fixture: a real store, a
// real engine over the configuration the caller wants running, and the server
// in front of them. One copy rather than one per file, because the argument
// lists it hides are what change whenever the frontend gains a dependency.
func portalServer(t *testing.T, running model.Config) (*Server, *engine.Engine, *store.Store) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	eng := engine.New(log, st, notify.New(log), running, []byte("secret"), t.TempDir())
	return New(eng, st, log, "test-psk"), eng, st
}

// trusted: these exercise the payload, not the login flow. The one test that
// is about the door asks for the untrusted handler itself.
func postCheck(t *testing.T, srv *Server, body any) *httptest.ResponseRecorder {
	t.Helper()
	return post(t, srv.Handler(true), "/api/config/check", body, nil)
}

// sendRaw sends bytes rather than a marshalled value, for the refusals that
// are about the shape of the file rather than the configuration inside it.
func sendRaw(t *testing.T, srv *Server, method, path, raw string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.Handler(true).ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(raw)))
	return rec
}

func errorMessage(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode refusal: %v: %s", err, rec.Body.String())
	}
	return body.Error
}

// withField marshals a configuration and adds a key to the top level of it,
// which is what a file written by a build that has one more setting than this
// one looks like.
func withField(t *testing.T, cfg model.Config, key string, value any) string {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if value == nil {
		delete(m, key)
	} else {
		m[key] = value
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	return string(out)
}

// An imported file has to come back as the same configuration, because that is
// the whole of what import means: a restore is meant to put the system back,
// not to put something near it back. The region lists are the part most worth
// pinning - they are the bulk of a real configuration and the part nobody
// could retype - and the parts a save would repair have to be repaired here
// too, because the settings form binds inputs directly to what this returns
// and cannot bind one to a group an older build never wrote.
func TestCheckConfigNormalisesAnImportedFile(t *testing.T) {
	srv, _, _ := portalServer(t, model.Defaults())

	file := model.Defaults()
	file.Protect.Regions = []model.GeoRegion{{
		Name:      "oceania",
		CIDRs:     []string{"203.0.113.0/24", "198.51.100.0/24"},
		Countries: []string{"au", "nz"},
	}}
	// What a file written before the quality weights existed carries: the
	// whole group at its zero value. model.Normalise is what fills it in.
	file.Failover.Quality = model.QualityConfig{}

	rec := postCheck(t, srv, file)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var got model.Config
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(got.Protect.Regions) != 1 {
		t.Fatalf("regions = %d, want the one the file carried", len(got.Protect.Regions))
	}
	r := got.Protect.Regions[0]
	if r.Name != "oceania" || len(r.CIDRs) != 2 || len(r.Countries) != 2 {
		t.Errorf("region came back as %+v, want the file's own list intact", r)
	}
	if got.Failover.Quality.LossWeight == 0 {
		t.Error("the quality group was left at zero; the form would render a scoring function that ignores loss")
	}
}

// Import fills the form and applies nothing. The endpoint is what has to hold
// that: a file is chosen from a disk rather than typed, and what it decides is
// every published port and every limit on a live system, so it goes through
// the operator's eyes and then through PUT /api/config like anything else.
func TestCheckConfigAppliesNothing(t *testing.T) {
	srv, eng, st := portalServer(t, model.Defaults())

	version := eng.ConfigVersion()

	file := model.Defaults()
	file.Protect.Enabled = true
	file.Protect.Regions = []model.GeoRegion{{Name: "oceania", CIDRs: []string{"203.0.113.0/24"}}}
	file.Notify.Enabled = true
	file.Notify.URL = "https://ntfy.example/homeport"

	if rec := postCheck(t, srv, file); rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", rec.Code, rec.Body.String())
	}

	live := eng.Config()
	if live.Protect.Enabled || len(live.Protect.Regions) != 0 || live.Notify.Enabled {
		t.Error("the running configuration moved; checking a file must not apply it")
	}
	// The engine's in-memory copy is the safest of the three places a
	// configuration can land, and asserting on it alone is how a future edit
	// that persisted the checked file - to give the form a memory of the last
	// import, say - would stay green while the next restart came up on a
	// configuration nobody approved and the backend was pushed its half.
	stored, err := st.LoadConfig()
	if err != nil {
		t.Fatalf("load stored config: %v", err)
	}
	if stored.Protect.Enabled || len(stored.Protect.Regions) != 0 || stored.Notify.Enabled {
		t.Error("the checked file was written to the database; a restart would come up on it")
	}
	if v := eng.ConfigVersion(); v != version {
		t.Errorf("config version moved from %d to %d; the backend would be pushed a configuration nobody saved", version, v)
	}
}

// The public interface and the address on it describe the box being imported
// into, not the configuration being imported. Getting one from a file is the
// quiet kind of wrong: the published ruleset is scoped to that interface, so a
// name belonging to another machine translates nothing at all while the save
// succeeds and every path goes on measuring perfectly. Backend egress is in
// the same struct and does travel, because it is a routing decision rather
// than a fact about the hardware.
func TestCheckConfigKeepsThisHostsPublicInterface(t *testing.T) {
	running := model.Defaults()
	running.Frontend.PublicIface = "ens3"
	running.Frontend.PublicIP = "203.0.113.10"
	srv, _, _ := portalServer(t, running)

	file := model.Defaults()
	file.Frontend.PublicIface = "eth0"
	file.Frontend.PublicIP = "198.51.100.7"
	file.Frontend.BackendEgress = true

	rec := postCheck(t, srv, file)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var got model.Config
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Frontend.PublicIface != running.Frontend.PublicIface {
		t.Errorf("public interface = %q, want this host's %q", got.Frontend.PublicIface, running.Frontend.PublicIface)
	}
	if got.Frontend.PublicIP != running.Frontend.PublicIP {
		t.Errorf("public IP = %q, want this host's %q", got.Frontend.PublicIP, running.Frontend.PublicIP)
	}
	if !got.Frontend.BackendEgress {
		t.Error("backend egress did not travel; it is a routing decision, not a fact about this box")
	}
}

// The two fields a save discards are discarded here too, so what the form is
// filled with is what a save would keep. A file taken from an armed host must
// not arm this one, and overlay addressing is bootstrap-owned on both hosts:
// shown on the form, a file's copy of either would be a value the save then
// silently threw away.
func TestCheckConfigPinsModeAndOverlay(t *testing.T) {
	running := model.Defaults()
	running.Mode = model.ModeObserve
	srv, _, _ := portalServer(t, running)

	file := model.Defaults()
	file.Mode = model.ModeArmed
	file.Overlay.BackendIP = "10.99.0.99"

	rec := postCheck(t, srv, file)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var got model.Config
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Mode != model.ModeObserve {
		t.Errorf("mode = %q, want the running %q", got.Mode, model.ModeObserve)
	}
	if got.Overlay.BackendIP != running.Overlay.BackendIP {
		t.Errorf("overlay backend IP = %q, want the running %q", got.Overlay.BackendIP, running.Overlay.BackendIP)
	}
}

// A file this build refuses is refused here rather than at save time, and the
// form is left holding the running configuration instead of a half-loaded one.
// That the message is the one a save would have given is pinned separately,
// against the save itself: asserted here it would only be this handler agreeing
// with itself.
func TestCheckConfigRefusesWhatASaveWouldRefuse(t *testing.T) {
	srv, eng, _ := portalServer(t, model.Defaults())

	file := model.Defaults()
	// Two paths on one fwmark: both would probe through whichever tunnel the
	// mark selects, and a dead link would test as healthy.
	file.Paths[1].Mark = file.Paths[0].Mark

	rec := postCheck(t, srv, file)
	if rec.Code == http.StatusOK {
		t.Fatalf("status 200, want a refusal: %s", rec.Body.String())
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Error == "" {
		t.Errorf("refusal carried no message (%v): %s", err, rec.Body.String())
	}
	if eng.Config().Paths[1].Mark == eng.Config().Paths[0].Mark {
		t.Error("the refused file reached the running configuration")
	}
}

// The endpoint's whole promise is that it answers the question a save would
// answer: what it accepts, a save accepts, and what it refuses carries the
// message the save would have given. Both doors decode through one helper, and
// this is what says so from outside - the same bytes posted to each, including
// the two refusals that are about the file rather than the configuration.
//
// Without it the divergence is silent in the direction that costs most: a file
// the check passes and the save then refuses blocks every unrelated edit in
// the form with a message the operator was promised at import time.
func TestCheckAndSaveAgreeOnTheSameBody(t *testing.T) {
	valid, err := json.Marshal(model.Defaults())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	clash := model.Defaults()
	// Two paths on one fwmark: both would probe through whichever tunnel the
	// mark selects, and a dead link would test as healthy.
	clash.Paths[1].Mark = clash.Paths[0].Mark
	clashing, err := json.Marshal(clash)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	cases := []struct {
		name string
		body string
		want int
	}{
		{"a configuration this build accepts", string(valid), http.StatusOK},
		{"two paths on one fwmark", string(clashing), http.StatusBadRequest},
		{"a setting this build has never heard of", withField(t, model.Defaults(), "query_cache_v2", true), http.StatusBadRequest},
		{"two configurations in one file", string(valid) + string(valid), http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, _ := portalServer(t, model.Defaults())
			check := sendRaw(t, srv, http.MethodPost, "/api/config/check", tc.body)
			save := sendRaw(t, srv, http.MethodPut, "/api/config", tc.body)
			if check.Code != tc.want || save.Code != tc.want {
				t.Fatalf("check %d, save %d, want %d from both: %s / %s",
					check.Code, save.Code, tc.want, check.Body.String(), save.Body.String())
			}
			if tc.want == http.StatusOK {
				return
			}
			if got, want := errorMessage(t, check), errorMessage(t, save); got != want {
				t.Errorf("check refused with %q, save with %q; the import reports a message the save does not", got, want)
			}
		})
	}
}

// The endpoint hands the whole configuration back to whoever asks, this host's
// overlay addressing, mode, public interface and notification token included,
// so it sits behind the same session as everything else. Pinned rather than
// left to the route table: login and logout are registered without the wrapper
// a dozen lines above it, so "registered without auth" is an ordinary-looking
// shape in that function.
func TestCheckConfigRequiresASession(t *testing.T) {
	srv, _, _ := portalServer(t, model.Defaults())

	w := post(t, srv.Handler(false), "/api/config/check", model.Defaults(), nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated check = %d, want 401: %s", w.Code, w.Body.String())
	}
}

// Rolling the frontend back is a documented flow, and restoring that morning's
// export into the older build is the obvious next step. The decoder's default
// is to drop what it does not recognise in silence, so the query cache, the
// per-service connection overrides and every remembered country code went
// missing, came back as an unconfigured form, and were written to the database
// on Save with nothing reporting a byte of it. The refusal names the field.
func TestCheckConfigRefusesAFileFromANewerBuild(t *testing.T) {
	srv, _, _ := portalServer(t, model.Defaults())

	rec := sendRaw(t, srv, http.MethodPost, "/api/config/check",
		withField(t, model.Defaults(), "sniper_mode", map[string]any{"enabled": true}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want a refusal: %s", rec.Code, rec.Body.String())
	}
	if msg := errorMessage(t, rec); !strings.Contains(msg, "sniper_mode") {
		t.Errorf("refusal was %q; it has to name the setting that was going to be dropped", msg)
	}
}

// Decode stops at the end of the first value, so two exports concatenated or a
// truncated file with anything after the cut were accepted on the strength of
// their first half - by the endpoint that exists to say whether a file is
// good, and which is the obvious thing to point a curl at from a shell where
// no JSON.parse is standing in front of it.
func TestCheckConfigRefusesAnythingAfterTheConfiguration(t *testing.T) {
	srv, _, _ := portalServer(t, model.Defaults())

	raw, err := json.Marshal(model.Defaults())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// A stray closing delimiter is the shape a hand edit leaves, and it is the
	// one json.Decoder.More does not see: it peeks at the next byte and
	// answers false for `}` and `]`, so the first version of this guard
	// refused a second object and passed the ordinary corruption.
	for _, trailing := range []string{"GARBAGE", "}", "]", "\n}", string(raw)} {
		rec := sendRaw(t, srv, http.MethodPost, "/api/config/check", string(raw)+trailing)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("trailing %q: status %d, want a refusal: %s", trailing, rec.Code, rec.Body.String())
		}
	}
	// And whitespace after the value is not content: every export ends in a
	// newline.
	rec := sendRaw(t, srv, http.MethodPost, "/api/config/check", string(raw)+"\n  \n")
	if rec.Code != http.StatusOK {
		t.Errorf("a trailing newline was refused: status %d: %s", rec.Code, rec.Body.String())
	}
}

// A hand-trimmed backup with the services key deleted came back as JSON null,
// and the settings form binds a row builder straight to it: it threw after the
// form had already been emptied, leaving a page that ended at Failover with no
// Save, no Discard and no Import on it to get back from. An empty list is what
// "no published services" means, and this endpoint exists so the browser never
// meets a shape it cannot render.
func TestCheckConfigServesAnAbsentServiceListAsEmpty(t *testing.T) {
	srv, _, _ := portalServer(t, model.Defaults())

	rec := sendRaw(t, srv, http.MethodPost, "/api/config/check",
		withField(t, model.Defaults(), "services", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Services []model.Service `json:"services"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Services == nil {
		t.Error("services came back as null; the settings form cannot bind a row builder to that")
	}
}

// The two host-identity fields are pinned after validate rather than before
// it, which is what keeps the promise above. Pinned first, this host's blank
// interface replaced the file's own good value and validate refused the file
// for it - naming a service the file publishes perfectly well, on a
// half-configured replacement box, which is exactly where a restore is being
// attempted and the one place there is no way to guess what to fix.
func TestCheckConfigDoesNotRefuseAFileForThisHostsBlankInterface(t *testing.T) {
	running := model.Defaults()
	running.Frontend.PublicIface = ""
	running.Frontend.PublicIP = ""
	srv, _, _ := portalServer(t, running)

	file := model.Defaults()
	file.Frontend.PublicIface = "eth0"
	file.Frontend.PublicIP = "203.0.113.10"
	file.Frontend.BackendEgress = true

	rec := postCheck(t, srv, file)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var got model.Config
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Frontend.PublicIface != "" {
		t.Errorf("public interface = %q, want this host's own (empty) one", got.Frontend.PublicIface)
	}
}

// The portal refuses an oversized file before it reads it, which it can only
// do against a copy of the bound this package enforces. A mirror nothing
// checks is a mirror that drifts, and it drifts badly in both directions: too
// high and a mispicked disk image is stringified whole in the tab before the
// frontend can refuse it, which is the whole point of checking there, and too
// low and the portal refuses a file this host would have taken.
func TestThePortalsFileSizeBoundMirrorsThisOne(t *testing.T) {
	js, err := assets.ReadFile("static/app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	want := fmt.Sprintf("const MAX_CONFIG_BYTES = %d << 20;", maxConfigBytes>>20)
	if !strings.Contains(string(js), want) {
		t.Errorf("app.js does not carry %q; its bound and maxConfigBytes have drifted apart", want)
	}
}
