package web

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/store"
)

// geoServer is a portal wired to a fake zone-file host instead of the real
// one: the tests must not touch the network, and the base URL being a field
// exists exactly so they do not have to.
func geoServer(t *testing.T, zones map[string]string) (*Server, *int) {
	t.Helper()
	hits := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		body, ok := zones[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(backend.Close)

	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s := New(nil, st, slog.New(slog.NewTextHandler(io.Discard, nil)), "test-psk")
	s.geoBase = backend.URL
	if err := st.CreateUser("admin", "first-run-password"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return s, &hits
}

func geoFetch(t *testing.T, s *Server, body any, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	return post(t, s.Handler(false), "/api/geo/fetch", body, cookie)
}

// The happy path: two countries, one merged list, per-country counts, and the
// order of the request preserved so the operator can read the toast against
// what they typed.
func TestGeoFetchReturnsTheMergedLists(t *testing.T) {
	s, _ := geoServer(t, map[string]string{
		"/au-aggregated.zone": "1.128.0.0/11\n101.160.0.0/11\n",
		"/nz-aggregated.zone": "49.224.0.0/14\n",
	})
	cookie := login(t, s, "admin", "first-run-password")

	w := geoFetch(t, s, geoFetchRequest{Countries: []string{"AU", "nz"}}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("fetch = %d: %s", w.Code, w.Body.String())
	}
	var res struct {
		CIDRs  []string        `json:"cidrs"`
		Counts []geoFetchCount `json:"counts"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(res.CIDRs) != 3 || res.CIDRs[0] != "1.128.0.0/11" || res.CIDRs[2] != "49.224.0.0/14" {
		t.Errorf("cidrs = %v", res.CIDRs)
	}
	if len(res.Counts) != 2 || res.Counts[0].Country != "au" || res.Counts[0].Networks != 2 ||
		res.Counts[1].Country != "nz" || res.Counts[1].Networks != 1 {
		t.Errorf("counts = %+v", res.Counts)
	}
}

// Whole-or-nothing is the property that keeps this endpoint safe to have. An
// error page with a 200 on it, or any line that is not an IPv4 network, must
// fail the entire request rather than become part of an allowlist.
func TestGeoFetchRefusesAListWithAnythingElseInIt(t *testing.T) {
	s, _ := geoServer(t, map[string]string{
		"/au-aggregated.zone": "1.128.0.0/11\n",
		"/nz-aggregated.zone": "<html>509 Bandwidth Limit Exceeded</html>\n",
	})
	cookie := login(t, s, "admin", "first-run-password")

	w := geoFetch(t, s, geoFetchRequest{Countries: []string{"au", "nz"}}, cookie)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("fetch = %d, want a bad gateway: %s", w.Code, w.Body.String())
	}
	// The quotes around the code arrive JSON-escaped, so the assertion looks
	// for the escaped form the browser actually receives.
	if body := w.Body.String(); !strings.Contains(body, `list for \"nz\"`) {
		t.Errorf("the error does not name the country that failed: %s", body)
	}
	if strings.Contains(w.Body.String(), "1.128.0.0/11") {
		t.Error("a failed fetch still returned partial data")
	}
}

// A missing country - a typo'd code - is a 404 at the source and must come
// back as an error naming the code, and an empty file is refused too: an
// empty allowlist saved into a region would drop everything at the port.
func TestGeoFetchRefusesMissingAndEmptyLists(t *testing.T) {
	s, _ := geoServer(t, map[string]string{"/xx-aggregated.zone": "\n\n"})
	cookie := login(t, s, "admin", "first-run-password")

	if w := geoFetch(t, s, geoFetchRequest{Countries: []string{"zz"}}, cookie); w.Code != http.StatusBadGateway {
		t.Errorf("a 404 from the source came back as %d: %s", w.Code, w.Body.String())
	}
	if w := geoFetch(t, s, geoFetchRequest{Countries: []string{"xx"}}, cookie); w.Code != http.StatusBadGateway {
		t.Errorf("an empty list came back as %d: %s", w.Code, w.Body.String())
	}
}

// The code goes into a URL, so everything that is not two letters is refused
// before any request leaves - path traversal included, which is what the hit
// counter is checking.
func TestGeoFetchRefusesABadCountryCodeBeforeFetchingAnything(t *testing.T) {
	s, hits := geoServer(t, map[string]string{})
	cookie := login(t, s, "admin", "first-run-password")

	for _, code := range []string{"../au", "aus", "a", "a1", "au nz"} {
		if w := geoFetch(t, s, geoFetchRequest{Countries: []string{code}}, cookie); w.Code != http.StatusBadRequest {
			t.Errorf("code %q came back as %d, want a refusal", code, w.Code)
		}
	}
	if *hits != 0 {
		t.Errorf("%d requests left for bad codes; want none", *hits)
	}
}

// Truncation is the quiet failure: a list cut mid-download is valid CIDRs all
// the way to the cut, so the size cap has to be a loud error, not a shorter
// list.
func TestGeoFetchRefusesAnOversizedList(t *testing.T) {
	s, _ := geoServer(t, map[string]string{
		"/au-aggregated.zone": strings.Repeat("1.128.0.0/11\n", geoFetchMaxBytes/13+2),
	})
	cookie := login(t, s, "admin", "first-run-password")

	w := geoFetch(t, s, geoFetchRequest{Countries: []string{"au"}}, cookie)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("an oversized list came back as %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "over") {
		t.Errorf("the error does not say the list was too big: %s", w.Body.String())
	}
}

// The endpoint reaches out to the internet on behalf of the caller, so it sits
// behind the same session as everything else.
func TestGeoFetchRequiresAuthentication(t *testing.T) {
	s, hits := geoServer(t, map[string]string{"/au-aggregated.zone": "1.128.0.0/11\n"})

	w := geoFetch(t, s, geoFetchRequest{Countries: []string{"au"}}, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated fetch = %d, want 401", w.Code)
	}
	if *hits != 0 {
		t.Error("an unauthenticated request still caused a fetch")
	}
}

// The remembered recipe is replayed into the fetch endpoint by the button, so
// validation holds it to the same two-letter shape rather than letting it be
// stored and fail there.
func TestARegionsRememberedCountryCodesAreValidated(t *testing.T) {
	cfg := model.Defaults()
	cfg.Frontend.PublicIface = "eth0"
	cfg.Protect.Enabled = true
	cfg.Protect.Regions = []model.GeoRegion{
		{Name: "oceania", CIDRs: []string{"1.128.0.0/11"}, Countries: []string{"AU", " nz "}},
	}
	if err := validate(&cfg); err != nil {
		t.Fatalf("valid codes were rejected: %v", err)
	}
	if got := cfg.Protect.Regions[0].Countries; len(got) != 2 || got[0] != "au" || got[1] != "nz" {
		t.Errorf("codes were not normalised: %v", got)
	}

	cfg.Protect.Regions[0].Countries = []string{"aus"}
	if err := validate(&cfg); err == nil {
		t.Fatal("a three-letter code was accepted")
	}
}
