package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/store"
)

// An interface name reaches nft text, ip and tc argv and a sysctl key as
// root, and used to be checked only for being non-empty. The kernel's own
// rule is fifteen bytes and no slash or whitespace; the three iproute2 read
// verbs are refused beside them because a name that is also a command word
// is a name waiting for the next scan.
func TestInterfaceNamesAreHeldToTheKernelsRules(t *testing.T) {
	for _, bad := range []string{`wg-main"`, "wg main", "wg/main", "abcdefghijklmnop", "list", "show", "get", "wg\tmain"} {
		cfg := model.Defaults()
		cfg.Paths[0].Iface = bad
		err := validate(&cfg)
		if err == nil || !strings.Contains(err.Error(), "interface") {
			t.Errorf("path interface %q was accepted: %v", bad, err)
		}
		cfg = model.Defaults()
		cfg.Frontend.PublicIface = bad
		if err := validate(&cfg); err == nil || !strings.Contains(err.Error(), "interface") {
			t.Errorf("public interface %q was accepted: %v", bad, err)
		}
	}
	for _, good := range []string{"eth0.100", "wg-main", "ens3", "eth0@if3", "br_lan:1"} {
		cfg := model.Defaults()
		cfg.Paths[0].Iface = good
		cfg.Frontend.PublicIface = good
		if err := validate(&cfg); err != nil {
			t.Errorf("interface %q was refused: %v", good, err)
		}
	}
}

// Two paths on one tunnel measure one tunnel, which is the failure the
// per-path tables and marks exist to prevent, and the interface is the one
// identity those checks do not cover.
func TestTwoPathsCannotShareAnInterface(t *testing.T) {
	cfg := model.Defaults()
	cfg.Paths[1].Iface = cfg.Paths[0].Iface
	err := validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), cfg.Paths[0].Name) || !strings.Contains(err.Error(), cfg.Paths[1].Name) {
		t.Fatalf("a shared interface was accepted or the message does not name both paths: %v", err)
	}
}

// The notification URL names a host this root process posts a bearer token
// to, and it used to go from the form into the request unchecked, with an
// unrecognised kind silently meaning webhook.
func TestNotifyTargetIsBounded(t *testing.T) {
	base := func() model.Config {
		cfg := model.Defaults()
		cfg.Notify.Enabled = true
		cfg.Notify.Kind = "ntfy"
		cfg.Notify.URL = "https://ntfy.example/topic"
		return cfg
	}
	shipped := model.Defaults()
	if err := validate(&shipped); err != nil {
		t.Fatalf("the shipped configuration no longer validates: %v", err)
	}
	for _, kind := range []string{"ntfy", "Telegram", "WEBHOOK"} {
		cfg := base()
		cfg.Notify.Kind = kind
		if err := validate(&cfg); err != nil {
			t.Errorf("kind %q refused: %v", kind, err)
		}
		if cfg.Notify.Kind != strings.ToLower(kind) {
			t.Errorf("kind %q was not normalised: %q", kind, cfg.Notify.Kind)
		}
	}
	for name, tweak := range map[string]func(*model.Config){
		"ftp scheme":   func(c *model.Config) { c.Notify.URL = "ftp://ntfy.example/topic" },
		"no scheme":    func(c *model.Config) { c.Notify.URL = "ntfy.example/topic" },
		"no host":      func(c *model.Config) { c.Notify.URL = "https:///topic" },
		"unknown kind": func(c *model.Config) { c.Notify.Kind = "slack" },
		"empty kind":   func(c *model.Config) { c.Notify.Kind = "" },
		"empty url":    func(c *model.Config) { c.Notify.URL = "" },
	} {
		cfg := base()
		tweak(&cfg)
		if err := validate(&cfg); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// A URL left in the form with the feature off is still checked: it is
	// what the feature will post to the day it is switched on.
	cfg := base()
	cfg.Notify.Enabled = false
	cfg.Notify.URL = "gopher://x"
	if err := validate(&cfg); err == nil {
		t.Error("a bad URL was accepted because notifications were off")
	}
}

// A negative, non-finite or oversized grant lands outside int64 on the way to
// bytes, and a negative ExtraBytes is read by quota as no byte limit at all:
// the outcome the time box exists to prevent, reached by typo.
func TestApproveRefusesAnUnboundedGrant(t *testing.T) {
	s, _, st := portalServer(t, model.Defaults())
	if err := st.CreateUser("admin", "first-run-password"); err != nil {
		t.Fatal(err)
	}
	cookie := login(t, s, "admin", "first-run-password")
	for _, body := range []string{
		`{"path_id":2,"hours":1,"extra_gb":-1}`,
		`{"path_id":2,"hours":1,"extra_gb":1e300}`,
		`{"path_id":2,"hours":1,"extra_gb":2147483648}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/approve", strings.NewReader(body))
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		s.Handler(false).ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s answered %d: %s", body, w.Code, w.Body.String())
		}
	}
}

// The session cookie is SameSite=Lax and that was the whole CSRF defence. A
// browser says where a request came from, and a state-changing request from
// another site is refused whatever cookie it carries; a same-origin one and
// one from no browser at all (failoverctl, curl) are untouched.
func TestCrossSiteStateChangesAreRefused(t *testing.T) {
	s, _, st := portalServer(t, model.Defaults())
	if err := st.CreateUser("admin", "first-run-password"); err != nil {
		t.Fatal(err)
	}
	cookie := login(t, s, "admin", "first-run-password")
	try := func(headers map[string]string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/pin", strings.NewReader(`{"path_id":0}`))
		req.Host = "10.98.0.2:8088"
		req.AddCookie(cookie)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		s.Handler(false).ServeHTTP(w, req)
		return w.Code
	}
	if code := try(map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}); code != http.StatusForbidden {
		t.Errorf("cross-site POST answered %d, want 403", code)
	}
	if code := try(map[string]string{"Origin": "http://10.98.0.2:9999"}); code != http.StatusForbidden {
		t.Errorf("same-site other-port POST answered %d, want 403", code)
	}
	// An opaque origin is a sandboxed iframe or a file:// page, never this
	// portal's own page.
	if code := try(map[string]string{"Origin": "null"}); code != http.StatusForbidden {
		t.Errorf("Origin: null POST answered %d, want 403", code)
	}
	// A browser too old to send either header still sends its form's content
	// type, and no form type is anything this API accepts.
	for _, ct := range []string{"application/x-www-form-urlencoded", "multipart/form-data; boundary=x", "text/plain"} {
		if code := try(map[string]string{"Content-Type": ct}); code != http.StatusForbidden {
			t.Errorf("headerless form POST (%s) answered %d, want 403", ct, code)
		}
	}
	for name, h := range map[string]map[string]string{
		"same origin": {"Sec-Fetch-Site": "same-origin", "Origin": "http://10.98.0.2:8088"},
		"no browser":  {},
		"shell json":  {"Content-Type": "application/json"},
	} {
		if code := try(h); code == http.StatusForbidden {
			t.Errorf("%s POST was refused as cross-site", name)
		}
	}
	// A GET carrying a cross-site marker is a navigation, and reads are not
	// where the harm is.
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.AddCookie(cookie)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()
	s.Handler(false).ServeHTTP(w, req)
	if w.Code == http.StatusForbidden {
		t.Error("a cross-site GET was refused")
	}
}

// Two of the API's bodies carry secrets, and nothing told a browser not to
// keep them.
func TestAPIResponsesAreNotCacheable(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusOK, map[string]string{"psk": "x"})
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
}

// Each password check is 600k PBKDF2 iterations in the process that runs the
// probers. The attempt is counted before the hash, so a burst that arrives
// before any result is still counted, and the semaphore refuses what it
// cannot run rather than queueing it.
func TestConcurrentLoginsAreBounded(t *testing.T) {
	s := passwordServer(t)
	// Hold both slots, then the next attempt must be refused without a hash.
	s.loginSem <- struct{}{}
	s.loginSem <- struct{}{}
	w := post(t, s.Handler(false), "/api/login", loginRequest{Username: "admin", Password: "first-run-password"}, nil)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("third concurrent login answered %d, want 429", w.Code)
	}
	<-s.loginSem
	<-s.loginSem

	// Below the lockout threshold a correct login still succeeds, and its
	// own reservation does not lock it out.
	for i := 0; i < 3; i++ {
		post(t, s.Handler(false), "/api/login", loginRequest{Username: "admin", Password: "wrong"}, nil)
	}
	login(t, s, "admin", "first-run-password")

	// A burst counts every attempt even before any has finished: after the
	// threshold the lockout answers without reaching the store.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			post(t, s.Handler(false), "/api/login", loginRequest{Username: "admin", Password: "wrong"}, nil)
		}()
	}
	wg.Wait()
	w = post(t, s.Handler(false), "/api/login", loginRequest{Username: "admin", Password: "wrong"}, nil)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("after a burst of failures the next attempt answered %d, want 429", w.Code)
	}
}

// An unknown account used to answer in microseconds against hundreds of
// milliseconds for a real one. Pinned structurally rather than by clock:
// both branches spend a hash.
func TestUnknownUserCostsAHash(t *testing.T) {
	st := passwordServer(t).st
	if st.CheckPassword("nobody", "whatever") {
		t.Fatal("an unknown user was accepted")
	}
	got := store.HashesSpent()
	st.CheckPassword("nobody", "whatever")
	if store.HashesSpent() != got+1 {
		t.Fatal("an unknown account did not cost a hash")
	}
	st.CheckPassword("admin", "wrong")
	if store.HashesSpent() != got+2 {
		t.Fatal("a wrong password did not cost exactly one hash")
	}
}
