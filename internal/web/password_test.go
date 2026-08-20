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

	"github.com/quinlan102/homeport/internal/store"
)

func passwordServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s := New(nil, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := st.CreateUser("admin", "first-run-password"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return s
}

func post(t *testing.T, h http.Handler, path string, body any, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw)))
	if cookie != nil {
		req.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func login(t *testing.T, s *Server, user, password string) *http.Cookie {
	t.Helper()
	w := post(t, s.Handler(false), "/api/login", loginRequest{Username: user, Password: password}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	t.Fatal("no session cookie was issued")
	return nil
}

// The first-run password is printed to the journal once and was then permanent:
// anything that could read the journal had it forever and there was no way to
// rotate it. This is that way.
func TestAnOperatorCanChangeTheirPassword(t *testing.T) {
	s := passwordServer(t)
	cookie := login(t, s, "admin", "first-run-password")

	w := post(t, s.Handler(false), "/api/password",
		passwordRequest{Current: "first-run-password", New: "a-much-better-one"}, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("change refused: %d %s", w.Code, w.Body.String())
	}
	if !s.st.CheckPassword("admin", "a-much-better-one") {
		t.Error("the new password does not work")
	}
	if s.st.CheckPassword("admin", "first-run-password") {
		t.Error("the old password still works")
	}
}

// Changing it is usually a response to somebody else having had it, and a
// thirty-day cookie would leave them logged in regardless.
func TestChangingThePasswordLogsOutOtherSessions(t *testing.T) {
	s := passwordServer(t)
	elsewhere := login(t, s, "admin", "first-run-password")
	mine := login(t, s, "admin", "first-run-password")

	w := post(t, s.Handler(false), "/api/password",
		passwordRequest{Current: "first-run-password", New: "a-much-better-one"}, mine)
	if w.Code != http.StatusOK {
		t.Fatalf("change refused: %d %s", w.Code, w.Body.String())
	}
	if _, err := s.st.Session(elsewhere.Value); err == nil {
		t.Error("a session opened elsewhere is still valid after the password changed")
	}
	// ...and the caller is handed a fresh one, so succeeding does not bounce
	// them to the login page.
	fresh := ""
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			fresh = c.Value
		}
	}
	if fresh == "" {
		t.Fatal("no replacement session was issued to the caller")
	}
	if _, err := s.st.Session(fresh); err != nil {
		t.Error("the replacement session is not valid")
	}
}

// Knowing the current one is what separates a change from a takeover of a
// session somebody left open.
func TestTheCurrentPasswordIsRequired(t *testing.T) {
	s := passwordServer(t)
	cookie := login(t, s, "admin", "first-run-password")

	w := post(t, s.Handler(false), "/api/password",
		passwordRequest{Current: "not-it", New: "a-much-better-one"}, cookie)
	if w.Code != http.StatusForbidden {
		t.Fatalf("a wrong current password returned %d, want 403", w.Code)
	}
	if !s.st.CheckPassword("admin", "first-run-password") {
		t.Error("the password changed anyway")
	}
}

// An unauthenticated request must not be able to set a password, or the login
// is decorative.
func TestChangingAPasswordNeedsASession(t *testing.T) {
	s := passwordServer(t)

	w := post(t, s.Handler(false), "/api/password",
		passwordRequest{Current: "first-run-password", New: "a-much-better-one"}, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("an unauthenticated change returned %d, want 401", w.Code)
	}
}

// The recovery path: root on the box, over the socket that has no login. It
// takes no current password because the case it exists for is not having one.
func TestTheLocalSocketCanResetAForgottenPassword(t *testing.T) {
	s := passwordServer(t)

	w := post(t, s.Handler(true), "/api/password", passwordRequest{New: "recovered-by-root"}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("reset refused: %d %s", w.Code, w.Body.String())
	}
	if !s.st.CheckPassword("admin", "recovered-by-root") {
		t.Error("the reset password does not work")
	}
}

// A floor, not a policy - but a floor, because the generated one it replaces is
// 24 characters of hex.
func TestAVeryShortPasswordIsRefused(t *testing.T) {
	s := passwordServer(t)
	cookie := login(t, s, "admin", "first-run-password")

	w := post(t, s.Handler(false), "/api/password",
		passwordRequest{Current: "first-run-password", New: "short"}, cookie)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("a five-character password returned %d, want 400", w.Code)
	}
}
