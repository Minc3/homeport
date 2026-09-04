// Package web serves the management portal.
//
// This is the only place the system is managed from. It lives on the frontend
// rather than the backend for one reason: when every tunnel is down, the
// backend is unreachable by definition, and that is exactly the moment an
// operator needs to see why and to approve an over-quota path. The frontend
// sits in the datacentre on independent internet, so the portal survives a
// total path outage.
//
// It is intended to be bound to an admin WireGuard interface rather than the
// public address. WireGuard already provides the encryption and peer
// authentication, so there are no certificates to renew and no public TCP
// surface to scan. The login below is defence in depth for a lost phone, not
// the security perimeter.
package web

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/quinlan102/homeport/internal/engine"
	"github.com/quinlan102/homeport/internal/store"
)

//go:embed static
var assets embed.FS

const (
	sessionCookie = "failover_session"
	sessionTTL    = 30 * 24 * time.Hour

	// defaultAdminUser is what a password reset over the local socket targets
	// when no account is named. It matches the frontend's -admin-user default.
	defaultAdminUser = "admin"
)

// Server is the portal HTTP server.
type Server struct {
	eng *engine.Engine
	st  *store.Store
	log *slog.Logger

	// The shared secret, as typed into the bootstrap file rather than the
	// derived key the engine holds. It exists here only to be handed back to
	// an authenticated operator setting up a linker: that host needs the same
	// string, and the alternative was reading it off the frontend over SSH and
	// retyping it beside four other values that the portal already knows.
	//
	// It is served by one endpoint, behind the same session as everything
	// else, and the page asks for it only when somebody opens a linker's setup
	// block. Anyone who can reach that endpoint can already revert the system,
	// arm it, or change the portal password, so the secret is not the weakest
	// thing behind this login - but it is the longest-lived, so it is not put
	// in the page unless it was asked for.
	psk string

	// The region-list fetch. A base URL and a client rather than constants,
	// so the tests can point the handler at a local server and the one
	// outbound dependency this package has is visible here in one place.
	geoBase   string
	geoClient *http.Client

	mu       sync.Mutex
	attempts map[string]*attemptRecord
	// loginSem bounds concurrent password checks; see handleLogin.
	loginSem chan struct{}
}

type attemptRecord struct {
	count int
	until time.Time
}

// New builds the portal server.
func New(eng *engine.Engine, st *store.Store, log *slog.Logger, psk string) *Server {
	return &Server{
		eng:       eng,
		st:        st,
		log:       log.With("component", "portal"),
		psk:       psk,
		geoBase:   geoFetchBase,
		geoClient: defaultGeoClient(),
		attempts:  map[string]*attemptRecord{},
		loginSem:  make(chan struct{}, maxConcurrentLogins),
	}
}

// EnsureAdmin creates the first account if none exists and returns the
// generated password, or an empty string if an account was already present.
func (s *Server) EnsureAdmin(username string) (string, error) {
	has, err := s.st.HasUsers()
	if err != nil {
		return "", err
	}
	if has {
		return "", nil
	}
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	password := hex.EncodeToString(b)
	if err := s.st.CreateUser(username, password); err != nil {
		return "", err
	}
	return password, nil
}

// Handler builds the HTTP handler. When trusted is true, authentication is
// skipped: that mode is only used for the root-owned unix socket that
// failoverctl talks to.
func (s *Server) Handler(trusted bool) http.Handler {
	mux := http.NewServeMux()

	sub, err := fs.Sub(assets, "static")
	if err != nil {
		panic(err)
	}
	files := http.FileServer(http.FS(sub))

	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)

	api := func(pattern string, h http.HandlerFunc) {
		mux.Handle(pattern, s.requireAuth(trusted, h))
	}
	api("GET /api/status", s.handleStatus)
	api("GET /api/psk", s.handlePSK)
	api("GET /api/config", s.handleGetConfig)
	api("GET /api/presets", s.handlePresets)
	api("GET /api/protect-presets", s.handleProtectPresets)
	api("PUT /api/config", s.handlePutConfig)
	// Checks a configuration without applying it, which is how an imported
	// file reaches the settings form: normalised and validated by the same
	// rules a save uses, so the form binds to a complete structure and a bad
	// file is refused with the message it would have been refused with anyway.
	api("POST /api/config/check", s.handleCheckConfig)
	api("GET /api/events", s.handleEvents)
	api("GET /api/history", s.handleHistory)
	api("GET /api/usage", s.handleUsage)
	api("POST /api/mode", s.handleMode)
	api("POST /api/pin", s.handlePin)
	api("POST /api/approve", s.handleApprove)
	api("POST /api/revoke", s.handleRevoke)
	api("POST /api/quarantine/clear", s.handleClearQuarantine)
	// Fetches region lists for the settings form. It fills the form, never
	// the configuration: what comes back still goes through the operator's
	// eyes and then through PUT /api/config like anything typed by hand.
	api("POST /api/geo/fetch", s.handleGeoFetch)
	api("POST /api/revert", s.handleRevert)
	// Takes the trusted flag directly: over the root-only socket there is no
	// session to read a username from, and no current password to demand from
	// somebody who already owns the machine.
	api("POST /api/password", s.handlePassword(trusted))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && !trusted && !s.authenticated(r) {
			http.Redirect(w, r, "/login.html", http.StatusFound)
			return
		}
		files.ServeHTTP(w, r)
	})
	return securityHeaders(mux)
}

// Serve runs the portal on a TCP address and, if socketPath is non-empty, on a
// root-only unix socket for failoverctl.
func (s *Server) Serve(ctx context.Context, addr, socketPath string) error {
	srv := &http.Server{
		Handler:           s.Handler(false),
		ReadHeaderTimeout: 10 * time.Second,
	}
	// The local socket comes up first and independently of the portal address.
	// failoverctl is the fallback for when the portal is unreachable, so tying
	// it to the portal's own listener would take it away in exactly the
	// situation it exists for.
	if socketPath != "" {
		go s.serveSocket(ctx, socketPath)
	}

	ln, err := s.listen(ctx, addr)
	if err != nil {
		return err
	}
	s.log.Info("portal listening", "addr", addr)

	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// listen opens the portal's TCP listener, retrying until it succeeds or the
// process is shutting down.
//
// It retries rather than failing because of what the failure costs. The portal
// binds an address on the admin WireGuard interface, and that address does not
// exist until wg-quick has brought the interface up - a unit ordering can ask
// for that but cannot guarantee it, and an admin tunnel that is down for any
// other reason has the same effect. Returning the error here takes the whole
// frontend down with it: probing stops, the control channel closes, and
// failover is gone until somebody notices a restart loop. A management
// interface must never be able to do that to the thing it manages.
func (s *Server) listen(ctx context.Context, addr string) (net.Listener, error) {
	var lc net.ListenConfig
	warned := false
	for {
		ln, err := lc.Listen(ctx, "tcp", addr)
		if err == nil {
			if warned {
				s.log.Info("portal address is available now", "addr", addr)
			}
			return ln, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !warned {
			// Once, not every five seconds: this is a normal few seconds during
			// boot and a standing condition otherwise, and neither is improved
			// by repeating it into the journal.
			s.log.Warn("cannot bind the portal yet; retrying every 5s. Everything else is running",
				"addr", addr, "err", err,
				"hint", "is the admin tunnel up? ip -4 addr show wg-admin")
			warned = true
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

func (s *Server) requireAuth(trusted bool, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if trusted {
			h(w, r)
			return
		}
		if !s.authenticated(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && crossSite(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request refused"})
			return
		}
		h(w, r)
	})
}

// crossSite reports a state-changing request that a browser says came from
// another site. The session cookie is SameSite=Lax, which stops a cross-site
// POST in a current browser, and that was the whole of the CSRF defence: it
// stops holding on an older mobile browser, which is exactly the lost phone
// the login is written for, and "same site" includes every other port on the
// portal's address. A cross-site POST here is `/api/revert` or arming the
// data plane. Browsers send Sec-Fetch-Site on every request and Origin on
// every POST, and a request from neither a browser nor the same origin
// (failoverctl over the socket, curl from a shell) carries neither header,
// so nothing that is not a browser is affected.
//
// Two shapes the headers alone would admit are refused as well. `Origin:
// null` is what a browser sends from an opaque origin, a sandboxed iframe or
// a file:// page, and it is never what this portal's own page sends. And a
// browser old enough to send neither header on a cross-site form POST, which
// is the browser this check exists for, still sends the form's content type:
// one of the three a form can produce, none of which this API accepts. A
// shell that posts JSON without naming the type is untouched; one that lets
// curl default to a form type is told why.
func crossSite(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return true
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		if origin == "null" {
			return true
		}
		u, err := url.Parse(origin)
		if err != nil || !strings.EqualFold(u.Host, r.Host) {
			return true
		}
	}
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	for _, form := range []string{"application/x-www-form-urlencoded", "multipart/form-data", "text/plain"} {
		if strings.HasPrefix(ct, form) {
			return true
		}
	}
	return false
}

func (s *Server) authenticated(r *http.Request) bool {
	_, ok := s.sessionUser(r)
	return ok
}

// sessionUser resolves the account behind a request's cookie.
func (s *Server) sessionUser(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", false
	}
	user, err := s.st.Session(c.Value)
	if err != nil {
		return "", false
	}
	return user, true
}

// minPasswordLen is a floor, not a policy. The portal is reachable only over
// the admin WireGuard tunnel, so this login is defence in depth rather than the
// perimeter, and a rule that pushes an operator towards a password they have to
// write down would make things worse rather than better.
const minPasswordLen = 10

// maxConcurrentLogins is how many password hashes may run at once. Each is
// 600k PBKDF2 iterations, a few hundred milliseconds of one core, in the
// process that also runs the probers and the decision loop.
const maxConcurrentLogins = 2

type passwordRequest struct {
	Username string `json:"username,omitempty"` // trusted socket only
	Current  string `json:"current,omitempty"`
	New      string `json:"new"`
}

// handlePassword changes an account's password.
//
// It exists because the alternative was worse than it looked: the first-run
// password is generated once, printed into the journal in the clear, and was
// then permanent. Anything that could read the journal had it forever, and an
// operator who wanted to rotate it had no way to.
//
// Over the trusted socket - root, on the box itself - no current password is
// required, because that is the recovery path for a password nobody has any
// more. Over the portal the current one must be given, and the account is
// whichever one the session belongs to rather than whichever one the request
// names.
func (s *Server) handlePassword(trusted bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req passwordRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
			return
		}
		if len(req.New) < minPasswordLen {
			writeJSON(w, http.StatusBadRequest,
				map[string]string{"error": fmt.Sprintf("the new password must be at least %d characters", minPasswordLen)})
			return
		}

		username := trimmed(req.Username)
		if !trusted {
			user, ok := s.sessionUser(r)
			if !ok {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
				return
			}
			username = user
			if !s.st.CheckPassword(username, req.Current) {
				s.log.Warn("password change refused: current password did not match", "user", username)
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "the current password is not correct"})
				return
			}
		}
		if username == "" {
			username = defaultAdminUser
		}
		if err := s.st.CreateUser(username, req.New); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		// Every existing session for this account goes, including the caller's.
		// The reason to change a password is usually that somebody else may
		// have had it, and a thirty-day cookie would leave them logged in
		// regardless.
		if err := s.st.DeleteSessionsFor(username); err != nil {
			s.log.Warn("could not clear existing sessions after a password change", "user", username, "err", err)
		}
		s.log.Warn("portal password changed", "user", username, "via", map[bool]string{true: "failoverctl", false: "portal"}[trusted])

		// The caller gets a fresh session so the portal does not bounce them to
		// the login page for succeeding. failoverctl has no cookie to replace.
		if !trusted {
			if token, err := s.st.NewSession(username, sessionTTL); err == nil {
				http.SetCookie(w, &http.Cookie{
					Name: sessionCookie, Value: token, Path: "/",
					HttpOnly: true, SameSite: http.SameSiteLaxMode,
					Expires: time.Now().Add(sessionTTL),
				})
			}
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "username": username})
	}
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if wait, blocked := s.throttled(host); blocked {
		writeJSON(w, http.StatusTooManyRequests,
			map[string]string{"error": "too many attempts, try again in " + wait.Round(time.Second).String()})
		return
	}

	var req loginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	// The attempt is counted before the hash rather than after it. Counted
	// after, a burst of concurrent requests all passed the lockout check
	// above before any of them had been counted, and each cost a full
	// PBKDF2 in the process that is also running the probers. A success
	// clears the count, so a correct login is never locked out by its own
	// reservation. The semaphore bounds how many hashes run at once: past
	// it the answer is the same 429 the lockout gives, without touching the
	// store, so an unauthenticated peer on the admin tunnel cannot hold the
	// frontend's CPU with parallel requests.
	s.recordFailure(host)
	select {
	case s.loginSem <- struct{}{}:
	default:
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many attempts, try again shortly"})
		return
	}
	ok := s.st.CheckPassword(req.Username, req.Password)
	<-s.loginSem
	if !ok {
		s.log.Warn("failed login", "user", req.Username, "remote", host)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	s.clearFailures(host)

	token, err := s.st.NewSession(req.Username, sessionTTL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(sessionTTL),
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		_ = s.st.DeleteSession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// throttled implements login lockout with escalating delay.
func (s *Server) throttled(host string) (time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.attempts[host]
	if !ok {
		return 0, false
	}
	if time.Now().Before(rec.until) {
		return time.Until(rec.until), true
	}
	return 0, false
}

func (s *Server) recordFailure(host string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Evict records whose lockout has long expired. The key is the remote
	// address, so without this the map grows for as long as somebody cares to
	// send login attempts from new source addresses - slowly, but with nothing
	// to stop it.
	if len(s.attempts) > 256 {
		cutoff := time.Now().Add(-time.Hour)
		for k, v := range s.attempts {
			if v.until.Before(cutoff) {
				delete(s.attempts, k)
			}
		}
	}

	rec, ok := s.attempts[host]
	if !ok {
		rec = &attemptRecord{}
		s.attempts[host] = rec
	}
	rec.count++
	if rec.count >= 5 {
		delay := time.Duration(rec.count-4) * 30 * time.Second
		if delay > 15*time.Minute {
			delay = 15 * time.Minute
		}
		rec.until = time.Now().Add(delay)
	}
}

func (s *Server) clearFailures(host string) {
	s.mu.Lock()
	delete(s.attempts, host)
	s.mu.Unlock()
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	// Two of these bodies carry secrets: the shared secret on /api/psk and
	// the notification token inside /api/config. Nothing tells a browser
	// not to keep a JSON body, and the device this portal is opened on is
	// the lost phone the login is written for.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func clientErr(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
}

func trimmed(s string) string { return strings.TrimSpace(s) }
