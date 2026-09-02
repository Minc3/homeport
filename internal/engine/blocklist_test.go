package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/notify"
	"github.com/quinlan102/homeport/internal/store"
)

// blocklistEngine is engineForReconcile with a state directory the caller
// chooses, so the cache written by one engine can be read by the next.
func blocklistEngine(t *testing.T, stateDir string) (*Engine, *queryRunner) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg := model.Defaults()
	cfg.Mode = model.ModeArmed
	cfg.Frontend.PublicIface = "eth0"
	cfg.Blocklist.Enabled = true
	log := quietLogger()
	e := New(log, st, notify.New(log), cfg, []byte("secret"), stateDir)

	q := &queryRunner{replies: healthyKernel()}
	e.real = q
	e.runner = q
	e.ifaceExists = func(string) bool { return true }
	return e, q
}

// feedServer serves a body and records how it was asked for.
type feedServer struct {
	body     string
	status   int
	etag     string
	requests int
	ifNone   string
}

func (f *feedServer) start(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests++
		f.ifNone = r.Header.Get("If-None-Match")
		if f.etag != "" {
			w.Header().Set("ETag", f.etag)
		}
		if f.status != 0 && f.status != http.StatusOK {
			w.WriteHeader(f.status)
			return
		}
		_, _ = w.Write([]byte(f.body))
	}))
	t.Cleanup(s.Close)
	return s
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

// A netset is comments, blanks, networks and bare addresses. The bare form is
// widened to /32 exactly as a portal region does with one typed by hand: the
// feeds mix both and they mean the same thing once the mask is explicit.
func TestBlocklistParsesANetset(t *testing.T) {
	body := "# firehol_level1\n#\n\n203.0.113.0/24\n198.51.100.7\n\t192.0.2.0/25\t\n; another comment\n"
	got, err := parseBlocklistBody([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []string{"203.0.113.0/24", "198.51.100.7/32", "192.0.2.0/25"}
	if len(got) != len(want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parsed %v, want %v", got, want)
		}
	}
}

// Whole or nothing, for fetchCountry's reason and one of its own. The danger
// is not a file that fails to parse, it is one that parses into something
// plausible - an error page, a redirect body, or half a list - every one of
// which produces a shorter perfectly valid list if bad lines are skipped.
func TestBlocklistRefusesAFileWithOneBadLine(t *testing.T) {
	body := "203.0.113.0/24\n<html>404 Not Found</html>\n198.51.100.0/24\n"
	if _, err := parseBlocklistBody([]byte(body)); err == nil {
		t.Fatal("a body with an HTML fragment in it parsed; a partial list is the failure this exists to prevent")
	}
	// And the message has to point at the line, because the operator's next
	// move is to go and look at the feed.
	_, err := parseBlocklistBody([]byte(body))
	if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("the error does not name the line: %v", err)
	}
}

// An IPv6 network parses as a network and renders into nothing, which is the
// silent-empty-ruleset failure this rule exists to prevent elsewhere.
func TestBlocklistRefusesIPv6(t *testing.T) {
	if _, err := parseBlocklistBody([]byte("2001:db8::/32\n")); err == nil {
		t.Fatal("an IPv6 network was accepted into an ip-family table")
	}
}

// A body with no networks at all is what a redirect page or an empty file
// looks like, and accepting it would be accepting an instruction to block
// nothing from a source that has no authority to give one.
func TestBlocklistRefusesAnEmptyFeed(t *testing.T) {
	if _, err := parseBlocklistBody([]byte("# nothing here\n\n")); err == nil {
		t.Fatal("a feed with no networks was accepted")
	}
}

// ---------------------------------------------------------------------------
// Refreshing
// ---------------------------------------------------------------------------

// The ordinary case: the list is fetched, remembered, and written to disk.
func TestBlocklistRefreshLoadsAndPersists(t *testing.T) {
	dir := t.TempDir()
	e, _ := blocklistEngine(t, dir)
	f := &feedServer{body: "203.0.113.0/24\n198.51.100.0/24\n", etag: `"v1"`}
	e.blURL = f.start(t).URL

	e.refreshBlocklist(context.Background())

	if got := len(e.blNetworks); got != 2 {
		t.Fatalf("loaded %d networks, want 2", got)
	}
	if e.blLastErr != "" {
		t.Fatalf("a successful fetch recorded an error: %s", e.blLastErr)
	}
	if e.blEtag != `"v1"` {
		t.Errorf("the ETag was not kept: %q", e.blEtag)
	}
	if _, err := os.Stat(filepath.Join(dir, blocklistCacheFile)); err != nil {
		t.Fatalf("the cache was not written: %v", err)
	}
}

// The cache is what makes a restart with the feed unreachable still install
// protection, and what stops boot waiting on somebody else's host.
func TestBlocklistCacheSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	first, _ := blocklistEngine(t, dir)
	f := &feedServer{body: "203.0.113.0/24\n198.51.100.0/24\n"}
	first.blURL = f.start(t).URL
	first.refreshBlocklist(context.Background())

	// A restart is a restart of the same frontend, so it asks the same host.
	// The loader only carries an age and an ETag across when the cache says
	// they came from the source it is about to ask again, and this engine was
	// built pointing at the shipped feed, so it has to be pointed back at the
	// test's server and read the cache again.
	second, _ := blocklistEngine(t, dir)
	second.blURL = first.blURL
	second.loadBlocklistCache()

	if got := len(second.blNetworks); got != 2 {
		t.Fatalf("a fresh engine started with %d networks, want 2 from the cache", got)
	}
	if second.blUpdated.IsZero() {
		t.Error("the fresh engine has no idea how old its list is, so it can never report it as stale")
	}
}

// A failure never empties anything. An old blocklist beats none, which is the
// opposite of the query cache's rule about stale data and right for the same
// reason: there, stale means advertising a server that may be gone.
func TestBlocklistFailedFetchKeepsThePreviousList(t *testing.T) {
	e, _ := blocklistEngine(t, t.TempDir())
	f := &feedServer{body: "203.0.113.0/24\n198.51.100.0/24\n"}
	srv := f.start(t)
	e.blURL = srv.URL
	e.refreshBlocklist(context.Background())
	before := append([]string(nil), e.blNetworks...)

	f.status = http.StatusInternalServerError
	e.refreshBlocklist(context.Background())

	if len(e.blNetworks) != len(before) {
		t.Fatalf("a failed fetch changed the loaded list: %d networks, was %d", len(e.blNetworks), len(before))
	}
	if e.blLastErr == "" {
		t.Fatal("a failed fetch was not recorded, so the portal would show the list as healthy")
	}
}

// The failure the parser cannot catch: a short but syntactically perfect list,
// which is what a half-generated or partly-migrated feed looks like. Nothing
// here can tell it from a genuine mass delisting, so the tie is broken towards
// keeping what works.
func TestBlocklistRefusesAnImplausibleShrink(t *testing.T) {
	e, _ := blocklistEngine(t, t.TempDir())
	var full strings.Builder
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&full, "203.0.%d.0/24\n", i)
	}
	f := &feedServer{body: full.String()}
	e.blURL = f.start(t).URL
	e.refreshBlocklist(context.Background())
	if len(e.blNetworks) != 100 {
		t.Fatalf("setup loaded %d networks, want 100", len(e.blNetworks))
	}

	f.body = "203.0.0.0/24\n203.0.1.0/24\n" // 2 of 100
	e.refreshBlocklist(context.Background())

	if len(e.blNetworks) != 100 {
		t.Fatalf("the shrunken list was accepted: %d networks loaded", len(e.blNetworks))
	}
	if !strings.Contains(e.blLastErr, "shrink") {
		t.Errorf("the refusal was not recorded as one: %q", e.blLastErr)
	}
}

// The floor is measured against the loaded list, which does not move on a
// refusal - so a genuine mass delisting is refused once and not forever, it
// is refused every time until somebody looks. That is the intended behaviour
// and this pins it, because the alternative reading (a ratchet that lets the
// list decay one refusal at a time) is what measuring against the fetched
// list would have given.
func TestBlocklistShrinkGuardDoesNotRatchetDown(t *testing.T) {
	e, _ := blocklistEngine(t, t.TempDir())
	var full strings.Builder
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&full, "203.0.%d.0/24\n", i)
	}
	f := &feedServer{body: full.String()}
	e.blURL = f.start(t).URL
	e.refreshBlocklist(context.Background())

	f.body = "203.0.0.0/24\n"
	for i := 0; i < 5; i++ {
		e.refreshBlocklist(context.Background())
	}
	if len(e.blNetworks) != 100 {
		t.Fatalf("five refusals left %d networks loaded, want the original 100", len(e.blNetworks))
	}
}

// A shrink inside the floor is a normal day's churn and must go through, or
// the guard is a second way for the list to stop updating.
func TestBlocklistAcceptsAnOrdinaryShrink(t *testing.T) {
	e, _ := blocklistEngine(t, t.TempDir())
	var full strings.Builder
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&full, "203.0.%d.0/24\n", i)
	}
	f := &feedServer{body: full.String()}
	e.blURL = f.start(t).URL
	e.refreshBlocklist(context.Background())

	var fewer strings.Builder
	for i := 0; i < 80; i++ {
		fmt.Fprintf(&fewer, "203.0.%d.0/24\n", i)
	}
	f.body = fewer.String()
	e.refreshBlocklist(context.Background())

	if len(e.blNetworks) != 80 {
		t.Fatalf("an ordinary 20%% shrink was refused: %d networks loaded", len(e.blNetworks))
	}
}

// The conditional request is what makes a short interval polite: an unchanged
// feed costs a 304 rather than a megabyte, every few hours, forever. And the
// feed answering "unchanged" is as good a confirmation as re-sending the
// bytes, so it has to move the age forward or a working list reads as going
// stale.
func TestBlocklistNotModifiedKeepsTheListAndRefreshesTheAge(t *testing.T) {
	e, _ := blocklistEngine(t, t.TempDir())
	f := &feedServer{body: "203.0.113.0/24\n198.51.100.0/24\n", etag: `"v1"`}
	e.blURL = f.start(t).URL
	e.refreshBlocklist(context.Background())

	e.blUpdated = time.Now().Add(-24 * time.Hour)
	f.status = http.StatusNotModified
	e.refreshBlocklist(context.Background())

	if f.ifNone != `"v1"` {
		t.Errorf("the request did not carry the stored ETag: %q", f.ifNone)
	}
	if len(e.blNetworks) != 2 {
		t.Fatalf("a 304 changed the loaded list: %d networks", len(e.blNetworks))
	}
	if time.Since(e.blUpdated) > time.Minute {
		t.Errorf("a 304 left the list looking %v old; the feed confirmed it is current", time.Since(e.blUpdated))
	}
	if e.blLastErr != "" {
		t.Errorf("a 304 was recorded as a failure: %s", e.blLastErr)
	}
}

// A response past the cap is a loud failure rather than a silently shorter
// list, which is the same rule the geo fetch holds.
func TestBlocklistRefusesAnOversizedFeed(t *testing.T) {
	e, _ := blocklistEngine(t, t.TempDir())
	var huge strings.Builder
	for huge.Len() <= blocklistMaxBytes {
		huge.WriteString("203.0.113.0/24\n")
	}
	f := &feedServer{body: huge.String()}
	e.blURL = f.start(t).URL

	e.refreshBlocklist(context.Background())

	if len(e.blNetworks) != 0 {
		t.Fatalf("an oversized feed was loaded: %d networks", len(e.blNetworks))
	}
	if e.blLastErr == "" {
		t.Fatal("an oversized feed was not recorded as a failure")
	}
}

// ---------------------------------------------------------------------------
// Scheduling
// ---------------------------------------------------------------------------

// Zero means the shipped default, and the bounds are held here as well as in
// validate for the blob validate never saw.
func TestBlocklistRefreshIntervalBounds(t *testing.T) {
	for _, tc := range []struct {
		hours int
		want  time.Duration
	}{
		{0, model.DefaultBlocklistRefreshHours * time.Hour},
		{6, 6 * time.Hour},
		{-3, model.MinBlocklistRefreshHours * time.Hour},
		{100000, model.MaxBlocklistRefreshHours * time.Hour},
	} {
		got := blocklistRefreshInterval(model.BlocklistConfig{RefreshHours: tc.hours})
		if got != tc.want {
			t.Errorf("%dh gave %v, want %v", tc.hours, got, tc.want)
		}
	}
}

// The feature off must never reach the feed. A frontend fetching from a third
// party on a timer for a feature nobody enabled is exactly the dependency the
// geo fetch's design note refuses.
func TestBlocklistDisabledFetchesNothing(t *testing.T) {
	e, _ := blocklistEngine(t, t.TempDir())
	e.cfg.Blocklist.Enabled = false
	f := &feedServer{body: "203.0.113.0/24\n"}
	e.blURL = f.start(t).URL

	e.maybeRefreshBlocklist(context.Background())

	if f.requests != 0 {
		t.Fatalf("the feed was fetched %d times with the feature off", f.requests)
	}
}

// A reverted engine installs and repairs nothing, so fetching a list it would
// have nowhere to put is the same activity the latch exists to stop.
func TestBlocklistRevertedFetchesNothing(t *testing.T) {
	e, _ := blocklistEngine(t, t.TempDir())
	e.reverted = true
	f := &feedServer{body: "203.0.113.0/24\n"}
	e.blURL = f.start(t).URL

	e.maybeRefreshBlocklist(context.Background())

	if f.requests != 0 {
		t.Fatalf("a reverted engine fetched the feed %d times", f.requests)
	}
}

// A fresh site with no list yet must fetch on the first pass rather than
// waiting out an interval, or enabling the feature does nothing for hours.
func TestBlocklistFetchesImmediatelyWithNoList(t *testing.T) {
	e, _ := blocklistEngine(t, t.TempDir())
	f := &feedServer{body: "203.0.113.0/24\n"}
	e.blURL = f.start(t).URL

	e.maybeRefreshBlocklist(context.Background())

	if f.requests != 1 {
		t.Fatalf("a site with no list made %d requests, want 1", f.requests)
	}
}

// And a list fetched a moment ago is not fetched again on the next pass, or
// the minute ticker would be a one-minute refresh interval against somebody
// else's static file.
func TestBlocklistDoesNotRefetchAFreshList(t *testing.T) {
	e, _ := blocklistEngine(t, t.TempDir())
	f := &feedServer{body: "203.0.113.0/24\n"}
	e.blURL = f.start(t).URL

	e.maybeRefreshBlocklist(context.Background())
	e.maybeRefreshBlocklist(context.Background())

	if f.requests != 1 {
		t.Fatalf("a fresh list was refetched: %d requests, want 1", f.requests)
	}
}

// A failure is retried sooner than a full interval, because a feed that is
// down for an hour should not cost most of a day's freshness.
func TestBlocklistRetriesSoonerThanAFullInterval(t *testing.T) {
	e, _ := blocklistEngine(t, t.TempDir())
	f := &feedServer{body: "203.0.113.0/24\n", status: http.StatusInternalServerError}
	e.blURL = f.start(t).URL

	e.maybeRefreshBlocklist(context.Background())
	if f.requests != 1 {
		t.Fatalf("setup made %d requests, want 1", f.requests)
	}
	// Just past the retry window, and far inside the refresh interval.
	e.blLastTry = time.Now().Add(-blocklistRetryEvery - time.Second)
	e.maybeRefreshBlocklist(context.Background())

	if f.requests != 2 {
		t.Fatalf("a failure was not retried inside the refresh interval: %d requests", f.requests)
	}
}

// ---------------------------------------------------------------------------
// Applying
// ---------------------------------------------------------------------------

// Invariant 7. This rule drops packets, so nothing about it may be felt in
// observe mode: no table, and no set contents either.
func TestObserveModeLoadsNoBlocklist(t *testing.T) {
	e, q := blocklistEngine(t, t.TempDir())
	cfg := e.cfg
	cfg.Mode = model.ModeObserve
	e.rememberBlocklist([]string{"203.0.113.0/24"})
	gated := &dryRunner{q}

	e.applyBlocklist(context.Background(), cfg, gated, e.real)

	for _, c := range q.writes() {
		if strings.HasPrefix(c, "nft -f") {
			t.Errorf("observe mode loaded a blocklist file: %q", c)
		}
	}
	if e.blOn {
		t.Error("observe mode recorded the blocklist as loaded")
	}
}

// A site with the feature off must have the table removed, because turning it
// off generates nothing to load and an empty load would leave the old rules
// dropping traffic with nothing in the configuration to explain it.
func TestDisablingTheBlocklistRemovesTheTable(t *testing.T) {
	e, q := blocklistEngine(t, t.TempDir())
	cfg := e.cfg
	cfg.Blocklist.Enabled = false

	e.applyBlocklist(context.Background(), cfg, e.runner, e.real)

	if q.count("nft delete table ip failover_blocklist") != 1 {
		t.Fatalf("the table was not removed; commands were %v", q.writes())
	}
}

// Armed, the table goes in and the list goes into it. The second half is what
// stops a settings save silently switching the list off for up to a refresh
// interval: rebuilding the table empties its set.
func TestApplyingTheBlocklistLoadsTheTableAndTheList(t *testing.T) {
	dir := t.TempDir()
	e, q := blocklistEngine(t, dir)
	e.rememberBlocklist([]string{"203.0.113.0/24", "198.51.100.0/24"})

	e.applyBlocklist(context.Background(), e.cfg, e.runner, e.real)

	if !e.blOn {
		t.Fatal("the blocklist was not recorded as loaded")
	}
	if q.count("nft -f "+filepath.Join(dir, "blocklist.nft")) != 1 {
		t.Errorf("the table was not loaded; commands were %v", q.writes())
	}
	if q.count("nft -f "+filepath.Join(dir, "blocklist-feed.nft")) != 1 {
		t.Errorf("the list was not loaded into the rebuilt table; commands were %v", q.writes())
	}
	feed, err := os.ReadFile(filepath.Join(dir, "blocklist-feed.nft"))
	if err != nil {
		t.Fatalf("read the feed file: %v", err)
	}
	if !strings.Contains(string(feed), "203.0.113.0/24") {
		t.Errorf("the feed file does not hold the list:\n%s", feed)
	}
}

// An unchanged table is not reloaded, for the reason applyProtect carries plus
// one of its own: a rebuild empties the feed set and resets the counter, and a
// save that touched a probe interval must not pay either.
func TestAnUnchangedBlocklistTableIsNotReloaded(t *testing.T) {
	dir := t.TempDir()
	e, q := blocklistEngine(t, dir)
	e.rememberBlocklist([]string{"203.0.113.0/24"})

	e.applyBlocklist(context.Background(), e.cfg, e.runner, e.real)
	before := q.count("nft -f " + filepath.Join(dir, "blocklist.nft"))
	e.applyBlocklist(context.Background(), e.cfg, e.runner, e.real)

	if got := q.count("nft -f " + filepath.Join(dir, "blocklist.nft")); got != before {
		t.Fatalf("an unchanged table was reloaded: %d loads, was %d", got, before)
	}
}

// Changing the exceptions does change the table, and the list has to go back
// into it - the case the reload-and-refill pairing exists for.
func TestChangingTheExceptionsReloadsAndRefills(t *testing.T) {
	dir := t.TempDir()
	e, q := blocklistEngine(t, dir)
	e.rememberBlocklist([]string{"203.0.113.0/24"})
	e.applyBlocklist(context.Background(), e.cfg, e.runner, e.real)

	cfg := e.cfg
	cfg.Blocklist.Exceptions = []string{"198.51.100.0/24"}
	e.applyBlocklist(context.Background(), cfg, e.runner, e.real)

	if got := q.count("nft -f " + filepath.Join(dir, "blocklist.nft")); got != 2 {
		t.Fatalf("the table was loaded %d times, want 2", got)
	}
	if got := q.count("nft -f " + filepath.Join(dir, "blocklist-feed.nft")); got != 2 {
		t.Fatalf("the list was loaded %d times, want 2 - a rebuilt table has an empty set", got)
	}
}

// A refresh must not touch the table, or every few hours it would reset the
// blocklist counter - and if this ever moved into failover_protect, unpark
// every blocked source and release every engaged region lock with it.
func TestARefreshLoadsOnlyTheElements(t *testing.T) {
	dir := t.TempDir()
	e, q := blocklistEngine(t, dir)
	e.rememberBlocklist([]string{"203.0.113.0/24"})
	e.applyBlocklist(context.Background(), e.cfg, e.runner, e.real)
	tableLoads := q.count("nft -f " + filepath.Join(dir, "blocklist.nft"))

	f := &feedServer{body: "203.0.113.0/24\n198.51.100.0/24\n192.0.2.0/24\n"}
	e.blURL = f.start(t).URL
	e.refreshBlocklist(context.Background())

	if got := q.count("nft -f " + filepath.Join(dir, "blocklist.nft")); got != tableLoads {
		t.Fatalf("a refresh reloaded the table: %d loads, was %d", got, tableLoads)
	}
	if got := q.count("nft -f " + filepath.Join(dir, "blocklist-feed.nft")); got != 2 {
		t.Fatalf("the refresh did not load the elements: %d loads, want 2", got)
	}
}

// The portal has to be able to tell a list that is working from one that
// stopped updating a week ago, and from one that never loaded.
func TestBlocklistStatusReportsAgeAndFailure(t *testing.T) {
	e, _ := blocklistEngine(t, t.TempDir())
	e.rememberBlocklist([]string{"203.0.113.0/24", "203.0.113.0/24", "10.0.0.0/8"})
	e.blUpdated = time.Now().Add(-30 * time.Hour)
	e.blLastErr = "dial tcp: no route to host"
	e.blOn = true

	st := e.blocklistStatus()
	if st == nil {
		t.Fatal("no blocklist status with the feature on")
	}
	// The loaded figure, not len(): the duplicate collapses and the private
	// network never reaches the kernel.
	if st.Networks != 1 {
		t.Errorf("reported %d networks, want the 1 that is really loaded", st.Networks)
	}
	if st.AgeHours < 29 || st.AgeHours > 31 {
		t.Errorf("reported an age of %.1fh, want about 30", st.AgeHours)
	}
	if st.LastError == "" {
		t.Error("a failing feed was not reported")
	}
	if !st.Loaded {
		t.Error("a loaded table was reported as not loaded")
	}
}

// Off means absent, like the protection block beside it: a card for a feature
// nobody enabled is noise on every portal load.
func TestBlocklistStatusAbsentWhenOff(t *testing.T) {
	e, _ := blocklistEngine(t, t.TempDir())
	e.cfg.Blocklist.Enabled = false
	if st := e.blocklistStatus(); st != nil {
		t.Fatalf("the feature is off and it reported %+v", st)
	}
}

// A revert takes the table down and must not leave the counter behind: a
// number describing a rule that no longer exists reads as live drops.
func TestRevertRemovesTheBlocklist(t *testing.T) {
	e, q := blocklistEngine(t, t.TempDir())
	e.rememberBlocklist([]string{"203.0.113.0/24"})
	e.applyBlocklist(context.Background(), e.cfg, e.runner, e.real)

	e.Revert(context.Background())

	if q.count("nft delete table ip failover_blocklist") != 1 {
		t.Errorf("the blocklist table was not removed; commands were %v", q.writes())
	}
	if e.blOn || e.blApplied != "" {
		t.Error("the engine still believes the blocklist is loaded")
	}
	if len(e.blNetworks) == 0 {
		t.Error("the list itself was discarded; it is agent state, so re-arming should not need another fetch")
	}
}

// An element load the kernel refused has to be retried, and nothing else in
// here would. blApplied describes the table rather than the set, so a later
// save with nothing changed takes the unchanged branch and skips the refill
// with the reload; and the feed republishes about daily against a four hour
// interval, so nearly every refresh is a 304, which loads no elements by
// design. Left alone, the table sits there dropping nothing while the portal
// reports the list loaded.
func TestARefusedElementLoadIsRetried(t *testing.T) {
	dir := t.TempDir()
	e, q := blocklistEngine(t, dir)
	feed := "nft -f " + filepath.Join(dir, "blocklist-feed.nft")
	q.fails = map[string]string{feed: "Error: Could not process rule"}
	e.rememberBlocklist([]string{"203.0.113.0/24"})

	e.applyBlocklist(context.Background(), e.cfg, e.runner, e.real)
	if got := q.count(feed); got != 1 {
		t.Fatalf("setup attempted the element load %d times, want 1", got)
	}
	if e.blLoadFailed.IsZero() {
		t.Fatal("a refused element load left nothing to retry from")
	}

	// Nothing is due: the list is fresh and no fetch has failed, so the retry
	// is the only thing that can bring the load back.
	e.blUpdated, e.blLastTry = time.Now(), time.Now()
	e.maybeRefreshBlocklist(context.Background())
	if got := q.count(feed); got != 1 {
		t.Fatalf("the retry ran inside its own window: %d loads, want 1", got)
	}

	e.blLoadFailed = time.Now().Add(-blocklistRetryEvery - time.Second)
	delete(q.fails, feed)
	e.maybeRefreshBlocklist(context.Background())

	if got := q.count(feed); got != 2 {
		t.Fatalf("the refused load was not retried: %d loads, want 2", got)
	}
	if !e.blLoadFailed.IsZero() {
		t.Error("a load that succeeded left the failure outstanding, so it will be retried forever")
	}
}

// Invariant 13: disarming is not a teardown, so a table loaded while armed is
// still in the kernel and still dropping. Recorded as unloaded, the portal
// said nothing was being dropped and that this was expected in observe mode,
// which is false in the one direction that matters, and the drop counter
// froze with it.
func TestDisarmingLeavesTheBlocklistRecordedAsLoaded(t *testing.T) {
	e, q := blocklistEngine(t, t.TempDir())
	e.rememberBlocklist([]string{"203.0.113.0/24"})
	e.applyBlocklist(context.Background(), e.cfg, e.runner, e.real)
	if !e.blOn {
		t.Fatal("the armed apply did not record the table as loaded")
	}

	cfg := e.cfg
	cfg.Mode = model.ModeObserve
	e.applyBlocklist(context.Background(), cfg, &dryRunner{q}, e.real)

	if !e.blOn {
		t.Error("a disarm recorded the blocklist as unloaded while its table is still in the kernel and still dropping")
	}
	if e.blApplied != "" {
		t.Error("the reload latch survived a disarm; what is loaded is no longer this ruleset")
	}
	if n := q.count("nft delete table ip failover_blocklist"); n != 0 {
		t.Errorf("a disarm removed the table %d times; disarming is not a teardown", n)
	}
}

// The other half of that, and the reason the mode is now checked separately
// from the table being loaded: a disarmed refresh must still fill nothing.
// Loading a fresh list changes what a live rule drops, which is the one thing
// observe mode may not do, and it would leave a feed file on disk describing
// a set the kernel does not have.
func TestADisarmedRefreshLoadsNoElements(t *testing.T) {
	dir := t.TempDir()
	e, q := blocklistEngine(t, dir)
	e.rememberBlocklist([]string{"203.0.113.0/24"})
	e.applyBlocklist(context.Background(), e.cfg, e.runner, e.real)

	feed := filepath.Join(dir, "blocklist-feed.nft")
	before := q.count("nft -f " + feed)
	if err := os.Remove(feed); err != nil {
		t.Fatalf("remove the feed file the armed apply wrote: %v", err)
	}

	e.runner = &dryRunner{q}
	e.installBlocklistElements(context.Background())

	if got := q.count("nft -f " + feed); got != before {
		t.Errorf("a disarmed refresh loaded the elements: %d loads, was %d", got, before)
	}
	if _, err := os.Stat(feed); !os.IsNotExist(err) {
		t.Error("a disarmed refresh wrote a feed file describing a set the kernel does not have")
	}
}

// The readback is the only thing here that reports the kernel rather than this
// agent's belief about it, so it is what corrects the belief, and both
// directions matter. A table that has gone must stop being reported as loaded,
// or the portal claims the rules are there immediately after the read proved
// they are not and every refresh loads elements into nothing. A table that
// really is there has to be found again, which is what makes clearing the
// record on one failed read safe - and it is also the only thing that notices
// one left behind by an armed process this one has replaced.
func TestTheBlocklistReadbackCorrectsTheLoadedRecord(t *testing.T) {
	e, q := blocklistEngine(t, t.TempDir())
	const list = "nft -j -t list table ip failover_blocklist"
	q.replies[list] = `{"nftables":[]}`
	q.fails = map[string]string{list: "Error: No such file or directory"}
	e.blOn, e.blApplied = true, "table ip failover_blocklist {}"

	e.sampleBlocklistCounter(context.Background())
	if e.blOn {
		t.Error("a table the kernel cannot answer for is still reported as loaded")
	}
	if e.blApplied != "" {
		t.Error("the reload latch survived a table that has gone, so the next save would skip the reload")
	}

	delete(q.fails, list)
	e.sampleBlocklistCounter(context.Background())

	if !e.blOn {
		t.Error("a table the kernel answered for was not recorded as loaded again")
	}
}

// The portal says a list is old past one threshold, and that threshold is this
// constant. Decided here rather than in the browser because it was written out
// in both places, and the two could drift with nothing failing.
func TestBlocklistStalenessIsDecidedByTheAgent(t *testing.T) {
	e, _ := blocklistEngine(t, t.TempDir())
	e.rememberBlocklist([]string{"203.0.113.0/24"})

	e.blUpdated = time.Now().Add(-blocklistStaleAfter + time.Hour)
	if st := e.blocklistStatus(); st.Stale {
		t.Errorf("a list %.0fh old was reported stale", st.AgeHours)
	}
	e.blUpdated = time.Now().Add(-blocklistStaleAfter - time.Hour)
	if st := e.blocklistStatus(); !st.Stale {
		t.Errorf("a list %.0fh old was not reported stale", st.AgeHours)
	}
	// Never fetched is not stale: there is no age for it to be past, and the
	// card says "never" rather than a number.
	e.blUpdated = time.Time{}
	if st := e.blocklistStatus(); st.Stale {
		t.Error("a list that has never been fetched was reported stale")
	}
}

// The age and the ETag describe a conversation with one host, so a cache
// written against a different source must not lend either to the new one: the
// card would report a freshness this frontend has never confirmed, and the
// If-None-Match would carry another host's tag format, answered with a full
// body rather than the 304 the refresh cadence is sized around. The list
// itself is kept, because an old list beats none and boot-time protection
// must not wait on a fetch.
func TestACacheFromAnotherSourceKeepsTheListAndNotTheAge(t *testing.T) {
	dir := t.TempDir()
	first, _ := blocklistEngine(t, dir)
	f := &feedServer{body: "203.0.113.0/24\n198.51.100.0/24\n", etag: `"from-the-old-host"`}
	first.blURL = f.start(t).URL
	first.refreshBlocklist(context.Background())

	// Built against the shipped feed, so the cache on disk names somebody
	// else - which is what changing the feed URL leaves behind on a live host.
	moved, _ := blocklistEngine(t, dir)

	if got := len(moved.blNetworks); got != 2 {
		t.Fatalf("the list was discarded with the source: %d networks, want 2", got)
	}
	if !moved.blUpdated.IsZero() {
		t.Error("an age confirmed against a different host was carried over to the new one")
	}
	if moved.blEtag != "" {
		t.Errorf("another host's ETag %q was kept to be sent to this one", moved.blEtag)
	}
}

// A readback that merely failed says nothing about the table, and the loader
// trusts the record this sampler keeps. Cleared on any failure, one slow nft
// while the portal was open left the record cleared once the tab was closed,
// since nothing else sets it: the next refresh then accepted a new list,
// wrote it to the cache and the card, saw no table to fill, loaded nothing
// and forgot the retry - and every 304 after that loads nothing by design.
// The kernel kept the old list while the card read as fresh. So a failure
// that does not name the table costs the latch and nothing else, and the
// refresh that follows it still loads.
func TestATransientReadbackFailureKeepsTheLoadedRecord(t *testing.T) {
	dir := t.TempDir()
	e, q := blocklistEngine(t, dir)
	const list = "nft -j -t list table ip failover_blocklist"
	q.fails = map[string]string{list: "Error: timed out"}
	e.blOn, e.blApplied = true, "table ip failover_blocklist {}"

	e.sampleBlocklistCounter(context.Background())
	if !e.blOn {
		t.Fatal("one failed read that said nothing about the table cleared the record of it being loaded")
	}
	if e.blApplied != "" {
		t.Error("the reload latch survived a failed read; the next save should reload rather than trust it")
	}

	e.rememberBlocklist([]string{"203.0.113.0/24"})
	e.installBlocklistElements(context.Background())
	if got := q.count("nft -f " + filepath.Join(dir, "blocklist-feed.nft")); got != 1 {
		t.Errorf("a refresh after a transient readback failure loaded the elements %d times, want 1", got)
	}
}

// The figures on the card describe the list the frontend accepted, and the
// list is accepted before it is loaded. So a load the kernel refused used to
// read as N networks, loaded, no error, while the set held the previous list
// or nothing, for as long as the retry kept failing. The refusal has to be in
// the status, and has to leave it once a load succeeds.
func TestARefusedElementLoadIsReportedInStatus(t *testing.T) {
	dir := t.TempDir()
	e, q := blocklistEngine(t, dir)
	feed := "nft -f " + filepath.Join(dir, "blocklist-feed.nft")
	q.fails = map[string]string{feed: "Error: Could not process rule"}
	e.rememberBlocklist([]string{"203.0.113.0/24"})

	e.applyBlocklist(context.Background(), e.cfg, e.runner, e.real)
	st := e.blocklistStatus()
	if st.LoadError == "" {
		t.Fatal("a load the kernel refused is not reported; the card reads as loaded and dropping")
	}
	if !st.Loaded {
		t.Error("the table itself is fine and should still read as loaded")
	}

	delete(q.fails, feed)
	e.blUpdated, e.blLastTry = time.Now(), time.Now()
	e.blLoadFailed = time.Now().Add(-blocklistRetryEvery - time.Second)
	e.maybeRefreshBlocklist(context.Background())
	if st := e.blocklistStatus(); st.LoadError != "" {
		t.Errorf("a load that succeeded left the refusal on the card: %q", st.LoadError)
	}
}

// A shrink refusal is a state rather than a failure: the feed serves the same
// short list until somebody looks. Retried at the failure cadence it was a
// full download, an Error line and an event row every fifteen minutes for as
// long as nobody intervened - nearly a hundred event rows a day, pushing real
// events out of the Activity tab. It is retried at the refresh interval, said
// out loud once per streak, and the streak ends when a list is accepted.
func TestAShrinkRefusalIsRetriedAtTheIntervalAndReportedOnce(t *testing.T) {
	e, _ := blocklistEngine(t, t.TempDir())
	var loaded []string
	for i := 0; i < 10; i++ {
		loaded = append(loaded, fmt.Sprintf("203.0.%d.0/24", i))
	}
	e.rememberBlocklist(loaded)

	feed := &feedServer{body: "198.51.100.0/24\n"}
	e.blURL = feed.start(t).URL
	e.blClient = http.DefaultClient

	e.refreshBlocklist(context.Background())
	e.refreshBlocklist(context.Background())
	if !e.blShrinkRefused {
		t.Fatal("two refusals did not record a streak")
	}
	events, err := e.st.Events(50)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	refusals := 0
	for _, ev := range events {
		if strings.Contains(fmt.Sprintf("%+v", ev), "refused") {
			refusals++
		}
	}
	if refusals != 1 {
		t.Errorf("two refusals in one streak wrote %d event rows, want 1", refusals)
	}

	// Past the failure cadence and inside the interval: not due.
	e.blLastTry = time.Now().Add(-blocklistRetryEvery - time.Minute)
	before := feed.requests
	e.maybeRefreshBlocklist(context.Background())
	if feed.requests != before {
		t.Error("a shrink refusal was retried at the failure cadence rather than the refresh interval")
	}
	// Past the interval: due.
	e.blLastTry = time.Now().Add(-blocklistRefreshInterval(e.cfg.Blocklist) - time.Minute)
	e.maybeRefreshBlocklist(context.Background())
	if feed.requests != before+1 {
		t.Errorf("a shrink refusal was not retried at the refresh interval: %d requests, want %d", feed.requests, before+1)
	}

	// The feed comes right and the streak ends with it, so the next refusal
	// is a new one and is said out loud again.
	feed.body = strings.Join(loaded, "\n") + "\n"
	e.refreshBlocklist(context.Background())
	if e.blShrinkRefused {
		t.Error("an accepted list did not end the refusal streak")
	}
}

// The cache is what boot-time protection installs when the feed is
// unreachable, and it is rewritten on every refresh. Written in place, a
// crash mid-write left a truncated file the loader refused whole, and the
// restart came up with nothing on disk to fall back on. It is written beside
// the target and renamed over it, so nothing is left behind and what is read
// back is always a whole list.
func TestBlocklistCacheIsReplacedWholeRatherThanRewrittenInPlace(t *testing.T) {
	dir := t.TempDir()
	e, _ := blocklistEngine(t, dir)
	e.saveBlocklistCache(blocklistCache{Source: e.blURL, Networks: []string{"203.0.113.0/24"}})
	e.saveBlocklistCache(blocklistCache{Source: e.blURL, Networks: []string{"203.0.113.0/24", "198.51.100.0/24"}})

	if _, err := os.Stat(filepath.Join(dir, blocklistCacheFile+".tmp")); !os.IsNotExist(err) {
		t.Error("the temporary file was left beside the cache")
	}
	e2, _ := blocklistEngine(t, dir)
	e2.loadBlocklistCache()
	if len(e2.blNetworks) != 2 {
		t.Errorf("read back %d networks from the replaced cache, want 2", len(e2.blNetworks))
	}
}

// The element load touches no route and can take nft seconds for a large
// interval set. Under applyMu a path condemned during a refresh waited behind
// it before evaluate could move traffic, so the refresher holds a lock of its
// own and never the one the decision loop needs.
func TestARefreshDoesNotWaitOnTheRouteWriters(t *testing.T) {
	e, _ := blocklistEngine(t, t.TempDir())
	e.rememberBlocklist([]string{"203.0.113.0/24"})
	e.blOn = true

	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	done := make(chan struct{})
	go func() {
		e.installBlocklistElements(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the refresher waited on applyMu, which the decision loop needs to move traffic")
	}
}

// What applyMu was buying the refresher was the runner: a swap to observe
// landing mid-load put elements in with the armed runner after the mode had
// changed. Taking the refresher off applyMu keeps that only if the swap waits
// on the refresher's own lock instead.
func TestTheRunnerSwapWaitsOnARefreshInProgress(t *testing.T) {
	e, _ := blocklistEngine(t, t.TempDir())

	e.blMu.Lock()
	done := make(chan struct{})
	cfg := e.cfg
	cfg.Mode = model.ModeObserve
	go func() {
		_ = e.Reconfigure(cfg)
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("the runner swap did not wait for a load in progress; elements could go in armed after a disarm")
	case <-time.After(300 * time.Millisecond):
	}
	e.blMu.Unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the swap never completed once the load finished")
	}
}
