package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/store"
	"github.com/quinlan102/homeport/internal/sysx"
)

// The threat feed.
// ---------------
// The second place the frontend talks to a third party, and unlike the geo
// fetch it does so on a timer with nobody watching. That is the whole
// difference and it drives every rule below.
//
// The geo fetch can be click-only because a country's address space going
// stale costs a handful of newly allocated networks. A blocklist's entire
// value is freshness, so a click-only one is a feature that quietly stops
// working the week after it is set up. But the argument the geo fetch makes
// for refusing a schedule does not simply transfer, and the reason is the
// direction: whole-or-nothing exists there because a truncated *allowlist*
// silently bars real players, which is the closed direction and unrecoverable
// without somebody noticing. A truncated *blocklist* drops less than it
// should, which is open. So a scheduled refresh is defensible here in a way
// it is not there, and what has to be defended instead is everything that
// could make this list wrong in the closed direction:
//
//   - Whole or nothing, exactly as fetchCountry is. A truncated download is
//     valid networks all the way to the cut, and a blocklist missing its tail
//     is not the danger; a blocklist that parsed a chunk of HTML error page
//     into something plausible is.
//   - A shrink guard. The failure the parse cannot catch is a feed that
//     returns a short but syntactically perfect list, which is what a
//     half-migrated or partly-generated file looks like. Refusing a sudden
//     collapse costs one stale cycle and catches it.
//   - Carrier-grade NAT and private space filtered out before anything is
//     loaded (sysx.dropNonInternet). A feed listing a slice of 100.64/10
//     would drop a large number of real mobile players at once.
//   - The last good list on disk, so a restart with the feed unreachable
//     still installs protection and boot never waits on the network.
//   - A failure keeps the previous list and says so, rather than emptying
//     anything. An old blocklist beats none, which is the opposite of the
//     query cache's rule about stale data and is right for the same reason:
//     there, stale means advertising a server that may be gone; here, stale
//     means blocking a network that may since have been cleaned up.
//
// The list never enters the configuration blob. It would bloat every export,
// bump cfgVersion on each refresh - which is what pushes configuration to the
// backend - and ride the PUT body cap. It is agent state, like the backend's
// meter baselines, and it lives in a file beside them.

// blocklistFeedURL is where the list comes from: FireHOL's level1, the
// conservative aggregate of DShield, abuse.ch Feodo, Spamhaus DROP and the
// bogon list, regenerated upstream continuously and published daily.
//
// Taken from the project's own distribution site rather than from the git
// repository the lists are built in, and that is upstream's request rather
// than a preference: GitHub asked them to limit how often that repository is
// updated because of its size and churn, so it now lands once a day and the
// README points every consumer at iplists.firehol.org for direct links. It
// costs this design nothing to comply. The file is byte for byte the same,
// and the only property the refresh cadence rests on - a conditional request
// answering 304 - holds there too, on an ETag and a Last-Modified both, in
// front of a CDN that caches it for two hours. That is a host built to be
// polled, which raw.githubusercontent.com is not.
//
// One built-in source rather than a configurable URL, and that is a security
// property rather than a limitation. The value would otherwise be an operator
// field naming a host this root process fetches from and loads into nftables
// on a timer, which is a much larger thing to get wrong than a country code -
// and web.handleGeoFetch already refuses anything that is not a country code
// rather than escaping it, for the same reason.
//
// level1 specifically, and not one of the larger lists beside it, because
// every false positive here is a visitor who cannot connect with nothing on
// this host saying why. The aggressive lists and the proxy lists will
// eventually name a carrier NAT, and this deployment's own per-source limits
// are already sized around 16 to 64 subscribers sharing one address.
const blocklistFeedURL = "https://iplists.firehol.org/files/firehol_level1.netset"

const (
	// blocklistMaxBytes caps one response. The real file is well under a
	// megabyte; anything past this is not a netset.
	blocklistMaxBytes = 8 << 20

	// blocklistMaxNetworks bounds what can be loaded into the kernel. The
	// real list is a few thousand and the byte cap alone would admit a few
	// hundred thousand, which is a set the kernel has to hold for the life
	// of the process.
	blocklistMaxNetworks = 200000

	// blocklistShrinkFloor is the fraction of the previous list a new one
	// must reach to be accepted. It catches the failure the parser cannot:
	// a syntactically perfect list that is missing most of itself.
	blocklistShrinkFloor = 0.5

	// blocklistTick is how often the refresher wakes to ask whether anything
	// is due. Far shorter than any refresh interval on purpose: it is what
	// makes a changed interval, or the feature being switched on, take effect
	// without the goroutine being torn down and restarted from a settings
	// save - which is invariant 9's whole family of bugs, avoided rather than
	// guarded against.
	blocklistTick = time.Minute

	// blocklistRetryEvery is how soon a failed attempt is retried, rather
	// than waiting out the full interval. A feed that is down for an hour
	// should not cost most of a day's freshness.
	blocklistRetryEvery = 15 * time.Minute

	// blocklistHTTPTimeout bounds one attempt. Generous, because the whole
	// file must arrive for the fetch to count and the refresher is not on
	// anybody's critical path.
	blocklistHTTPTimeout = 60 * time.Second

	// blocklistStaleAfter is when the portal starts saying the list is old.
	// It never stops the list being used; see the package comment.
	blocklistStaleAfter = 48 * time.Hour
)

// blocklistCacheFile is the last good list, on disk beside the generated
// rulesets. Agent state rather than configuration: it is what the frontend
// fetched, not what the operator decided.
const blocklistCacheFile = "blocklist-cache.json"

// blocklistCache is the on-disk form.
type blocklistCache struct {
	Source string `json:"source"`
	// Fetched is when the list was last confirmed current with the feed,
	// which includes a 304: the feed answering "unchanged" is as good a
	// confirmation as re-sending the bytes, and treating it as no answer at
	// all would have a working list read as going stale.
	Fetched time.Time `json:"fetched"`
	// ETag lets an unchanged feed cost a 304 rather than a megabyte, every
	// few hours, forever.
	ETag     string   `json:"etag,omitempty"`
	Networks []string `json:"networks"`
}

// loadBlocklistCache reads the last good list at startup, before anything is
// installed, so applySystemConfig has something to fill the set with. A
// missing or unreadable file is not an error: it is a first start, and the
// refresher fills it within the minute.
func (e *Engine) loadBlocklistCache() {
	raw, err := os.ReadFile(filepath.Join(e.stateDir, blocklistCacheFile))
	if err != nil {
		return
	}
	var c blocklistCache
	if err := json.Unmarshal(raw, &c); err != nil {
		e.log.Warn("cannot parse the cached blocklist; it will be fetched again", "err", err)
		return
	}
	// The same floor and ceiling the fetch applies, because a cache written
	// by a build that had neither is a list this build would have refused,
	// and boot is the one moment it is installed without a fetch. Starting
	// with no list is the refusal's meaning here: the refresher fetches
	// within the minute and judges the feed's copy the same way.
	if err := e.rememberBlocklist(c.Networks); err != nil {
		e.log.Error("the cached blocklist is refused and will not be installed; the feed will be fetched again",
			"err", err, "networks", len(c.Networks))
		return
	}
	e.mu.Lock()
	// The list is kept whatever served it, because an old list beats none and
	// that is this feature's rule everywhere else. The age and the ETag are
	// not: both describe a conversation with one particular host. Carried
	// across a change of source they have the card report a freshness this
	// frontend has never confirmed with the host it now names, and send an
	// If-None-Match built from another host's tag format, which is answered
	// with a full body rather than the 304 the cadence is sized around.
	// Zeroed, the refresher fetches on its next pass and both become true
	// again - and the networks are still there in the meantime, so nothing
	// about boot-time protection changes.
	//
	// Source was written and never read until this. That is the shape of
	// record that starts lying without anything failing, which is exactly
	// what blocklistStaleAfter was doing one commit ago.
	if c.Source == e.blURL {
		e.blUpdated = c.Fetched
		e.blEtag = c.ETag
	} else if c.Source != "" {
		e.log.Info("the cached blocklist came from a different source; keeping the list and fetching again",
			"cached", c.Source, "source", e.blURL)
	}
	e.mu.Unlock()
}

// rememberBlocklist judges a new list by the prefix floor and the coverage
// ceiling and, if it passes, records it together with the merged elements
// that will really be loaded from it. It is the one writer of that pair, in
// production and in the tests, so a list nothing here would accept cannot be
// seeded past the check: the cache at boot, the feed on a refresh and a test
// fixture all arrive through the same door. On a refusal nothing is changed.
//
// The elements are stored rather than derived on demand because Status is
// polled once a second and holds the state lock while it renders: deriving
// the count there meant parsing, filtering and sorting several thousand
// networks under that lock, every second, for a number that changes a few
// times a day. And they are stored rather than re-derived at load time
// because the merge is the expensive half of accepting a feed.
//
// It takes the lock itself, after the check, and that is the same reasoning
// from the other side: the check is the whole parse, filter and merge over
// up to two hundred thousand entries, and held under the write lock it
// stalled the decision loop, every probe result and every status request
// for the duration - strictly worse than the read lock Status used to hold.
// The caller must not hold e.mu.
func (e *Engine) rememberBlocklist(nets []string) error {
	elems, err := sysx.CheckBlocklist(nets)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.blNetworks, e.blElems, e.blCount = nets, elems, len(elems)
	e.mu.Unlock()
	return nil
}

// saveBlocklistCache writes the last good list, whole or not at all.
//
// A temporary file renamed over the target, because this file is what
// boot-time protection installs when the feed is unreachable and it is
// rewritten on every refresh, a 304 included: written in place, a crash or a
// power cut mid-write left a truncated file that loadBlocklistCache refused
// whole, and the restart came up with an empty set and nothing on disk to
// fall back on - which is the outage the cache exists to prevent. The rename
// is atomic on the filesystems a state directory lives on, so what the next
// start reads is either the previous list or this one.
func (e *Engine) saveBlocklistCache(c blocklistCache) {
	raw, err := json.Marshal(c)
	if err != nil {
		e.log.Error("cannot encode the blocklist cache", "err", err)
		return
	}
	path := filepath.Join(e.stateDir, blocklistCacheFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		e.log.Error("cannot write the blocklist cache; a restart will refetch it", "err", err, "path", tmp)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		e.log.Error("cannot replace the blocklist cache; a restart will refetch it", "err", err, "path", path)
		_ = os.Remove(tmp)
	}
}

// wakeBlocklist asks the refresher to reconsider now rather than on its next
// tick. Buffered one deep and written without blocking, like wake: the
// question it answers is idempotent, so a queued nudge is as good as two.
func (e *Engine) wakeBlocklist() {
	select {
	case e.blWake <- struct{}{}:
	default:
	}
}

// runBlocklist is the refresher. Started from Run on the base context, never
// from a request (invariant 9), and it exits on cancellation between attempts
// or inside one, because the fetch carries the same context.
func (e *Engine) runBlocklist(ctx context.Context) {
	t := time.NewTicker(blocklistTick)
	defer t.Stop()
	for {
		e.maybeRefreshBlocklist(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-e.blWake:
		}
	}
}

// maybeRefreshBlocklist fetches if one is due.
//
// Everything it needs to decide is re-read each pass rather than captured
// when the goroutine started, which is what lets the interval change, the
// feature be switched on, and a revert take hold without any of them having
// to reach in here.
func (e *Engine) maybeRefreshBlocklist(ctx context.Context) {
	e.mu.RLock()
	cfg := e.cfg
	reverted := e.reverted
	updated, lastTry, lastErr := e.blUpdated, e.blLastTry, e.blLastErr
	have := len(e.blNetworks)
	loadFailed := e.blLoadFailed
	refused := e.blRefused
	e.mu.RUnlock()

	// A reverted engine installs and repairs nothing, and fetching a list it
	// would have nowhere to put is the same kind of activity the latch exists
	// to stop.
	if !cfg.Blocklist.Enabled || reverted {
		return
	}

	now := time.Now()

	// An element load the kernel refused is retried here, and this is the only
	// thing that retries it. applyBlocklist's latch describes the table rather
	// than the set, so a later save with nothing changed takes the unchanged
	// branch and skips the refill along with the reload; and the feed
	// republishes about daily against a four hour interval, so nearly every
	// refresh is a 304, which loads no elements by design. Without this the
	// table sits there dropping nothing while the portal reports the list
	// loaded, for as long as it takes somebody to change a blocklist setting.
	if !loadFailed.IsZero() && !now.Before(loadFailed.Add(blocklistRetryEvery)) {
		e.installBlocklistElements(ctx)
	}

	due := updated.Add(blocklistRefreshInterval(cfg.Blocklist))
	switch {
	case refused:
		// A refusal by the shrink guard or the coverage ceiling is a state,
		// not a failure: the feed serves the same list until somebody looks,
		// so retrying at the failure cadence bought nothing and cost a full
		// download, an Error line and an event row every fifteen minutes.
		// The ETag is deliberately not advanced on a refusal - a 304 against
		// a list this host never loaded would read as confirmation - so each
		// attempt is a full body, at the interval the operator chose.
		due = lastTry.Add(blocklistRefreshInterval(cfg.Blocklist))
	case lastErr != "" || have == 0:
		due = lastTry.Add(blocklistRetryEvery)
	}
	if now.Before(due) {
		return
	}
	e.refreshBlocklist(ctx)
}

// blocklistRefreshInterval resolves the configured cadence. The bounds are
// validate's, held again here for a blob validate never saw - a value stored
// by an older build, where there is nobody at this boundary to tell.
func blocklistRefreshInterval(bl model.BlocklistConfig) time.Duration {
	h := bl.RefreshHours
	if h == 0 {
		h = model.DefaultBlocklistRefreshHours
	}
	if h < model.MinBlocklistRefreshHours {
		h = model.MinBlocklistRefreshHours
	}
	if h > model.MaxBlocklistRefreshHours {
		h = model.MaxBlocklistRefreshHours
	}
	return time.Duration(h) * time.Hour
}

// refreshBlocklist makes one attempt and records what happened either way.
func (e *Engine) refreshBlocklist(ctx context.Context) {
	e.mu.RLock()
	etag := e.blEtag
	previous := len(e.blNetworks)
	e.mu.RUnlock()

	networks, newEtag, notModified, err := e.fetchBlocklist(ctx, etag)
	now := time.Now()
	if err != nil {
		// Never a state change, only a record of the attempt. The loaded list
		// stays exactly where it was, which is the whole point.
		e.mu.Lock()
		e.blLastTry, e.blLastErr = now, err.Error()
		e.mu.Unlock()
		e.log.Warn("could not refresh the blocklist; the previous list stays loaded",
			"err", err, "networks", previous, "source", e.blURL)
		return
	}
	if notModified {
		e.mu.Lock()
		e.blLastTry, e.blLastErr, e.blUpdated = now, "", now
		cache := blocklistCache{Source: e.blURL, Fetched: now, ETag: e.blEtag, Networks: e.blNetworks}
		e.mu.Unlock()
		e.saveBlocklistCache(cache)
		e.log.Debug("blocklist unchanged at the source", "networks", previous)
		return
	}

	// The shrink guard. A list that parsed cleanly can still be most of a
	// list, and that is the shape a half-generated or partly-migrated feed
	// takes: nothing here can tell it from a genuine mass delisting, so the
	// tie is broken towards keeping what works.
	//
	// The floor is measured against the *loaded* list, which a refusal does
	// not move, so a real collapse is refused on every attempt rather than
	// letting the list ratchet down one refusal at a time - which is what
	// measuring against the previous fetch would have given. That means a
	// genuine mass delisting needs somebody to look, and it is why this is an
	// Error with an event beside it rather than a Warn: it is the one state
	// here that does not resolve itself.
	if previous > 0 && float64(len(networks)) < blocklistShrinkFloor*float64(previous) {
		e.refuseBlocklist(now, len(networks), previous,
			fmt.Sprintf("feed returned %d networks against %d loaded; refused as an implausible shrink",
				len(networks), previous),
			"the blocklist feed shrank implausibly; the previous list stays loaded")
		return
	}

	// The prefix floor and the coverage ceiling, on what would actually be
	// loaded. The floor is a whole-or-nothing failure like a bad line, since
	// no honest feed produces a survivor that short; the ceiling is a state
	// like the shrink guard, since a feed that has absorbed too much serves
	// the same list until somebody looks. Both keep the loaded list.
	if err := e.rememberBlocklist(networks); err != nil {
		if errors.Is(err, sysx.ErrBlocklistCoverage) {
			e.refuseBlocklist(now, len(networks), previous,
				"refused: "+err.Error(),
				"the blocklist feed covers too much of the internet; the previous list stays loaded")
			return
		}
		e.mu.Lock()
		e.blLastTry, e.blLastErr = now, err.Error()
		e.mu.Unlock()
		e.log.Warn("could not accept the blocklist; the previous list stays loaded",
			"err", err, "networks", previous, "source", e.blURL)
		return
	}

	// The window in which the list is new and the age is not is harmless,
	// because nothing reads the two together except Status, which renders
	// either truthfully.
	e.mu.Lock()
	e.blUpdated, e.blLastTry, e.blLastErr = now, now, ""
	e.blEtag = newEtag
	e.blRefused = false
	loaded := e.blCount
	cache := blocklistCache{Source: e.blURL, Fetched: now, ETag: newEtag, Networks: networks}
	e.mu.Unlock()
	e.saveBlocklistCache(cache)

	e.log.Info("blocklist refreshed", "networks", loaded, "fetched", len(networks), "source", e.blURL)
	e.installBlocklistElements(ctx)
}

// refuseBlocklist records a list refused as a state rather than a failure:
// the shrink guard and the coverage ceiling both mean the feed will serve the
// same list until somebody looks.
//
// Once per streak at Error with an event beside it, because it is the one
// kind of state here that does not resolve itself and somebody has to look.
// Every later attempt is the same refusal of the same list, and a line per
// attempt for as long as nobody intervenes is the peer-driven journal volume
// ControlServer.throttle exists to stop, with the feed as the peer. The
// status carries the refusal throughout, so the portal is not waiting on
// the log.
//
// The hint has to be true. The guards are measured against the list in
// memory, and the cache file is read once, at start: deleting it on a running
// frontend changes nothing, and the first version of this said it did.
// Accepting the feed's new list means starting with no list, which is exactly
// what a stopped unit, a deleted cache and a start again produce.
func (e *Engine) refuseBlocklist(now time.Time, returned, previous int, status, headline string) {
	e.mu.Lock()
	e.blLastTry = now
	e.blLastErr = status
	first := !e.blRefused
	e.blRefused = true
	e.mu.Unlock()
	if first {
		e.log.Error(headline,
			"returned", returned, "loaded", previous, "source", e.blURL, "reason", status,
			"hint", "check the feed by hand; to accept what it now serves, stop the unit, delete "+
				blocklistCacheFile+" from the state directory and start it again")
		_ = e.st.AddEvent(store.EventSystem, 0, "blocklist refresh refused: %s", status)
	} else {
		e.log.Warn("the blocklist feed is still serving a refused list; the previous list stays loaded",
			"returned", returned, "loaded", previous, "source", e.blURL, "reason", status)
	}
}

// fetchBlocklist downloads and parses the feed.
//
// Conditional on the stored ETag, so an unchanged feed costs a 304 rather
// than a megabyte every few hours forever - the polite half of fetching a
// static file from somebody else's host on a schedule, and the reason the
// interval can be short enough to be worth having.
func (e *Engine) fetchBlocklist(ctx context.Context, etag string) (networks []string, newEtag string, notModified bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, blocklistHTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.blURL, nil)
	if err != nil {
		return nil, "", false, err
	}
	req.Header.Set("User-Agent", "homeport-failover-frontend")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := e.blClient.Do(req)
	if err != nil {
		return nil, "", false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return nil, etag, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", false, fmt.Errorf("%s: %s", e.blURL, resp.Status)
	}

	// One byte past the cap, so a response that is exactly at it is still
	// distinguishable from one that overran - a silently shorter list is the
	// failure this whole file is arranged against.
	body, err := io.ReadAll(io.LimitReader(resp.Body, blocklistMaxBytes+1))
	if err != nil {
		return nil, "", false, err
	}
	if len(body) > blocklistMaxBytes {
		return nil, "", false, fmt.Errorf("%s returned more than %d MB; that is not a network list",
			e.blURL, blocklistMaxBytes>>20)
	}
	nets, err := parseBlocklistBody(body)
	if err != nil {
		return nil, "", false, err
	}
	return nets, resp.Header.Get("ETag"), false, nil
}

// parseBlocklistBody reads a netset: comments, blank lines, and one network
// or bare address per line.
//
// Whole or nothing, for fetchCountry's reason. The danger is not a file that
// fails to parse, it is one that parses into something plausible: an error
// page, a redirect body, or half a list, any of which produces a shorter
// perfectly valid list if bad lines are simply skipped. So one unusable line
// fails the fetch, and the loaded list stays where it was.
func parseBlocklistBody(body []byte) ([]string, error) {
	var out []string
	for i, raw := range strings.Split(string(body), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if len(out) >= blocklistMaxNetworks {
			return nil, fmt.Errorf("more than %d networks; that is more than this is meant to load into the kernel",
				blocklistMaxNetworks)
		}
		// A bare address is widened to /32, matching what the portal does
		// with one typed into a region: the feeds mix the two forms and both
		// mean the same thing to nft once the mask is explicit.
		if !strings.Contains(line, "/") {
			ip := net.ParseIP(line)
			if ip == nil || ip.To4() == nil {
				return nil, fmt.Errorf("line %d is neither a network nor an IPv4 address: %q", i+1, truncateLine(line))
			}
			out = append(out, ip.To4().String()+"/32")
			continue
		}
		if n := sysx.NetworkLiteral(line); n != "" {
			out = append(out, n)
			continue
		}
		return nil, fmt.Errorf("line %d is not an IPv4 network: %q", i+1, truncateLine(line))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the feed returned no networks at all")
	}
	return out, nil
}

// truncateLine keeps a bad line quotable in a log entry. The body is
// somebody else's file and a single line of it can be a megabyte.
func truncateLine(s string) string {
	const most = 60
	if len(s) <= most {
		return s
	}
	return s[:most] + "..."
}

// applyBlocklist installs or removes the table.
//
// Removal has to be explicit, for the reason applyProtect and applyEgress
// record: a disabled feature renders an empty ruleset, and an empty ruleset
// loads nothing at all rather than replacing what is there.
//
// The caller holds applyMu.
func (e *Engine) applyBlocklist(ctx context.Context, cfg model.Config, gated, real sysx.Runner) {
	ruleset := sysx.BuildBlocklistRuleset(sysx.BlocklistSpec{
		Enabled:     cfg.Blocklist.Enabled,
		PublicIface: cfg.Frontend.PublicIface,
		Exceptions:  cfg.Blocklist.Exceptions,
	})
	if ruleset == "" {
		if cfg.Blocklist.Enabled && strings.TrimSpace(cfg.Frontend.PublicIface) == "" {
			e.log.Warn("the blocklist is enabled but cannot be applied; set the frontend's public interface")
			_ = e.st.AddEvent(store.EventSystem, 0,
				"blocklist not applied: the frontend has no public interface configured")
		}
		sysx.RemoveBlocklistRuleset(ctx, real)
		e.mu.Lock()
		e.forgetBlocklistTable()
		e.mu.Unlock()
		return
	}

	// Against the refresher, which loads elements under this lock alone. The
	// caller's applyMu does not cover it, and that is the point of blMu.
	e.blMu.Lock()
	defer e.blMu.Unlock()

	// The same latch applyProtect carries, for a weaker version of the same
	// reason: a rebuild here resets one counter rather than unparking every
	// blocked source, but it also empties the feed set, so an unchanged
	// ruleset must not be reloaded on every save.
	armed := gated.Applying()
	e.mu.Lock()
	unchanged := armed && e.blOn && e.blApplied == ruleset
	e.mu.Unlock()
	if unchanged {
		return
	}
	if _, err := sysx.ApplyBlocklistRuleset(ctx, gated, e.stateDir, ruleset); err != nil {
		e.log.Error("failed to apply the blocklist ruleset", "err", err)
		_ = e.st.AddEvent(store.EventSystem, 0, "blocklist apply failed: %v", err)
		e.mu.Lock()
		e.blApplied = ""
		e.mu.Unlock()
		return
	}
	e.mu.Lock()
	if armed {
		e.blOn = true
		e.blApplied = ruleset
		// The rebuild zeroed the rule, so the sample describing the old one
		// goes with it.
		e.blCounter = model.ProtectCounter{}
	} else {
		// Observe mode ran no nft, so blOn is left exactly where it was, and
		// that is invariant 13 rather than an oversight: disarming is not a
		// teardown, so a table loaded while armed is still in the kernel and
		// still dropping. Recorded as unloaded, the portal said nothing was
		// being dropped and that this was expected in observe mode, which is
		// false in the one direction that matters - and the counter froze
		// with it, because sampleProtect used to read the same field. The
		// latch still goes, because whatever is loaded is no longer this
		// ruleset.
		e.blApplied = ""
	}
	nets := e.blCount
	e.mu.Unlock()

	if armed {
		// The table has just been rebuilt, so its feed set is empty whatever
		// was in it a moment ago. Refilling it here rather than waiting for
		// the refresher is what keeps a settings save from silently switching
		// the list off for up to a refresh interval.
		e.loadBlocklistElements(ctx, gated)
		e.log.Info("blocklist active", "iface", cfg.Frontend.PublicIface, "networks", nets)
		if nets == 0 {
			e.log.Warn("the blocklist is active with no list yet; it drops nothing until the first fetch succeeds",
				"source", e.blURL)
		}
	}
	// Enabling it, or changing the exceptions, is exactly when a fetch is
	// worth reconsidering: a first-ever start has no list at all.
	e.wakeBlocklist()
}

// installBlocklistElements loads the current list into the kernel. This is
// the refresher's entry point; applyBlocklist calls loadBlocklistElements
// directly because it already holds the lock.
//
// blMu and not applyMu, deliberately. The load touches no route, and an
// interval set of tens of thousands of elements takes nft seconds: under
// applyMu a path condemned during a refresh waited behind it before evaluate
// could move traffic. What applyMu was buying here was the runner - a swap to
// observe landing mid-load - and Reconfigure now takes blMu around the swap
// for exactly that, so the runner captured below is the one in force for the
// whole load.
func (e *Engine) installBlocklistElements(ctx context.Context) {
	e.blMu.Lock()
	defer e.blMu.Unlock()
	e.mu.RLock()
	gated := e.runner
	e.mu.RUnlock()
	e.loadBlocklistElements(ctx, gated)
}

// forgetBlocklistTable records that the table is not in the kernel: the
// feature switched off, the revert that removed it, or the readback saying it
// has gone. One spelling for the three, because the record is three fields
// that describe one thing and the next field added to it - the retry latch,
// say - has to be cleared at every site or the portal assembles a state from
// fields reset on different occasions. The caller holds e.mu for writing.
func (e *Engine) forgetBlocklistTable() {
	e.blOn = false
	e.blApplied = ""
	e.blCounter = model.ProtectCounter{}
}

// loadBlocklistElements writes the set contents in one nft transaction.
//
// Two conditions rather than one, because blOn survives a disarm. The table
// being in the kernel is what makes a set exist to fill: absent - never armed,
// a failed apply, the feature off - the nft call would be an error every
// refresh. The runner applying is what keeps observe mode's promise, and it is
// the load-bearing half now that the two can differ: a load past it would
// change what a live table drops, which is the one thing this rule may never
// do unarmed, and would leave a feed file on disk describing a set the kernel
// does not have.
//
// The caller holds blMu.
func (e *Engine) loadBlocklistElements(ctx context.Context, gated sysx.Runner) {
	e.mu.RLock()
	on := e.blOn
	nets, elems := e.blNetworks, e.blElems
	e.mu.RUnlock()
	if !on || !gated.Applying() || len(nets) == 0 {
		e.forgetBlocklistLoadFailure()
		return
	}
	elements := sysx.RenderBlocklistElements(elems)
	if elements == "" {
		// Nothing survived the parse and the merge. A fault, not an
		// instruction: the set keeps whatever it holds. The list came
		// through parseBlocklistBody, so reaching this means every entry
		// was private or reserved space, which no real feed produces.
		//
		// Not retried either, for the reason the linker's refused egress push
		// carries: the parse of a fixed list is deterministic, so the next
		// attempt fails identically. Only the kernel refusing a load is worth
		// coming back for.
		e.forgetBlocklistLoadFailure()
		e.log.Error("the blocklist has no usable networks; the loaded set is left alone", "fetched", len(nets))
		return
	}
	if _, err := sysx.ApplyBlocklistElements(ctx, gated, e.stateDir, elements); err != nil {
		e.log.Error("failed to load the blocklist networks; it will be retried", "err", err,
			"retry", blocklistRetryEvery.String())
		_ = e.st.AddEvent(store.EventSystem, 0, "blocklist networks not loaded: %v", err)
		e.mu.Lock()
		e.blLoadFailed = time.Now()
		e.blLoadErr = err.Error()
		e.mu.Unlock()
		return
	}
	e.forgetBlocklistLoadFailure()
}

// forgetBlocklistLoadFailure drops any outstanding retry. Called from every
// exit of loadBlocklistElements that is not a refused load, including the ones
// that install nothing: with no table to fill there is nothing to come back
// for, and the apply that puts one there loads the list itself.
func (e *Engine) forgetBlocklistLoadFailure() {
	e.mu.Lock()
	e.blLoadFailed = time.Time{}
	e.blLoadErr = ""
	e.mu.Unlock()
}

// sampleBlocklistCounter reads the drop rule's tally back out of the kernel.
// Shares sampleProtect's idle gate: this feeds the portal and nothing else.
func (e *Engine) sampleBlocklistCounter(ctx context.Context) {
	c, err := sysx.BlocklistState(ctx, e.realRunner())
	if err != nil {
		e.log.Debug("cannot read blocklist state", "err", err)
		// The table may be gone underneath the agent. Dropping the latch makes
		// the next save load it again rather than skipping it as unchanged,
		// exactly as sampleProtect does - and when the kernel says the table
		// is not there, the record of it being loaded goes with it, because
		// this readback is the only thing here that reports the kernel rather
		// than this agent's belief about it. Leaving it set had the portal
		// claim the rules were in the kernel immediately after the read
		// proved they were not, and had every refresh load elements into a
		// table that is not there.
		//
		// Only when the kernel says so, and not on any failure, because the
		// loader trusts this record and this sampler runs only while the
		// portal is open. Cleared by one slow nft, it stayed cleared once the
		// tab was closed; the next refresh then wrote the new list to the
		// cache and the count to the card, saw no table to fill, loaded
		// nothing and forgot the retry, and every 304 after that loads no
		// elements by design - so the kernel kept the old list for as long
		// as it took the feed to change with the portal open again, while the
		// card read as fresh. A failure that says nothing about the table
		// costs the latch and nothing else.
		e.mu.Lock()
		e.blApplied = ""
		if sysx.TableMissing(err) {
			e.forgetBlocklistTable()
		}
		e.mu.Unlock()
		return
	}
	e.mu.Lock()
	// And upward, which is what makes clearing it above safe on a read that
	// merely failed once: a table that really is there is found again on the
	// next tick. It is also the only thing that notices one left behind by an
	// armed process this one has replaced, since the unit runs under
	// Restart=always and a restart into observe mode installs nothing.
	e.blOn = true
	e.blCounter = c
	e.mu.Unlock()
}

// blocklistStatus renders the feature for the portal. Callers hold e.mu at
// least for reading.
//
// Absent when the feature is off, like the protection block beside it. Present
// but unloaded is a real state and has to be reported as one: observe mode, a
// missing public interface, or an apply that failed all leave the switch on
// and nothing in the kernel.
func (e *Engine) blocklistStatus() *model.BlocklistStatus {
	if !e.cfg.Blocklist.Enabled {
		return nil
	}
	st := &model.BlocklistStatus{
		Networks:   e.blCount,
		Exceptions: len(e.cfg.Blocklist.Exceptions),
		Source:     e.blURL,
		UpdatedAt:  e.blUpdated,
		LastTry:    e.blLastTry,
		LastError:  e.blLastErr,
		LoadError:  e.blLoadErr,
		Loaded:     e.blOn,
		Packets:    e.blCounter.Packets,
		Bytes:      e.blCounter.Bytes,
	}
	if !e.blUpdated.IsZero() {
		st.AgeHours = time.Since(e.blUpdated).Hours()
		// Decided here rather than in the browser, because the threshold was
		// written down in both places and only one of them was this constant.
		st.Stale = st.AgeHours >= blocklistStaleAfter.Hours()
	}
	return st
}
