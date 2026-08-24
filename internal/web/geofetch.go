package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Region list fetching
// --------------------
// The one place the frontend talks to a third party, and it is shaped to keep
// that as small as it sounds. The fetch happens only when an operator clicks
// the button in the portal, the result goes into the settings form rather than
// into the configuration, and nothing is stored or applied until they review
// it and save - so the config database remains the only source of truth and
// the running system still never depends on an external service. There is no
// scheduled refresh, deliberately: an automatic fetch that fails, or half
// succeeds, at 3am replaces a working allowlist with nobody watching, and the
// cost of staleness here is a few newly allocated networks missing from a
// region, not an outage.
//
// It is whole-or-nothing, because the dangerous failure is not garbage - the
// parse catches that - but a plausible fragment. A truncated download is
// valid CIDRs all the way to the cut, and a region quietly missing half a
// country looks exactly like a working lock until the day it drops a player
// it should have admitted. Any line that does not parse, an empty list, or a
// response over the size cap fails the whole request with nothing returned.

// geoFetchBase is where the aggregated per-country lists come from: ipdeny's
// zone files, built from the RIR delegation statistics. The same files
// deploy/geo-zones.sh fetches, so the button and the script cannot drift.
const geoFetchBase = "https://www.ipdeny.com/ipblocks/data/aggregated"

// geoFetchMaxBytes caps one country's response. The largest real file (US) is
// well under a megabyte; anything bigger is not a zone file.
const geoFetchMaxBytes = 4 << 20

// geoFetchMaxCountries bounds one request. A generous region is a dozen
// codes; a list longer than this is a mistake, and each code costs an
// outbound request.
const geoFetchMaxCountries = 24

// geoFetchParallel is how many of those requests are in flight at once:
// enough that a worst-case fetch is bounded by a few timeouts rather than
// one per code, small enough to be polite to a host serving static files.
const geoFetchParallel = 4

type geoFetchRequest struct {
	Countries []string `json:"countries"`
}

type geoFetchCount struct {
	Country  string `json:"country"`
	Networks int    `json:"networks"`
}

// handleGeoFetch fetches the aggregated network lists for a set of ISO
// country codes and returns them for the settings form to display.
func (s *Server) handleGeoFetch(w http.ResponseWriter, r *http.Request) {
	var req geoFetchRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		clientErr(w, fmt.Errorf("bad request: %w", err))
		return
	}
	if len(req.Countries) == 0 {
		clientErr(w, fmt.Errorf("name at least one country code, e.g. au"))
		return
	}
	if len(req.Countries) > geoFetchMaxCountries {
		clientErr(w, fmt.Errorf("%d country codes in one request; the most a fetch accepts is %d",
			len(req.Countries), geoFetchMaxCountries))
		return
	}

	// Every code is checked before anything goes near a URL - a whole first
	// pass, not a check inside the fetch loop, so a bad code in any position
	// is refused with zero requests sent rather than after the codes ahead of
	// it were already fetched. Everything that is not a country code is
	// refused, not escaped.
	codes := make([]string, 0, len(req.Countries))
	seen := map[string]bool{}
	for _, cc := range req.Countries {
		cc = strings.ToLower(trimmed(cc))
		if cc == "" || seen[cc] {
			continue
		}
		seen[cc] = true
		if bad := badCountryCode(cc); bad != "" {
			clientErr(w, fmt.Errorf("%q is not an ISO country code: %s", cc, bad))
			return
		}
		codes = append(codes, cc)
	}
	if len(codes) == 0 {
		clientErr(w, fmt.Errorf("no country codes left after trimming"))
		return
	}

	// The fetches are independent, so they run together rather than in
	// series: serial, an unreachable host cost 10 seconds per code before the
	// first error surfaced, minutes for a generous region. Bounded, because
	// two dozen sockets at once buys nothing from one static host. Tied to
	// the request context so an operator who gives up and closes the tab
	// cancels the downloads instead of leaving them running for a reply
	// nobody will read; the first failure cancels the rest the same way.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	lists := make([][]string, len(codes))
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		fetchErr error
	)
	sem := make(chan struct{}, geoFetchParallel)
	for i, cc := range codes {
		wg.Add(1)
		go func(i int, cc string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			list, err := s.fetchCountry(ctx, cc)
			if err != nil {
				mu.Lock()
				// The first error is the root cause; anything after it is
				// mostly the cancellation it triggered.
				if fetchErr == nil {
					fetchErr = err
				}
				mu.Unlock()
				cancel()
				return
			}
			lists[i] = list
		}(i, cc)
	}
	wg.Wait()
	if fetchErr != nil {
		// 502 rather than 400: the operator's input was fine, the world
		// was not, and the fix is to retry or to paste by hand.
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": fetchErr.Error()})
		return
	}
	if ctx.Err() != nil {
		// The client is gone; nobody is listening for a body.
		return
	}

	// Indexed by position above, so the merged list and the counts come back
	// in request order whatever order the fetches finished in.
	var cidrs []string
	counts := make([]geoFetchCount, 0, len(codes))
	for i, cc := range codes {
		cidrs = append(cidrs, lists[i]...)
		counts = append(counts, geoFetchCount{Country: cc, Networks: len(lists[i])})
	}
	writeJSON(w, http.StatusOK, map[string]any{"cidrs": cidrs, "counts": counts})
}

// fetchCountry downloads and checks one country's list.
func (s *Server) fetchCountry(ctx context.Context, cc string) ([]string, error) {
	url := s.geoBase + "/" + cc + "-aggregated.zone"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("could not fetch the list for %q: %v", cc, err)
	}
	resp, err := s.geoClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not fetch the list for %q: %v", cc, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the list for %q came back as %s; check the ISO country code", cc, resp.Status)
	}

	// One byte past the cap is read so truncation is a loud error rather than
	// a shorter list: a response cut mid-line usually still parses, and a
	// region silently missing half a country is the failure this whole
	// handler is shaped to prevent.
	body, err := io.ReadAll(io.LimitReader(resp.Body, geoFetchMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("could not read the list for %q: %v", cc, err)
	}
	if len(body) > geoFetchMaxBytes {
		return nil, fmt.Errorf("the list for %q is over %d bytes, which no country's list is; refusing it", cc, geoFetchMaxBytes)
	}

	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		line = trimmed(line)
		if line == "" {
			continue
		}
		// Every line must be an IPv4 network or the whole fetch fails: an
		// error page with a 200 on it is the classic shape of this going
		// wrong, and it must not become an allowlist. The same test validate
		// applies on save, so a list this accepts cannot be refused there.
		if _, err := parseIPv4Network(line); err != nil {
			return nil, fmt.Errorf("the list for %q contains %q, which is not an IPv4 network; refusing the whole list", cc, line)
		}
		out = append(out, line)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the list for %q is empty", cc)
	}
	return out, nil
}

// badCountryCode says what is wrong with a would-be ISO code, or "".
func badCountryCode(cc string) string {
	if len(cc) != 2 {
		return "a code is exactly two letters"
	}
	for _, r := range cc {
		if r < 'a' || r > 'z' {
			return "a code is two letters, a-z"
		}
	}
	return ""
}

// defaultGeoClient bounds each outbound fetch. Ten seconds is a long time for
// a static file and a short time for an operator watching a button.
func defaultGeoClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}
