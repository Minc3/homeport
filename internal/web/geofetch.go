package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
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

	var cidrs []string
	var counts []geoFetchCount
	seen := map[string]bool{}
	for _, cc := range req.Countries {
		cc = strings.ToLower(trimmed(cc))
		if cc == "" || seen[cc] {
			continue
		}
		seen[cc] = true
		// Two lowercase letters and nothing else, checked before the code goes
		// anywhere near a URL. Everything that is not a country code is
		// refused, not escaped.
		if bad := badCountryCode(cc); bad != "" {
			clientErr(w, fmt.Errorf("%q is not an ISO country code: %s", cc, bad))
			return
		}
		list, err := s.fetchCountry(cc)
		if err != nil {
			// 502 rather than 400: the operator's input was fine, the world
			// was not, and the fix is to retry or to paste by hand.
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		cidrs = append(cidrs, list...)
		counts = append(counts, geoFetchCount{Country: cc, Networks: len(list)})
	}
	if len(cidrs) == 0 {
		clientErr(w, fmt.Errorf("no country codes left after trimming"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cidrs": cidrs, "counts": counts})
}

// fetchCountry downloads and checks one country's list.
func (s *Server) fetchCountry(cc string) ([]string, error) {
	url := s.geoBase + "/" + cc + "-aggregated.zone"
	resp, err := s.geoClient.Get(url)
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
		// wrong, and it must not become an allowlist.
		if _, netw, err := net.ParseCIDR(line); err != nil || netw.IP.To4() == nil {
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
