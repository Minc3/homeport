package web

import (
	"strings"
	"testing"

	"github.com/quinlan102/homeport/internal/model"
)

// The one thing that cannot be worked around. Without an interface to scope
// them to, the rules would also match traffic arriving on a tunnel - which is
// where the probes and the control channel arrive. A limiter able to drop those
// would have the frontend condemn a healthy link on the strength of its own
// firewall, so this fails closed rather than generating something narrower.
func TestProtectionIsRefusedWithoutThePublicInterface(t *testing.T) {
	cfg := model.Defaults()
	cfg.Frontend.PublicIface = ""
	cfg.Protect.Enabled = true

	err := validate(&cfg)
	if err == nil {
		t.Fatal("protection was accepted with no public interface to scope it to")
	}
	if !strings.Contains(err.Error(), "public interface") {
		t.Errorf("the error does not say what is missing: %v", err)
	}
}

// A shaping rate of 2 where 20 was meant would throttle the link to
// uselessness and read as a deliberate setting. Refused rather than applied,
// because the symptom - everything suddenly slow - looks like the link failing.
func TestAnAbsurdlySmallShapingRateIsRefused(t *testing.T) {
	cfg := model.Defaults()
	cfg.Paths[0].Shape.ToBackendMbit = 0.5

	err := validate(&cfg)
	if err == nil {
		t.Fatal("a rate of 0.5 Mbit/s was accepted")
	}
	if !strings.Contains(err.Error(), "typo") {
		t.Errorf("the error does not explain itself: %v", err)
	}
}

// Zero is how shaping is switched off and must stay perfectly valid.
func TestNoShapingIsValid(t *testing.T) {
	cfg := model.Defaults()
	if err := validate(&cfg); err != nil {
		t.Fatalf("the shipped configuration was rejected: %v", err)
	}
}

// A negative limit would invert every comparison it appears in.
func TestNegativeLimitsAreRefused(t *testing.T) {
	base := func() model.Config {
		cfg := model.Defaults()
		cfg.Frontend.PublicIface = "eth0"
		cfg.Protect.Enabled = true
		return cfg
	}
	for name, mutate := range map[string]func(*model.Config){
		"connections per second": func(c *model.Config) { c.Protect.NewConnsPerSec = -1 },
		"packets per second":     func(c *model.Config) { c.Protect.PacketsPerSec = -5 },
		"block seconds":          func(c *model.Config) { c.Protect.BlockSeconds = -60 },
		"service ceiling":        func(c *model.Config) { c.Services[0].CeilingPPS = -1 },
		"shaping rate":           func(c *model.Config) { c.Paths[0].Shape.ToFrontendMbit = -10 },
	} {
		cfg := base()
		mutate(&cfg)
		if err := validate(&cfg); err == nil {
			t.Errorf("a negative %s was accepted", name)
		}
	}
}

// Turning the master switch on and filling nothing in is a legitimate state -
// it is what somebody does before deciding on their first threshold - and must
// save without complaint, generating no rules at all.
func TestProtectionOnWithNoThresholdsIsValid(t *testing.T) {
	cfg := model.Defaults()
	cfg.Frontend.PublicIface = "eth0"
	cfg.Protect.Enabled = true

	if err := validate(&cfg); err != nil {
		t.Fatalf("protection with no thresholds was rejected: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Region locks
// ---------------------------------------------------------------------------

// geoBase is a configuration with one region and the minecraft service locked
// to it, which is the shape every valid lock shares.
func geoBase() model.Config {
	cfg := model.Defaults()
	cfg.Frontend.PublicIface = "eth0"
	cfg.Protect.Enabled = true
	cfg.Protect.Regions = []model.GeoRegion{
		{Name: "oceania", CIDRs: []string{"1.128.0.0/11"}},
	}
	for i := range cfg.Services {
		if cfg.Services[i].Name == "minecraft" {
			cfg.Services[i].GeoRegions = []string{"oceania"}
		}
	}
	return cfg
}

// The happy path, including the automatic variant, has to save - and the save
// normalises: a bare address becomes a /32 and a host-part CIDR is masked to
// its network, because both end up as set elements the kernel checks exactly.
func TestAValidRegionLockSaves(t *testing.T) {
	cfg := geoBase()
	cfg.Protect.Regions[0].CIDRs = []string{"1.128.0.0/11", "101.167.4.20", "49.224.1.5/14"}
	for i := range cfg.Services {
		if cfg.Services[i].Name == "minecraft" {
			cfg.Services[i].GeoAutoPPS = 50000
		}
	}
	cfg.Protect.GeoLockSeconds = 120

	if err := validate(&cfg); err != nil {
		t.Fatalf("a valid region lock was rejected: %v", err)
	}
	got := cfg.Protect.Regions[0].CIDRs
	want := []string{"1.128.0.0/11", "101.167.4.20/32", "49.224.0.0/14"}
	if len(got) != len(want) {
		t.Fatalf("networks = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("network %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// A lock naming a region nobody defined would silently not lock the port: the
// build skips what it cannot resolve, so this is the layer that has to refuse.
func TestALockOnAnUndefinedRegionIsRefused(t *testing.T) {
	cfg := geoBase()
	for i := range cfg.Services {
		if cfg.Services[i].Name == "minecraft" {
			cfg.Services[i].GeoRegions = []string{"atlantis"}
		}
	}
	err := validate(&cfg)
	if err == nil {
		t.Fatal("a lock on an undefined region was accepted")
	}
	if !strings.Contains(err.Error(), "atlantis") {
		t.Errorf("the error does not name the missing region: %v", err)
	}
}

// A lock on a region with nothing in it is an allowlist that admits nobody,
// and the port would drop everything arriving at it.
func TestALockOnAnEmptyRegionIsRefused(t *testing.T) {
	cfg := geoBase()
	cfg.Protect.Regions[0].CIDRs = nil
	if err := validate(&cfg); err == nil {
		t.Fatal("a lock on an empty region was accepted")
	}
}

// A network that does not parse would reach the generated ruleset and fail the
// whole table load, taking every other limit down with it.
func TestABadRegionNetworkIsRefused(t *testing.T) {
	cfg := geoBase()
	cfg.Protect.Regions[0].CIDRs = []string{"1.128.0.0/11", "not-a-network"}
	if err := validate(&cfg); err == nil {
		t.Fatal("an unparsable region network was accepted")
	}
	cfg.Protect.Regions[0].CIDRs = []string{"2404:e80::/32"}
	if err := validate(&cfg); err == nil {
		t.Fatal("an IPv6 network was accepted into an ip-family table")
	}
}

// An IPv4-mapped IPv6 network passes a bare To4 test, but String() renders it
// with a 128-bit mask length ("1.128.0.0/120") - a value the generator skips
// in silence, so the lock saves and does not exist, and a later ParseCIDR
// refuses outright, so validate then rejects a string it wrote itself and
// blocks every unrelated save until the region is hand-edited. Refused whole.
func TestAnIPv4MappedRegionNetworkIsRefused(t *testing.T) {
	cfg := geoBase()
	cfg.Protect.Regions[0].CIDRs = []string{"::ffff:1.128.0.0/120"}
	if err := validate(&cfg); err == nil {
		t.Fatal("an IPv4-mapped IPv6 network was accepted into an ip-family table")
	}
	// The same hole existed in the egress source check, which feeds the same
	// family of generated rulesets and shares the helper.
	cfg = geoBase()
	cfg.Egress.Sources[0].CIDR = "::ffff:172.18.0.0/112"
	if err := validate(&cfg); err == nil {
		t.Fatal("an IPv4-mapped IPv6 network was accepted as an egress source")
	}
}

// The per-protocol lockdown sets live in the same namespace as the region
// sets, so a region name that folds onto one of theirs would define the set
// twice with two different types - and nft rejects the whole table, every
// other limit included. The generator shifts a stale blob's set aside; here,
// where the operator can still pick another name, the name is refused.
func TestARegionNameReservedByTheLockdownSetsIsRefused(t *testing.T) {
	for _, name := range []string{"lockdown_tcp", "lockdown-tcp", "lockdown_udp", "lockdown-udp"} {
		cfg := geoBase()
		cfg.Protect.Regions[0].Name = name
		for i := range cfg.Services {
			if cfg.Services[i].Name == "minecraft" {
				cfg.Services[i].GeoRegions = []string{name}
			}
		}
		err := validate(&cfg)
		if err == nil {
			t.Errorf("reserved region name %q was accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), "reserved") {
			t.Errorf("the error does not say the name is reserved: %v", err)
		}
	}
}

// Region names become nftables set names, where a hyphen folds to an
// underscore - so two names the fold makes identical are one set defined
// twice, and nft refuses the table.
func TestRegionNamesThatCollideAsSetNamesAreRefused(t *testing.T) {
	cfg := geoBase()
	cfg.Protect.Regions = append(cfg.Protect.Regions,
		model.GeoRegion{Name: "south-america", CIDRs: []string{"131.0.0.0/16"}},
		model.GeoRegion{Name: "south_america", CIDRs: []string{"131.108.0.0/16"}})
	if err := validate(&cfg); err == nil {
		t.Fatal("two regions rendering to one set name were accepted")
	}
}

// The name itself is held to the identifier characters rather than folded
// behind the operator's back: what they typed is what the ruleset shows.
func TestARegionNameOutsideTheSlugIsRefused(t *testing.T) {
	for _, name := range []string{"Oceania", "océanie", "south america", ""} {
		cfg := geoBase()
		cfg.Protect.Regions[0].Name = name
		for i := range cfg.Services {
			if cfg.Services[i].Name == "minecraft" {
				cfg.Services[i].GeoRegions = []string{name}
			}
		}
		if err := validate(&cfg); err == nil {
			t.Errorf("region name %q was accepted", name)
		}
	}
}

// An auto-lock threshold with no regions has nothing to lock the port to, and
// the operator who set it believes a protection now exists.
func TestAnAutoThresholdWithoutRegionsIsRefused(t *testing.T) {
	cfg := geoBase()
	for i := range cfg.Services {
		if cfg.Services[i].Name == "minecraft" {
			cfg.Services[i].GeoRegions = nil
			cfg.Services[i].GeoAutoPPS = 50000
		}
	}
	err := validate(&cfg)
	if err == nil {
		t.Fatal("an auto-lock threshold with no regions was accepted")
	}
	if !strings.Contains(err.Error(), "auto-lock") {
		t.Errorf("the error does not say what is wrong: %v", err)
	}
}

// A negative threshold or release lag would invert the comparisons they
// appear in, like every other protection number.
func TestNegativeRegionLockNumbersAreRefused(t *testing.T) {
	cfg := geoBase()
	cfg.Protect.GeoLockSeconds = -1
	if err := validate(&cfg); err == nil {
		t.Error("a negative release lag was accepted")
	}
	cfg = geoBase()
	for i := range cfg.Services {
		if cfg.Services[i].Name == "minecraft" {
			cfg.Services[i].GeoAutoPPS = -1
		}
	}
	if err := validate(&cfg); err == nil {
		t.Error("a negative auto-lock threshold was accepted")
	}
}

// The caps are one story: a configuration validate accepts must always fit
// back through the PUT body cap, or one generous region blocks every later
// save of anything with an opaque "request body too large". Refused here,
// where the error can say which lists to trim, before the body cap ever has
// to say nothing.
func TestRegionListsOverTheTotalCapAreRefused(t *testing.T) {
	cfg := model.Defaults()
	cfg.Frontend.PublicIface = "eth0"
	cfg.Protect.Enabled = true
	entries := make([]string, (maxRegionsBytes/len("203.0.113.0/24"))+2)
	for i := range entries {
		entries[i] = "203.0.113.0/24"
	}
	cfg.Protect.Regions = []model.GeoRegion{{Name: "everything", CIDRs: entries}}

	err := validate(&cfg)
	if err == nil {
		t.Fatal("a region list larger than a save can carry was accepted")
	}
	if !strings.Contains(err.Error(), "trim a list") {
		t.Errorf("the error does not say what to do: %v", err)
	}
}
