package web

import (
	"strings"
	"testing"

	"github.com/quinlan102/homeport/internal/model"
)

func blocklistConfig() model.Config {
	cfg := model.Defaults()
	cfg.Frontend.PublicIface = "eth0"
	cfg.Blocklist.Enabled = true
	return cfg
}

// The same rule protection fails closed on, and for a sharper reason: without
// an interface to scope to, a third party's list would be able to drop the
// probes and the control channel, condemning a healthy link and moving traffic
// to a metered one.
func TestBlocklistIsRefusedWithoutThePublicInterface(t *testing.T) {
	cfg := blocklistConfig()
	cfg.Frontend.PublicIface = ""

	err := validate(&cfg)
	if err == nil {
		t.Fatal("the blocklist was accepted with no public interface to scope it to")
	}
	if !strings.Contains(err.Error(), "public interface") {
		t.Errorf("the error does not say what is missing: %v", err)
	}
}

// Zero is the shipped default and has to keep saving, because it is what every
// configuration written before this field existed carries.
func TestBlocklistRefreshZeroMeansTheDefault(t *testing.T) {
	cfg := blocklistConfig()
	cfg.Blocklist.RefreshHours = 0
	if err := validate(&cfg); err != nil {
		t.Fatalf("an unset refresh interval was refused: %v", err)
	}
}

// Both bounds, with the reason in the message: below the floor this polls
// somebody else's host harder than their file changes, above the ceiling the
// list is older than the freshness the whole feature exists for.
func TestBlocklistRefreshBounds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		hours int
	}{
		// The floor is 1, so negative is the whole of "under the floor" and
		// there is nothing between them to test separately.
		{"negative", -1},
		{"over the ceiling", model.MaxBlocklistRefreshHours + 1},
	} {
		cfg := blocklistConfig()
		cfg.Blocklist.RefreshHours = tc.hours
		if err := validate(&cfg); err == nil {
			t.Errorf("a %s refresh of %dh was accepted", tc.name, tc.hours)
		}
	}
	for _, h := range []int{model.MinBlocklistRefreshHours, 4, model.MaxBlocklistRefreshHours} {
		cfg := blocklistConfig()
		cfg.Blocklist.RefreshHours = h
		if err := validate(&cfg); err != nil {
			t.Errorf("a refresh of %dh at the boundary was refused: %v", h, err)
		}
	}
}

// An exception becomes an element of an nftables interval set, so it is held
// to what nft will load - a bad one is not cosmetic, it is the whole table
// refused and the blocklist silently absent.
func TestBlocklistExceptionsAreHeldToWhatNftablesWillLoad(t *testing.T) {
	for _, bad := range []string{
		"not-a-network",
		"2001:db8::/32",
		"::ffff:203.0.113.0/120", // an IPv4-mapped network, which stores and then fails to re-parse
		"203.0.113.0/33",
	} {
		cfg := blocklistConfig()
		cfg.Blocklist.Exceptions = []string{bad}
		if err := validate(&cfg); err == nil {
			t.Errorf("%q was accepted as an exception", bad)
		}
	}
}

// A bare address is widened to /32 and a host-part network is masked, exactly
// as a region's list is: an exception is usually one address somebody has just
// found in the feed, and nft refuses 203.0.113.5/24 outright.
func TestBlocklistExceptionsAreNormalised(t *testing.T) {
	cfg := blocklistConfig()
	cfg.Blocklist.Exceptions = []string{" 198.51.100.7 ", "203.0.113.5/24"}

	if err := validate(&cfg); err != nil {
		t.Fatalf("a valid exception list was refused: %v", err)
	}
	want := []string{"198.51.100.7/32", "203.0.113.0/24"}
	if len(cfg.Blocklist.Exceptions) != len(want) {
		t.Fatalf("got %v, want %v", cfg.Blocklist.Exceptions, want)
	}
	for i := range want {
		if cfg.Blocklist.Exceptions[i] != want[i] {
			t.Fatalf("got %v, want %v", cfg.Blocklist.Exceptions, want)
		}
	}
}

// The cap is not a size story like the region lists; it is a shape one. A
// deployment with hundreds of exceptions has decided it disagrees with the
// feed, and wants the feature off rather than overridden.
func TestTooManyBlocklistExceptionsAreRefused(t *testing.T) {
	cfg := blocklistConfig()
	for i := 0; i <= maxBlocklistExceptions; i++ {
		cfg.Blocklist.Exceptions = append(cfg.Blocklist.Exceptions, "203.0.113.0/24")
	}
	err := validate(&cfg)
	if err == nil {
		t.Fatal("an unbounded exception list was accepted")
	}
	if !strings.Contains(err.Error(), "exceptions") {
		t.Errorf("the error does not name what is too long: %v", err)
	}
}

// The feature off must stay saveable with nothing set, which is every
// configuration written before it existed.
func TestBlocklistOffSavesUntouched(t *testing.T) {
	cfg := model.Defaults()
	if err := validate(&cfg); err != nil {
		t.Fatalf("the shipped configuration was refused: %v", err)
	}
	if cfg.Blocklist.Enabled {
		t.Error("the shipped configuration has the blocklist enabled; a fresh install must not " +
			"start dropping traffic on the strength of a feed nobody has looked at")
	}
}
