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
