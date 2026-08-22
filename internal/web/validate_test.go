package web

import (
	"strings"
	"testing"

	"github.com/quinlan102/homeport/internal/model"
	"github.com/quinlan102/homeport/internal/sysx"
)

func TestValidateAcceptsDefaults(t *testing.T) {
	cfg := model.Defaults()
	if err := validate(&cfg); err != nil {
		t.Fatalf("the shipped defaults must validate: %v", err)
	}
}

func TestValidateRejectsDuplicateMark(t *testing.T) {
	cfg := model.Defaults()
	cfg.Paths[1].Mark = cfg.Paths[0].Mark
	err := validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "fwmark") {
		// Two paths sharing an fwmark means both probe through the same
		// tunnel, and a dead link would keep testing as healthy.
		t.Fatalf("duplicate fwmark should be rejected, got %v", err)
	}
}

func TestValidateRejectsDuplicateTable(t *testing.T) {
	cfg := model.Defaults()
	cfg.Paths[2].Table = cfg.Paths[0].Table
	if err := validate(&cfg); err == nil {
		t.Fatal("duplicate routing table should be rejected")
	}
}

func TestValidateRejectsCeilingBelowQuota(t *testing.T) {
	cfg := model.Defaults()
	cfg.Paths[1].Quota.CeilingBytes = 1 << 30 // below the 60 GiB limit
	if err := validate(&cfg); err == nil {
		t.Fatal("a ceiling below the quota is contradictory and should be rejected")
	}
}

func TestValidateRejectsUnknownTimezone(t *testing.T) {
	cfg := model.Defaults()
	cfg.Paths[1].Quota.Timezone = "Mars/Olympus"
	if err := validate(&cfg); err == nil {
		t.Fatal("an unknown timezone would silently shift the billing boundary")
	}
}

func TestValidateFillsAnEmptyTimezoneWithTheDeploymentsOwn(t *testing.T) {
	cfg := model.Defaults()
	cfg.Paths[1].Quota.Timezone = ""
	if err := validate(&cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// A blank field used to become UTC, which draws the billing boundary ten
	// hours off where the carrier draws it: usage on the first of the month
	// lands in the previous period and the quota trips days late.
	if cfg.Paths[1].Quota.Timezone != model.DefaultTimezone {
		t.Errorf("timezone = %q, want %q", cfg.Paths[1].Quota.Timezone, model.DefaultTimezone)
	}
}

func TestValidateNormalisesCalibration(t *testing.T) {
	cfg := model.Defaults()
	cfg.Paths[1].Quota.Calibration = 0
	if err := validate(&cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// A zero calibration would multiply every metered figure by zero and the
	// quota would never trip.
	if cfg.Paths[1].Quota.Calibration != 100 {
		t.Errorf("calibration = %v, want it normalised to 100", cfg.Paths[1].Quota.Calibration)
	}
}

func TestValidateRejectsStandbyFasterThanActive(t *testing.T) {
	cfg := model.Defaults()
	cfg.Probe.StandbyIntervalMs = 100
	cfg.Probe.ActiveIntervalMs = 250
	if err := validate(&cfg); err == nil {
		t.Fatal("probing standby paths faster than the active one wastes metered data")
	}
}

func TestValidateRejectsBadMode(t *testing.T) {
	cfg := model.Defaults()
	cfg.Mode = "yolo"
	if err := validate(&cfg); err == nil {
		t.Fatal("an unknown mode should be rejected rather than silently arming")
	}
}

func TestValidateRejectsBadService(t *testing.T) {
	cfg := model.Defaults()
	cfg.Services = append(cfg.Services, model.Service{Name: "bad", Proto: "sctp", Port: 1234, Enabled: true})
	if err := validate(&cfg); err == nil {
		t.Fatal("only tcp and udp can be published")
	}
}

func TestValidateRejectsEmptyPaths(t *testing.T) {
	cfg := model.Defaults()
	cfg.Paths = nil
	if err := validate(&cfg); err == nil {
		t.Fatal("a configuration with no paths cannot make a decision")
	}
}

// Without an output interface the egress rule would have to match every way
// out, tunnels included - and rewriting the source of a reply on its way back
// to a player is the one translation this system exists to avoid. Rejecting is
// better than quietly ignoring: the operator ticked a box and would otherwise
// be told it was on while nothing happened.
func TestValidateRejectsBackendEgressWithoutAPublicInterface(t *testing.T) {
	cfg := model.Defaults()
	cfg.Frontend.BackendEgress = true
	cfg.Frontend.PublicIface = ""
	if err := validate(&cfg); err == nil {
		t.Error("backend egress with no public interface must be rejected")
	}

	cfg.Frontend.PublicIface = "eth0"
	if err := validate(&cfg); err != nil {
		t.Errorf("backend egress with a public interface should be accepted: %v", err)
	}
}

func TestValidateRejectsBadPublicIP(t *testing.T) {
	cfg := model.Defaults()
	cfg.Frontend.PublicIP = "not-an-address"
	if err := validate(&cfg); err == nil {
		t.Error("an unparseable public IP must be rejected")
	}
}

// The CIDR ends up inside a generated nftables rule, so it is parsed here
// rather than passed through. A malformed value would fail the whole ruleset
// load on the backend, taking its reply marking down with it - a bad network
// address would break published services, not just this feature.
func TestValidateRejectsAMalformedEgressNetwork(t *testing.T) {
	cfg := model.Defaults()
	cfg.Egress.Sources = []model.EgressSource{{Name: "gmod", CIDR: "172.18.0.0/nope", Enabled: true}}
	if err := validate(&cfg); err == nil {
		t.Error("an unparseable network must be rejected")
	}

	cfg.Egress.Sources = []model.EgressSource{{Name: "gmod", CIDR: "", Enabled: true}}
	if err := validate(&cfg); err == nil {
		t.Error("an empty network must be rejected")
	}

	// The ruleset is an `ip` table, so a v6 network would load as nonsense.
	cfg.Egress.Sources = []model.EgressSource{{Name: "gmod", CIDR: "fd00::/8", Enabled: true}}
	if err := validate(&cfg); err == nil {
		t.Error("an IPv6 network must be rejected while the table is ip-only")
	}
}

// Docker reports a container's network as the address plus prefix it was given,
// so an operator pasting that in gets 172.18.0.5/16. Normalising means the
// generated rule matches the network rather than one host of it.
func TestValidateNormalisesAnEgressNetwork(t *testing.T) {
	cfg := model.Defaults()
	cfg.Egress.Sources = []model.EgressSource{{Name: "gmod", CIDR: " 172.18.0.5/16 ", Enabled: true}}
	if err := validate(&cfg); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got := cfg.Egress.Sources[0].CIDR; got != "172.18.0.0/16" {
		t.Errorf("CIDR = %q, want it normalised to 172.18.0.0/16", got)
	}
}

// The new selection mode has to be opt-in. An older stored config has no
// selection field at all, and defaulting it to anything but priority would
// change the behaviour of a running system on upgrade.
func TestValidateDefaultsSelectionToPriority(t *testing.T) {
	cfg := model.Defaults()
	cfg.Failover.Selection = ""
	if err := validate(&cfg); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if cfg.Failover.Selection != model.SelectionPriority {
		t.Errorf("selection = %q, want it to default to priority", cfg.Failover.Selection)
	}
}

func TestValidateRejectsAnUnknownSelectionMode(t *testing.T) {
	cfg := model.Defaults()
	cfg.Failover.Selection = "fastest"
	if err := validate(&cfg); err == nil {
		t.Error("an unknown selection mode must be rejected")
	}
}

// A negative weight inverts the meaning of a measurement: the path losing the
// most packets would score best and win the traffic.
func TestValidateRejectsNegativeQualityWeights(t *testing.T) {
	cfg := model.Defaults()
	cfg.Failover.Quality.LossWeight = -1
	if err := validate(&cfg); err == nil {
		t.Error("a negative weight must be rejected")
	}
}

// At 100% nothing can ever beat anything, which looks like the feature being
// broken rather than being configured off. Above it the comparison inverts.
func TestValidateRejectsAnImpossibleMargin(t *testing.T) {
	cfg := model.Defaults()
	cfg.Failover.Quality.MarginPct = 100
	if err := validate(&cfg); err == nil {
		t.Error("a 100% margin must be rejected")
	}
}

// Quality selection with every weight at zero scores every path identically,
// so it would silently behave as priority order while claiming otherwise.
func TestValidateRejectsQualitySelectionWithNoWeights(t *testing.T) {
	cfg := model.Defaults()
	cfg.Failover.Selection = model.SelectionQuality
	cfg.Failover.Quality.LossWeight = 0
	cfg.Failover.Quality.RTTWeight = 0
	cfg.Failover.Quality.JitterWeight = 0
	if err := validate(&cfg); err == nil {
		t.Error("quality selection with no weights must be rejected")
	}
}

// A configuration stored before these fields existed unmarshals with all of
// them at zero, and Defaults() only ever applies to a first run. Without
// normalisation every existing deployment inherits zero weights - every path
// scores identically - while a fresh install gets the shipped values. This is
// what the portal showed as a form full of zeros.
func TestValidateFillsInQualitySettingsAnOlderConfigNeverHad(t *testing.T) {
	cfg := model.Defaults()
	cfg.Failover.Selection = ""
	cfg.Failover.Quality = model.QualityConfig{} // as an older config unmarshals

	if err := validate(&cfg); err != nil {
		t.Fatalf("validate: %v", err)
	}
	want := model.Defaults().Failover.Quality
	if cfg.Failover.Quality != want {
		t.Errorf("quality = %+v, want the shipped defaults %+v", cfg.Failover.Quality, want)
	}
	if cfg.Failover.Selection != model.SelectionPriority {
		t.Errorf("selection = %q, want priority", cfg.Failover.Selection)
	}
}

// Filling in a group wholesale must not overwrite a deliberate individual zero:
// no margin, or no dwell, are both things an operator may legitimately choose.
func TestValidateKeepsADeliberateZero(t *testing.T) {
	cfg := model.Defaults()
	cfg.Failover.Quality.MarginPct = 0
	cfg.Failover.Quality.MinDwellSec = 0

	if err := validate(&cfg); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if cfg.Failover.Quality.MarginPct != 0 || cfg.Failover.Quality.MinDwellSec != 0 {
		t.Errorf("a deliberate zero was overwritten: %+v", cfg.Failover.Quality)
	}
}

// A path may not take any mark this system already uses, not merely the
// control channel's.
//
// The one that mattered was the backend's return mark. Its rule selects the
// same packets as the path rule and sits ahead of the probe band, so it wins:
// that path's probe replies leave by whichever tunnel is currently active
// rather than by the one their request arrived on. The standby still gets
// replies and still reads healthy, while what it is actually measuring is a
// round trip over two tunnels - so a link that is dead in the return direction
// tests as perfect, and the failover has nothing to fall back to on the day it
// is needed. Every one of these was reachable from the settings form.
func TestPathsCannotTakeAReservedFwmark(t *testing.T) {
	for _, reserved := range []int{
		sysx.ControlMark,
		sysx.ReturnMark,
		sysx.EgressMark,
		sysx.LinkerReturnMark,
		sysx.LinkerEgressMark,
	} {
		cfg := model.Defaults()
		cfg.Paths[1].Mark = reserved
		if err := validate(&cfg); err == nil {
			t.Errorf("fwmark %#x was accepted for a path; it is reserved elsewhere in the system", reserved)
		}
	}

	// And the shipped marks must still be fine, or this check has gone too far.
	cfg := model.Defaults()
	if err := validate(&cfg); err != nil {
		t.Errorf("the shipped configuration no longer validates: %v", err)
	}
}

// A service name is rendered into the generated ruleset as an nftables comment,
// on the DNAT rule and on the protection ceiling beside it. nft rejects the
// whole table over one bad comment, so an unbounded name is not a cosmetic
// problem: the load fails, the previously installed rules stay live, and the
// save reports success while nothing new has reached the kernel.
func TestValidateRejectsAServiceNameNftablesCannotCarry(t *testing.T) {
	cases := map[string]string{
		"a quote ends the comment early":       `gmod "main"`,
		"a backslash starts an escape":         `gmod\main`,
		"a newline is a second rule":           "gmod\ncounter drop",
		"a control character is not printable": "gmod\x01",
		"too long for the kernel's bound":      strings.Repeat("g", maxServiceName+1),
	}
	for why, name := range cases {
		cfg := model.Defaults()
		cfg.Services[0].Name = name
		if err := validate(&cfg); err == nil {
			t.Errorf("%s: %q should have been rejected", why, name)
		}
	}
}

// Ordinary names keep working, and are trimmed the way every other free-text
// field here is.
func TestValidateAcceptsAndTrimsAnOrdinaryServiceName(t *testing.T) {
	cfg := model.Defaults()
	cfg.Services[0].Name = "  gmod: main server (27015)  "
	if err := validate(&cfg); err != nil {
		t.Fatalf("an ordinary name must validate: %v", err)
	}
	if cfg.Services[0].Name != "gmod: main server (27015)" {
		t.Errorf("name = %q, want it trimmed", cfg.Services[0].Name)
	}
}

// Every detection preset has to come out of the portal's own validation
// clean, on the shipped configuration and on one whose standby interval has
// been tuned down below the slowest preset's active interval. The bounds are
// asserted here by running validate, not by copying its numbers: a copy would
// keep passing after the real rule moved, and the first anybody heard would be
// a preset the dropdown offers that Save refuses.
func TestEveryDetectionPresetSurvivesValidate(t *testing.T) {
	for _, d := range model.DetectionPresets() {
		cfg := model.Defaults()
		d.Apply(&cfg.Probe)
		if err := validate(&cfg); err != nil {
			t.Errorf("preset %s on the shipped config does not validate: %v", d.Name, err)
		}

		short := model.Defaults()
		short.Probe.StandbyIntervalMs = short.Probe.ActiveIntervalMs
		d.Apply(&short.Probe)
		if err := validate(&short); err != nil {
			t.Errorf("preset %s on a site with a short standby interval does not validate: %v", d.Name, err)
		}
	}
}

// A DNAT rule with no interface to scope it to matches its port on every
// interface the frontend has, the admin tunnel included - and that is the
// tunnel the portal is reached over. A row naming the portal's own port would
// hand the operator's portal connections to the backend and remove the only
// way to undo that. Enabling a service therefore needs a public interface.
func TestValidateRejectsPublishingWithoutAPublicInterface(t *testing.T) {
	cfg := model.Defaults()
	cfg.Frontend.PublicIface = ""
	if err := validate(&cfg); err != nil {
		t.Fatalf("nothing is published, so no interface is needed yet: %v", err)
	}
	cfg.Services[0].Enabled = true
	if err := validate(&cfg); err == nil {
		t.Fatal("a published service with no public interface must be refused")
	}
}

// Both rule priorities a path owns are derived from its id, so the id has a
// ceiling: at 100 the lookup lands on the egress rule's priority, and a large
// one carries the refusal past the source rules, where a probe would be routed
// by the return table before it was refused.
func TestValidateBoundsPathIDs(t *testing.T) {
	cfg := model.Defaults()
	cfg.Paths[0].ID = sysx.ProbeDenyBandSize
	if err := validate(&cfg); err == nil {
		t.Fatalf("path id %d must be refused", sysx.ProbeDenyBandSize)
	}
	cfg.Paths[0].ID = sysx.ProbeDenyBandSize - 1
	if err := validate(&cfg); err != nil {
		t.Fatalf("path id %d is inside the band and must be accepted: %v", sysx.ProbeDenyBandSize-1, err)
	}
}
