package sysx

import (
	"context"
	"strings"
	"testing"
)

// shapeRunner records what was run and answers readbacks from a script.
type shapeRunner struct {
	calls   []string
	replies map[string]string
	fail    map[string]bool
}

func (f *shapeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	cmd := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, cmd)
	for k, v := range f.replies {
		if strings.HasPrefix(cmd, k) {
			return v, nil
		}
	}
	if f.fail[cmd] {
		return "", context.DeadlineExceeded
	}
	return "", nil
}

func (f *shapeRunner) Applying() bool { return true }

func (f *shapeRunner) ran(substr string) bool {
	for _, c := range f.calls {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

// An unshaped path must issue no tc command beyond the readback, on any host.
// This is the guarantee that turning nothing on changes nothing.
func TestAnUnshapedPathInstallsNothing(t *testing.T) {
	f := &shapeRunner{replies: map[string]string{
		"tc qdisc show": "qdisc noqueue 0: root refcnt 2",
	}}
	changed, err := EnsureQdisc(context.Background(), f, "wg-nbn", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed {
		t.Error("reported a change on a path that is not shaped")
	}
	if f.ran("tc qdisc replace") || f.ran("tc qdisc del") {
		t.Errorf("touched the interface anyway: %v", f.calls)
	}
}

// The rate has to reach the kernel as the operator entered it, with the
// encapsulation overhead accounted for - the shaper counts the payload it is
// handed, the carrier bills what leaves the WAN.
func TestShapingInstallsTheConfiguredRate(t *testing.T) {
	f := &shapeRunner{replies: map[string]string{
		"tc qdisc show": "qdisc noqueue 0: root refcnt 2",
	}}
	if _, err := EnsureQdisc(context.Background(), f, "wg-lte1", 18); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !f.ran("tc qdisc replace dev wg-lte1 root cake bandwidth 18mbit overhead 80") {
		t.Errorf("did not install the rate as configured: %v", f.calls)
	}
}

// A shaper that is already correct must be left alone. Replacing it every ten
// seconds would throw away the queue's state - which is the very thing doing
// the work - and hide the one log line that matters when it really was lost.
func TestAnIntactShaperIsLeftAlone(t *testing.T) {
	f := &shapeRunner{replies: map[string]string{
		"tc qdisc show": "qdisc cake 8003: root refcnt 2 bandwidth 18Mbit besteffort triple-isolate " +
			"nonat nowash no-ack-filter split-gso rtt 100ms noatm overhead 80",
	}}
	changed, err := EnsureQdisc(context.Background(), f, "wg-lte1", 18)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed {
		t.Error("reported a change when the shaper was already right")
	}
	if f.ran("tc qdisc replace") {
		t.Errorf("reinstalled a correct shaper: %v", f.calls)
	}
}

// What a tunnel restart leaves behind. `wg-quick down` deletes the interface
// and the queue discipline goes with it; the new one comes back with the
// kernel's default and nothing says so.
func TestAShaperLostWithTheInterfaceIsRestored(t *testing.T) {
	f := &shapeRunner{replies: map[string]string{
		"tc qdisc show": "qdisc noqueue 0: root refcnt 2",
	}}
	changed, err := EnsureQdisc(context.Background(), f, "wg-nbn", 40)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Error("did not report restoring the shaper")
	}
	if !f.ran("tc qdisc replace dev wg-nbn root cake bandwidth 40mbit") {
		t.Errorf("did not reinstall the shaper: %v", f.calls)
	}
}

// Turning shaping off in the portal has to take the shaper off the interface.
// A rate that is simply no longer applied would leave the last one running,
// with nothing in the configuration to explain why the link is capped.
func TestClearingTheRateRemovesTheShaper(t *testing.T) {
	f := &shapeRunner{replies: map[string]string{
		"tc qdisc show": "qdisc cake 8003: root refcnt 2 bandwidth 18Mbit besteffort",
	}}
	changed, err := EnsureQdisc(context.Background(), f, "wg-lte1", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed || !f.ran("tc qdisc del dev wg-lte1 root") {
		t.Errorf("did not remove the shaper: changed=%v calls=%v", changed, f.calls)
	}
}

// Somebody else's queue discipline is somebody else's. The agent reports what
// it found and leaves it, the same way the linker refuses to write a routing
// table it was not given.
func TestAForeignQdiscIsNotRemoved(t *testing.T) {
	f := &shapeRunner{replies: map[string]string{
		"tc qdisc show": "qdisc htb 1: root refcnt 2 r2q 10 default 0x10",
	}}
	changed, err := EnsureQdisc(context.Background(), f, "wg-nbn", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed || f.ran("tc qdisc del") {
		t.Errorf("removed a queue discipline this agent did not install: %v", f.calls)
	}
}

// tc prints back the units it chose, not the ones it was given.
func TestRatesAreReadBackInWhateverUnitsTCPrints(t *testing.T) {
	for _, tc := range []struct {
		printed string
		want    float64
	}{
		{"18Mbit", 18},
		{"2500Kbit", 2.5},
		{"1Gbit", 1000},
		{"unlimited", 0},
	} {
		if got := parseRate(tc.printed); !sameRate(got, tc.want) {
			t.Errorf("%s read back as %v, want %v", tc.printed, got, tc.want)
		}
	}
}
