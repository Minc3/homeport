package sysx

import (
	"context"
	"strings"
	"testing"
)

// chainRunner answers the DOCKER-USER listing and records what is done to it.
type chainRunner struct {
	listing string
	calls   []string
}

func (c *chainRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	line := name + " " + strings.Join(args, " ")
	c.calls = append(c.calls, line)
	if strings.Contains(line, "list chain") {
		return c.listing, nil
	}
	return "", nil
}
func (c *chainRunner) Applying() bool { return true }

func (c *chainRunner) did(substr string) int {
	n := 0
	for _, l := range c.calls {
		if strings.Contains(l, substr) {
			n++
		}
	}
	return n
}

// The rule was written once and then never revisited, because the check was
// "is my comment present" rather than "is my prefix right". Setting
// overlay.subnet afterwards widened the route and the egress NAT and left this
// accept pinned to the backend's /32 - so a service published to a linker was
// DNAT'd correctly and then dropped by the forward policy on the way out, which
// presents as a timeout and reads as the far host being down.
func TestForwardExceptionWidensWhenTheOverlaySubnetIsSet(t *testing.T) {
	r := &chainRunner{listing: `table ip filter {
	chain DOCKER-USER {
		ct state established,related accept comment "failover" # handle 4
		ip daddr 10.99.0.2 accept comment "failover" # handle 5
	}
}`}

	if err := EnsureForwardExceptions(context.Background(), r, "10.99.0.0/24"); err != nil {
		t.Fatalf("ensure: %v", err)
	}

	if r.did("delete rule ip filter DOCKER-USER handle 5") != 1 {
		t.Errorf("the stale /32 rule was not removed; calls were %v", r.calls)
	}
	if r.did("insert rule ip filter DOCKER-USER ip daddr 10.99.0.0/24 accept") != 1 {
		t.Errorf("the widened rule was not inserted; calls were %v", r.calls)
	}
	// The state rule carries no prefix and must survive untouched.
	if r.did("delete rule ip filter DOCKER-USER handle 4") != 0 {
		t.Errorf("the connection-state rule was removed; calls were %v", r.calls)
	}
}

// The common case by far, and it must stay silent: a chain already carrying the
// right rules is left completely alone, or every reapply churns the packet
// filter of a host that is serving traffic.
func TestForwardExceptionLeavesACorrectChainAlone(t *testing.T) {
	r := &chainRunner{listing: `table ip filter {
	chain DOCKER-USER {
		ct state established,related accept comment "failover" # handle 4
		ip daddr 10.99.0.2 accept comment "failover" # handle 5
	}
}`}

	if err := EnsureForwardExceptions(context.Background(), r, "10.99.0.2"); err != nil {
		t.Fatalf("ensure: %v", err)
	}

	if n := r.did("insert rule"); n != 0 {
		t.Errorf("inserted %d rules into an already-correct chain; calls were %v", n, r.calls)
	}
	if n := r.did("delete rule"); n != 0 {
		t.Errorf("deleted %d rules from an already-correct chain; calls were %v", n, r.calls)
	}
}

// A first install still installs both.
func TestForwardExceptionInstallsIntoAnEmptyChain(t *testing.T) {
	r := &chainRunner{listing: `table ip filter {
	chain DOCKER-USER {
	}
}`}

	if err := EnsureForwardExceptions(context.Background(), r, "10.99.0.2"); err != nil {
		t.Fatalf("ensure: %v", err)
	}

	if r.did("ip daddr 10.99.0.2 accept") != 1 {
		t.Errorf("destination rule missing; calls were %v", r.calls)
	}
	if r.did("ct state established,related accept") != 1 {
		t.Errorf("state rule missing; calls were %v", r.calls)
	}
}

// Operators keep their own rules in DOCKER-USER. Ours are found by comment and
// deleted by handle precisely so theirs are never touched.
func TestForwardExceptionNeverTouchesRulesItDoesNotOwn(t *testing.T) {
	r := &chainRunner{listing: `table ip filter {
	chain DOCKER-USER {
		ip saddr 10.99.0.2 accept # handle 2
		ip daddr 10.99.0.2 accept comment "failover" # handle 5
	}
}`}

	if err := EnsureForwardExceptions(context.Background(), r, "10.99.0.0/24"); err != nil {
		t.Fatalf("ensure: %v", err)
	}

	if r.did("handle 2") != 0 {
		t.Errorf("touched a rule with no comment of ours; calls were %v", r.calls)
	}
}

// "failover" is a prefix of "failover_egress", so a loose match would have the
// two exceptions delete each other.
func TestForwardExceptionDoesNotDisturbTheEgressException(t *testing.T) {
	r := &chainRunner{listing: `table ip filter {
	chain DOCKER-USER {
		ip saddr 10.99.0.2 accept comment "failover_egress" # handle 3
		ip daddr 10.99.0.2 accept comment "failover" # handle 5
	}
}`}

	if err := EnsureForwardExceptions(context.Background(), r, "10.99.0.0/24"); err != nil {
		t.Fatalf("ensure: %v", err)
	}

	if r.did("handle 3") != 0 {
		t.Errorf("the egress exception was removed by the published one; calls were %v", r.calls)
	}
}

// The egress side has the same defect and the same fix: widening the overlay
// has to widen what may leave by it, or a linker's outbound traffic is dropped
// where the backend's is allowed.
func TestEgressForwardExceptionWidensToo(t *testing.T) {
	r := &chainRunner{listing: `table ip filter {
	chain DOCKER-USER {
		ip saddr 10.99.0.2 accept comment "failover_egress" # handle 3
	}
}`}

	if err := EnsureEgressForwardException(context.Background(), r, "10.99.0.0/24"); err != nil {
		t.Fatalf("ensure: %v", err)
	}

	if r.did("delete rule ip filter DOCKER-USER handle 3") != 1 {
		t.Errorf("stale egress rule not removed; calls were %v", r.calls)
	}
	if r.did("insert rule ip filter DOCKER-USER ip saddr 10.99.0.0/24 accept") != 1 {
		t.Errorf("widened egress rule not inserted; calls were %v", r.calls)
	}
}
