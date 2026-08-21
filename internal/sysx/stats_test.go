package sysx

import (
	"context"
	"testing"
)

// What the portal shows on each path card, and the input to the check for two
// tunnels riding one service. The frontend configures no endpoint at all, so
// what wg reports here is where the backend's packets were observed coming
// from - the public address of the WAN that tunnel actually used.
func TestPeerEndpointsAreReadPerInterface(t *testing.T) {
	f := &shapeRunner{replies: map[string]string{
		"wg show all endpoints": "wg-main\tkeyA=\t203.0.113.10:51820\n" +
			"wg-lte1\tkeyB=\t198.51.100.20:41234\n" +
			"wg-lte2\tkeyC=\t198.51.100.99:52001",
	}}

	got := PeerEndpoints(context.Background(), f)
	for iface, want := range map[string]string{
		"wg-main": "203.0.113.10:51820",
		"wg-lte1": "198.51.100.20:41234",
		"wg-lte2": "198.51.100.99:52001",
	} {
		if got[iface] != want {
			t.Errorf("%s read as %q, want %q", iface, got[iface], want)
		}
	}
}

// Before the first handshake there is nothing to report, and reporting nothing
// is what the portal renders as "not known yet". A literal "(none)" shown as an
// address would be worse than a blank.
func TestATunnelWithNoHandshakeReportsNoEndpoint(t *testing.T) {
	f := &shapeRunner{replies: map[string]string{
		"wg show all endpoints": "wg-main\tkeyA=\t203.0.113.10:51820\n" +
			"wg-lte2\tkeyC=\t(none)",
	}}

	got := PeerEndpoints(context.Background(), f)
	if _, ok := got["wg-lte2"]; ok {
		t.Errorf("a tunnel with no handshake reported %q", got["wg-lte2"])
	}
	if got["wg-main"] == "" {
		t.Error("the tunnel that does have a handshake was dropped too")
	}
}

// Several peers on one interface is not a configuration this system uses, and
// picking one of them arbitrarily would make the comparison between paths mean
// nothing - the whole point is that two paths showing one address is a fault.
func TestAnInterfaceWithSeveralPeersReportsNothing(t *testing.T) {
	f := &shapeRunner{replies: map[string]string{
		"wg show all endpoints": "wg-main\tkeyA=\t203.0.113.10:51820\n" +
			"wg-main\tkeyB=\t203.0.113.55:51820",
	}}

	if got := PeerEndpoints(context.Background(), f); len(got) != 0 {
		t.Errorf("reported %v for an interface with two peers", got)
	}
}

// The comparison is on the address alone. Two tunnels riding one WAN arrive
// from the same address on different source ports - the carrier's NAT assigns
// those - so comparing the whole endpoint would miss exactly the case this
// exists to catch.
func TestTheEndpointPortIsNotPartOfTheComparison(t *testing.T) {
	for _, tc := range []struct{ endpoint, want string }{
		{"203.0.113.10:51820", "203.0.113.10"},
		{"198.51.100.20:41234", "198.51.100.20"},
		{"[2001:db8::1]:51820", "2001:db8::1"},
		{"", ""},
	} {
		if got := EndpointHost(tc.endpoint); got != tc.want {
			t.Errorf("EndpointHost(%q) = %q, want %q", tc.endpoint, got, tc.want)
		}
	}
}
