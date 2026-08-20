package sysx

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Counters is a raw snapshot of one interface's kernel statistics.
//
// Packets matter as much as bytes: the carrier meters the encapsulated
// datagram on the WAN, not the inner payload, so usage has to be reconstructed
// as bytes + packets * per-packet overhead.
type Counters struct {
	RxBytes   int64
	TxBytes   int64
	RxPackets int64
	TxPackets int64
}

// Bytes is the total inner payload in both directions.
func (c Counters) Bytes() int64 { return c.RxBytes + c.TxBytes }

// Packets is the total packet count in both directions.
func (c Counters) Packets() int64 { return c.RxPackets + c.TxPackets }

// ReadCounters reads an interface's statistics from sysfs.
func ReadCounters(iface string) (Counters, error) {
	base := filepath.Join("/sys/class/net", iface, "statistics")
	read := func(name string) (int64, error) {
		b, err := os.ReadFile(filepath.Join(base, name))
		if err != nil {
			return 0, err
		}
		return strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	}
	var c Counters
	var err error
	if c.RxBytes, err = read("rx_bytes"); err != nil {
		return c, fmt.Errorf("read counters for %s: %w", iface, err)
	}
	if c.TxBytes, err = read("tx_bytes"); err != nil {
		return c, fmt.Errorf("read counters for %s: %w", iface, err)
	}
	if c.RxPackets, err = read("rx_packets"); err != nil {
		return c, fmt.Errorf("read counters for %s: %w", iface, err)
	}
	if c.TxPackets, err = read("tx_packets"); err != nil {
		return c, fmt.Errorf("read counters for %s: %w", iface, err)
	}
	return c, nil
}

// IfaceExists reports whether an interface is present.
func IfaceExists(iface string) bool {
	_, err := os.Stat(filepath.Join("/sys/class/net", iface))
	return err == nil
}

// PeerEndpoints returns the address each tunnel's peer is currently seen at,
// keyed by interface.
//
// Read on the frontend, where it is a real diagnostic: the frontend configures
// no Endpoint at all - the backend is behind CGNAT and dials out - so what
// WireGuard reports here is the address the backend's packets were observed
// arriving from, which is the public address of whichever service that tunnel
// actually rode.
//
// That makes it the one direct check on the thing this system cannot verify for
// itself. pfSense is supposed to pin each tunnel to its own WAN; if it does not
// - a gateway group instead of a gateway, or gateway monitoring pulling a
// policy route and letting the traffic fall through to the default - two
// tunnels ride one link. Every probe still succeeds, all three paths read
// healthy, and there is no failover to be had because there is only one link.
// Two paths reporting the same public address is that fault, visible.
//
// Reading it on the backend would be useless: there the endpoint is the
// frontend's public address, which is the same for all three by design.
func PeerEndpoints(ctx context.Context, r Runner) map[string]string {
	out, err := r.Run(ctx, "wg", "show", "all", "endpoints")
	if err != nil {
		return map[string]string{}
	}
	ends := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		endpoint := f[len(f)-1]
		// Before the first handshake there is nothing to report. wg prints
		// "(none)"; an empty string is what the portal renders as unknown.
		if endpoint == "(none)" {
			continue
		}
		// Several peers on one interface is not a configuration this system
		// uses, and picking one arbitrarily would make the comparison between
		// paths meaningless. Report nothing rather than something misleading.
		if _, seen := ends[f[0]]; seen {
			ends[f[0]] = ""
			continue
		}
		ends[f[0]] = endpoint
	}
	for iface, e := range ends {
		if e == "" {
			delete(ends, iface)
		}
	}
	return ends
}

// EndpointHost strips the port from an endpoint, leaving the address.
//
// The port is noise for the comparison that matters: it is whatever source port
// the carrier's NAT happened to assign, and it differs between two tunnels that
// are riding the same WAN - which is precisely the case that has to be caught.
func EndpointHost(endpoint string) string {
	if endpoint == "" {
		return ""
	}
	// IPv6 literals are bracketed; the overlay is v4 but the parse should not
	// produce nonsense if one ever appears.
	if i := strings.LastIndex(endpoint, "]:"); i >= 0 {
		return strings.TrimPrefix(endpoint[:i], "[")
	}
	if i := strings.LastIndex(endpoint, ":"); i >= 0 {
		return endpoint[:i]
	}
	return endpoint
}

// HandshakeAges returns the age of the most recent WireGuard handshake per
// interface.
//
// This is a corroborating signal for the portal only. It is never the basis of
// a routing decision: a WireGuard interface stays technically up long after
// the link underneath it has failed, which is precisely the failure mode the
// end-to-end probes exist to catch.
func HandshakeAges(ctx context.Context, r Runner) map[string]float64 {
	ages := map[string]float64{}
	out, err := r.Run(ctx, "wg", "show", "all", "latest-handshakes")
	if err != nil {
		return ages
	}
	now := time.Now().Unix()
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		ts, err := strconv.ParseInt(f[len(f)-1], 10, 64)
		if err != nil || ts == 0 {
			continue
		}
		iface := f[0]
		age := float64(now - ts)
		// Several peers on one interface: keep the freshest.
		if prev, ok := ages[iface]; !ok || age < prev {
			ages[iface] = age
		}
	}
	return ages
}
