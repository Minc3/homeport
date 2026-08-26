package model

import "testing"

func qcCfg() Config {
	cfg := Defaults()
	cfg.QueryCache.Enabled = true
	cfg.Services = []Service{
		{Name: "gmod", Proto: "udp", Port: 27015, PortEnd: 27018, Enabled: true, SourceEngine: true},
	}
	return cfg
}

// The enumeration is the single source of truth for both the nftables
// redirects and the responder sockets, so what it excludes matters as much
// as what it includes: a port redirected with no socket behind it answers
// nothing, and a socket with no redirect wastes a bind. Everything that is
// not an enabled, Source-ticked UDP service must produce nothing.
func TestQueryCachePortsEnumeratesOnlyOptedInUDPServices(t *testing.T) {
	if got := QueryCachePorts(Defaults()); got != nil {
		t.Errorf("the shipped config enumerates %v; the cache is off and nothing opted in", got)
	}

	cfg := qcCfg()
	cfg.QueryCache.Enabled = false
	if got := QueryCachePorts(cfg); got != nil {
		t.Errorf("cache disabled still enumerates %v", got)
	}

	cfg = qcCfg()
	spans := QueryCachePorts(cfg)
	if len(spans) != 1 || spans[0].From != 27015 || spans[0].To != 27018 {
		t.Fatalf("spans = %+v, want one 27015-27018", spans)
	}
	if spans[0].Target != cfg.Overlay.BackendIP {
		t.Errorf("target = %q, want the backend %q by default", spans[0].Target, cfg.Overlay.BackendIP)
	}

	for _, breakIt := range []struct {
		what string
		mut  func(*Service)
	}{
		{"a disabled service", func(s *Service) { s.Enabled = false }},
		{"a service not ticked Source engine", func(s *Service) { s.SourceEngine = false }},
		{"a TCP service", func(s *Service) { s.Proto = "tcp" }},
	} {
		cfg := qcCfg()
		breakIt.mut(&cfg.Services[0])
		if got := QueryCachePorts(cfg); got != nil {
			t.Errorf("%s still enumerates %v", breakIt.what, got)
		}
	}
}

// A service targeting a linker refreshes from that linker, because that is
// the host really answering: refreshing the backend for a port DNAT'd past
// it would cache the wrong server's answers, or nothing.
func TestQueryCachePortsHonourTheServiceTarget(t *testing.T) {
	cfg := qcCfg()
	cfg.Services[0].Target = "10.99.0.3"
	spans := QueryCachePorts(cfg)
	if len(spans) != 1 || spans[0].Target != "10.99.0.3" {
		t.Fatalf("spans = %+v, want the linker's address", spans)
	}
}

// Two services covering the same port must produce it once. The port is a
// socket, and the second bind of a duplicated enumeration would fail against
// the first and report a phantom conflict.
func TestQueryCachePortsDeduplicateAcrossServices(t *testing.T) {
	cfg := qcCfg()
	cfg.Services = append(cfg.Services,
		Service{Name: "overlap", Proto: "udp", Port: 27017, PortEnd: 27020, Enabled: true, SourceEngine: true})
	total := 0
	seen := map[int]bool{}
	for _, sp := range QueryCachePorts(cfg) {
		for p := sp.From; p <= sp.To; p++ {
			if seen[p] {
				t.Fatalf("port %d enumerated twice", p)
			}
			seen[p] = true
			total++
		}
	}
	if total != 6 {
		t.Errorf("enumerated %d ports, want the 6 distinct ones", total)
	}
}

// The cap holds, because each port is a bound socket and a refresh stream
// and a range typo of 27015-65535 must not become forty thousand of each.
// The uncapped remainder is simply not enumerated, which the generator turns
// into "not redirected": those queries still reach the real server, degraded
// rather than blackholed.
func TestQueryCachePortsAreCapped(t *testing.T) {
	cfg := qcCfg()
	cfg.Services[0].PortEnd = 27015 + 10*MaxQueryCachePorts
	total := 0
	for _, sp := range QueryCachePorts(cfg) {
		total += sp.To - sp.From + 1
	}
	if total != MaxQueryCachePorts {
		t.Errorf("enumerated %d ports, want the cap of %d", total, MaxQueryCachePorts)
	}
}
