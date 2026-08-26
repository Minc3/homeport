package model

import (
	"reflect"
	"testing"
)

// A fresh install must not move or divert a single packet on the strength of
// nobody having deleted a shipped example row. The services are DNAT rules and
// the egress source pulls a whole Docker bridge onto the tunnel, and through
// the metered quota; both are examples of what to fill in, not requests.
func TestNothingInTheShippedConfigurationIsLive(t *testing.T) {
	cfg := Defaults()

	if cfg.Mode != ModeObserve {
		t.Errorf("mode = %q, want %q", cfg.Mode, ModeObserve)
	}
	for _, s := range cfg.Services {
		if s.Enabled {
			t.Errorf("service %s ships enabled", s.Name)
		}
	}
	if cfg.Frontend.BackendEgress {
		t.Error("backend egress ships on, which would send the row below out the tunnel")
	}
	if cfg.QueryCache.Enabled {
		t.Error("the query cache ships on, which would bind service ports and answer for servers nobody opted in")
	}
	for _, s := range cfg.Egress.Sources {
		if s.Enabled {
			t.Errorf("egress source %s (%s) ships enabled", s.Name, s.CIDR)
		}
	}
}

// The Pterodactyl bridge is the one network almost every site here ends up
// adding by hand, so it ships as a row to tick rather than a CIDR to look up.
func TestTheShippedEgressRowIsThePterodactylBridge(t *testing.T) {
	srcs := Defaults().Egress.Sources
	if len(srcs) != 1 {
		t.Fatalf("egress sources = %d, want the one example row", len(srcs))
	}
	if srcs[0].Name != "pterodactyl" || srcs[0].CIDR != "172.18.0.0/16" {
		t.Errorf("row = %+v, want pterodactyl on 172.18.0.0/16", srcs[0])
	}
	// Empty Host means the backend, which is where a single-host site runs it.
	if srcs[0].Host != "" {
		t.Errorf("host = %q, want empty so it belongs to the backend", srcs[0].Host)
	}
}

// The shipped services are the shape of the deployment this was built for, so
// a fresh portal shows the rows to tick rather than a list to type. Every one
// ships disabled - the test above holds that - and the Source row is a range,
// one rule for every server a panel spawns.
func TestTheShippedServicesAreThisDeploymentsPorts(t *testing.T) {
	want := []Service{
		{Name: "http", Proto: "tcp", Port: 80},
		{Name: "https", Proto: "tcp", Port: 443},
		{Name: "pterodactyl-sftp", Proto: "tcp", Port: 2022},
		{Name: "pterodactyl-wings", Proto: "tcp", Port: 8080},
		{Name: "source", Proto: "udp", Port: 27015, PortEnd: 27030},
		{Name: "minecraft", Proto: "tcp", Port: 25565},
	}
	got := Defaults().Services
	if len(got) != len(want) {
		t.Fatalf("services = %d rows, want %d", len(got), len(want))
	}
	// DeepEqual because Service carries slices now (the region locks), which
	// == cannot compare. It also holds that no shipped row carries a lock:
	// want lists none, and a mismatch here would say so.
	for i := range want {
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Errorf("service %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}
