package model_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/quinlan102/homeport/internal/model"
)

func TestLinkerExampleLoads(t *testing.T) {
	b, err := model.LoadBootstrap("../../deploy/linker.json.example")
	if err != nil {
		t.Fatalf("linker example must load: %v", err)
	}
	if b.Role != model.RoleLinker || b.Linker.OverlayIP != "10.99.0.3" || b.Linker.BackendLAN != "192.168.1.2" {
		t.Fatalf("unexpected linker bootstrap: %+v", b)
	}
}

// A linker missing either field would start, install a rule for an address it
// does not hold, and look perfectly healthy. Refuse instead.
func TestLinkerBootstrapRejectsMissingFields(t *testing.T) {
	cases := map[string]string{
		"no overlay_ip":     `{"role":"linker","psk":"x","linker":{"backend_lan":"192.168.1.2"}}`,
		"no backend_lan":    `{"role":"linker","psk":"x","linker":{"overlay_ip":"10.99.0.3"}}`,
		"clashes with back": `{"role":"linker","psk":"x","linker":{"overlay_ip":"10.99.0.2","backend_lan":"192.168.1.2"}}`,
	}
	for name, body := range cases {
		p := filepath.Join(t.TempDir(), "linker.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := model.LoadBootstrap(p); err == nil {
			t.Errorf("%s: should have been rejected", name)
		}
	}
}

// The checks are scoped to the linker role: a frontend or backend config has no
// linker section and must keep loading exactly as before.
func TestFrontendBootstrapIsUnaffectedByLinkerChecks(t *testing.T) {
	p := filepath.Join(t.TempDir(), "frontend.json")
	if err := os.WriteFile(p, []byte(`{"role":"frontend","psk":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := model.LoadBootstrap(p); err != nil {
		t.Fatalf("a frontend config must still load: %v", err)
	}
}

// public_iface is a frontend-only seed for the first start. It is optional, and
// LoadBootstrap must neither require it nor invent one: an absent value means
// the shipped default stands.
func TestPublicIfaceIsOptionalAndCarriedThrough(t *testing.T) {
	dir := t.TempDir()

	with := filepath.Join(dir, "with.json")
	if err := os.WriteFile(with, []byte(`{"role":"frontend","psk":"x","public_iface":"ens3"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := model.LoadBootstrap(with)
	if err != nil {
		t.Fatal(err)
	}
	if b.PublicIface != "ens3" {
		t.Fatalf("public_iface = %q, want ens3", b.PublicIface)
	}

	without := filepath.Join(dir, "without.json")
	if err := os.WriteFile(without, []byte(`{"role":"frontend","psk":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err = model.LoadBootstrap(without)
	if err != nil {
		t.Fatal(err)
	}
	if b.PublicIface != "" {
		t.Fatalf("public_iface = %q, want empty so the portal default stands", b.PublicIface)
	}
}
