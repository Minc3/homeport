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

// 253, 254 and 255 are default, main and local. The agent writes a default
// route into whichever table it is given and the reconciler puts it back ten
// seconds after anybody removes it, so a typo here redirects the whole host to
// the backend and cannot be undone without stopping the unit. The portal
// applies the same bound, and cannot help: this file is where the value has to
// be typed, because the rule it names is what carries the control channel.
func TestLinkerBootstrapRejectsAKernelRoutingTable(t *testing.T) {
	body := func(table string) string {
		return `{"role":"linker","psk":"x","linker":{"overlay_ip":"10.99.0.3",` +
			`"backend_lan":"192.168.1.2","table":` + table + `}}`
	}
	for name, table := range map[string]string{
		"default":  "253",
		"main":     "254",
		"local":    "255",
		"beyond":   "1000",
		"negative": "-1",
	} {
		p := filepath.Join(t.TempDir(), "linker.json")
		if err := os.WriteFile(p, []byte(body(table)), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := model.LoadBootstrap(p); err == nil {
			t.Errorf("table %s (%s) should have been rejected", table, name)
		}
	}
}

// Zero has to stay legal: it is what the portal writes when the column is left
// blank, and TableOr resolves it to the shipped default. Refusing it would
// reject the generated file.
func TestLinkerBootstrapAcceptsAnOmittedTable(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"omitted": `{"role":"linker","psk":"x","linker":{"overlay_ip":"10.99.0.3","backend_lan":"192.168.1.2"}}`,
		"zero":    `{"role":"linker","psk":"x","linker":{"overlay_ip":"10.99.0.3","backend_lan":"192.168.1.2","table":0}}`,
		"chosen":  `{"role":"linker","psk":"x","linker":{"overlay_ip":"10.99.0.3","backend_lan":"192.168.1.2","table":220}}`,
	} {
		p := filepath.Join(dir, name+".json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := model.LoadBootstrap(p); err != nil {
			t.Errorf("%s: should load, got %v", name, err)
		}
	}
}
