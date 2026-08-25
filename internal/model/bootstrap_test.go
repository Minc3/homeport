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

// An address that is present but is not an address is refused here, because
// nothing downstream refuses it loudly.
//
// Both fields end up in generated nftables rules, and the generators answer an
// address they cannot parse by rendering nothing at all. An empty ruleset is a
// zero-byte file that `nft -f` loads without complaint, so a typo bought a
// linker that started, logged its egress networks as installed, and had no
// table. This file is the one moment somebody is looking at the value.
func TestLinkerBootstrapRejectsAnAddressThatIsNotOne(t *testing.T) {
	cases := map[string]string{
		"overlay_ip is a hostname":  `{"role":"linker","psk":"x","linker":{"overlay_ip":"gs1.local","backend_lan":"192.168.1.2"}}`,
		"overlay_ip has a typo":     `{"role":"linker","psk":"x","linker":{"overlay_ip":"10.99.0.300","backend_lan":"192.168.1.2"}}`,
		"overlay_ip is a network":   `{"role":"linker","psk":"x","linker":{"overlay_ip":"10.99.0.3/24","backend_lan":"192.168.1.2"}}`,
		"backend_lan is a hostname": `{"role":"linker","psk":"x","linker":{"overlay_ip":"10.99.0.3","backend_lan":"backend"}}`,
		"backend_lan has a typo":    `{"role":"linker","psk":"x","linker":{"overlay_ip":"10.99.0.3","backend_lan":"192.168.1."}}`,
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

// The overlay addresses are checked on every role, not just a linker's.
//
// They go into `ip` commands and into generated nftables rules on all three
// agents, and a generator handed an address it cannot parse renders nothing at
// all - which loads as an empty file and installs nothing. Absent is fine and
// takes the default; present and unparseable is a typo, and this file is where
// it was typed.
func TestBootstrapRejectsAnOverlayAddressThatIsNotOne(t *testing.T) {
	cases := map[string]string{
		"frontend_ip typo": `{"role":"frontend","psk":"x","overlay":{"frontend_ip":"10.99.0.256"}}`,
		"backend_ip typo":  `{"role":"backend","psk":"x","overlay":{"backend_ip":"10.99.0."}}`,
		"backend_ip name":  `{"role":"backend","psk":"x","overlay":{"backend_ip":"backend.local"}}`,
		"subnet not cidr":  `{"role":"backend","psk":"x","overlay":{"subnet":"10.99.0.0"}}`,
	}
	for name, body := range cases {
		p := filepath.Join(t.TempDir(), "boot.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := model.LoadBootstrap(p); err == nil {
			t.Errorf("%s: should have been rejected", name)
		}
	}

	// And the ordinary config, which names none of them, still loads on its
	// defaults. This check must not become a reason to write them out.
	p := filepath.Join(t.TempDir(), "boot.json")
	if err := os.WriteFile(p, []byte(`{"role":"backend","psk":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := model.LoadBootstrap(p)
	if err != nil {
		t.Fatalf("a config with no overlay section should load: %v", err)
	}
	if b.Overlay.BackendIP != "10.99.0.2" || b.Overlay.FrontendIP != "10.99.0.1" {
		t.Errorf("defaults did not survive: %+v", b.Overlay)
	}
}

// The point of the address checks is the generators downstream, and every one
// of them is IPv4 only: sysx.AddressLiteral answers anything else by rendering
// nothing, which `nft -f` loads as an empty file without complaint. A bare
// net.ParseIP check passed an IPv6 address straight through, so the agent
// started, logged its rules installed, and had none - the exact failure these
// checks exist to prevent, reached by the typo that parses rather than the one
// that does not.
func TestBootstrapRejectsAnAddressTheGeneratorsCannotUse(t *testing.T) {
	cases := map[string]string{
		"linker overlay_ip":  `{"role":"linker","psk":"x","linker":{"overlay_ip":"2001:db8::3","backend_lan":"192.168.1.2"}}`,
		"linker backend_lan": `{"role":"linker","psk":"x","linker":{"overlay_ip":"10.99.0.3","backend_lan":"2001:db8::2"}}`,
		"overlay frontend":   `{"role":"frontend","psk":"x","overlay":{"frontend_ip":"2001:db8::1"}}`,
		"overlay backend":    `{"role":"backend","psk":"x","overlay":{"backend_ip":"2001:db8::2"}}`,
		"subnet family":      `{"role":"frontend","psk":"x","overlay":{"subnet":"2001:db8::/32"}}`,
	}
	for name, body := range cases {
		p := filepath.Join(t.TempDir(), "b.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := model.LoadBootstrap(p); err == nil {
			t.Errorf("%s: an address no generator can render must be refused", name)
		}
	}
}

// nft rejects "10.99.0.5/24" outright with "Address has host bits set", and it
// rejects the whole table with it - so a subnet carrying host bits would take
// the mark chain and the source NAT down together. net.ParseCIDR accepts the
// string and reports the masked network, but the unmasked original was what got
// stored and what reached the generated rules. Masked here, at the one moment
// somebody is looking at this file, matching what the portal does with a pasted
// CIDR.
func TestBootstrapMasksHostBitsOffTheOverlaySubnet(t *testing.T) {
	p := filepath.Join(t.TempDir(), "frontend.json")
	body := `{"role":"frontend","psk":"x","overlay":{"subnet":"10.99.0.5/24"}}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := model.LoadBootstrap(p)
	if err != nil {
		t.Fatalf("a subnet with host bits should be masked, not refused: %v", err)
	}
	if b.Overlay.Subnet != "10.99.0.0/24" {
		t.Fatalf("overlay.subnet = %q, want the masked network 10.99.0.0/24", b.Overlay.Subnet)
	}
}

// Invariant 19: a site that has not set a subnet must stay byte-identical to a
// build that had never heard of one. Normalising the field must not invent it.
func TestBootstrapLeavesAnAbsentSubnetEmpty(t *testing.T) {
	p := filepath.Join(t.TempDir(), "frontend.json")
	if err := os.WriteFile(p, []byte(`{"role":"frontend","psk":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := model.LoadBootstrap(p)
	if err != nil {
		t.Fatal(err)
	}
	if b.Overlay.Subnet != "" {
		t.Fatalf("overlay.subnet = %q, want it left empty", b.Overlay.Subnet)
	}
}
