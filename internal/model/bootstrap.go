package model

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
)

// Bootstrap is the small on-disk file each agent reads at startup.
//
// It holds only what must exist before anything else can work: where to put
// state, and the shared secret. Everything else - paths, quotas, services,
// thresholds - lives in the database and is edited in the portal, so there is
// exactly one place to manage the system from.
type Bootstrap struct {
	Role         string        `json:"role"`          // frontend or backend
	PSK          string        `json:"psk"`           // shared secret, identical on both hosts
	StateDir     string        `json:"state_dir"`     // runtime files
	DBPath       string        `json:"db_path"`       // frontend only
	PortalListen string        `json:"portal_listen"` // frontend only, e.g. 10.98.0.2:8088
	Overlay      OverlayConfig `json:"overlay"`       // backend needs this before config is pushed
	Linker       LinkerInfo    `json:"linker"`        // linker only

	// PublicIface seeds Frontend.PublicIface the first time the database is
	// created, and is ignored on every start after that. Frontend only.
	//
	// It is here because it is the one setting the installer can discover and
	// the shipped default cannot: Defaults() says eth0, and a datacentre box
	// running a modern Debian names it ens3 or enp1s0. Getting it wrong is
	// silent - the egress and protection rules are scoped to it, so they simply
	// never match - which is exactly the kind of fault worth removing from the
	// first install rather than documenting.
	//
	// Deliberately a seed and not an override. Overlay addressing is bootstrap
	// authoritative because both hosts must agree on it; this is one host's
	// local fact, it is editable in the portal, and a value that quietly
	// reappeared on every restart would be worse than no value at all.
	PublicIface string `json:"public_iface,omitempty"`

	// Warnings is what LoadBootstrap found wrong with the file without
	// refusing it: a shared secret too short to be the random one the
	// installer generates, or a file readable by more than root. Neither is
	// fatal, because both are hardening faults on a host that may be the only
	// thing keeping traffic flowing, and a refusal on a restart is an outage.
	// The agents log them at Error so they are not ignorable.
	Warnings []string `json:"-"`
}

// PSKPlaceholder is the value the example bootstrap files ship with. A file
// still carrying it authenticates every probe, decision and control frame
// against a secret printed in this repository.
const PSKPlaceholder = "CHANGE-ME"

// MinPSKBytes is the shortest shared secret that is not reported. The key is
// an unsalted sha256 of the secret, which is fine for the 64 hex characters
// the installers generate and brute-forceable offline from one captured probe
// for a short human-chosen passphrase - and a linker's first hop is plaintext
// TCP on somebody's LAN.
const MinPSKBytes = 32

// LinkerInfo is the local topology a linker cannot be told over the wire.
//
// Both fields are bootstrap-owned for the same reason the overlay addresses
// are: the frontend has no way to discover either of them. It does not know
// which overlay address this host was given, and it certainly does not know the
// backend's address on a LAN it has never seen.
type LinkerInfo struct {
	// Table is the routing table this host uses for overlay traffic. Zero means
	// the default.
	//
	// It lives here as well as in the portal, and it has to: the rule and route
	// it names are what carry the control connection, so the agent needs it
	// before it can be told anything. The portal generates this file with the
	// value it holds, and the agent reports back what it actually used so a
	// disagreement is visible rather than silent.
	Table int `json:"table,omitempty"`

	// OverlayIP is this host's own overlay address, e.g. 10.99.0.3. It must be
	// inside the frontend's overlay subnet, and unique among the linkers.
	OverlayIP string `json:"overlay_ip"`

	// BackendLAN is the backend's address on the local network - the next hop
	// for anything this host sends from its overlay address.
	BackendLAN string `json:"backend_lan"`
}

// Roles.
const (
	RoleFrontend = "frontend"
	RoleBackend  = "backend"

	// RoleLinker is an optional extra host that holds an overlay address and
	// terminates no tunnels. Most sites never run one.
	RoleLinker = "linker"
)

// LoadBootstrap reads and validates the bootstrap file.
func LoadBootstrap(path string) (Bootstrap, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Bootstrap{}, fmt.Errorf("read bootstrap config: %w", err)
	}
	var b Bootstrap
	if err := json.Unmarshal(raw, &b); err != nil {
		return Bootstrap{}, fmt.Errorf("parse bootstrap config: %w", err)
	}
	if b.PSK == "" {
		return Bootstrap{}, fmt.Errorf("bootstrap config: psk must be set and identical on both hosts")
	}
	// Refused outright rather than reported: nothing has ever run on this
	// value, so no site is taken down by the refusal, and a host that starts
	// on it is a host whose every authenticated message is forgeable by anyone
	// who has read the example file.
	if strings.HasPrefix(b.PSK, PSKPlaceholder) {
		return Bootstrap{}, fmt.Errorf("bootstrap config: psk is still the example placeholder; generate one with: openssl rand -hex 32")
	}
	if len(b.PSK) < MinPSKBytes {
		b.Warnings = append(b.Warnings, fmt.Sprintf(
			"psk is %d characters; the installers generate 64 (openssl rand -hex 32), and a short secret is brute-forceable offline from one captured probe",
			len(b.PSK)))
	}
	// The file holds the one secret in the system. A mode that lets any local
	// account read it hands that account the key that steers every host's
	// routing, and the installers write it 0600 precisely so it does not.
	// Windows has no such bits, and it is where development happens.
	if runtime.GOOS != "windows" {
		if st, err := os.Stat(path); err == nil && st.Mode().Perm()&0o077 != 0 {
			b.Warnings = append(b.Warnings, fmt.Sprintf(
				"%s is mode %04o and readable by more than root; it holds the shared secret, chmod 0600 it",
				path, st.Mode().Perm()))
		}
	}
	if b.StateDir == "" {
		b.StateDir = "/var/lib/failover"
	}
	if b.DBPath == "" {
		b.DBPath = b.StateDir + "/failover.db"
	}
	if b.PortalListen == "" {
		b.PortalListen = "127.0.0.1:8088"
	}
	if b.Overlay.FrontendIP == "" {
		b.Overlay.FrontendIP = "10.99.0.1"
	}
	if b.Overlay.BackendIP == "" {
		b.Overlay.BackendIP = "10.99.0.2"
	}
	if b.Overlay.Device == "" {
		b.Overlay.Device = "dummy0"
	}
	if b.Overlay.ProbePort == 0 {
		b.Overlay.ProbePort = 51999
	}
	if b.Overlay.ControlPort == 0 {
		b.Overlay.ControlPort = 51998
	}
	// Every role, because every role puts these into `ip` commands and into
	// generated nftables rules, and the generators answer an address they
	// cannot parse by rendering nothing - which loads as an empty file and
	// installs nothing. Defaulted above when absent, so reaching here with
	// something unparseable means somebody typed it.
	//
	// IPv4 specifically, and that is the point rather than pedantry. A plain
	// net.ParseIP check accepted an IPv6 address here and let the agent start,
	// and every generator downstream then rendered nothing at all, which is the
	// silent-empty-ruleset failure this check exists to catch - it was catching
	// only the typo that does not parse and missing the one that parses into
	// something unusable. The normalised form is stored back, so what the
	// generators see is what was checked.
	if v := ipv4Literal(b.Overlay.FrontendIP); v == "" {
		return Bootstrap{}, fmt.Errorf("bootstrap config: overlay.frontend_ip %q is not an IPv4 address", b.Overlay.FrontendIP)
	} else {
		b.Overlay.FrontendIP = v
	}
	if v := ipv4Literal(b.Overlay.BackendIP); v == "" {
		return Bootstrap{}, fmt.Errorf("bootstrap config: overlay.backend_ip %q is not an IPv4 address", b.Overlay.BackendIP)
	} else {
		b.Overlay.BackendIP = v
	}
	// Optional, so only checked when it is there. Empty is the ordinary case
	// and means one host at the far end.
	if b.Overlay.Subnet != "" {
		v := ipv4Network(b.Overlay.Subnet)
		if v == "" {
			return Bootstrap{}, fmt.Errorf("bootstrap config: overlay.subnet %q is not an IPv4 network in CIDR form", b.Overlay.Subnet)
		}
		b.Overlay.Subnet = v
	}
	// A linker with either field missing would start, install nothing useful
	// and look healthy. Both are load-bearing and neither has a sane default,
	// so refuse rather than guess.
	if b.Role == RoleLinker {
		if b.Linker.OverlayIP == "" {
			return Bootstrap{}, fmt.Errorf("bootstrap config: a linker needs linker.overlay_ip, its own address inside the overlay subnet")
		}
		if b.Linker.BackendLAN == "" {
			return Bootstrap{}, fmt.Errorf("bootstrap config: a linker needs linker.backend_lan, the backend's address on this network")
		}
		// Parsed, not just present. Both end up in generated nftables rules,
		// and the generators refuse an address they cannot parse by rendering
		// nothing at all - which `nft -f` accepts as an empty file, so a typo
		// here bought a linker that started, reported its egress networks
		// installed, and had no ruleset. Refused at the one moment somebody is
		// looking at this file.
		if v := ipv4Literal(b.Linker.OverlayIP); v == "" {
			return Bootstrap{}, fmt.Errorf("bootstrap config: linker.overlay_ip %q is not an IPv4 address", b.Linker.OverlayIP)
		} else {
			b.Linker.OverlayIP = v
		}
		if v := ipv4Literal(b.Linker.BackendLAN); v == "" {
			return Bootstrap{}, fmt.Errorf("bootstrap config: linker.backend_lan %q is not an IPv4 address", b.Linker.BackendLAN)
		} else {
			b.Linker.BackendLAN = v
		}
		if b.Linker.OverlayIP == b.Overlay.BackendIP || b.Linker.OverlayIP == b.Overlay.FrontendIP {
			return Bootstrap{}, fmt.Errorf("bootstrap config: linker.overlay_ip %s is already the frontend's or the backend's address", b.Linker.OverlayIP)
		}
		// The kernel owns 253 to 255: default, main and local. A default route
		// written into main points this entire host at the backend, and the
		// reconciler puts it back ten seconds after anybody deletes it, so an
		// operator cannot undo it without stopping the agent first.
		//
		// Refused rather than warned about. The example file's _table note
		// already says 1-252 and explains why the number matters, which is
		// exactly as much as a comment in a JSON file can do: the parser throws
		// it away. The two checks above exist for the same reason.
		//
		// The portal applies this bound too, along with the collisions only it
		// can see. It cannot help here: this file is where the value has to be
		// typed, because the rule it names is what carries the channel the
		// portal would otherwise arrive over.
		if b.Linker.Table < 0 || b.Linker.Table > 252 {
			return Bootstrap{}, fmt.Errorf(
				"bootstrap config: linker.table is %d; it must be between 1 and 252, "+
					"or left out for the default. 253 to 255 are the kernel's own tables, "+
					"and writing a default route into main would send this host's traffic to the backend",
				b.Linker.Table)
		}
	}
	return b, nil
}

// Key derives the 32-byte authentication key from the shared secret, so the
// bootstrap file can hold a human-typed passphrase rather than raw hex.
func (b Bootstrap) Key() []byte {
	sum := sha256.Sum256([]byte(b.PSK))
	return sum[:]
}

// ipv4Literal and ipv4Network are the checks the generators actually apply,
// enforced at the one moment somebody is looking at this file.
//
// They mirror sysx.AddressLiteral and sysx.NetworkLiteral deliberately rather
// than calling them: sysx imports model, so the dependency cannot run the other
// way. If the rule in either of those moves, move it here too - the failure of
// them disagreeing is an agent that starts, reports its rules installed, and
// has none.
func ipv4Literal(addr string) string {
	ip := net.ParseIP(strings.TrimSpace(addr))
	if ip == nil || ip.To4() == nil {
		return ""
	}
	return ip.To4().String()
}

// ipv4Network masks host bits off rather than refusing them, matching what the
// portal already does with a pasted CIDR. Left in, they are not a cosmetic
// difference: nft rejects "10.99.0.5/24" with "Address has host bits set" and
// rejects the whole table with it.
func ipv4Network(cidr string) string {
	_, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil || n.IP.To4() == nil {
		return ""
	}
	if _, bits := n.Mask.Size(); bits != 32 {
		return ""
	}
	return n.String()
}
