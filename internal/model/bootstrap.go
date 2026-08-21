package model

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
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
	PortalListen string        `json:"portal_listen"` // frontend only, e.g. 10.98.0.2:8080
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
}

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
	if b.StateDir == "" {
		b.StateDir = "/var/lib/failover"
	}
	if b.DBPath == "" {
		b.DBPath = b.StateDir + "/failover.db"
	}
	if b.PortalListen == "" {
		b.PortalListen = "127.0.0.1:8080"
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
