#!/usr/bin/env bash
#
# Install the failover frontend on this host (the datacentre box).
#
#   git clone <repo> && cd homeport
#   sudo ./deploy/install-frontend.sh
#
# Re-running is safe: binaries and the unit file are replaced, an existing
# /etc/failover/frontend.json is left alone unless --force-config is given.
# Everything else about the system is configured in the portal, not here.
#
# Read deploy/SETUP.md first. This script assumes the WireGuard tunnels and the
# pfSense policy routing already work; it will warn if they obviously do not,
# but it cannot check pfSense for you.

set -euo pipefail

BIN_DIR=/usr/local/bin
CONF_DIR=/etc/failover
STATE_DIR=/var/lib/failover
UNIT=failover-frontend.service
CONFIG="$CONF_DIR/frontend.json"

PSK=""
PORTAL=""
PUBLIC_IFACE=""
ASK=1
FRONTEND_IP=10.99.0.1
BACKEND_IP=10.99.0.2
# Empty is the normal case: one host at the far end. Only a site running
# linker agents sets this, and it must match on every host and be covered by
# AllowedIPs on the frontend's peers - which the shipped WireGuard setup
# already is. See SETUP.md section 10.
SUBNET=""
FORCE_CONFIG=0
START=1

usage() {
	cat <<EOF
usage: sudo $0 [options]

  --psk <hex>        shared secret; must be identical on the backend.
                     Generated if omitted and no config exists yet.
  --portal <addr>    portal listen address. Defaults to the address on
                     wg-admin, port 8080, e.g. 10.98.0.2:8080.
  --public-iface <n> the interface facing the internet, e.g. ens3. Detected
                     from the default route, and confirmed with you when this
                     is run on a terminal.
  --no-ask           never prompt; take the detected value or leave it unset.
  --frontend-ip <ip> frontend overlay address (default $FRONTEND_IP)
  --backend-ip <ip>  backend overlay address (default $BACKEND_IP)
  --subnet <cidr>    overlay subnet, e.g. 10.99.0.0/24. Only for a site with
                     linker agents; must match on every host.
  --force-config     overwrite an existing $CONFIG
  --no-start         install but do not enable or start the service
  -h, --help         this message
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
	--psk) PSK="$2"; shift 2 ;;
	--portal) PORTAL="$2"; shift 2 ;;
	--public-iface) PUBLIC_IFACE="$2"; shift 2 ;;
	--no-ask) ASK=0; shift ;;
	--frontend-ip) FRONTEND_IP="$2"; shift 2 ;;
	--backend-ip) BACKEND_IP="$2"; shift 2 ;;
	--subnet) SUBNET="$2"; shift 2 ;;
	--force-config) FORCE_CONFIG=1; shift ;;
	--no-start) START=0; shift ;;
	-h | --help) usage; exit 0 ;;
	*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
	esac
done

if [ "$(id -u)" -ne 0 ]; then
	echo "error: run this with sudo - it installs a systemd unit and touches routing" >&2
	exit 1
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[33mwarning: %s\033[0m\n' "$*" >&2; }

# ---------------------------------------------------------------------------
# Build
#
# A prebuilt binary in build/ is used if there is no Go toolchain, so the same
# script works on a box that only ever receives artefacts.
# ---------------------------------------------------------------------------

say "Building"
if command -v go >/dev/null 2>&1; then
	version="$(git -C "$REPO" describe --tags --always --dirty 2>/dev/null || echo dev)"
	mkdir -p build
	for cmd in failover-frontend failoverctl; do
		echo "  $cmd ($version)"
		CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
			go build -ldflags "-s -w -X main.version=$version" -o "build/$cmd" "./cmd/$cmd"
	done
else
	warn "no Go toolchain found, using the prebuilt binaries in build/"
	for cmd in failover-frontend failoverctl; do
		[ -f "build/$cmd" ] || { echo "error: build/$cmd is missing and cannot be built" >&2; exit 1; }
	done
fi

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

# Checked before anything is installed. `openssl` in particular is only reached
# after the binaries and the unit are already in place, so a box without it used
# to abort halfway through with set -e and leave a half-installed system.
missing=""
for c in ip nft sysctl openssl systemctl; do
	command -v "$c" >/dev/null 2>&1 || missing="$missing $c"
done
if [ -n "$missing" ]; then
	echo "error: missing required command(s):$missing" >&2
	echo "       on Debian: apt install iproute2 nftables procps openssl" >&2
	exit 1
fi

say "Checking the environment"
for iface in wg-nbn wg-lte1 wg-lte2; do
	if ip link show "$iface" >/dev/null 2>&1; then
		echo "  $iface present"
	else
		warn "$iface does not exist - that path will probe as down until wg-quick brings it up"
	fi
done

if ! ip link show wg-admin >/dev/null 2>&1; then
	warn "wg-admin does not exist - the portal has nothing to bind to yet"
fi

# The tunnels must not install their own routes, or all three fight over the
# same destination and the per-path tables become meaningless.
for conf in /etc/wireguard/wg-nbn.conf /etc/wireguard/wg-lte1.conf /etc/wireguard/wg-lte2.conf; do
	if [ -f "$conf" ] && ! grep -qiE '^[[:space:]]*Table[[:space:]]*=[[:space:]]*off' "$conf"; then
		warn "$conf has no 'Table = off' - wg-quick will install competing routes"
	fi
done

# ---------------------------------------------------------------------------
# Portal address
# ---------------------------------------------------------------------------

if [ -z "$PORTAL" ]; then
	admin_ip="$(ip -4 -o addr show wg-admin 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1 || true)"
	if [ -n "$admin_ip" ]; then
		PORTAL="$admin_ip:8080"
		echo "  portal will bind $PORTAL (from wg-admin)"
	else
		PORTAL="127.0.0.1:8080"
		warn "could not read an address from wg-admin; defaulting the portal to $PORTAL"
		warn "pass --portal <ip>:8080 once the admin tunnel is up, or the portal is only reachable locally"
	fi
fi

# An existing bootstrap file is never rewritten, so on an upgrade there is
# nothing to ask about: the answer would only be discarded.
if [ -f "$CONFIG" ] && [ "$FORCE_CONFIG" -eq 0 ]; then
	WRITE_CONFIG=0
else
	WRITE_CONFIG=1
fi

# ---------------------------------------------------------------------------
# Public interface
#
# The interface facing the internet. It scopes the egress source NAT and every
# protection rule, and the shipped default is eth0, which a datacentre box
# running a modern Debian is not called. Getting it wrong is silent: a rule
# scoped to an interface that does not exist simply never matches, and the
# heartbeat keeps leaving by pfSense.
#
# Detected here and written into the bootstrap file, which seeds it into the
# portal's configuration the first time the agent creates its database. After
# that the portal owns it.
# ---------------------------------------------------------------------------

detect_public_iface() {
	local dev=""
	# `ip route get` rather than reading the default route directly: it resolves
	# policy routing as well, and it is the same command SETUP.md tells you to
	# run to answer this question by hand.
	dev="$(ip -4 route get 1.1.1.1 2>/dev/null |
		awk '{ for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit } }')"
	if [ -z "$dev" ]; then
		dev="$(ip -4 route show default 2>/dev/null |
			awk '{ for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit } }')"
	fi
	# Never one of this system's own interfaces. If the default route already
	# points down a tunnel something is wrong that guessing cannot fix.
	case "$dev" in
	lo | wg-* | dummy*) dev="" ;;
	esac
	printf '%s' "$dev"
}

if [ "$WRITE_CONFIG" -eq 1 ]; then
	say "Public interface"
	detected="$(detect_public_iface)"
	if [ -n "$PUBLIC_IFACE" ]; then
		echo "  using $PUBLIC_IFACE, given on the command line"
	elif [ "$ASK" -eq 1 ] && [ -r /dev/tty ]; then
		answer=""
		if [ -n "$detected" ]; then
			printf '  which interface faces the internet? [%s] ' "$detected"
		else
			printf '  which interface faces the internet? (none detected, blank to skip) '
		fi
		read -r answer </dev/tty || answer=""
		PUBLIC_IFACE="${answer:-$detected}"
	else
		PUBLIC_IFACE="$detected"
		if [ -n "$PUBLIC_IFACE" ]; then
			echo "  detected $PUBLIC_IFACE"
		fi
	fi

	if [ -n "$PUBLIC_IFACE" ]; then
		if ! ip link show "$PUBLIC_IFACE" >/dev/null 2>&1; then
			warn "$PUBLIC_IFACE does not exist on this host - check the name, or set it later in the portal"
		fi
	else
		warn "could not work out the public interface; the portal default of eth0 will stand"
		warn "set it in Settings -> Frontend, or re-run with --public-iface <name>"
	fi
fi

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

say "Installing binaries and unit"
install -d -m 0755 "$CONF_DIR" "$STATE_DIR"

# A running binary cannot be overwritten in place, hence the .new dance.
for cmd in failover-frontend failoverctl; do
	install -m 0755 "build/$cmd" "$BIN_DIR/$cmd.new"
	mv "$BIN_DIR/$cmd.new" "$BIN_DIR/$cmd"
	echo "  $BIN_DIR/$cmd"
done
install -m 0644 "deploy/$UNIT" "/etc/systemd/system/$UNIT"
echo "  /etc/systemd/system/$UNIT"

# ---------------------------------------------------------------------------
# Bootstrap config
#
# Owned by root and readable only by root. The unit drops CAP_DAC_OVERRIDE, so
# root gets no DAC bypass: a config owned by anyone else fails to open and the
# service restart-loops on "permission denied" while `sudo cat` works fine.
# ---------------------------------------------------------------------------

say "Bootstrap configuration"
if [ "$WRITE_CONFIG" -eq 0 ]; then
	echo "  $CONFIG exists, leaving it alone (--force-config to replace)"
	# Nothing is lost by not rewriting it: public_iface only ever seeds a
	# database that does not exist yet, so on a host that has already run the
	# agent the portal holds the value and is the only place to change it.
	echo "  the public interface is a portal setting once the agent has started:"
	echo "  Settings -> Frontend -> Public interface"
	if [ -n "$PUBLIC_IFACE" ]; then
		warn "--public-iface $PUBLIC_IFACE was ignored: it seeds a first install only"
	fi
	chown root:root "$CONFIG"
	chmod 0600 "$CONFIG"
else
	if [ -z "$PSK" ]; then
		PSK="$(openssl rand -hex 32)"
		generated=1
	fi
	umask 077
	cat >"$CONFIG" <<EOF
{
  "role": "frontend",
  "psk": "$PSK",
  "state_dir": "$STATE_DIR",
  "db_path": "$STATE_DIR/failover.db",
  "portal_listen": "$PORTAL",
  "public_iface": "$PUBLIC_IFACE",
  "overlay": {
    "frontend_ip": "$FRONTEND_IP",
    "backend_ip": "$BACKEND_IP",
    "subnet": "$SUBNET",
    "probe_port": 51999,
    "control_port": 51998
  }
}
EOF
	chown root:root "$CONFIG"
	chmod 0600 "$CONFIG"
	echo "  wrote $CONFIG"
fi

# ---------------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------------

systemctl daemon-reload
if [ "$START" -eq 1 ]; then
	say "Starting"
	systemctl enable --now "$UNIT" >/dev/null
	systemctl restart "$UNIT"
	sleep 3
	systemctl --no-pager --lines=0 status "$UNIT" || true
else
	echo "  --no-start given; run: systemctl enable --now $UNIT"
fi

say "Done"
cat <<EOF
Mode is observe: the agent probes, decides and logs, but installs no route and
no DNAT until you arm it.

  failoverctl status
  journalctl -u $UNIT -f

Portal:   http://$PORTAL
EOF

if [ "$START" -eq 1 ]; then
	# The agent logs JSON, and prints this line exactly once, on first start.
	pw="$(journalctl -u "$UNIT" --no-pager 2>/dev/null |
		grep 'portal account created' | tail -n1 |
		grep -o '"password":"[^"]*"' | cut -d'"' -f4 || true)"
	if [ -n "$pw" ]; then
		echo "Login:    admin / $pw"
		echo "          Generated on first start and left in this host's journal in"
		echo "          the clear, so change it: Settings -> Portal account in the"
		echo "          portal, or 'sudo failoverctl passwd' here if you lose it."
	fi
fi

if [ "${generated:-0}" -eq 1 ]; then
	cat <<EOF

The shared secret was generated. The backend must have the identical value:

  sudo ./deploy/install-backend.sh --psk $PSK
EOF
fi
