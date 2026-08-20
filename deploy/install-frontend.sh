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
if [ -f "$CONFIG" ] && [ "$FORCE_CONFIG" -eq 0 ]; then
	echo "  $CONFIG exists, leaving it alone (--force-config to replace)"
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
