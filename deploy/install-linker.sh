#!/usr/bin/env bash
#
# Install a failover linker on this host.
#
#   git clone <repo> && cd homeport
#   sudo ./deploy/install-linker.sh --psk <the frontend's psk> \
#        --overlay-ip 10.99.0.3 --backend-lan 192.168.1.2
#
# A linker is an extra machine behind the backend. It holds an overlay address
# so the frontend can publish services to it, and routes anything sent from that
# address to the backend, which puts it on whichever tunnel is active. It
# terminates no tunnels, answers no probes and makes no decisions.
#
# MOST SITES DO NOT NEED THIS. One backend at the far end of the tunnels is the
# normal arrangement. Install a linker only where the box doing the work is not
# the box terminating the tunnels.
#
# Read deploy/SETUP.md section 10 first - there are two steps this script cannot
# do for you, and it prints them at the end.
#
# Re-running is safe: the binary and unit are replaced, an existing
# /etc/failover/linker.json is left alone unless --force-config is given.

set -euo pipefail

BIN_DIR=/usr/local/bin
CONF_DIR=/etc/failover
STATE_DIR=/var/lib/failover
UNIT=failover-linker.service
CONFIG="$CONF_DIR/linker.json"

PSK=""
OVERLAY_IP=""
BACKEND_LAN=""
FRONTEND_IP=10.99.0.1
BACKEND_IP=10.99.0.2
# Derived from the two addresses above after parsing, so a site that moved them
# gets a range that contains them rather than the shipped one that would not.
SUBNET=""
SUBNET_GIVEN=0
# The routing table this host uses for overlay traffic. It belongs to this
# machine's own namespace, not to this system, so it is a real setting rather
# than a constant: the first deployment landed on a box already using 200 for
# its second ISP and the agent wrote its default route straight over that
# host's. It must match the Table column in the portal's linker row - the rule
# it names is what carries the control channel, so the agent needs the value
# before it can be told anything.
TABLE=200
FORCE_CONFIG=0
START=1

usage() {
	cat <<EOF
usage: sudo $0 --psk <hex> --overlay-ip <ip> --backend-lan <ip> [options]

  --psk <hex>         shared secret. Must be byte-identical to the frontend's:
                        sudo grep psk /etc/failover/frontend.json
                      Required unless $CONFIG already exists.
  --overlay-ip <ip>   this host's overlay address, e.g. 10.99.0.3. Must be
                      inside the overlay subnet and unique among the linkers.
  --backend-lan <ip>  the backend's address on this network, e.g. 192.168.1.2.
                      This is the next hop for overlay traffic, not the
                      backend's overlay address.
  --subnet <cidr>     overlay subnet. Defaults to the /24 the overlay addresses
                      sit in, e.g. 10.99.0.0/24. Must match overlay.subnet on
                      the frontend and the backend, and --overlay-ip must be
                      inside it. Recorded here and used to check that; the
                      agent itself does not read it yet.
  --frontend-ip <ip>  frontend overlay address (default $FRONTEND_IP)
  --backend-ip <ip>   backend overlay address (default $BACKEND_IP)
  --table <n>         routing table for overlay traffic on this host,
                      1-252, default $TABLE. Must match the Table column in
                      this host's row in the portal. Pick another number if
                      this box already policy-routes - a second ISP, a VPN -
                      or the agent writes its default route over that one.
  --force-config      overwrite an existing $CONFIG. Needs --psk with it, or
                      the secret would be blanked.
  --no-start          install but do not enable or start the service
  -h, --help          this message
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
	--psk) PSK="$2"; shift 2 ;;
	--overlay-ip) OVERLAY_IP="$2"; shift 2 ;;
	--backend-lan) BACKEND_LAN="$2"; shift 2 ;;
	--subnet) SUBNET="$2"; SUBNET_GIVEN=1; shift 2 ;;
	--table) TABLE="$2"; shift 2 ;;
	--frontend-ip) FRONTEND_IP="$2"; shift 2 ;;
	--backend-ip) BACKEND_IP="$2"; shift 2 ;;
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

if [ "$SUBNET_GIVEN" -eq 0 ]; then
	f24="$(printf '%s' "$FRONTEND_IP" | cut -d. -f1-3)"
	b24="$(printf '%s' "$BACKEND_IP" | cut -d. -f1-3)"
	if [ -n "$f24" ] && [ "$f24" = "$b24" ]; then
		SUBNET="$f24.0/24"
	else
		echo "error: $FRONTEND_IP and $BACKEND_IP are not in one /24; pass --subnet <cidr>" >&2
		echo "       it must be the same value as overlay.subnet on both of those hosts" >&2
		exit 2
	fi
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[33mwarning: %s\033[0m\n' "$*" >&2; }

# ---------------------------------------------------------------------------
# Arguments
#
# Every one of these is load-bearing and none has a sane default, so refuse
# rather than guess. A linker that starts with the wrong address installs a rule
# for traffic that will never exist and reports itself perfectly healthy.
# ---------------------------------------------------------------------------

if [ ! -f "$CONFIG" ] || [ "$FORCE_CONFIG" -eq 1 ]; then
	[ -n "$PSK" ] || {
		echo "error: --psk is required; it must match the frontend exactly" >&2
		echo "       read it there with: sudo grep psk /etc/failover/frontend.json" >&2
		exit 2
	}
	[ -n "$OVERLAY_IP" ] || { echo "error: --overlay-ip is required, e.g. 10.99.0.3" >&2; exit 2; }
	[ -n "$BACKEND_LAN" ] || { echo "error: --backend-lan is required, e.g. 192.168.1.2" >&2; exit 2; }

	# 253-255 are default/main/local: writing a default route into one of them
	# redirects the whole host, which is the opposite of what a linker is for.
	case "$TABLE" in
	'' | *[!0-9]*)
		echo "error: --table $TABLE is not a number; it must be between 1 and 252" >&2
		exit 2
		;;
	esac
	if [ "$TABLE" -lt 1 ] || [ "$TABLE" -gt 252 ]; then
		echo "error: --table $TABLE is out of range; it must be between 1 and 252" >&2
		exit 2
	fi

	if [ "$OVERLAY_IP" = "$FRONTEND_IP" ] || [ "$OVERLAY_IP" = "$BACKEND_IP" ]; then
		echo "error: --overlay-ip $OVERLAY_IP is already the frontend's or the backend's address" >&2
		exit 2
	fi
	# The backend is reached as a neighbour on the LAN. Its overlay address is
	# not routable from here yet - that is what this agent is being installed to
	# arrange - so passing it is a mistake that produces a route to nowhere.
	if [ "$BACKEND_LAN" = "$BACKEND_IP" ]; then
		echo "error: --backend-lan must be the backend's LAN address, not its overlay address" >&2
		echo "       overlay traffic reaches the backend as a neighbour on this network" >&2
		exit 2
	fi

	# An address outside the overlay subnet installs perfectly and does nothing.
	# The frontend rejects it as a service target, but that is a message on
	# another host, and this agent would sit here reporting itself healthy.
	# Compared on the network part only - enough to catch a typed digit, which
	# is the mistake that actually happens.
	net="${SUBNET%/*}"
	case "$SUBNET" in
	*/8)  want="${net%%.*}." ;;
	*/16) want="$(echo "$net" | cut -d. -f1-2)." ;;
	*/24) want="$(echo "$net" | cut -d. -f1-3)." ;;
	*)    want="" ;;
	esac
	if [ -n "$want" ] && [ "${OVERLAY_IP#"$want"}" = "$OVERLAY_IP" ]; then
		echo "error: --overlay-ip $OVERLAY_IP is not inside --subnet $SUBNET" >&2
		echo "       the frontend cannot route to it, so nothing published here would arrive" >&2
		exit 2
	fi
fi

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

say "Building"
if command -v go >/dev/null 2>&1; then
	version="$(git -C "$REPO" describe --tags --always 2>/dev/null || echo dev)"
	mkdir -p build
	echo "  failover-linker ($version)"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags "-s -w -X main.version=$version" -o build/failover-linker ./cmd/failover-linker
else
	warn "no Go toolchain found, using the prebuilt binary in build/"
	[ -f build/failover-linker ] || { echo "error: build/failover-linker is missing and cannot be built" >&2; exit 1; }
fi

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

missing=""
# nft as well as ip: the linker loads one nftables table of its own, which is
# what marks connections addressed to its overlay address so a containerised
# service's replies find their way back to the backend. Without it the agent
# starts, routes correctly, and anything containerised here answers into a black
# hole - which is a bad way to find out nftables was not installed.
for c in ip nft sysctl systemctl; do
	command -v "$c" >/dev/null 2>&1 || missing="$missing $c"
done
if [ -n "$missing" ]; then
	echo "error: missing required command(s):$missing" >&2
	echo "       on Debian: apt install iproute2 nftables procps" >&2
	exit 1
fi

say "Checking the environment"

if [ -n "$BACKEND_LAN" ]; then
	# Reachability is not required to install - the backend may be rebooting -
	# but an unreachable neighbour is almost always a typo or the wrong subnet.
	if ip route get "$BACKEND_LAN" >/dev/null 2>&1; then
		via="$(ip -o route get "$BACKEND_LAN" 2>/dev/null | head -n1)"
		echo "  backend reachable: $via"
	else
		warn "no route to $BACKEND_LAN - check it is the backend's address on this network"
	fi
fi

# Not changed, only reported. On a host with a single route to the internet the
# reverse lookup for a client address lands on the interface the packet arrived
# on, so filtering passes and there is nothing to fix. Turning it off system-wide
# on somebody's server is their call, not this script's.
rpf="$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null || echo 0)"
if [ "$rpf" != "0" ]; then
	warn "net.ipv4.conf.all.rp_filter is $rpf"
	warn "  harmless on a host with one route to the internet"
	warn "  suspect it first if published traffic arrives here but is never answered"
fi

if command -v docker >/dev/null 2>&1; then
	echo "  docker present"
	warn "containers on a bridge network are not yet handled by this agent"
	warn "  run them with --network host and bind $OVERLAY_IP, or see SETUP.md section 10"
fi

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

say "Installing binary and unit"
install -d -m 0755 "$CONF_DIR" "$STATE_DIR"

install -m 0755 build/failover-linker "$BIN_DIR/failover-linker.new"
mv "$BIN_DIR/failover-linker.new" "$BIN_DIR/failover-linker"
echo "  $BIN_DIR/failover-linker"

install -m 0644 "deploy/$UNIT" "/etc/systemd/system/$UNIT"
echo "  /etc/systemd/system/$UNIT"

# ---------------------------------------------------------------------------
# Bootstrap config
#
# Root-owned, 0600. The unit drops CAP_DAC_OVERRIDE, so root can only read a
# file it actually owns; a config left owned by the login user makes the service
# restart-loop on "permission denied" while `sudo cat` works fine.
# ---------------------------------------------------------------------------

say "Bootstrap configuration"
if [ -f "$CONFIG" ] && [ "$FORCE_CONFIG" -eq 0 ]; then
	echo "  $CONFIG exists, leaving it alone (--force-config to replace)"
	chown root:root "$CONFIG"
	chmod 0600 "$CONFIG"
	# Read back what this host is actually configured as, so the checks and the
	# closing instructions below describe the running system rather than the
	# defaults. Empty means the parse failed on a hand-edited file, and an empty
	# value would turn every check below into one that passes on anything.
	OVERLAY_IP="$(sed -n 's/.*"overlay_ip"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CONFIG" | head -n1)"
	BACKEND_LAN="$(sed -n 's/.*"backend_lan"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CONFIG" | head -n1)"
	SUBNET="$(sed -n 's/.*"subnet"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CONFIG" | head -n1)"
	existing_table="$(sed -n 's/.*"table"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' "$CONFIG" | head -n1)"
	if [ -n "$existing_table" ]; then
		TABLE="$existing_table"
	fi
	if [ -z "$OVERLAY_IP" ] || [ -z "$BACKEND_LAN" ]; then
		echo "error: cannot read overlay_ip and backend_lan out of $CONFIG" >&2
		echo "       the agent still reads the file itself, so it may be fine - but this" >&2
		echo "       script cannot verify the result, so it is stopping rather than" >&2
		echo "       printing checks that would pass on anything" >&2
		exit 1
	fi
else
	umask 077
	cat >"$CONFIG" <<EOF
{
  "role": "linker",
  "psk": "$PSK",
  "state_dir": "$STATE_DIR",
  "overlay": {
    "frontend_ip": "$FRONTEND_IP",
    "backend_ip": "$BACKEND_IP",
    "subnet": "$SUBNET",
    "device": "dummy0",
    "probe_port": 51999,
    "control_port": 51998
  },
  "linker": {
    "overlay_ip": "$OVERLAY_IP",
    "backend_lan": "$BACKEND_LAN",
    "table": $TABLE
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
	sleep 2
	systemctl --no-pager --lines=0 status "$UNIT" || true

	say "Result"
	if ip -o addr show | grep -q " $OVERLAY_IP/32 "; then
		echo "  $OVERLAY_IP is up on dummy0"
	else
		warn "$OVERLAY_IP is not on any interface - check: journalctl -u $UNIT -n 30"
	fi
	if ip route show default table "$TABLE" 2>/dev/null | grep -q "$BACKEND_LAN"; then
		echo "  overlay table $TABLE points at $BACKEND_LAN"
	else
		warn "table $TABLE has no route to $BACKEND_LAN - check: journalctl -u $UNIT -n 30"
	fi
else
	echo "  --no-start given; run: systemctl enable --now $UNIT"
fi

# ---------------------------------------------------------------------------
# What this script cannot do from here
# ---------------------------------------------------------------------------

say "What remains is in the portal, not on any host"

cat <<EOF
IN THE PORTAL, on the frontend:

  - Settings -> Linkers: add a row for this host if there is not one already -
    overlay address $OVERLAY_IP, LAN address <this host's address on the
    backend's network>. Saving is what tells the backend how to reach it: it
    installs the route and repairs it, so there is nothing to run on the
    backend and nothing to persist by hand.

  - Settings -> Published services: set "Published to" to $OVERLAY_IP for each
    service that lives on this host. The portal will refuse the address unless
    a linker row exists for it, because a target the backend cannot forward to
    swallows every request in silence.

  - overlay.subnet must be set in the frontend's and the backend's bootstrap
    files, to $SUBNET. Check the frontend's peers cover the range as well -
    "wg show wg-nbn allowed-ips" should list it, and a peer that excludes
    this host drops its traffic in silence. See SETUP.md section 10.

This host still does not appear in the portal. A linker reports nothing about
itself - it has no control channel, so the frontend knows only what you typed.
Liveness is checked from here:

  systemctl status $UNIT
  ip rule show | grep $OVERLAY_IP
  ip route show table $TABLE

And from the backend, once both halves are in place:

  ping -c3 $OVERLAY_IP

To take the routing down again without touching the overlay address:

  failover-linker -revert
EOF
