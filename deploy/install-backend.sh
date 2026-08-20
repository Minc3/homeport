#!/usr/bin/env bash
#
# Install the failover backend on this host (the box at the house).
#
#   git clone <repo> && cd homeport
#   sudo ./deploy/install-backend.sh --psk <the frontend's psk>
#
# The backend makes no decisions and has no web interface. It answers probes,
# routes replies back out the tunnel the frontend chose, and meters the LTE
# interfaces. Everything it knows is pushed down from the frontend and cached,
# so the only thing that has to be configured here is the shared secret.
#
# Re-running is safe: binaries and the unit file are replaced, an existing
# /etc/failover/backend.json is left alone unless --force-config is given.

set -euo pipefail

BIN_DIR=/usr/local/bin
CONF_DIR=/etc/failover
STATE_DIR=/var/lib/failover
UNIT=failover-backend.service
CONFIG="$CONF_DIR/backend.json"

PSK=""
FRONTEND_IP=10.99.0.1
BACKEND_IP=10.99.0.2
# Derived from the overlay addresses below unless --subnet says otherwise: the
# /24 they sit in, so the shipped 10.99.0.1 and .2 give 10.99.0.0/24. It has to
# be identical to the frontend's - the two ends disagreeing about the range is
# a fault nothing reports. See SETUP.md section 10.
SUBNET=""
SUBNET_GIVEN=0
FORCE_CONFIG=0
START=1

usage() {
	cat <<EOF
usage: sudo $0 --psk <hex> [options]

  --psk <hex>        shared secret. Must be byte-identical to the frontend's,
                     which printed it when install-frontend.sh generated it:
                       sudo grep psk /etc/failover/frontend.json
                     Required unless $CONFIG already exists.
  --frontend-ip <ip> frontend overlay address (default $FRONTEND_IP)
  --backend-ip <ip>  backend overlay address (default $BACKEND_IP)
  --subnet <cidr>    overlay subnet. Defaults to the /24 the overlay addresses
                     sit in, e.g. 10.99.0.0/24, and must match the frontend's.
                     Pass '' for none. On a re-run this is the one field that
                     can be changed in an existing config: it is patched in
                     place, leaving the shared secret alone, so it needs no
                     --force-config and no --psk.
  --force-config     overwrite an existing $CONFIG. Needs --psk with it, or
                     the secret would be blanked.
  --no-start         install but do not enable or start the service
  -h, --help         this message
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
	--psk) PSK="$2"; shift 2 ;;
	--frontend-ip) FRONTEND_IP="$2"; shift 2 ;;
	--backend-ip) BACKEND_IP="$2"; shift 2 ;;
	--subnet) SUBNET="$2"; SUBNET_GIVEN=1; shift 2 ;;
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

# The psk is the only thing on this host that cannot be recovered from
# elsewhere, so every path that writes the config must have one to write.
# --force-config on its own used to reach the writer with $PSK still empty,
# which produces a config the agent rejects outright ("psk must be set") - so
# the service restart-loops on a host that was working a moment earlier.
if [ -z "$PSK" ] && [ ! -f "$CONFIG" ]; then
	echo "error: --psk is required on a first install; it must match the frontend exactly" >&2
	echo "       read it there with: sudo grep psk /etc/failover/frontend.json" >&2
	exit 2
fi
if [ -z "$PSK" ] && [ "$FORCE_CONFIG" -eq 1 ]; then
	echo "error: --force-config rewrites $CONFIG, so it needs --psk as well" >&2
	echo "       without one the secret is blanked and the agent refuses to start" >&2
	echo "       the current value is in: sudo grep psk $CONFIG" >&2
	exit 2
fi

# ---------------------------------------------------------------------------
# Overlay subnet
#
# Derived from the two overlay addresses rather than hardcoded, so a site that
# moved them somewhere else gets a subnet that actually contains them instead
# of a default that quietly contains nothing. If they do not share a /24 there
# is nothing safe to guess, and empty is the answer that changes no rules.
# ---------------------------------------------------------------------------

derive_subnet() {
	local a="$1" b="$2"
	case "$a$b" in
	*[!0-9.]*) printf ''; return ;;
	esac
	local a24 b24
	a24="$(printf '%s' "$a" | cut -d. -f1-3)"
	b24="$(printf '%s' "$b" | cut -d. -f1-3)"
	if [ -n "$a24" ] && [ "$a24" = "$b24" ]; then
		printf '%s.0/24' "$a24"
	fi
}

if [ "$SUBNET_GIVEN" -eq 0 ]; then
	SUBNET="$(derive_subnet "$FRONTEND_IP" "$BACKEND_IP")"
	if [ -z "$SUBNET" ]; then
		warn "$FRONTEND_IP and $BACKEND_IP are not in one /24, so no overlay subnet is set"
		warn "  pass --subnet <cidr> if this site will run linker agents"
	fi
fi

# patch_subnet changes overlay.subnet in an existing bootstrap file and touches
# nothing else.
#
# The whole file is deliberately never rewritten on a re-run, because it holds
# the shared secret - the one value on a host that cannot be recovered from
# anywhere else. But the subnet is the one field somebody has a real reason to
# change later: it cannot be edited from the portal, and without it no linker
# can be configured at all. So it is edited in place, against a backup, and the
# result is checked for both keys before the backup is dropped.
patch_subnet() {
	local file="$1" want="$2" current backup
	current="$(sed -n 's/.*"subnet"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$file" | head -n1)"
	if [ "$current" = "$want" ]; then
		echo "  overlay subnet is already ${want:-none}"
		return 0
	fi

	backup="$file.bak.$$"
	cp -a "$file" "$backup"

	if grep -q '"subnet"' "$file"; then
		sed -i "s|\"subnet\"[[:space:]]*:[[:space:]]*\"[^\"]*\"|\"subnet\": \"$want\"|" "$file"
	else
		# Written by an older version of this script, which had no such line.
		sed -i "s|\(\"backend_ip\"[[:space:]]*:[[:space:]]*\"[^\"]*\",\)|\1\n    \"subnet\": \"$want\",|" "$file"
	fi

	local now psk
	now="$(sed -n 's/.*"subnet"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$file" | head -n1)"
	psk="$(sed -n 's/.*"psk"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$file" | head -n1)"
	if [ "$now" != "$want" ] || [ -z "$psk" ]; then
		mv "$backup" "$file"
		warn "could not set the overlay subnet in $file; it has been left exactly as it was"
		warn "  edit it by hand: \"subnet\": \"$want\" inside the overlay block"
		return 1
	fi
	rm -f "$backup"
	echo "  overlay subnet set to ${want:-none} in $file"
	if [ -z "$want" ]; then
		warn "clearing it leaves the widened route behind: the agent removes a /32 that a"
		warn "  subnet superseded, but has no record of a subnet to clean up going the"
		warn "  other way. Check with: ip route show | grep 10.99"
	fi
	return 0
}

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

say "Building"
if command -v go >/dev/null 2>&1; then
	version="$(git -C "$REPO" describe --tags --always 2>/dev/null || echo dev)"
	mkdir -p build
	echo "  failover-backend ($version)"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags "-s -w -X main.version=$version" -o build/failover-backend ./cmd/failover-backend
else
	warn "no Go toolchain found, using the prebuilt binary in build/"
	[ -f build/failover-backend ] || { echo "error: build/failover-backend is missing and cannot be built" >&2; exit 1; }
fi

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

# Checked before anything is installed, so a missing tool cannot leave a
# half-installed system behind. The backend shells out to nft as well as ip:
# it installs the return-marking table, and the egress table when egress
# networks are configured.
missing=""
for c in ip nft sysctl systemctl; do
	command -v "$c" >/dev/null 2>&1 || missing="$missing $c"
done
if [ -n "$missing" ]; then
	echo "error: missing required command(s):$missing" >&2
	echo "       on Debian: apt install iproute2 nftables procps" >&2
	exit 1
fi

# `wg` is not required: it is read only for handshake age, which is displayed
# for context and never influences a decision. A tunnel stays up long after the
# link beneath it has died, which is why the probes are end-to-end.
if ! command -v wg >/dev/null 2>&1; then
	warn "wg not found - handshake age will be blank in the portal (nothing else is affected)"
fi

say "Checking the environment"
for iface in wg-nbn wg-lte1 wg-lte2; do
	if ip link show "$iface" >/dev/null 2>&1; then
		echo "  $iface present"
	else
		warn "$iface does not exist - that path will probe as down until wg-quick brings it up"
	fi
done

for conf in /etc/wireguard/wg-nbn.conf /etc/wireguard/wg-lte1.conf /etc/wireguard/wg-lte2.conf; do
	[ -f "$conf" ] || continue
	if ! grep -qiE '^[[:space:]]*Table[[:space:]]*=[[:space:]]*off' "$conf"; then
		warn "$conf has no 'Table = off' - wg-quick will install competing routes"
	fi
	# The LTE services are behind CGNAT, so the frontend can never initiate.
	# Without keepalive the standby tunnels' NAT bindings expire and failing
	# over costs an extra handshake at the worst possible moment.
	if ! grep -qiE '^[[:space:]]*PersistentKeepalive' "$conf"; then
		warn "$conf has no PersistentKeepalive - standby tunnels will drop their NAT bindings"
	fi
	# AllowedIPs is a filter, not just a route. Published traffic arrives
	# carrying the client's real address, so a backend that only allows the
	# frontend's overlay address drops every request before it reaches the
	# interface - while probes and the control channel, which really do come
	# from that address, keep working perfectly.
	if ! grep -qiE '^[[:space:]]*AllowedIPs[[:space:]]*=[[:space:]]*0\.0\.0\.0/0' "$conf"; then
		warn "$conf does not set 'AllowedIPs = 0.0.0.0/0'"
		warn "  published services will not work: WireGuard will drop client traffic"
		warn "  before it reaches the interface, while probes keep reporting healthy"
	fi
done

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

say "Installing binary and unit"
install -d -m 0755 "$CONF_DIR" "$STATE_DIR"

install -m 0755 build/failover-backend "$BIN_DIR/failover-backend.new"
mv "$BIN_DIR/failover-backend.new" "$BIN_DIR/failover-backend"
echo "  $BIN_DIR/failover-backend"

install -m 0644 "deploy/$UNIT" "/etc/systemd/system/$UNIT"
echo "  /etc/systemd/system/$UNIT"

# ---------------------------------------------------------------------------
# Bootstrap config
#
# Root-owned, 0600. The unit drops CAP_DAC_OVERRIDE, so root can only read a
# file it actually owns; a config left owned by the login user makes the
# service restart-loop on "permission denied" while `sudo cat` works fine.
# ---------------------------------------------------------------------------

say "Bootstrap configuration"
if [ -f "$CONFIG" ] && [ "$FORCE_CONFIG" -eq 0 ] && [ -z "$PSK" ]; then
	echo "  $CONFIG exists, leaving it alone (--force-config to replace)"
	# ...with one exception, and only when asked for explicitly. See
	# patch_subnet.
	if [ "$SUBNET_GIVEN" -eq 1 ]; then
		patch_subnet "$CONFIG" "$SUBNET" || true
	fi
	chown root:root "$CONFIG"
	chmod 0600 "$CONFIG"
else
	if [ -f "$CONFIG" ] && [ "$FORCE_CONFIG" -eq 0 ]; then
		echo "  replacing $CONFIG with the supplied --psk"
	fi
	umask 077
	cat >"$CONFIG" <<EOF
{
  "role": "backend",
  "psk": "$PSK",
  "state_dir": "$STATE_DIR",
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
	sleep 5
	systemctl --no-pager --lines=0 status "$UNIT" || true

	say "Result"
	if journalctl -u "$UNIT" --since "-1 min" --no-pager 2>/dev/null | grep -q 'control channel connected'; then
		echo "  control channel is up; the frontend is pushing configuration down"
	else
		warn "the control channel has not connected yet"
		echo "  It retries with backoff, so give it a minute. If it stays down:"
		echo "    journalctl -u $UNIT -n 30 --no-pager"
		echo "  'i/o timeout' means the frontend cannot route back to $BACKEND_IP."
		echo "  Repeated 'dropping unauthenticated probe packets' means the psk differs."
	fi
else
	echo "  --no-start given; run: systemctl enable --now $UNIT"
fi

say "Done"
cat <<EOF
Nothing else to configure here. Paths, quotas and thresholds arrive from the
frontend's portal and are cached in $STATE_DIR/backend-config.json, so a
frontend outage cannot leave this host unable to route replies.

  journalctl -u $UNIT -f
EOF
