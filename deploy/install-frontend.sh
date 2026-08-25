#!/usr/bin/env bash
#
# Install the failover frontend on this host (the datacentre box).
#
#   git clone https://github.com/Minc3/homeport.git && cd homeport
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
# Derived from the overlay addresses below unless --subnet says otherwise: the
# /24 they sit in, so the shipped 10.99.0.1 and .2 give 10.99.0.0/24. It must
# match on every host and be covered by AllowedIPs on the frontend's peers,
# which the shipped WireGuard setup already is. See SETUP.md step 14.
#
# Wide by default for the same reason AllowedIPs is: on a site with one host at
# the far end everything it enables is inert, because nothing holds the other
# addresses - while not having it is a two-host file edit and two restarts at
# the moment somebody is trying to add a second machine. --subnet '' opts out.
SUBNET=""
SUBNET_GIVEN=0
FORCE_CONFIG=0
START=1

usage() {
	cat <<EOF
usage: sudo $0 [options]

  --psk <hex>        shared secret; must be identical on the backend.
                     Generated if omitted and no config exists yet.
  --portal <addr>    portal listen address. Defaults to the address on
                     wg-admin, port 8088, e.g. 10.98.0.2:8088. With that tunnel
                     down there is no address to read, and the portal falls back
                     to 127.0.0.1:8088 - local to the frontend and nothing else.
  --public-iface <n> the interface facing the internet, e.g. ens3. Detected
                     from the default route, and confirmed with you when this
                     is run on a terminal.
  --no-ask           never prompt; take the detected value or leave it unset.
  --frontend-ip <ip> frontend overlay address (default $FRONTEND_IP)
  --backend-ip <ip>  backend overlay address (default $BACKEND_IP)
  --subnet <cidr>    overlay subnet. Defaults to the /24 the overlay addresses
                     sit in, e.g. 10.99.0.0/24, and must match on every host.
                     Pass '' for none, which is all a site that will never run
                     a linker needs. On a re-run this is the one field that can
                     be changed in an existing config: it is patched in place,
                     leaving the shared secret alone.
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

# ---------------------------------------------------------------------------
# Build
#
# A prebuilt binary in build/ is used if there is no Go toolchain, so the same
# script works on a box that only ever receives artefacts.
# ---------------------------------------------------------------------------

say "Building"
if command -v go >/dev/null 2>&1; then
	version="$(git -C "$REPO" describe --tags --always 2>/dev/null || echo dev)"
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
for iface in wg-main wg-lte1 wg-lte2; do
	if ip link show "$iface" >/dev/null 2>&1; then
		echo "  $iface present"
	else
		warn "$iface does not exist - that path will probe as down until wg-quick brings it up"
	fi
done

if ! ip link show wg-admin >/dev/null 2>&1; then
	warn "wg-admin does not exist - the portal cannot bind until wg-quick brings it up"
fi

# The tunnels must not install their own routes, or all three fight over the
# same destination and the per-path tables become meaningless.
for conf in /etc/wireguard/wg-main.conf /etc/wireguard/wg-lte1.conf /etc/wireguard/wg-lte2.conf; do
	if [ -f "$conf" ] && ! grep -qiE '^[[:space:]]*Table[[:space:]]*=[[:space:]]*off' "$conf"; then
		warn "$conf has no 'Table = off' - wg-quick will install competing routes"
	fi
done

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
# Portal address
# ---------------------------------------------------------------------------

# An existing bootstrap file is never rewritten, so on an upgrade there is
# nothing to ask about: the answer would only be discarded. Decided before the
# address is worked out, because on a re-run the file already holds one and
# detecting a second is worse than useless - it would warn about a fallback the
# agent is never going to use.
if [ -f "$CONFIG" ] && [ "$FORCE_CONFIG" -eq 0 ]; then
	WRITE_CONFIG=0
else
	WRITE_CONFIG=1
fi

PORTAL_FALLBACK=0

if [ "$WRITE_CONFIG" -eq 0 ]; then
	existing_portal="$(sed -n 's/.*"portal_listen"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CONFIG" | head -n1)"
	if [ -n "$existing_portal" ]; then
		if [ -n "$PORTAL" ] && [ "$PORTAL" != "$existing_portal" ]; then
			warn "--portal $PORTAL was ignored: $CONFIG already sets $existing_portal"
			warn "  edit it there and restart, or re-run with --force-config"
		fi
		PORTAL="$existing_portal"
	fi
elif [ -z "$PORTAL" ]; then
	admin_ip="$(ip -4 -o addr show wg-admin 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1 || true)"
	if [ -n "$admin_ip" ]; then
		PORTAL="$admin_ip:8088"
		echo "  portal will bind $PORTAL (from wg-admin)"
	else
		# The usual cause is that the admin tunnel has not been brought up yet,
		# and the fallback is deliberately a loopback address rather than a
		# guess: the portal is the only way to arm the agent or approve an
		# overage, and one bound to a wrong or public address is worse than one
		# that is plainly local-only. It is a bootstrap value the portal cannot
		# edit - the address it is served on is not something it can change out
		# from under itself - so fixing it is a file and a restart.
		PORTAL="127.0.0.1:8088"
		PORTAL_FALLBACK=1
		if ip link show wg-admin >/dev/null 2>&1; then
			warn "wg-admin has no IPv4 address, so the portal falls back to $PORTAL"
		else
			warn "wg-admin is not up, so the portal falls back to $PORTAL"
		fi
		warn "which is reachable from this host and nowhere else"
		cat >&2 <<EOF

  Bring the admin tunnel up, then point the portal at it:

    systemctl enable --now wg-quick@wg-admin
    ip -4 addr show wg-admin
    editor $CONFIG
    systemctl restart $UNIT

  The third step is one field - "portal_listen": "10.98.0.2:8088", using the
  address the second step printed. Or re-run this script with --portal
  <ip>:8088 and it will write that instead.

  The tunnel itself is /etc/wireguard/wg-admin.conf, which no install script
  writes; the configuration this expects is in deploy/SETUP.md section 2.

EOF
	fi
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
install -d -m 0755 "$CONF_DIR"
# The state directory is 0700, unlike the backend's and the linker's, because
# of what is in this one: failover.db holds portal session tokens in the clear
# beside the password hashes, so anything able to read it has a thirty-day
# login to the portal - which serves the shared secret, arms the data plane and
# reverts it. `install -d` applies the mode to a directory that already exists,
# so this corrects an install made before that was understood. The agent sets
# the same mode on every start and the unit asks systemd for it; all three are
# here because they cover different moments.
install -d -m 0700 "$STATE_DIR"

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
	# ...with one exception, and only when asked for explicitly. See
	# patch_subnet: it is the field that cannot be set from the portal and
	# without which no linker can be configured at all.
	if [ "$SUBNET_GIVEN" -eq 1 ]; then
		patch_subnet "$CONFIG" "$SUBNET" || true
		echo "  the backend needs the identical value:"
		echo "    sudo ./deploy/install-backend.sh --subnet '$SUBNET'"
	fi
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

if [ "$PORTAL_FALLBACK" -eq 1 ]; then
	cat <<EOF

The portal is on loopback, because wg-admin had no address when this ran, so it
is reachable from this host and nowhere else. Until the admin tunnel is up,
'ssh -L 8088:127.0.0.1:8088 <this host>' gets a browser onto it.

To move it onto the tunnel:

  systemctl enable --now wg-quick@wg-admin
  ip -4 addr show wg-admin
  editor $CONFIG
  systemctl restart $UNIT

Set "portal_listen" to that address with :8088 on the end. The tunnel itself is
/etc/wireguard/wg-admin.conf, and deploy/SETUP.md section 2 is the configuration
this expects.

Nothing else is waiting on it. The portal retries its listen every 5s rather
than exiting - it must never be able to take the agent down - so the probing,
the decisions and the control channel are running either way, and
'failoverctl status' works over the local socket regardless.
EOF
fi

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
