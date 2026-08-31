#!/usr/bin/env bash
#
# Remove a failover agent from this host - frontend, backend or linker.
#
#   sudo ./deploy/uninstall.sh                  # remove the agent and its files
#   sudo ./deploy/uninstall.sh --keep-state     # ... but keep the database
#
# This is the counterpart to the three install scripts, and it does what they
# did, backwards: it reverts the system changes, stops and disables the unit,
# and removes the unit file, the binaries, the bootstrap config and the state
# directory. Uninstalled means gone, so keeping things is what takes a flag.
# The frontend's database is copied aside before it goes.
#
# It needs nothing from the repository, so it can be copied to a host on its
# own. The role is worked out from what is installed here.
#
# ORDER MATTERS ACROSS HOSTS. Run this on the frontend first, then the backend,
# then any linkers - the same order as the manual rollback in SETUP.md. Taking
# the backend's reply path down while the frontend is still armed and DNATing
# breaks every published service on the spot: requests keep arriving down the
# tunnel and their replies leave by the LAN to pfSense, where the client's flow
# has no state.
#
# What is never touched, on any host and with any flag:
#
#   - WireGuard. The agents did not create the tunnels and nothing here reads
#     or writes /etc/wireguard.
#   - Routing tables that belong to the host. A revert deletes the entries this
#     system installed, by priority, and never flushes a table - a box that
#     already policy-routes keeps its own rules in 100, 200 and 101-103.
#   - The overlay address, unless --overlay is given. Something may still be
#     bound to it, and taking it away from a service that is mid-connection is
#     not this script's decision to make by default.

set -euo pipefail

BIN_DIR=/usr/local/bin
CONF_DIR=/etc/failover

ROLE=""
KEEP_CONFIG=0
KEEP_STATE=0
BACKUP=1
REVERT=1
OVERLAY=0
FORCE=0
YES=0

usage() {
	cat <<EOF
usage: sudo $0 [options]

  --frontend         uninstall the frontend (detected if only one is present)
  --backend          uninstall the backend
  --linker           uninstall the linker
  --keep-config      leave $CONF_DIR/<role>.json in place, so a reinstall
                     picks up the same shared secret. It is the one value on
                     this host that cannot be recovered from anywhere else,
                     though the other hosts have the same string.
  --keep-state       leave the state directory in place. On the frontend that
                     is the database: the whole configuration and the usage
                     ledger, which is what a reinstall would otherwise start
                     from nothing.
  --no-backup        do not copy failover.db aside before removing it. The
                     ledger is the part that cannot be recreated: losing it
                     resets metered-byte accounting mid-period, so both LTE
                     paths believe they have a full month of headroom.
  --no-revert        leave the routing and nftables changes in place. For the
                     case where they were already reverted, or where the data
                     plane must keep working while the agent goes away.
  --overlay          also remove this host's overlay address, and dummy0 with
                     it if nothing else is on it.
  --force            carry on even if the revert failed. Without this the
                     script stops before removing the binary, because the
                     binary is the only thing that can take those rules down.
  --yes              do not ask for confirmation. Required when this is not
                     run on a terminal.
  -h, --help         this message
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
	--frontend) ROLE=frontend; shift ;;
	--backend) ROLE=backend; shift ;;
	--linker) ROLE=linker; shift ;;
	--keep-config) KEEP_CONFIG=1; shift ;;
	--keep-state) KEEP_STATE=1; shift ;;
	--purge)
		# It was opt-in for one day. Anything that learned the old spelling
		# should say so rather than quietly doing something else.
		echo "note: --purge is the default now; --keep-config and --keep-state are the opposites" >&2
		shift
		;;
	--no-backup) BACKUP=0; shift ;;
	--no-revert) REVERT=0; shift ;;
	--overlay) OVERLAY=1; shift ;;
	--force) FORCE=1; shift ;;
	--yes | -y) YES=1; shift ;;
	-h | --help) usage; exit 0 ;;
	*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
	esac
done

if [ "$(id -u)" -ne 0 ]; then
	echo "error: run this with sudo - it stops a systemd unit and changes routing" >&2
	exit 1
fi

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[33mwarning: %s\033[0m\n' "$*" >&2; }

# ---------------------------------------------------------------------------
# Role
#
# Worked out from what is actually installed rather than asked for, because the
# answer is on the disk and getting it wrong reverts the wrong host. A machine
# carrying two of them is not a supported arrangement, so it is a question
# rather than a guess.
# ---------------------------------------------------------------------------

detect_role() {
	local found=""
	for r in frontend backend linker; do
		if [ -f "$CONF_DIR/$r.json" ] ||
			[ -f "/etc/systemd/system/failover-$r.service" ] ||
			[ -x "$BIN_DIR/failover-$r" ]; then
			found="$found $r"
		fi
	done
	printf '%s' "${found# }"
}

if [ -z "$ROLE" ]; then
	found="$(detect_role)"
	case "$found" in
	"")
		echo "error: nothing to uninstall - no failover config, unit or binary on this host" >&2
		exit 1
		;;
	*" "*)
		echo "error: more than one agent is installed here ($found)" >&2
		echo "       say which one: --frontend, --backend or --linker" >&2
		exit 2
		;;
	*) ROLE="$found" ;;
	esac
fi

UNIT="failover-$ROLE.service"
CONFIG="$CONF_DIR/$ROLE.json"
case "$ROLE" in
frontend) BINARIES="failover-frontend failoverctl" ;;
backend) BINARIES="failover-backend" ;;
linker) BINARIES="failover-linker" ;;
esac

# ---------------------------------------------------------------------------
# Read the bootstrap file before anything is removed
#
# The state directory, the database path and the overlay address all live in
# it, and --purge deletes it. Parsed with sed rather than a JSON tool: this has
# to work on a bare Debian box, and the file is one this system wrote.
# ---------------------------------------------------------------------------

jstr() { sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$2" | head -n1; }

STATE_DIR=/var/lib/failover
DB_PATH=""
OVERLAY_IP=""
OVERLAY_DEV=dummy0

if [ -f "$CONFIG" ]; then
	v="$(jstr state_dir "$CONFIG")"
	if [ -n "$v" ]; then STATE_DIR="$v"; fi
	DB_PATH="$(jstr db_path "$CONFIG")"
	v="$(jstr device "$CONFIG")"
	if [ -n "$v" ]; then OVERLAY_DEV="$v"; fi
	case "$ROLE" in
	frontend) OVERLAY_IP="$(jstr frontend_ip "$CONFIG")" ;;
	backend) OVERLAY_IP="$(jstr backend_ip "$CONFIG")" ;;
	linker) OVERLAY_IP="$(jstr overlay_ip "$CONFIG")" ;;
	esac
else
	warn "$CONFIG is missing; assuming state in $STATE_DIR"
	if [ "$OVERLAY" -eq 1 ]; then
		warn "--overlay cannot work out which address to remove without it"
	fi
fi
[ -n "$DB_PATH" ] || DB_PATH="$STATE_DIR/failover.db"

# ---------------------------------------------------------------------------
# Confirm
# ---------------------------------------------------------------------------

say "About to uninstall the $ROLE from $(hostname)"
echo "  revert system changes:  $([ "$REVERT" -eq 1 ] && echo yes || echo 'no (--no-revert)')"
echo "  stop and disable:       $UNIT"
bins=""
for b in $BINARIES; do bins="$bins $BIN_DIR/$b"; done
echo "  remove binaries:       $bins"
if [ "$KEEP_CONFIG" -eq 1 ]; then
	echo "  keep config:            $CONFIG"
else
	echo "  remove config:          $CONFIG (the shared secret goes with it)"
fi
if [ "$KEEP_STATE" -eq 1 ]; then
	echo "  keep state:             $STATE_DIR"
else
	echo "  remove state:           $STATE_DIR"
	if [ "$ROLE" = frontend ]; then
		if [ "$BACKUP" -eq 1 ]; then
			echo "  database:               $DB_PATH (copied aside first)"
		else
			echo "  database:               $DB_PATH (NOT backed up)"
		fi
	fi
fi
if [ "$OVERLAY" -eq 1 ]; then
	echo "  remove overlay address: ${OVERLAY_IP:-unknown} on $OVERLAY_DEV"
fi
if [ "$ROLE" = frontend ]; then
	echo
	echo "  Do the backend next, and any linkers after that. Published services"
	echo "  break in the meantime only if you do it the other way round."
fi

if [ "$YES" -eq 0 ]; then
	if [ ! -r /dev/tty ]; then
		echo >&2
		echo "error: not a terminal, and this removes things - pass --yes to confirm" >&2
		exit 2
	fi
	printf '\ncontinue? [y/N] '
	read -r answer </dev/tty || answer=""
	case "$answer" in
	y | Y | yes | YES) ;;
	*) echo "nothing was changed"; exit 1 ;;
	esac
fi

# ---------------------------------------------------------------------------
# Revert
#
# First, and while the agent is still installed: this is the step that takes the
# DNAT table, the policy rules and the routes back out, and the binary about to
# be deleted is the only thing that knows what they were.
#
# Installed, but not running, on the backend and the linker. Their reverts are
# separate processes and cannot tell the agent anything, while the agent's
# reconciler re-reads the kernel every ten seconds and puts back everything it
# finds missing: the probe tables and their rules, the overlay route, the routes
# to every extra host. Reverting underneath a live agent leaves a half reverted
# host that reports itself clean, and then deletes the only binary that could
# have finished the job.
#
# The frontend is the exception and needs the opposite. Its revert goes over the
# local control socket into the running engine, which is also what disarms it,
# so it must be up: a stopped or crashed frontend is exactly the state somebody
# uninstalling is likely to be in, so it is started for the purpose and stopped
# again below. That reinstalls nothing that was not already installed: an armed
# agent's rules are on the host whether the process is running or not.
# ---------------------------------------------------------------------------

reverted=0

revert_frontend() {
	local sock="$STATE_DIR/ctl/ctl.sock" started=0 i
	[ -x "$BIN_DIR/failoverctl" ] || { warn "failoverctl is not installed; cannot revert"; return 1; }
	if [ ! -S "$sock" ]; then
		if [ -f "/etc/systemd/system/$UNIT" ]; then
			echo "  the control socket is absent; starting $UNIT to revert through it"
			systemctl start "$UNIT" >/dev/null 2>&1 || true
			started=1
			for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
				if [ -S "$sock" ]; then break; fi
				sleep 1
			done
		fi
	fi
	if [ ! -S "$sock" ]; then
		warn "no control socket at $sock"
		if [ "$started" -eq 1 ]; then
			systemctl stop "$UNIT" >/dev/null 2>&1 || true
		fi
		return 1
	fi
	"$BIN_DIR/failoverctl" -socket "$sock" revert
}

# stop_agent takes the unit down before an agent reverts itself. See the note
# above: the reconciler would put the routing back within ten seconds of the
# revert removing it, and the binary that knows what to remove is deleted below.
# Not for the frontend, whose revert needs its agent up.
#
# The stop is unconditional. `is-active` answers no for a unit that is
# 'activating' - mid-start, or sitting in a Restart= loop, which is a likely
# state for an agent somebody is uninstalling - and a unit skipped on that
# answer finishes starting seconds later and reinstalls everything the revert
# just removed. `systemctl stop` is a no-op on a unit that is already down and
# cancels one that is on its way up, so there is nothing to gain by asking
# first; the state is only read to keep the final report honest about whether
# anything was actually running.
AGENT_WAS_UP=0
stop_agent() {
	# 'deactivating' counts as up: a unit caught mid-stop was serving moments
	# ago, and telling the operator it "was not running to begin with" would
	# be the report lying in the other direction.
	case "$(systemctl is-active "$UNIT" 2>/dev/null)" in
	active | activating | reloading | deactivating) AGENT_WAS_UP=1 ;;
	esac
	if [ "$AGENT_WAS_UP" -eq 1 ]; then
		echo "  stopping $UNIT first, so its reconciler cannot reinstall what this removes"
	else
		echo "  $UNIT is not running; stopping it anyway in case it is on its way up"
	fi
	systemctl stop "$UNIT" >/dev/null 2>&1 || true
	systemctl reset-failed "$UNIT" >/dev/null 2>&1 || true
}

if [ "$REVERT" -eq 1 ]; then
	say "Reverting system changes"
	case "$ROLE" in
	frontend)
		if revert_frontend; then reverted=1; fi
		;;
	backend)
		stop_agent
		if [ -x "$BIN_DIR/failover-backend" ] && [ -f "$CONFIG" ]; then
			if "$BIN_DIR/failover-backend" -config "$CONFIG" -revert; then reverted=1; fi
		else
			warn "need both $BIN_DIR/failover-backend and $CONFIG to revert"
		fi
		;;
	linker)
		stop_agent
		if [ -x "$BIN_DIR/failover-linker" ] && [ -f "$CONFIG" ]; then
			if "$BIN_DIR/failover-linker" -config "$CONFIG" -revert; then reverted=1; fi
		else
			warn "need both $BIN_DIR/failover-linker and $CONFIG to revert"
		fi
		;;
	esac

	if [ "$reverted" -eq 1 ]; then
		echo "  reverted"
	elif [ "$FORCE" -eq 1 ]; then
		warn "the revert failed and --force was given; continuing"
		warn "  rules this agent installed are still on this host and nothing left"
		warn "  here can remove them - see the end of this output"
	else
		cat >&2 <<EOF

error: the revert did not succeed, so nothing has been removed.

  The binary is the only thing that knows which rules, routes and priorities
  belong to this system, so removing it now would strand them: a revert deletes
  what it installed rather than flushing a table, and by hand that means
  matching every rule by priority.

  Fix the revert and re-run, or accept the leftovers with --force:
EOF
		case "$ROLE" in
		frontend) echo "    systemctl start $UNIT && failoverctl revert" >&2 ;;
		backend) echo "    failover-backend -revert" >&2 ;;
		linker) echo "    failover-linker -revert" >&2 ;;
		esac
		if [ "$ROLE" != frontend ]; then
			echo >&2
			if [ "$AGENT_WAS_UP" -eq 1 ]; then
				echo "  $UNIT was stopped for the revert and has been left stopped, so that" >&2
				echo "  nothing reinstalls the rules underneath you. 'systemctl start $UNIT'" >&2
				echo "  puts the agent back if you would rather keep serving for now." >&2
			else
				echo "  $UNIT was not running to begin with and has been left that way." >&2
			fi
		fi
		exit 1
	fi
fi

# ---------------------------------------------------------------------------
# Stop
# ---------------------------------------------------------------------------

say "Stopping and disabling $UNIT"
systemctl disable --now "$UNIT" >/dev/null 2>&1 || true
systemctl stop "$UNIT" >/dev/null 2>&1 || true
if [ -f "/etc/systemd/system/$UNIT" ]; then
	rm -f "/etc/systemd/system/$UNIT"
	echo "  removed /etc/systemd/system/$UNIT"
fi
systemctl daemon-reload
systemctl reset-failed "$UNIT" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# Overlay address
#
# After the unit is stopped, never before: the reconcilers re-read the kernel
# every 10s and put back anything missing, so an address removed from under a
# running agent is back within the tick.
#
# Left in place by default. Revert deliberately does not touch it either - a
# service may be bound to it, and on the backend the whole point of binding to
# it is that traffic then leaves by the frontend's public address.
# ---------------------------------------------------------------------------

if [ "$OVERLAY" -eq 1 ]; then
	say "Overlay address"
	if [ -z "$OVERLAY_IP" ]; then
		warn "no overlay address known for this host; nothing removed"
	elif ip -4 -o addr show dev "$OVERLAY_DEV" 2>/dev/null | grep -q " $OVERLAY_IP/"; then
		if ip addr del "$OVERLAY_IP/32" dev "$OVERLAY_DEV"; then
			echo "  removed $OVERLAY_IP from $OVERLAY_DEV"
		fi
		# The device only goes if it is empty. A dummy interface is a normal
		# thing for a host to have of its own, and one carrying another address
		# is plainly not ours to delete.
		if [ -z "$(ip -4 -o addr show dev "$OVERLAY_DEV" 2>/dev/null)" ] &&
			[ -z "$(ip -6 -o addr show dev "$OVERLAY_DEV" scope global 2>/dev/null)" ]; then
			if ip link delete "$OVERLAY_DEV" 2>/dev/null; then
				echo "  removed $OVERLAY_DEV, which held nothing else"
			fi
		else
			echo "  left $OVERLAY_DEV in place; it carries other addresses"
		fi
	else
		echo "  $OVERLAY_IP is not on $OVERLAY_DEV; nothing to do"
	fi
fi

# ---------------------------------------------------------------------------
# Binaries
# ---------------------------------------------------------------------------

say "Removing binaries"
for b in $BINARIES; do
	if [ -e "$BIN_DIR/$b" ]; then
		rm -f "$BIN_DIR/$b"
		echo "  removed $BIN_DIR/$b"
	fi
	rm -f "$BIN_DIR/$b.new" # an install interrupted between install and mv
done

# ---------------------------------------------------------------------------
# Config and state
#
# Only with --purge, and by name rather than by emptying the directory: the
# state directory is this system's, but the same cannot be assumed of anything
# an operator has put beside its files. Whatever is left is reported instead.
# ---------------------------------------------------------------------------

if [ "$KEEP_CONFIG" -eq 0 ] || [ "$KEEP_STATE" -eq 0 ]; then
	say "Removing configuration and state"

	if [ "$KEEP_STATE" -eq 0 ] && [ "$ROLE" = frontend ] && [ -f "$DB_PATH" ] && [ "$BACKUP" -eq 1 ]; then
		backup="/root/failover.db.$(date +%Y%m%d-%H%M%S).bak"
		cp -a "$DB_PATH" "$backup"
		chmod 0600 "$backup"
		echo "  copied the database to $backup"
		echo "  it holds the usage ledger as well as the configuration; restoring it"
		echo "  is a matter of copying it back before the new agent first starts"
	fi

	if [ "$KEEP_STATE" -eq 0 ]; then
		case "$ROLE" in
		frontend) files="failover.db failover.db-wal failover.db-shm ruleset.nft egress.nft protect.nft blocklist.nft blocklist-feed.nft blocklist-cache.json" ;;
		backend) files="backend-config.json usage-buffer.jsonl meter-state.json return.nft egress.nft" ;;
		linker) files="linker-return.nft linker-egress.nft" ;;
		esac
		for f in $files; do
			[ -e "$STATE_DIR/$f" ] || continue
			rm -f "$STATE_DIR/$f"
			echo "  removed $STATE_DIR/$f"
		done
		# The database can sit outside the state directory, and the frontend's
		# control socket lives in a subdirectory of it.
		if [ "$ROLE" = frontend ]; then
			rm -f "$DB_PATH" "$DB_PATH-wal" "$DB_PATH-shm"
			rm -rf "$STATE_DIR/ctl"
		fi
	fi

	if [ "$KEEP_CONFIG" -eq 0 ] && [ -f "$CONFIG" ]; then
		rm -f "$CONFIG"
		echo "  removed $CONFIG"
	fi

	for d in "$STATE_DIR" "$CONF_DIR"; do
		[ -d "$d" ] || continue
		if [ -z "$(ls -A "$d" 2>/dev/null)" ]; then
			rmdir "$d"
			echo "  removed $d"
		else
			echo "  left $d in place; it is not empty:"
			ls -A "$d" | sed 's/^/    /'
		fi
	done
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

say "Done"
cat <<EOF
The $ROLE is gone from this host.

Untouched, deliberately:
  - /etc/wireguard and every tunnel. The agent never created them.
  - Routing tables that predate this system. A revert removes its own rules by
    the priority it found them at and never flushes a table.
EOF
if [ "$OVERLAY" -eq 0 ] && [ -n "$OVERLAY_IP" ]; then
	echo "  - $OVERLAY_IP on $OVERLAY_DEV. Remove it with"
	echo "    'ip addr del $OVERLAY_IP/32 dev $OVERLAY_DEV', or re-run with --overlay."
fi
if [ "$KEEP_CONFIG" -eq 1 ]; then
	echo "  - $CONFIG, so a reinstall keeps the shared secret."
fi
if [ "$KEEP_STATE" -eq 1 ]; then
	if [ "$ROLE" = frontend ]; then
		echo "  - $STATE_DIR, so a reinstall keeps the configuration and the usage ledger."
	else
		echo "  - $STATE_DIR."
	fi
fi

if [ "$reverted" -eq 0 ] && [ "$REVERT" -eq 1 ]; then
	cat <<EOF

WHAT IS STILL INSTALLED, because the revert did not run:
  nftables tables beginning 'failover', and the policy rules and routes this
  agent added. Reinstall the agent and revert properly, or list them with:
    nft list tables | grep failover
    ip rule show
EOF
fi

case "$ROLE" in
frontend) echo "
Next: 'sudo ./deploy/uninstall.sh' on the backend, then on each linker." ;;
esac
