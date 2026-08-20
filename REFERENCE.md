# homeport reference

The detail behind [the README](README.md): how each piece works and why it
works that way. Read the README first for what the system is and whether you
want it; read [deploy/SETUP.md](deploy/SETUP.md) when you are ready to install.

The examples throughout describe a three-tunnel deployment — a fixed line and
two LTE services — because that is the arrangement with the most moving parts.
Everything except the selection policy and the quotas applies just as well to a
single tunnel.

```
                    Internet
                       │
              Debian FRONTEND  (datacentre)
                       │   probes all three, picks one, DNATs published ports
        ┌──────────────┼──────────────┐
     wg-nbn         wg-lte1        wg-lte2
        └──────────────┼──────────────┘
                    pfSense           pins each tunnel to its own WAN
                       │
              Debian BACKEND    terminates the tunnels, meters LTE usage
```

## What makes the switch invisible

Both hosts carry a fixed overlay address on a dummy interface. Failover is one
command:

```sh
ip route replace 10.99.0.2/32 dev wg-lte1 src 10.99.0.1
```

Only the outgoing interface changes. The source and destination addresses, and
therefore every client's 5-tuple, are untouched — so conntrack keeps its
entries, Source game sessions do not drop, and established TCP connections
stall for about two seconds and then carry on. No reconnect, no browser error.

Because the frontend does destination NAT and never source NAT, the game server
and the web server see **real client IPs**, for UDP as well as TCP. No proxy,
no PROXY protocol, no `X-Forwarded-For`.

## Health is measured end to end

Probes are authenticated UDP datagrams sent to the backend *through* each
tunnel, using per-path fwmarks and routing tables so that standby paths are
tested continuously and not just the active one. The question asked is "can I
reach the backend through this tunnel", never "is this interface up" — a
WireGuard interface stays up long after the link beneath it has died.

The active path is probed every 250 ms and standby paths every 5 s, because the
two answer different questions. The active path is being watched for failure and
every extra second of detection is a second of traffic going nowhere; a standby
path only has to be known-good by the time it is needed, and on a metered link
the probes are themselves billed against the quota being held in reserve. At one
second a standby tunnel spends around 650 MB a month on probes alone; at five,
around 130 MB. The cost is failback speed and nothing else — a recovered path
takes ten clean probes to read `up`, so about 50 s, before its hold-down even
starts. Both intervals are settings.

WireGuard handshake age is collected and displayed, but it never influences a
routing decision.

## Selection policy

Strict priority by default: NBN → LTE1 → LTE2.

- **Failover is immediate.** Being on a working link beats being on the
  preferred one.
- **Failback waits.** A better path must be continuously clean for the hold-down
  window (90s by default) before traffic returns, so a marginal NBN service
  cannot drag traffic back and forth.
- **A path is skipped** when it is unreachable, degraded past the loss/latency
  thresholds, quarantined by the flap circuit breaker, over its data quota, or
  switched off.
- **Nothing usable?** The last route stays installed and the system alerts. It
  never withdraws the route and blackholes traffic.

Optionally, selection can be switched to **quality**, which changes exactly one
thing: once the preferred path is out, the replacement is the best-*measuring*
eligible path rather than the next one down the list. A clean LTE2 beats an LTE1
dropping one packet in ten.

It never displaces the preferred path, however much better a fallback measures.
Priority order here is the *cost* order — NBN is unmetered and the LTE services
are capped — and a selector that simply chased the lowest score would park
traffic on a metered link and call it optimising. Moving between two fallbacks
needs a margin, a hold-down and a minimum dwell, so noise cannot cause a swap
and a genuine alternation cannot cause an endless run of them.

## LTE quotas

Per-path monthly allowances (60 GB and 20 GB by default), resetting on a
configurable day in a configurable timezone.

Usage is reconstructed as `payload bytes + packets × 60 × calibration%`,
because the carrier meters the encapsulated datagram on the WAN rather than the
payload inside the tunnel. Counting payload alone undercounts by 5–15%. The
calibration percentage is tunable per path once you have a month to compare
against the carrier's own figures.

The backend buffers metering deltas on disk whenever the control channel is
down — which is exactly when LTE data is being burned hardest.

Over quota, a path is blocked. If that leaves nothing usable, the system parks
and the portal offers a **time-boxed** approval: "use LTE2 for 24 hours" or
"allow 5 GB more". The grant expires on its own, so a 2am click cannot silently
disable quota enforcement for the rest of the month. An absolute ceiling, if
set, overrides even an approval.

> Turn notifications on. The approval policy means the system waits for a human;
> without an alert, that wait lasts until you next open the portal.

## Traffic going the other way

Off by default. Turned on, connections the *backend* originates from its overlay
address leave by the frontend's public address instead of the house's own
internet service.

This exists for Source engine server registration. A server is listed in the
browser at the address Steam observes its heartbeat coming from, and there is no
way to declare a different one. Without this the server is advertised at the
home WAN address: no port forward behind it, changes when the service does, and
unreachable entirely while a CGNAT'd LTE path is carrying traffic — so players
who found it through the browser would bypass the failover completely.

It is the one source NAT in the system, it lives in its own nftables table, and
it applies only to the opposite direction, where there is no client address to
preserve because there is no client. It is opt-in because everything else the
backend sends from that address goes the same way, and therefore through the LTE
quota during a failover.

## More than one host at the far end

Also optional, and most deployments never need it. Where the box terminating the
tunnels is not the box doing the work — a small dedicated backend that only
routes, with the game servers and the websites on separate machines behind it —
each extra host runs `failover-linker`.

A linker holds its own overlay address (`10.99.0.3`, `10.99.0.4`, …) and routes
anything sent from it to the backend, which puts it on whichever tunnel is
active. It terminates no tunnels, answers no probes, and is never told which
path is carrying traffic, because it has no use for that — the backend already
tracks the active tunnel, and a second thing that had to agree about it is the
failure mode this whole design avoids.

Extra hosts are declared in the portal under **Linkers**: a name, the overlay
address, the machine's address on the backend's network, and the routing table
it should use. Saving is what tells the backend how to reach it — the route is
installed and reconciled by the backend agent, so nothing is ever run there by
hand. The portal also generates that host's `/etc/failover/linker.json` ready to
copy, and shows the host under **Extra hosts** on the dashboard once its agent
checks in.

Services are pointed at it per port in the portal, and containers work in both
directions: published to a bridge container by connection marking, and outbound
through the frontend's address by adding the container's network under **Backend
networks routed out through the frontend** with **On host** set to that linker.

Nothing changes for a site that does not configure one: with no overlay subnet
set, the generated rules and routing commands are identical to a build without
the feature.

[`deploy/LINKER-NOTES.md`](deploy/LINKER-NOTES.md) is the field record from the
first one: the faults hit bringing it up, and how to debug this path.

## The portal

One page on the frontend, bound to an admin WireGuard interface. No
certificates, no public TCP surface, and reachable from anywhere — including
during a total path outage, because the frontend is in the datacentre on
independent internet.

It is the only place you manage the system from: live path health, usage
graphs, every setting, the activity log, the approve button, and the arm
switch. The backend has no web interface and never needs to be logged into; it
receives its configuration over the control channel and caches it locally.

## Safety

- **Observe mode** ships as the default. The agent probes, decides and logs, but
  changes nothing until it is armed.
- **Dead-man behaviour**: no usable path means keep the last route, keep
  probing, alert loudly.
- **Circuit breaker**: a path that keeps flapping is quarantined for an
  escalating cooldown instead of being switched to over and over.
- **Rollback, one command per host**: `failoverctl revert` on the frontend, then
  `failover-backend -revert`, in that order — each removes the nftables tables
  and policy routes its own agent installed. WireGuard tunnels are untouched,
  because the agent never created them, and so is the overlay address, because
  something may still be bound to it.
- **Uninstall is the same order**: `sudo ./deploy/uninstall.sh` on each host,
  frontend first. It reverts before it removes anything, and stops rather than
  strand rules the binary it is about to delete is the only thing that can take
  down.

## Build and install

Clone the repo on each host and run its script. They build the binaries,
install the systemd unit, write a root-owned bootstrap file and start the
service in observe mode.

```sh
sudo ./deploy/install-frontend.sh          # on the datacentre box
```

That generates the shared secret and prints it, along with the portal address
and the one-time admin password. Then, on the box at the house:

```sh
sudo ./deploy/install-backend.sh --psk <the value it printed>
```

Both are safe to re-run — that is how you upgrade — and leave an existing
bootstrap file alone unless `--force-config` is given. `--help` lists the
overlay and portal address options. [SETUP.md](deploy/SETUP.md) section 12
covers updating: what a restart of each agent costs, and why replacing a binary
by hand needs a `systemctl stop` while the script does not.

To build on a workstation and push instead:

```sh
make test
make build                       # static linux/amd64, CGO disabled
make deploy-frontend FRONTEND_HOST=root@dc.example.net
make deploy-backend  BACKEND_HOST=root@home.example.net
```

For an extra host behind the backend — rarely, and only after reading
[SETUP.md](deploy/SETUP.md) section 10, which covers the WireGuard change it
requires:

```sh
sudo ./deploy/install-linker.sh --psk <the frontend's psk> \
     --overlay-ip 10.99.0.3 --backend-lan 192.168.1.2
```

The bootstrap files hold only the shared secret and where to put state —
everything else lives in the portal. On first start the frontend prints a
generated portal password to the journal, exactly once:

```sh
journalctl -u failover-frontend | grep 'portal account created'
```

## Uninstall

One script for all three roles, which it works out from what is installed:

```sh
sudo ./deploy/uninstall.sh                 # revert, stop, remove the binaries
sudo ./deploy/uninstall.sh --purge         # ... and the config and state
```

Run it on the frontend first, then the backend, then any linkers — the ordering
in [SETUP.md](deploy/SETUP.md) section 8, for the same reason. It reverts while
the agent is still installed and refuses to go further if that fails, since the
binary is the only thing that knows which rules and priorities are this
system's. The bootstrap file and the state directory survive unless `--purge` is
given, and `--purge` copies the database aside first, because the usage ledger
in it cannot be recreated. WireGuard is never touched, and neither is the
overlay address unless `--overlay` says so.

**Before any of this, read [deploy/SETUP.md](deploy/SETUP.md).** The agents
assume the WireGuard tunnels and pfSense policy routing are already correct,
and there are two pfSense settings that will silently pin all three tunnels to
one link if you miss them.

## CLI

```
failoverctl status                       paths, health, quota, active route
failoverctl events [n]                   recent activity
failoverctl pin <path> | unpin           force or release a path
failoverctl approve <path> <hours> [gb]  allow an over-quota path
failoverctl revoke <path>                cancel an overage approval
failoverctl clear-quarantine <path>      lift the circuit breaker on a path
failoverctl mode <observe|armed>         arm or disarm
failoverctl revert                       remove every system change
failoverctl version
```

`failoverctl` is the frontend's CLI and reverts the frontend. The backend has a
half of its own — the reply rules, table 100's default route, the marking table
and the routes to any extra hosts — which comes down with `failover-backend
-revert`, run **after** the frontend's. The other order breaks every published
service for as long as it lasts: requests keep arriving down the tunnel while
their replies leave by the LAN, where the client's flow has no state.

On a linker there is no CLI. It appears in the portal under **Extra hosts** —
connected or not, its build and how long it has been up — but everything it does
is driven from the frontend. `failover-linker -revert` removes the routing and
the marking it installed, leaving the overlay address in place so anything bound
to it keeps listening.

## Layout

```
cmd/failover-frontend    probing, selection, DNAT, control server, portal
cmd/failover-backend     probe responder, return routing, LTE metering
cmd/failover-linker      optional extra host: overlay address, route to backend
cmd/failoverctl          CLI over the frontend's local unix socket
internal/engine          decision loop, probers, per-path state machines
internal/agent           backend responder, meter, control client
internal/linker          the linker agent: routing, container marking, control client
internal/quota           billing periods, metering, enforcement
internal/sysx            ip / nft / sysfs interaction, observe-mode runner
internal/proto           authenticated probe packet and control frames
internal/store           SQLite: config, ledger, history, events
internal/web             portal and JSON API
```

## Further reading

- [README.md](README.md) — what this is and whether you want it
- [deploy/SETUP.md](deploy/SETUP.md) — installation, WireGuard and pfSense
- [deploy/LINKER-NOTES.md](deploy/LINKER-NOTES.md) — the field record from the
  first multi-host deployment
- [CLAUDE.md](CLAUDE.md) — the design reasoning, invariants and traps, written
  for anyone about to change the code
