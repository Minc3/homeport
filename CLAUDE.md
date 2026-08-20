# homeport — orientation for an AI agent

Read this before changing anything. The design has several load-bearing
decisions that look like arbitrary complexity until you know why they are
there, and undoing one of them breaks the system in ways that are hard to
notice from a passing test run.

If you only read one section, read **Invariants** and **Why it is like this**.

If you are working on linkers specifically, read
[`deploy/LINKER-NOTES.md`](deploy/LINKER-NOTES.md) as well. This file has the
design reasoning; that one is the field record from the first real deployment —
which faults were hit, in what order, what each looked like at the time, and
what is still unfinished.

---

## 1. What the system does

A Garry's Mod server and some websites are hosted on a Debian box at a house.
They are published to the internet from a Debian box in a datacentre. Between
the two are three WireGuard tunnels riding three different internet services —
NBN (fixed line), and two LTE services.

The job: give the datacentre box **one stable path** to the home box, and move
it between the three tunnels automatically when one fails, without players
being disconnected and without silently burning through LTE data caps.

```
                    Internet
                       │
              Debian FRONTEND  (datacentre, public IP, always reachable)
                       │
        ┌──────────────┼──────────────┐
     wg-nbn         wg-lte1        wg-lte2
        └──────────────┼──────────────┘
                    pfSense       (pins each tunnel to a fixed WAN, nothing more)
                       │
              Debian BACKEND    (terminates all three tunnels)
```

Two binaries: `failover-frontend` (the brain) and `failover-backend` (thin
helper). Plus `failoverctl`, a CLI over a local unix socket.

There is a fourth, `failover-linker`, and most sites never run it. It is for the
arrangement where the box terminating the tunnels is not the box doing the work:
a small dedicated backend that only routes, with the game servers and the
websites on separate machines behind it. **Treat it as an addon throughout.** A
site that has not configured one must generate byte-identical rules and
identical `ip` commands to a build that had never heard of it — see invariant
19.

**The frontend is authoritative for everything.** The backend makes no
decisions, has no web interface, and never needs to be logged into.

---

## 2. Working with the repo

```sh
go test ./...                    # all tests, no network or root needed
go vet ./...
gofmt -w ./cmd ./internal

# static linux/amd64, no CGO (modernc.org/sqlite is pure Go)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o build/failover-frontend ./cmd/failover-frontend

make build                       # frontend, backend, failoverctl
make linker                      # the optional extra-host agent, on its own
make deploy-frontend FRONTEND_HOST=root@dc
make deploy-backend  BACKEND_HOST=root@home
make deploy-linker   LINKER_HOST=root@gs1     # one host at a time
```

Rolling back takes one command per host, in this order (see invariant 8):

```sh
failoverctl revert                            # frontend, first
failover-backend -revert                      # backend, second
failover-linker -revert                       # each extra host, if any
```

Removing an agent entirely is `sudo ./deploy/uninstall.sh` on each host, in that
same order. It runs the revert above first, while the binary that knows what it
installed is still there, and refuses to remove anything if that fails. Config
and state survive unless `--purge` is given; WireGuard and the overlay address
survive regardless.

- **Commit straight to `main`.** No feature branches, no PRs — this is a
  single-operator repo and the branch would only ever be merged by the person
  who wrote it. Do not create one "to be safe"; just commit.
- Go 1.25. Module `github.com/quinlan102/homeport`.
- **One external dependency**: `modernc.org/sqlite`. Keep it that way unless
  there is a strong reason — CGO must stay disabled so the binaries are static.
- Development happens on Windows, deployment is Debian. Linux-only code goes in
  `_linux.go` files with a `!linux` stub beside it (see `internal/sysx/mark_*.go`),
  so the tree still builds and tests on the dev machine.
- **Line endings are LF everywhere**, pinned by `.gitattributes`. Without it
  `core.autocrlf` hands the Windows working tree CRLF while the blobs stay LF,
  and `gofmt -l` then reports every Go file as unformatted. The check above
  is then useless, and `gofmt -w` rewrites the tree, burying whatever change it was
  run alongside. If you clone and see that, your git predates the file: `git rm
  -r --cached . && git reset --hard` re-checks-out with the right endings.
- System interaction is done by shelling out to `ip`, `nft`, `wg` and `sysctl`
  rather than via netlink libraries. This is deliberate: the commands are the
  same ones an operator would type, so failures are diagnosable and the observe
  mode journal is human-readable.

---

## 3. The core mechanism, in one command

Everything else in this repo exists to decide *when* to run this:

```sh
ip route replace 10.99.0.2/32 dev wg-lte1 src 10.99.0.1
```

Both hosts carry a fixed overlay address on a **dummy interface**:

- frontend `10.99.0.1/32` on `dummy0`
- backend `10.99.0.2/32` on `dummy0`

Failover changes only the outgoing interface. The source and destination
addresses never change, so:

- conntrack keeps its entries — the DNAT binding for a player's UDP flow stays
  valid,
- the client's 5-tuple is untouched — srcds sees the same peer,
- established TCP connections stall for ~2s, retransmit, and continue.

That is why a failover is a brief freeze rather than a mass disconnect. If you
ever find yourself putting the overlay address on a tunnel interface, or adding
SNAT, or terminating traffic in a userspace proxy, you have destroyed this
property.

The three tunnels also each get their own routing table (101/102/103) and
fwmark, purely so the prober can reach the backend through **one specific
tunnel** regardless of which one is active.

---

## 4. Package map

| Package | Role |
|---|---|
| `internal/model` | Config and runtime types shared by the agents. `Defaults()` is the shipped configuration. `Bootstrap` is the tiny on-disk file each agent reads at startup. |
| `internal/proto` | Wire formats. The 66-byte authenticated probe packet, and the newline-delimited JSON control frames. |
| `internal/sysx` | Everything that touches the OS: `ip`/`nft`/`wg`/sysfs, plus the `Runner` abstraction that implements observe mode. |
| `internal/engine` | Frontend brain: probers, per-path health trackers, the selector, the applier, the control server. |
| `internal/agent` | Backend: probe responder, return-route management, LTE metering, control client. |
| `internal/linker` | Optional extra host: overlay address, one policy route to the backend, connection marking so containers can be published, a control client, a reconciler. No probes, no decisions, no metering. |
| `internal/quota` | Billing periods, metered-byte reconstruction, enforcement decisions. |
| `internal/store` | SQLite. Config, usage ledger, history, events, grants, users/sessions. |
| `internal/web` | Portal HTTP server, JSON API, config validation, embedded static assets. |
| `internal/notify` | Outbound alerts (ntfy / telegram / webhook). |

### Frontend files worth knowing

- `engine/engine.go` — the `Engine` struct and its `Run` loop. `selectPath` is
  the policy; `evaluate` computes blocks and applies the choice;
  `reconcileRouting` puts back what the kernel discarded (see invariant 18).
- `engine/tracker.go` — per-path health state machine. Knows nothing about
  priorities or quotas by design.
- `engine/prober.go` — one UDP prober per path, plus the sliding `Window` used
  for loss/RTT/jitter.
- `engine/control.go` — accepts the backend's connection, pushes config, folds
  in usage deltas.
- `sysx/route.go` — every routing command, with the addressing model explained
  in comments. Also the kernel readbacks the reconcilers depend on (`RouteVia`,
  `DefaultVia`, `RPFilterOff`), which report what is actually installed rather
  than what the agent believes it installed.
- `sysx/nft.go` — DNAT ruleset generation, plus the separate `failover_egress`
  source NAT and the Docker forward exceptions both of them need.

### Backend files

- `agent/agent.go` — state, config application, `SetActivePath`, and
  `reconcileRouting`, which shares `applyLoop`'s goroutine so route repairs
  cannot race a decision being applied. Also `Revert`, the backend half of a
  rollback, reached by `failover-backend -revert` rather than over the control
  channel: revert is the panic button, and one a lost frame can press is not a
  panic button.
- `agent/responder.go` — probe replies, and applying the frontend's decision.
- `agent/meter.go` — counter sampling with on-disk buffering.
- `agent/client.go` — dials the frontend, reports upward.

### Linker files

- `linker/linker.go` — the agent. `apply` installs, `reconcile` re-reads,
  `applyEgress` handles what the frontend pushes down. That last one keeps two
  lists: what the frontend asked for and what actually went in. They differ only
  after a failed install, and `reconcile` retries the difference. The frontend
  pushes once per configuration version, so without a retry a transient failure
  at boot (no route to the backend yet, so no interface to scope the source NAT
  to) would last until somebody saved settings again.
- `linker/client.go` — the control client. Dials the frontend from a socket
  bound to the overlay address, so the channel rides the active tunnel like
  everything else this host sends.
- `sysx/linker.go` — the rules, the readbacks, the two nftables tables, and
  `DefaultLinkerTable` (200, and only a default — see `Linker.Table`).

---

## 5. How the pieces talk

### The probe round trip (every 250ms on the active path, 5s on standby)

The two cadences answer different questions, which is why they are so far
apart. The active path is being watched for failure, and every extra second of
detection is a second of traffic going nowhere. A standby path only has to be
known-good by the time it is needed, and probing it is itself billed against
the very quota it is being held in reserve for. At one second a standby tunnel
spent about 650 MB a month on probes alone; at five it spends about 130.

What that costs is failback speed, and only failback. `RecoverThreshold` is a
count of probes, not a duration, so a recovered path now takes
`RecoverThreshold × 5s` to read `up`, about 50s with the shipped values,
before its `HoldDownSec` clean streak even begins. Roughly 140s from a link
coming back to traffic returning to it, against roughly 100s before. Failover
*away* from a dying path is untouched: that is the active path, still at 250ms.

1. Frontend prober for path *N* sends a 66-byte packet from a socket stamped
   with path *N*'s fwmark. The mark selects table 101/102/103, which routes to
   that specific tunnel.
2. The packet carries: path id, sequence, tx timestamp, **the frontend's
   current active path and a monotonic decision sequence**, and an HMAC-SHA256
   tag over everything.
3. Backend responder authenticates it, applies the decision if the sequence
   advanced, and replies from a socket marked for the *same* path — so the
   reply leaves by the tunnel the request arrived on.
4. Frontend matches the reply to its outstanding sequence and records an RTT.
   Unanswered probes are resolved as lost after the timeout.
5. Results are delivered to the tracker **in sequence order** (`Prober.flush`).

### The linker control channel (TCP, JSON, linker dials frontend)

Only where extra hosts exist. Far smaller than the backend's: the linker reports
liveness, hostname, build and the routing table it actually used, and receives
the egress networks belonging to its own overlay address. It reports no usage
and is told no path or mode.

Its socket is bound to the overlay address deliberately — that is what puts it
on the `from <overlay> lookup <table>` rule and therefore onto the backend, so
the channel follows failover for free. Unbound it would leave by the host's own
default route and never arrive.

The frontend checks the address a linker claims against the configured list
before pushing anything: the shared secret proves a peer belongs to the
deployment, not that it may hold a particular address.

### The control channel (TCP, JSON, backend dials frontend)

Carries configuration down and usage accounting up. Authenticated by an
HMAC challenge/response over the pre-shared key. Runs inside WireGuard, so
there is no second layer of encryption.

**It deliberately does not carry the routing decision.** See §6.

### A failover

`Engine.evaluate` runs every 500ms:

1. Compute a `Block` for each path, in this precedence order:
   `!Enabled → disabled`, `quarantined → quarantine`, `over quota → quota`,
   `degraded → degraded`.
2. `selectPath` returns a chosen path id, or `0` with `held=true`.
3. If the choice changed, install the route, log an event, notify, bump
   `decisionSeq`, and flip the probers' active/standby cadence.
4. The new decision reaches the backend on the next probe, over whichever
   tunnel is alive.

### A usage delta

1. Backend samples `/sys/class/net/<iface>/statistics` every 10s.
2. Computes `Δbytes` and `Δpackets`. A negative delta means the interface was
   recreated — rebaseline, do not log.
3. Buffers the delta to disk with a per-path sequence number.
4. Ships batches up the control channel; the frontend dedupes on the sequence
   (`meta` key `usage_seq:<pathID>`) and folds them into the SQLite ledger,
   converting to billed bytes with `quota.Metered`.

---

## 6. Why it is like this

These are the decisions most likely to be "helpfully" reverted. Each one has a
concrete failure it prevents.

**The routing decision rides on the probe packets, not the control channel.**
The control channel is TCP over the overlay, which follows the active route. If
the frontend decided "switch to LTE1" and sent that over TCP, the message would
travel across the path that just died. Probes go out all three tunnels
continuously, so the decision arrives over whatever still works. The monotonic
`DecisionSeq` stops a reordered probe from rewinding it.

**DNAT only, never SNAT.** Leaving the source address alone is the whole reason
srcds and the web server see real client IPs — for UDP as well as TCP, which no
proxy could do. The cost is that the backend must route replies from
`10.99.0.2` back out the tunnel (`ip rule from 10.99.0.2 lookup 100`) instead of
out pfSense. `sysx/nft_test.go` asserts the ruleset never contains a masquerade.

**The one source NAT is for traffic going the other way, and lives in its own
table.** `Frontend.BackendEgress` (off by default) makes connections the
*backend* originates from `10.99.0.2` leave by the frontend's public address.
That is not a weakening of the rule above: it applies to the opposite direction,
where there is no client address to preserve because there is no client. It
exists because a Source game server is listed in the server browser at the
address Steam observes its heartbeat coming from — there is no way to declare a
different one, deliberately, as anti-spoofing — so without it the server is
advertised at the house's own WAN address, which has no port forward behind it,
changes with the service, and is unreachable entirely while a CGNAT'd LTE path
is carrying traffic. Players who found it through the browser would bypass the
failover completely.

It is a separate nftables table (`failover_egress`) so the assertion on the
published ruleset stays literally true and the feature can be removed on its
own. The rule is scoped to `oifname <public>`: unscoped, it would also match
traffic leaving down a tunnel, which is a reply on its way to a player, and
rewriting that source is exactly what the rule above forbids. It is opt-in
because everything else the backend sends from the overlay address goes the same
way, and therefore through the LTE quota during a failover.

**The container half is selected by source network, because nothing else is
available.** Binding to the overlay address (`-ip 10.99.0.2`) is enough for a
service on the backend host, and needs no backend rules at all — the existing
`ip rule from 10.99.0.2 lookup 100` already puts that traffic on the tunnel. A
container cannot do it: the overlay address does not exist in its network
namespace. Nor can it be identified by process — `meta skuid` and cgroup
matching work on locally *originated* packets, and a container's are *forwarded*
through the host, so there is no local socket to inspect. What is left is the
bridge network's address range, which is what `Egress.Sources` configures.

Two rules on the backend, doing two jobs (`BuildBackendEgressRuleset`). The
prerouting `meta mark` diverts the traffic — a forwarded packet is routed after
that hook, so the mark is what sends it to table 100 rather than out to pfSense,
and table 100 already tracks the active tunnel so it follows failover for free.
The postrouting `snat to 10.99.0.2` is what makes the frontend's rule match and
gives the reply somewhere to come back to. That SNAT sits at priority `-10`,
ahead of `srcnat` (100) where Docker installs its masquerade: allowed to run
first, Docker would rewrite the source to an address on the output interface,
and the tunnels have none.

**`BuildReturnRuleset` marks only `ct direction original`** because of this
feature. Egress connections have their replies arrive on a tunnel too. Without
the qualifier those replies would be stamped with `ReturnMark`, routed by table
100, and sent straight back out the tunnel instead of to the container waiting
for them. Only a connection whose *first* packet came from a tunnel is one whose
replies belong back down it.

**`Suspect` paths stay selectable.** A single lost probe demotes a path from
`up` to `suspect`. If suspect were ineligible, one dropped packet would abandon
the active tunnel — and LTE drops packets routinely. Sustained trouble is
caught two other ways: `FailThreshold` consecutive losses condemn the path, and
the loss/RTT thresholds block it as degraded. `Tracker.Usable()` is the
eligibility test; do not change it back to `Health() == HealthUp`.

**Failover is immediate, failback waits.** Moving to a worse path happens the
instant the current one is ineligible. Moving back to a better one requires an
unbroken clean streak of `HoldDownSec`. Any lost probe clears `cleanSince`, so a
marginal NBN service that keeps half-recovering cannot drag traffic back and
forth.

**Quality selection only chooses between fallbacks, never against the preferred
path.** `Failover.Selection = "quality"` (off by default) changes exactly one
thing: once the preferred path is out, the replacement is the best-*measuring*
eligible path rather than simply the next one down the list — a clean LTE2 beats
an LTE1 dropping one packet in ten.

It is deliberately not "pick the best path". While the preferred path is usable
it keeps the traffic whatever the numbers say, and it wins the traffic back on
its clean streak alone. Priority order here is the *cost* order: NBN is
unmetered and the LTE services are capped, and LTE frequently measures better
than a congested fixed line. A selector that simply chased the lowest score
would park traffic on a metered link indefinitely and report itself as
optimising. `preferredPathID` is the guard; `qualityTarget` returns early on it.

Moving between two fallbacks needs both dampers, and neither is optional. The
candidate must beat the running path by `Quality.MarginPct` — measured against
the path actually carrying traffic, not against the one that is down, or a third
path could pull traffic off a second one it is no better than — and it must hold
that lead for `HoldDownSec`. Without the margin two similar links trade places on
measurement noise; every swap is a visible stall for connected players.
`Engine.beatenSince` times that hold-down against *the active path being beaten*
rather than against a particular challenger, because two candidates alternating
for the lead would otherwise restart the clock forever and the switch would
never happen however badly the active path was performing.

Because the margin applies in both directions there is a dead zone rather than a
threshold — moving A→B needs `score(B) < 0.75×score(A)`, moving back needs
`score(A) < 0.75×score(B)`, and both cannot hold at once — so oscillation on
noise is impossible rather than merely unlikely. What that does *not* bound is
how often a genuine alternation can switch: two links really taking turns being
much better, which is what a carrier working on a tower produces, would move
traffic every hold-down for as long as it lasted. `Quality.MinDwellSec` is the
floor under that, and it applies only to a choice between two working fallbacks
— it never delays leaving a path that has become unusable, nor a failback to the
preferred path.

The score is milliseconds-equivalent: `loss% × LossWeight + rtt × RTTWeight +
jitter × JitterWeight`. `LossWeight` defaults to 25 because for a game server a
clean 60ms link genuinely beats a lossy 30ms one. A flawless path scores zero
and cannot be displaced — the margin comparison is strict, so two idle tunnels
never swap.

**No eligible path means keep the last route.** `selectPath` returns `0`, the
caller leaves `e.active` alone, and the installed route stays. Withdrawing it
would blackhole traffic; leaving it means a path that recovers finds the route
already pointing at it. This is the dead-man behaviour and it is intentional.

**Quota is a policy block, not a health verdict.** An over-quota path stays
`up` in the portal and is simply not selectable. That distinction is what lets
the system say "these links work, you just have not approved paying for them"
and offer the approve button. Merging the two states would lose that.

**Overage approvals are time-boxed.** `store.Grant` has `Until` and optional
`ExtraBytes`. A 2am click must not silently disable quota enforcement for the
rest of the month. The absolute `CeilingBytes`, if set, overrides even a live
grant.

**Packets are metered alongside bytes.** The carrier bills the encapsulated
datagram on the WAN, not the payload inside the tunnel. `quota.Metered` computes
`(bytes + packets × overhead) × calibration%`. Counting payload alone
undercounts by 5–15%, meaning the real cap is hit while the ledger still thinks
there is headroom.

**Usage deltas are buffered on disk when the control channel is down.** That
window is exactly when LTE data is burning hardest — a failover to LTE often
coincides with the frontend being unreachable. Dropping accounting then would
lose the usage that matters most.

**The portal lives on the frontend, not the backend.** When all three tunnels
are down, the backend is unreachable by definition — and that is precisely when
somebody needs to see why and click "use LTE2 anyway". The frontend is in a
datacentre on independent internet, so the portal survives a total path outage.

**The portal must never be able to take the agent down.** It binds an address on
the admin tunnel, and that address does not exist until `wg-quick` has brought
the interface up — unit ordering asks for that but cannot guarantee it, and an
admin tunnel down for any other reason has the same effect. Returning the listen
error killed the process: probing stopped, the control channel closed, and
failover was gone until somebody noticed a restart loop. `Server.listen` retries
every 5s instead, warning once, and the failoverctl socket is opened *before*
the portal so the local fallback exists in exactly the situation it is for.

**The first-run password has to be changeable, because of where it is written.**
It is generated on first start and logged in the clear, so it lives in the
journal for as long as the journal is kept. Without a way to rotate it, anything
that could read the journal held a permanent credential. `POST /api/password`
takes the account from the *session* rather than the request body, requires the
current password, and drops every other session for that account — the usual
reason to change a password is that somebody else may have had it. Over the
root-only socket (`failoverctl passwd`) no current password is required, because
the case that path exists for is not having one, and anyone who can reach that
socket can read the database anyway.

**The portal binds an admin WireGuard interface, not the public IP.** WireGuard
already provides encryption and peer authentication, so there are no
certificates to renew and no public TCP surface. The login is defence in depth
for a lost phone, not the perimeter. (It also sidesteps a real conflict: ports
80 and 443 are DNAT'd straight through to the backend, so the portal could not
have used them anyway, and ACME HTTP-01/TLS-ALPN-01 would both fail.)

**An extra host gets its own overlay address, not a second layer of DNAT.**
Publishing from a machine behind the backend could have been done by DNAT'ing
again on the backend and demultiplexing by port. Giving it `10.99.0.3` on its
own `dummy0` instead means no second translation, no port demux, and no port
collisions — two boxes can both run 27015. It also carries the stable-address
property one hop further, so the linker's replies survive a failover for the
same reason everything else does. The backend needs one route to reach it and
its existing connection marking handles the replies unchanged.

The bigger payoff is egress selection. On the backend, binding a service to the
overlay address *is* the selector for leaving via the frontend's public address.
That holds one hop down: `srcds -ip 10.99.0.3` gets the server-browser heartbeat
right for free, while everything else on that box keeps its normal route. The
`Egress.Sources` CIDR list is not needed and should not be used there — it
exists for containers, which cannot bind an address that does not exist in their
namespace, and it catches every packet from the network it names.

**A linker is never told which tunnel is active, because it does not need to
be.** Its whole job is to put traffic sourced from its overlay address onto the
backend, and the backend already tracks the active path in table 100. That is
why there are no probes, no `decisionSeq`, and no metering in `internal/linker`
— not an unfinished agent, a complete one for a job that is genuinely this
small. Adding decision handling to it would create a second thing that has to
agree with the frontend, which is the failure mode §8 warns about for pfSense.

**A linker has no observe mode, and that is a decision.** The other two agents
need one because their rules move published traffic the moment they exist. The
linker's rules match only packets sourced from, or addressed to, its own overlay
address — and nothing on the box uses that address unless a service was
deliberately bound to it, or the frontend's DNAT points at it. So on a host
where nothing has opted in they are inert. What actually directs traffic to a
linker is that DNAT, which has an observe mode and is where the decision belongs.

**A linker's routing table is configurable, and that is not a nicety.** The
number belongs to the host's own namespace, not to this system. `DefaultLinkerTable`
is 200; the first real deployment landed on a machine already using 200 for its
second ISP, under the name `isp2`, and the agent wrote its own default route
straight over that host's — sending the operator's other traffic to the backend
with nothing anywhere reporting it. `Linker.Table` is set in the portal row and
must also appear in that host's bootstrap file, because the rule it names is what
carries the control channel: the agent cannot be told a value it needs in order
to be told anything. The agent reports back what it actually used so the two
cannot drift unnoticed.

**The linker reports `rp_filter` and never sets it.** The other two turn it off
because their tunnels carry no address of their own, which makes even "loose"
mode drop probe replies — broken by construction, as §8 explains at length. A
linker has an ordinary interface with an ordinary address, and on a host with
one route to the internet the reverse lookup lands on the arrival interface and
passes. Silently changing a system-wide sysctl on a machine that is somebody's
game server first is not this agent's business, so it warns and says when to
suspect it.

**Egress networks belong to exactly one host.** `EgressSource.Host` is not
tidiness. Docker's default bridge is `172.17.0.0/16` on every machine and the
allocator walks `172.18`, `172.19` and so on in the same order on each one, so
several hosts routinely hold the identical subnet. A global list would have
every agent installing every row — pulling containers onto the tunnel on hosts
the row was never meant to touch, silently, and billing them to the LTE quota.
The matching rule is the opposite of the one for paths: the same CIDR on two
hosts is normal and must stay legal, while a repeat within one host is rejected.

**Shaping is at both ends because a queue only controls the direction it sits
in front of.** `Path.Shape.ToBackendMbit` is the frontend's queue on that
tunnel — the house's download — and `ToFrontendMbit` is the backend's, the
house's upload. Only the second is sent down the control channel, because the
first is none of the backend's business. Both are zero by default and a site
that sets neither issues no `tc` command that changes anything.

The value belongs slightly *under* the measured line rate. At or above it the
queue forms in the carrier's buffer instead of ours, which is the entire thing
being fixed: that buffer is enormous, serves in arrival order, and puts seconds
of delay in front of a game packet stuck behind a download. CAKE rather than
fq_codel because it does the rate limiting itself rather than needing an htb or
tbf parent, and because its flow isolation gives sparse flows priority — which
is what keeps a 66-byte probe every 250ms out from behind a bulk transfer with
no classification to maintain. `ShapeOverheadBytes` is 80 because the shaper
counts the payload it is handed while the carrier bills what leaves the WAN.

Being able to shape the *download* direction at all is a property of owning both
ends. An ordinary home router can only drop traffic that has already crossed the
bottleneck; the frontend is upstream of it.

**Protection is a separate nftables table, and everything in it is off.** Same
reasoning as `failover_egress`: `NFTTable` carries the published services and is
asserted to contain no translation, this can be removed on its own, and a reader
can tell which rules publish from which rules drop. Two chains, because they
need different information — `raw` (-300) runs before conntrack, so the
blocklist and the malformed packets cost nothing to discard, and `filter` (-150)
runs after conntrack and before `dstnat` (-100), the only window where a rule
can know a packet's connection state and still stop it before it is translated
and sent down a tunnel.

**Every protection rule is scoped to the public interface, and that is a safety
property rather than an optimisation.** The system's own traffic — probes on
51999, the control channel on 51998, everything between overlay addresses —
arrives on the tunnels. A limiter that could match it would let the frontend
condemn a healthy link because of its own firewall and move traffic to a metered
one. `web.validate` refuses to enable protection without a public interface for
exactly this reason, and `sysx/protect_test.go` asserts that neither port nor
either overlay address ever appears in the generated ruleset.

**There is no SYN-proxy option and its absence is deliberate.** SYN proxying
requires the handshake to be untracked (`notrack` in the raw hook), and this
frontend has to track every connection in order to DNAT it. The two cannot both
hold, so the switch would have broken every published service the moment it was
ticked. Per-source connection-rate and concurrent-connection limits cover the
same ground here.

**Source-engine limiting matches only connectionless packets.** `@th,64,32
0xffffffff` is the first four bytes after the UDP header, which the A2S queries
and connection attempts carry and an in-game client never does — its packets are
sequence numbered. That is what makes a limit of two or three per second safe:
it cannot touch the traffic of a player already connected. Without the payload
match the same rule would throttle gameplay at a rate chosen for queries.

**Counters exist because a limiter nobody can see is worse than none.** "Some
players cannot connect" and "that threshold is too tight" look identical from
outside. Every drop rule carries a `counter` and a comment; `sysx.ProtectState`
reads them back out of the kernel with `nft -j`, because the numbers live in the
rules and reloading the table resets them. The portal shows them beside the
parked sources.

**WireGuard handshake age never influences a decision.** It is collected and
displayed for context only. A WireGuard interface stays up long after the link
beneath it has died — catching that is the entire reason the probes are
end-to-end.

---

## 7. Invariants

Breaking any of these is a correctness bug even if the tests pass.

1. The overlay addresses live on `dummy0` and never change. Failover changes
   only `dev`.
2. No SNAT, no masquerade, no userspace forwarding of **published** traffic.
   The `failover_egress` table is the one source NAT, it applies only to
   connections the backend originates outbound, and it must stay in its own
   table and stay scoped to the public interface.
3. Each path has a **unique** routing table and a **unique** fwmark. Two paths
   sharing either means both probe through the same tunnel and a dead link
   tests as healthy. `web.validate` rejects duplicates. The per-path fwmark
   rules also carry an **explicit priority** (`sysx.ProbeRulePrefBase`) so they
   outrank the backend's broader `from <overlay> lookup 100` rule. `ip rule
   add` without one takes the first rule's priority minus one, so each rule
   added lands *ahead* of the previous — and the backend adds the path rules
   first. That put the source rule on top and sent every probe reply down the
   active tunnel instead of its own: standby paths still got replies, so they
   read healthy while measuring a mix of two tunnels.

   **Both sides of that comparison must be pinned, not just one.** Fixing only
   the path rules leaves the same bug waiting for the next source rule anybody
   adds — which is exactly what happened when `overlay.subnet` introduced a
   second one. The path rules were correctly at 30001-30003, the new `from
   10.99.0.0/24 lookup 100` was handed 30000 by the kernel, and every probe
   reply went back to matching the wrong rule. Source rules now carry
   `sysx.ReturnRulePrefBase` (32500), behind the path band and ahead of main,
   and `EnsureReturnRule` moves any rule it finds at another priority rather
   than leaving it beside the correct one. Never add an `ip rule` here without
   an explicit `pref`.

   **And it happened a third time, in the two rules nobody had got to yet.**
   The frontend's control rule and the backend's return-mark rule were still
   being added bare, so the kernel handed both 30000, immediately ahead of the
   path band. They are now `sysx.ControlRulePref` (29999) and
   `sysx.ReturnMarkRulePref` (29998). Those values are deliberately where the
   kernel had been putting them rather than where they arguably belong: nothing
   sits between them and 30001, so pinning changed no ordering on any running
   host. Moving them behind the path band is a separate decision, not a
   side-effect of writing the number down.

   Ahead of the path rules was survivable only because no path shared their
   marks, which was a property of the configuration and not of this code, so
   `web.validate` now rejects a path mark equal to any of `ControlMark`,
   `ReturnMark`, `EgressMark`, `LinkerReturnMark` or `LinkerEgressMark`. Before
   that, typing `0x200` into the settings form was enough to make one tunnel's
   probe replies leave by whichever tunnel was active, and read healthy doing
   it.

   **Moving a rule adds before it deletes.** The gap only exists on an upgrade,
   which is the one time these run, but during it a marked packet matches
   nothing and falls through to main: a probe then measures whichever tunnel is
   active instead of its own, and in observe mode the control channel has no
   route at all. `ensureProbeRoute`, `EnsureControlRoute`, `EnsureEgressRule`
   and `EnsureReturnMarkRule` all install the pinned rule first and clear the
   strays afterwards.
4. Probe results reach the tracker in sequence order. Out-of-order delivery
   scrambles the consecutive-loss counts that condemn a path.
5. Every probe and control frame is HMAC-authenticated. Nobody outside can
   forge path health or steer traffic.
6. Backend reply routing must match the frontend's choice. Asymmetric flows
   break pfSense state.
7. Observe mode must not move traffic — but it must still measure. The split is
   deliberately not "changes nothing": the overlay address, sysctls, per-path
   probe tables, fwmark rules and the backend's route to the frontend overlay
   are installed for real in both modes, because without them the probe sockets
   cannot bind and every path would follow the single active route, making the
   observation worthless. None of that moves traffic. Observe mode suppresses
   the main-table route to the backend, the DNAT ruleset, the backend's
   reply-path default route, and — added with them, for the same reason — the
   shapers and the protection rules. A queue discipline does not misdirect
   traffic the way a route does, but it decides what is dropped and when, and a
   rate limiter plainly does; observe mode's promise is that nothing the agent
   has done can be felt by a player. See `Engine.applySystemConfig` and
   `Agent.ApplyConfig`; `realRunner()` is the escape hatch.

   **`sysx.isReadOnly` is the other half of that promise, and it fails in the
   dangerous direction.** A command it wrongly calls a mutation is not run and
   returns `("", nil)`, success with empty output, which every readback in this
   package reads as "not installed". So a misclassified *read* does not error;
   it tells the agent the opposite of the truth and the agent reinstalls what is
   already there. Three were wrong: `tc qdisc show` (live, because `EnsureQdisc`
   takes the gated runner), and `nft -a list` / `nft -j list`, which failed an
   `args[0] == "list"` test on the flag. When you add a command here, add it to
   `TestDryRunnerSuppressesMutationsButRunsQueries` in both directions: the
   read list and the mutation list.
8. **Revert must remove everything the agent installed and touch nothing it did
   not**. In particular, never the WireGuard tunnels, never the overlay
   address (something may be bound to it), and never a queue discipline on a
   tunnel this system was not shaping. `Engine.Revert` removes a shaper only
   from paths that have a rate configured, because an interface the agent never
   shaped carries somebody else's.

   **It takes two commands, because there are two hosts.** `failoverctl revert`
   reaches only the frontend; the backend's half is `failover-backend -revert`,
   and it must be run second. Taking the reply path down while the frontend is
   still armed and DNATing breaks every published service on the spot: requests
   keep arriving down the tunnel and their replies leave by the LAN to pfSense,
   where the client's flow has no state.

   This was a gap for a long while and an invisible one: `RemoveReturnRoutes`,
   `RemoveOverlayLocalRule` and `RemoveReturnRuleset` were all written and none
   of them was called from anywhere, so a revert reported success while the
   backend kept its reply rules, its table-100 default route, its marking table
   and its routes to every extra host. If you add teardown for something new,
   grep for the call site; the compiler will not tell you it is missing.

   **A revert deletes what it installed; it never flushes a table.** The number
   belongs to the host, not to this system, and a backend that already
   policy-routes may keep its own entries in 100. `Agent.Revert` removes table
   100's default route specifically, and removes source rules by the priority
   it found them at rather than by selector alone. `ip rule del` given only a
   selector drops one arbitrary match, so a duplicate from an older build
   survives the revert.
9. **Never start long-lived goroutines from an HTTP request context.** It is
   cancelled the moment the handler returns. `Engine.Reconfigure` takes no
   context for exactly this reason; it uses `e.baseCtx`. Starting the probers
   from `r.Context()` silently stopped all probing on the first settings save.
10. **Commit state only after the system accepts the change.** Both
    `Engine.evaluate` and `Agent.SetActivePath` install routes first and record
    the new active path second. Recording first means a failed `ip route
    replace` is never retried, because the next pass sees the choice as already
    current — and the portal reports a path traffic is not using.
11. **`decisionSeq` must increase across a frontend restart.** The backend
    remembers the highest sequence it has seen and ignores anything lower. It is
    seeded from the wall clock in `New`; do not reset it to zero.
12. **Revert must also disarm.** The decision loop runs every 500ms. Removing
    the rules without dropping to observe means the very next tick sees no
    active path, picks one, and reinstalls the route — leaving the host half
    reverted, routing restored and nftables gone.
13. **Disarming is not a teardown.** Going armed → observe stops further
    changes but deliberately leaves installed rules in place, because deleting
    the DNAT table would drop every published service instantly. `Status.
    RulesActive` exists so the portal says this out loud; `revert` is the way to
    actually take them down.
14. **Overlay addressing is bootstrap-owned, never portal-editable.** Both hosts
    must agree on it, and a change would tear down the channel the change has to
    travel over. `handlePutConfig` overwrites whatever the client sent.
15. **The backend installs its plumbing at startup, before the responder and
    control client start** — overlay address, sysctls, per-path probe routes,
    return rule and the seeded route to the frontend overlay. It cannot wait
    for the frontend's first push: the push arrives over a TCP connection
    sourced from the overlay address and routed down a tunnel, so a backend
    that waits deadlocks — the responder cannot bind, the client cannot dial,
    and both retry forever. `wg-quick` sets `Table = off`, so without the
    seeded route the kernel sends overlay traffic out the LAN to pfSense and
    the dial times out. `Agent.Run` calls `applyPlumbing` with the cached
    config, or with `provisionalConfig()` (bootstrap overlay + the shipped
    default paths) on a first-ever start. `ApplyConfig` re-asserting it
    afterwards is idempotent and is what installs the operator's real paths.
16. **Never block the probe read loop.** `Agent.SetActivePath` queues to a
    worker (`applyLoop`); only `applyDecision` shells out. Doing route work
    inline stalls replies on *every* path at once, so a slow `ip` looks
    identical to all three tunnels dying.
17. **A goroutine blocked on a socket must have that socket closed on
    cancellation.** A context does not interrupt a read in progress. Every read
    loop here sits on a connection with only a deadline behind it, and a silent
    channel is the normal healthy case — the frontend speaks only when it has
    something to say — so cancelling the context alone leaves the goroutine
    parked for up to `proto.ControlDeadline` (45s). `Agent.Run` waits on all
    four of its goroutines, the unit's `TimeoutStopSec` is 10s, and the result
    was that every backend restart ended in SIGKILL rather than a clean exit.
    The pattern is a `go func() { <-ctx.Done(); conn.Close() }()` beside the
    loop; `Responder.listen`, `Agent.runSession` and `ControlServer.serve` all
    carry it.
18. **Per-interface state must be reconciled against the kernel, not just
    installed once.** Deleting an interface deletes every route that used it
    *and* resets its sysctls, and `wg-quick down` deletes the interface.
    Bringing the tunnel back restores neither, so `systemctl restart
    wg-quick@wg-nbn` leaves that path's probe table empty and its `rp_filter`
    back at the system default of 2 — either alone is enough to make the path
    read as down forever, while the tunnel recovers on the wire and never
    recovers in the portal. `Engine.reconcileRouting` and
    `Agent.reconcileRouting` re-read the kernel every 10s and reinstall only
    what is missing. Both run on the same goroutine as the code that installs
    routes (`Run`'s select, `applyLoop`), because a reconciler racing a switch
    in progress would read the kernel between the route going in and the
    decision being recorded, and undo it.

    **The queue discipline is on that list too.** A shaper belongs to the
    interface exactly as `rp_filter` does, so `wg-quick down` takes it with the
    device and the replacement comes back with the kernel default. Nothing
    reports it: traffic keeps flowing, unshaped, and the only symptom is that
    latency under load quietly gets bad again — the hardest kind of regression
    to attribute, weeks later. Both reconcilers call `sysx.EnsureQdisc` for any
    path with a rate, and neither runs `tc` at all for a path without one.
19. **Multi-host support must be invisible until it is configured.** With
    `overlay.subnet` empty — the state every site starts in and most stay in —
    the generated rulesets and the `ip` commands must be byte-identical to a
    build with no linker support at all. This is not neatness: a site with one
    host at the far end has no reason to have a range routed down its tunnel,
    its `DOCKER-USER` exceptions widened, or its egress NAT matching addresses
    nothing holds — and every one of those is a live rule on a working system.
    So nothing here is derived or inferred — not from whether any service names
    a target, not from anything else. `sysx/linker_test.go` pins the generated output; the real check is to
    diff it against the previous commit.
20. **`MatchPrefix` and `RoutePrefix` look redundant and are not.** nftables
    matched the backend on a bare address while `ip route` installed an
    explicit `/32`. Collapsing them into one helper changes whichever of the
    two you did not pick, on every existing deployment — equivalent to the
    kernel, and a diff in `ruleset.nft` on a host where nothing was meant to
    move. They return the same string once a subnet is set, which is what makes
    the duplication look pointless. Leave them.

    For the same reason, `sysx.RouteVia` takes the prefix that was **installed**
    rather than an address inside it. `ip route show` filters on an exact prefix
    — unlike `ip route get`, it will not report a `/24` when asked about a `/32`
    within it — so a caller that installs a range and reads back a host address
    sees "no route" on every tick and reinstalls what was already there. Each
    call site passes its own prefix so which one widens is visible where it is
    decided.
21. **A widened route must remove the one it superseded.** `ip route replace`
    writes the new prefix and leaves any other alone, so setting a subnet on a
    running site leaves both `10.99.0.2/32` and `10.99.0.0/24` installed — and
    the `/32` is more specific. The backend stays pinned to whichever tunnel
    was active at that moment while every later failover moves only the range.
    Nothing reports it: probes and the control channel are steered into their
    own tables by fwmark, so all three paths go on measuring perfectly.
    `Engine.dropSupersededHostRoute` removes it, on apply and on reconcile,
    and only in the widening direction — it has no record of a previous subnet
    to clean up in the other.

---

## 8. Traps

**pfSense will silently defeat the whole design.** Two settings matter, both
documented in `deploy/SETUP.md`:

- Each tunnel must be policy-routed to a *single* gateway, never a gateway
  group. Two systems making the same failover decision from different
  information will fight.
- Gateway monitoring **action** must be disabled per gateway. By default,
  pfSense removes policy-routing rules for a gateway it thinks is down, and the
  traffic falls through to the default gateway. The "LTE1 tunnel" would then
  ride NBN — three tunnels on one link, all probing healthy, no failover at all.

**`AllowedIPs` is asymmetric, and the backend's must be `0.0.0.0/0`.** It is a
filter as well as a route: WireGuard drops an inbound packet whose source falls
outside it. Published traffic carries the client's real address - the whole
point of DNAT without SNAT - so a backend peer limited to `10.99.0.1/32` drops
every request before it reaches the interface, and cannot send replies either.
Probes and the control channel keep working, because those genuinely do come
from the overlay address, so the portal shows three healthy paths while nothing
published works. `tcpdump` on the tunnel shows nothing at all, since the packet
never gets injected.

The frontend's side is `10.99.0.0/24` — the whole overlay range, not the
backend's `/32`. The `/32` is narrower and is what a backend-only site strictly
needs, but the default is the wider one because of the shape of the failure: the
day the site adds a second host at `10.99.0.3`, a peer pinned to the backend's
address silently refuses to transmit to it, and the only symptom is one
unreachable machine long after anybody last edited a WireGuard file. The range
is private, carries nothing but this system, and every channel on it is
separately authenticated — `Engine.KnownLinker` refuses an address that is not
configured whatever key the peer holds — so the wider filter gives away very
little. Deliberately narrowing it on a site that will only ever have one backend
is a reasonable hardening step and is documented as one.

**Docker rewrites the packet filter on whichever host runs it.** On the
frontend it sets the FORWARD policy to drop, which discards DNAT'd traffic; the
agent inserts exceptions into `DOCKER-USER` (`sysx.EnsureForwardExceptions`),
matched by destination and connection state, never by source - a reply's source
is rewritten back before the forward hook runs. On the backend a container on a
bridge network defeats the source-based return rule, because the reply is
routed while it still carries the container's address; `sysx.BuildReturnRuleset`
marks connections arriving from a tunnel and restores the mark on replies only.
Restoring it in both directions sends incoming requests back out their own
tunnel.

**Restarting a tunnel silently empties its routing table.** `wg-quick down`
runs `ip link delete`, and the kernel discards every route pointing at that
device — the path's probe/reply route in table 10x, and, if it was the active
tunnel, the main-table route and the return-path default too. `wg show` looks
perfect afterwards (a handshake seconds ago) while the path probes as 100%
loss, because the packets have nowhere to go. The reconcilers exist for this;
see invariant 18. To confirm it by hand: `ip route show table 101` should name
the tunnel, and an empty result is the bug.

**`Table = off` in every `wg-quick` config.** Otherwise wg-quick installs its
own route for the peer's AllowedIPs and the three tunnels fight over the same
destination.

**`PersistentKeepalive` on the backend side.** The LTE services are behind
CGNAT so the frontend can never initiate. Without keepalive the standby
tunnels' NAT bindings expire and failing over costs an extra handshake at the
worst moment.

**`rp_filter` must be OFF (0), not merely loose.** This one cost an entire
deployment evening. The tunnels have no IPv4 address of their own - `wg-quick`
with `Table = off` and no `Address =` - and on an address-less interface the
kernel's "loose" mode does not do what its name says. In
`__fib_validate_source`, if the reverse lookup resolves to a different device
than the packet arrived on, it checks `no_addr`, finds it true, and jumps to
`last_resort`, which drops for *any* non-zero `rp_filter`. The second,
device-scoped lookup that makes loose mode loose never runs.

And that reverse lookup can only ever name one tunnel: each path's forward
route lives in its own fwmark table, while an arriving packet carries no mark,
so the lookup falls through to `main`. Whichever tunnel `main` points at, the
other two paths have their probe replies dropped below the socket - no log, no
counter, indistinguishable from two dead links. `sysx.EnsureSysctls` sets both
`all` and each tunnel to 0, because the effective value is `max(all, dev)`.

**And setting it once is not enough.** The value belongs to the interface, not
to the name. `wg-quick down` deletes the device and `up` creates a new one,
which inherits `net.ipv4.conf.default.rp_filter` — systemd ships that as 2 —
rather than the zero the agent set on the device it replaced. So restarting a
tunnel silently re-arms the filter on it and every probe arriving there is
dropped, while `wg show` reports a handshake seconds ago. The fingerprint is a
tunnel whose `received` counter climbs at the probe rate while `sent` shows
only 32-byte keepalives. `sysx.RPFilterOff`, called from both reconcilers on
every tick, is what keeps it off; see invariant 18.

**The backend's return rule matches on source, and the overlay includes the
frontend.** Once `overlay.subnet` is set, `from 10.99.0.0/24 lookup 100` also
matches packets the *frontend* sends to a linker - and table 100's default points
back down the active tunnel, so the backend returns them to the sender. A
linker's control channel can never complete: its SYN goes up fine, and the
frontend's SYN-ACK is bounced straight back to the frontend.

Nothing reports it and published traffic is unaffected, because a client's source
address is public and never matches the rule. Only overlay-to-overlay traffic is
bounced, so every service keeps working while the hosts cannot talk to each
other. Routing reads as correct on every host individually; the fault is in the
combination. `sysx.EnsureOverlayLocalRule` is the exception that fixes it, at
`OverlayLocalRulePref` immediately ahead of the return rules, and it exists only
when a subnet does.

To see it directly, on the backend:

```sh
ip route get 10.99.0.3 from 10.99.0.1 iif wg-nbn
```

Answering with the tunnel rather than the LAN is the bug.

**`ip rule show` prints table *names*, and a readback that greps for the number
goes blind.** Wherever `/etc/iproute2/rt_tables` gives a table a name, the
kernel prints that name instead: a host that calls table 200 `isp2` - an
entirely ordinary dual-ISP setup - turns `lookup 200` into `lookup isp2`, and
every `strings.Contains(rules, "lookup "+table)` in this package stops matching.
The agent then cannot recognise rules it installed seconds earlier, re-adds them
on every tick and logs `File exists` forever, while the rules it is complaining
about are sitting right there. Read rules with `listRulesInTable`, which asks the
kernel to filter by number - the alias changes how a rule is *printed*, never how
it is *selected*.

Every readback in this package now does. That took two passes: the first
converted the return rules and the linker's, and left `ensureProbeRoute`,
`EnsureControlRoute`, `EnsureEgressRule` and `RemoveProbeRoutes` still grepping
the full listing for a number. On the probe rules that was the worst of them -
a failed `ip rule add` is fatal for the whole batch, so one named table meant
the paths after it never got rules either. If you add a readback, filter by
number; if you add a *delete*, name the table by number too, which is always
accepted whatever the alias.

**A routing table number belongs to the host, not to this system.** The same
dual-ISP box was already using 200 for its own policy routing, and the linker
installed `ip route replace default via <backend> table 200` straight over the
top of it - so that host's second-ISP traffic went to the backend instead, with
nothing anywhere saying so. `Linker.Table` exists for this; the default is only a
default. The same hazard applies to the backend's 100 and the probe tables
101-103 on any host that already policy-routes, and `failoverctl revert` flushing
a shared table would take the operator's routes with it.

**Windows clock granularity in tests.** `time.Now()` can return identical values
for calls microseconds apart. Tests drive the trackers with explicit
timestamps (`base`, `feedAt`) rather than the wall clock. Keep doing that.

---

## 9. State and storage

**Frontend** — SQLite at `/var/lib/failover/failover.db`:

| Table | Contents |
|---|---|
| `config` | Single row, the whole configuration as JSON. The portal is the only writer. |
| `ledger` | Accumulated metered bytes per path per billing period. Authoritative for quota enforcement. |
| `usage_samples` | Per-sample usage for graphs. Retained 13 months. |
| `path_samples` | RTT/loss/jitter for graphs. Retained 30 days. |
| `events` | Switches, failures, quota events, approvals. Retained 90 days. |
| `grants` | Live overage approvals. |
| `users`, `sessions` | Portal auth. PBKDF2-SHA256, 600k iterations. |
| `meta` | Small key/value, e.g. `usage_seq:<pathID>` for delta dedupe. |

Also on disk: `ruleset.nft` (the generated DNAT ruleset, left in place as a
readable record), `egress.nft` (the source NAT for backend-originated traffic,
written only when `Frontend.BackendEgress` is on), `protect.nft` (the rate
limiting and edge filtering, written only when protection is on and something in
it is configured) and `ctl.sock` (the failoverctl socket, mode 0600).

**Backend** — no database. `backend-config.json` (cached pushed config, so a
frontend outage does not leave it unable to route replies after a restart),
`usage-buffer.jsonl` (undelivered deltas), `meter-state.json` (counter
baselines and sequence numbers — persisting the baseline means usage during
agent downtime is still accounted for).

**Bootstrap files** (`/etc/failover/{frontend,backend}.json`) hold only the
shared secret, state paths and overlay addressing. Everything else is in the
portal, on purpose: there is one place to manage the system from.

**Linker** — no database and no state files at all. `/etc/failover/linker.json`
carries the shared secret, the overlay addressing, and the two things the
frontend has no way to discover: this host's own overlay address and the
backend's address on the local network. `LoadBootstrap` refuses a linker config
missing either, because an agent that starts with neither installs a rule for
traffic that will never arrive and reports itself perfectly healthy.

---

## 10. Configuration model

**Adding a field to `model.Config` does not give existing deployments its
default.** The whole config is one JSON blob in SQLite, so a config written by
an older build unmarshals with every newer field at its zero value, and
`Defaults()` only ever runs on a first start. Shipping the quality weights
without accounting for that gave every upgraded system a scoring function where
all weights were zero and the portal a form full of zeros. `model.Normalise` is
where that is repaired, and it is called on load and on save. It fills in a
group only when every field in it is zero — which cannot be deliberate — so an
individually chosen zero, a margin or a dwell of none, survives.


**Five fields exist only for multi-host sites, and empty means "the backend"
for all of them.** That is what keeps them invisible: an older config
unmarshals with every one at its zero value and behaves exactly as it did.
`Normalise` deliberately leaves them alone — there is nothing to repair,
because zero is already the right answer.

| Field | Empty means | Owned by |
|---|---|---|
| `Overlay.Subnet` | one host at the far end, routed as a `/32` | bootstrap file, both hosts |
| `Service.Target` | published to the backend | portal |
| `EgressSource.Host` | the network belongs to the backend | portal |
| `Config.Linkers` | no extra hosts; the backend forwards to nothing | portal |
| `Config.BackendLAN` | no linkers to generate a config for | portal |
| `Path.Shape` | no shaping; no `tc` command changes anything | portal |
| `Config.Protect` | no filtering; the table is not loaded at all | portal |
| `Service.SourceEngine`, `Service.CeilingPPS` | an ordinary published port | portal |

`Config.Linkers` is the topology the backend cannot work out for itself. An
overlay address says nothing about which machine holds it, so each row pairs one
with the neighbour the backend forwards to, and the list is pushed down the
control channel with the rest of the config. That is what makes the route an
agent-installed, reconciled thing rather than a static route somebody has to
remember to persist.

The list is **declared, never announced**. Letting a linker register itself would
let an unauthenticated box on the LAN claim any address in the overlay and move
the backend's routing from outside it. `web.validate` fails closed in both
directions: a linker must sit inside the subnet and not collide with the
frontend, the backend or another linker, and a `Service.Target` must name a
linker that actually exists — being inside the subnet only proves the *frontend*
can route it.

`Config.BackendLAN` routes nothing. It is the one fact a linker's own bootstrap
file needs that nothing else here carries, and holding it is what lets the portal
generate that file instead of the operator assembling it by hand.

`Overlay.Subnet` is bootstrap-owned rather than portal-editable for the reason
in invariant 14, plus one of its own: it has to be covered by `AllowedIPs` on
the frontend's peers, and the portal cannot edit a WireGuard config. The shipped
setup puts the whole range there from the start precisely so that this is
normally already true — see the `AllowedIPs` trap for why the narrower value is
the more dangerous default.

`model.Config` is the whole user-editable surface. The portal `PUT`s it whole;
`web.validate` normalises and rejects it; `Engine.Reconfigure` persists it,
restarts the probers, reapplies system config, and bumps `cfgVersion`. The
control server notices the version change within 2s and pushes the backend's
subset down.

Defaults (`model.Defaults()`) match the intended deployment: NBN/LTE1/LTE2 at
priorities 1/2/3, tables 101/102/103, marks `0x101`/`0x102`/`0x103`, 250ms
active and 5s standby probing, 8 losses to condemn (~2s detection), 90s
failback hold-down, 60 GB and 20 GB quotas resetting on the 1st in
`Australia/Sydney`, services `27015/udp`, `27020/udp`, `80/tcp`, `443/tcp`, and
**observe mode**.

Ports in use: probe `51999/udp`, control `51998/tcp`, tunnels
`51820`/`51821`/`51822` (distinct so pfSense can policy-route by source port),
admin tunnel `51830/udp`, portal `10.98.0.2:8080`.

---

## 11. Testing

Tests are pure and fast — no network, no root, no sockets. They cover the parts
where a subtle regression would be invisible in production until an outage:

- `engine/select_test.go` — the whole selection policy: priority, immediate
  failover, hold-down failback, quota skip, held states, dead-man, pinning.
- `engine/quality_test.go` — quality selection: that it never displaces the
  preferred path however much better a fallback measures, that priority mode is
  untouched, that loss outranks latency, that the margin and hold-down both
  apply between fallbacks, that identical paths never swap, that a change of
  challenger does not restart the clock, and that the dead-man and pinning
  still win.
- `engine/tracker_test.go` — health transitions, the suspect-stays-usable rule,
  clean-streak reset, circuit breaker and its backoff, degraded thresholds.
- `quota/quota_test.go` — billing period boundaries including short-month
  clamping, metered-byte reconstruction, grants expiring by time and by bytes,
  ceiling overriding a grant.
- `proto/proto_test.go` — round trip, and rejection of wrong keys, tampering,
  wrong sizes and replayed challenges.
- `sysx/nft_test.go` — the published ruleset never masquerades; atomic replace;
  the egress source NAT stays in its own table, stays scoped to the public
  interface, and renders nothing at all when it is off; the two forward-exception
  comments cannot match each other; the backend egress SNAT stays ahead of
  Docker's masquerade and never fires off the tunnels; no two fwmarks collide;
  return marking is limited to connections that originated from a tunnel.
- `web/password_test.go` — a password can be changed, doing so logs out every
  other session while keeping the caller signed in, the current password is
  required, an unauthenticated request cannot change one, the local socket can
  reset a forgotten one, and a very short password is refused.
- `sysx/protect_test.go` — protection off generates no table at all, and the
  switch on with no thresholds generates none either; every chain excludes
  non-public traffic in its first rule; the system's own ports and overlay
  addresses never appear; the table never translates an address; the chains run
  before dstnat; sources are parked only when a block time is set; the blocklist
  is consulted first; query limiting matches only connectionless packets and
  needs a service to opt in; every drop is counted; the blocklist set is dynamic
  and bounded; two services on one port still produce a set nftables will
  accept; and the counters and blocklist parse back out of `nft -j`.

  The last two are load failures, not cosmetic ones, and both were found by
  reading the generated ruleset rather than by any test passing. A set that is
  not `dynamic` refuses every `add` from the packet path, and a set literal with
  a repeated or overlapping element is rejected outright — in each case nft
  rejects the **whole table**, so one duplicated service port would have taken
  every limit down with it. Generated nftables is worth reading by eye before
  trusting: the tests can only assert what somebody thought to assert.
- `sysx/shape_test.go` — an unshaped path installs nothing, the configured rate
  reaches the kernel with the overhead, an intact shaper is left alone, one lost
  with its interface is restored, clearing the rate removes it, a queue
  discipline this agent did not install is never removed, and tc's units are
  read back whichever it chose to print.
- `engine/protect_test.go`, and the shaping cases in `agent/reconcile_test.go` —
  observe mode neither shapes nor loads a limiter, disabling protection removes
  the table, shaping lost with a tunnel is restored while an intact one is left
  alone, an unshaped site never runs `tc` in the reconciler, and revert removes
  only the shapers this agent installed.
- `sysx/route_test.go` — that a table with a name in `rt_tables` does not hide
  the agent's own rules from it, that the control and return-mark rules carry an
  explicit priority ahead of the probe band, that moving a rule to its pinned
  priority adds before it deletes, the control rule selects on mark not addresses,
  rp_filter is off rather than loose, the path rules are pinned ahead of the
  return rule, and a purged table reads back as no interface rather than an
  error.
- `engine/reconcile_test.go`, `agent/reconcile_test.go` — what a tunnel restart
  leaves behind gets repaired, an intact system is left completely alone, a
  tunnel that has not come back is skipped, and observe mode repairs
  measurement without installing anything that moves traffic.
- `sysx/linker_test.go` — that a site with no subnet generates byte-identical
  rules, that the two prefix helpers agree once one is set, that a service
  target moves only the DNAT, and that the source rules stay behind the
  per-path rules and get moved when found elsewhere.
- `agent/revert_test.go` — the backend takes down what it installed: both return
  sources, the mark rule, the marking and egress tables, the routes to extra
  hosts, the probe tables and the overlay route; that it deletes table 100's
  default route rather than flushing the table; that it removes only the shapers
  it installed; that it acts in observe mode; and, the one guarding every
  existing site, that a site with no subnet and no linkers reverts nothing that
  mentions either.
- `linker/linker_test.go` — an egress install the kernel refused is not recorded
  as applied and is retried on the next reconcile tick, an unchanged push costs
  nothing, a host the frontend has never spoken to has its egress left alone,
  an intact linker is left alone, the route lost with
  the LAN interface is restored, revert leaves the overlay address in place, the
  agent writes no sysctls, and it loads exactly one nftables table of its own
  which never translates an address. Also that marking happens before dstnat and
  only in the original direction, which is what makes it match the overlay
  address rather than the container's.
- `engine/linker_registry_test.go` — each linker receives only its own networks,
  an unowned row never leaks to one, nothing is pushed while the egress master
  switch is off, only configured linkers are accepted, and a configured host
  that has never connected still reports as down rather than vanishing.
- `engine/linker_session_test.go` — the control channel end to end over a real
  socket: authentication, the first push, liveness registration, a linker
  claiming an address nobody configured being refused, and a roleless hello
  still being understood as the backend.
- `sysx/forward_test.go` — the Docker forward exceptions widen when the overlay
  subnet is set, leave an already-correct chain alone, and never touch a rule
  they do not own.
- `web/linker_config_test.go` also covers the routing table: out of range,
  colliding with a table this system uses at the far end, and zero meaning the
  default.
- `engine/superseded_test.go` — the `/32` a widened route replaced is removed
  once, not repeatedly, never without a subnet, and never in observe mode.
- `engine/egresshost_test.go` — each agent receives only its own egress
  networks, and an unowned row still means the backend.
- `agent/linker_test.go` — the backend installs a route per linker, repairs one
  lost with the LAN interface, corrects one pointing at the wrong host, leaves
  an intact one alone, withdraws one that was removed, and — the one that
  guards every existing site — issues no `via` route at all when no linker is
  configured.
- `web/linker_config_test.go` — the fail-closed rules: no linkers without a
  subnet, no two on one address, none outside the subnet or colliding with the
  frontend or backend, no publishing to an address no linker holds.
- `engine/linker_push_test.go` — only enabled linkers reach the backend, and a
  site with none sends nothing.
- `web/validate_test.go` — a path mark colliding with any of the five the system
  reserves, duplicate marks/tables, contradictory ceilings,
  unknown timezones.

When you add behaviour to the selector or the trackers, add a test that states
the *reason* in its name and comment. The existing ones do; that is how the
next agent learns which behaviours are deliberate.

---

## 12. Known gaps

- IPv4 only. The nftables table is `ip`, not `inet`, and the overlay is v4.
- No TOTP on the portal. The admin WireGuard tunnel is the real control.
- The frontend does not verify that the backend actually applied a decision; it
  assumes the probe reply implies it. A mismatch would show as asymmetric
  routing and is not currently detected.
- A recreated interface is noticed by polling, not by netlink. The reconcilers
  read the kernel every 10s, so a restarted tunnel is unusable for up to that
  long after it comes back — on top of the probes needed to prove it healthy.
  Subscribing to `RTM_NEWLINK` would make it immediate, at the cost of the
  first netlink dependency in a codebase that deliberately shells out.
- Egress selection is by overlay source address (host services, via `-ip`) or by
  source network (`Egress.Sources`, for containers). There is no per-process
  selector. A host service that opens an unbound socket — a Lua `http.Fetch`, a
  workshop download — picks its source from the route to the destination and
  still leaves via pfSense, and `-ip` does not change that. Covering it would
  mean `meta skuid` or cgroup matching in an output chain, which is not built.
  The container case has the opposite property: the network match catches
  *everything* in that network, wanted or not.
- The reconcilers repair routes and `rp_filter`. Anything else the kernel
  attaches to an interface — a queue discipline, an nftables device set — would
  be lost on a restart with nothing to notice.
- Metering trusts the WireGuard interface counters plus a calibration factor
  rather than reading pfSense's WAN counters. It should land within a few
  percent, but the calibration exists because it might not.
- No Prometheus endpoint. The portal owns observability.
- **A linker's control channel is minimal on purpose.** It reports liveness,
  hostname and build, and receives the egress networks for its own address. It
  reports no usage - a linker meters nothing, because the tunnels it would be
  metering are not its - and it is told no path and no mode, because it makes no
  decisions.

  Liveness deliberately does **not** reach the trackers. A second box being down
  is not a path problem, and feeding it to `engine/tracker.go` would make
  rebooting a game server look like a failing tunnel and move traffic to LTE. It
  sits beside the paths in the portal, never among them.

  **Liveness and last contact are two different questions and the portal asks
  only one at a time.** `LinkerState.Since` is how long the current session has
  been up, which is worth nothing once there is no session; `LastSeen` is when a
  frame last arrived and is deliberately kept afterwards, because a card that
  went blank on disconnect said exactly what one for a host that had never
  connected said, and those are different faults. It is stamped on every frame
  rather than at connect - a pong answering the keepalive is the only thing a
  healthy linker ever says - and persisted to `meta` under `linker_seen:<ip>`,
  throttled to `linkerSeenPersistEvery` and forced at connect and disconnect, so
  a host that was already silent before a frontend restart still reports how long
  it has been silent.

  **A linker's teardown is keyed to its session, not just its address.** Same
  fault `backendConns` exists for: a linker whose TCP connection dies silently -
  which is what a failover looks like from the frontend - redials and
  authenticates while the old session is still parked on its read deadline, and
  an unkeyed `SetLinkerDown` then deletes the entry the new session just made.
  The portal shows a healthy host as disconnected indefinitely, because that host
  has a working channel and no reason to dial again.

  The direction the declaration flows is load-bearing: the operator states the
  topology in the portal and the agents are told. A linker announces which
  address it believes it holds, and `Engine.KnownLinker` checks that against the
  configured list before anything is pushed - the shared secret proves a peer
  belongs to this deployment, not that it is entitled to any particular address.
  A linker that could name itself could be handed another linker's networks, or
  take over the traffic published to one.

- **A linker handles containers in both directions.** Publishing to one works
  through `BuildLinkerReturnRuleset`, which marks connections addressed to the
  overlay address so their replies route back to the backend whatever source
  address they are carrying at the time. Container-originated traffic works
  through `BuildLinkerEgressRuleset`, which is the backend's egress feature
  reshaped for a host with no tunnels: mark into table 200, SNAT to this
  linker's own overlay address, scoped to the LAN interface rather than to
  tunnels it does not terminate. The SNAT sits at priority -10 for the same
  reason the backend's does, ahead of where Docker installs its masquerade.

  The outbound half installs only when `Frontend.BackendEgress` is on, the same
  gate the backend's has: without the frontend's source NAT waiting at the other
  end, pulling a network onto the overlay sends its traffic somewhere it cannot
  be answered. A network assigned to a host that is not a configured linker is
  rejected by `web.validate` rather than filtered out in silence.
