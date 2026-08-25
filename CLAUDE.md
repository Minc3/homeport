# homeport - orientation for an AI agent

Read this before changing anything. The design has several load-bearing
decisions that look like arbitrary complexity until you know why they are
there, and undoing one of them breaks the system in ways that are hard to
notice from a passing test run.

If you only read one section, read **Invariants** and **Why it is like this**.

---

## 1. What the system does

A Garry's Mod server and some websites are hosted on a Debian box at a house.
They are published to the internet from a Debian box in a datacentre. Between
the two are three WireGuard tunnels riding three different internet services -
a main fixed line, and two LTE services.

The job: give the datacentre box **one stable path** to the home box, and move
it between the three tunnels automatically when one fails, without players
being disconnected and without silently burning through LTE data caps.

```
                    Internet
                       │
              Debian FRONTEND  (datacentre, public IP, always reachable)
                       │
        ┌──────────────┼──────────────┐
     wg-main         wg-lte1        wg-lte2
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
identical `ip` commands to a build that had never heard of it - see invariant
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

**The wire version is 2, and hosts do not interoperate across it.** The probe
MAC and the control handshake are domain separated (see §6), so an older
frontend's probes do not authenticate against a newer backend and neither
half of the handshake matches. Upgrade the backend first and the frontend
straight after: only the newer host can recognise the older one's probes as a
version mismatch rather than as a failed authentication, so that order puts the
accurate message on the host doing the reporting (`deploy/SETUP.md` §15 shows
both). In the window between them the frontend measures 100% loss on every path, the
dead-man behaviour keeps the installed route where it is, and published traffic
carries on over whichever tunnel was already active. Three dead paths in the
portal during an upgrade is that, not a fault, and it is not a reason to reach
for `revert`. Linkers can follow at leisure: an un-upgraded one keeps routing
what it was already routing and simply receives no egress pushes until it is
updated.

Rolling back goes host by host, in this order (see invariant 8):

```sh
failoverctl revert                            # frontend, first, agent running
systemctl stop failover-backend               # backend, second
failover-backend -revert
systemctl stop failover-linker                # each extra host, if any
failover-linker -revert
```

The frontend's revert needs its agent **up**, because it goes over the control
socket into the running engine, which is also what disarms it. It also latches
the engine: the probers stop and the reconciler and decision loop hold off
until the next settings save or mode change, because observe mode deliberately
repairs measurement plumbing and would otherwise reinstall the probe tables
within a tick of the revert removing them. A reverted frontend measures
nothing until it is told to resume. The latch is persisted (a `meta` key) and
honoured by the startup sequence, because the unit runs under `Restart=always`:
held only in memory, any crash between the revert and the `systemctl stop`
that follows brought the process back reinstalling everything the revert had
just removed. The portal says the hold out loud (`Status.Reverted`), since the
trackers freeze at whatever they last measured and the frozen cards otherwise
read as three healthy paths. The other two
need theirs **stopped**: those reverts are separate processes with no way to
tell a running agent anything, and the reconciler puts back everything it finds
missing within ten seconds. Reverting underneath a live agent leaves a host that
is half reverted and reports itself clean.

Removing an agent entirely is `sudo ./deploy/uninstall.sh` on each host, in that
same order. It runs the revert above first, while the binary that knows what it
installed is still there, and refuses to remove anything if that fails. Config
and state go with it unless `--keep-config` or `--keep-state` says otherwise;
WireGuard and the overlay address survive regardless.

- **Commit straight to `main`.** No feature branches, no PRs - this is a
  single-operator repo and the branch would only ever be merged by the person
  who wrote it. Do not create one "to be safe"; just commit.
- Go 1.25. Module `github.com/quinlan102/homeport`.
- **One external dependency**: `modernc.org/sqlite`. Keep it that way unless
  there is a strong reason - CGO must stay disabled so the binaries are static.
- Development happens on Windows, deployment is Debian. Linux-only code goes in
  `_linux.go` files with a `!linux` stub beside it (see `internal/sysx/mark_*.go`),
  so the tree still builds and tests on the dev machine.
- **No em dashes, anywhere.** Not in docs, code comments, portal text, help
  strings or generated files. Use a comma, a colon, a spaced hyphen or a new
  sentence instead. The docs and the portal have been purged of them more than
  once; writing a new one is a regression, not a style choice.
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

- conntrack keeps its entries - the DNAT binding for a player's UDP flow stays
  valid,
- the client's 5-tuple is untouched - srcds sees the same peer,
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

- `engine/engine.go` - the `Engine` struct and its `Run` loop. `selectPath` is
  the policy; `evaluate` computes blocks and applies the choice;
  `reconcileRouting` puts back what the kernel discarded (see invariant 18).
- `engine/tracker.go` - per-path health state machine. Knows nothing about
  priorities or quotas by design.
- `engine/prober.go` - one UDP prober per path, plus the sliding `Window` used
  for loss/RTT/jitter.
- `engine/control.go` - accepts the backend's connection, pushes config, folds
  in usage deltas.
- `sysx/route.go` - every routing command, with the addressing model explained
  in comments. Also the kernel readbacks the reconcilers depend on (`RouteVia`,
  `DefaultVia`, `RPFilterOff`), which report what is actually installed rather
  than what the agent believes it installed.
- `sysx/nft.go` - DNAT ruleset generation, plus the separate `failover_egress`
  source NAT and the Docker forward exceptions both of them need.

### Backend files

- `agent/agent.go` - state, config application, `SetActivePath`, and
  `reconcileRouting`, which shares `applyLoop`'s goroutine so route repairs
  cannot race a decision being applied. Also `Revert`, the backend half of a
  rollback, reached by `failover-backend -revert` rather than over the control
  channel: revert is the panic button, and one a lost frame can press is not a
  panic button.
- `agent/responder.go` - probe replies, and applying the frontend's decision.
- `agent/meter.go` - counter sampling with on-disk buffering.
- `agent/client.go` - dials the frontend, reports upward.

### Linker files

- `linker/linker.go` - the agent. `apply` installs, `reconcile` re-reads,
  `applyEgress` handles what the frontend pushes down. That last one keeps two
  lists: what the frontend asked for and what actually went in. They differ only
  after a failed install, and `reconcile` retries the difference. The frontend
  pushes once per configuration version, so without a retry a transient failure
  at boot (no route to the backend yet, so no interface to scope the source NAT
  to) would last until somebody saved settings again.
- `linker/client.go` - the control client. Dials the frontend from a socket
  bound to the overlay address, so the channel rides the active tunnel like
  everything else this host sends.
- `sysx/linker.go` - the rules, the readbacks, the two nftables tables, and
  `DefaultLinkerTable` (200, and only a default - see `Linker.Table`).

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
   advanced, and replies from a socket marked for the *same* path - so the
   reply leaves by the tunnel the request arrived on.
4. Frontend matches the reply to its outstanding sequence and records an RTT.
   Unanswered probes are resolved as lost after the timeout.
5. Results are delivered to the tracker **in sequence order** (`Prober.flush`).

### The linker control channel (TCP, JSON, linker dials frontend)

Only where extra hosts exist. Far smaller than the backend's: the linker reports
liveness, hostname, build and the routing table it actually used, and receives
the egress networks belonging to its own overlay address. It reports no usage
and is told no path or mode.

Its socket is bound to the overlay address deliberately - that is what puts it
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
   `decisionSeq`, flip the probers' active/standby cadence, and **nudge every
   prober** (`Prober.Nudge`) so each sends a probe now instead of on its next
   tick.
4. The new decision reaches the backend on that probe, over whichever tunnel
   is alive. The nudge is what makes this immediate: without it a standby
   path's next probe was wherever its 5s ticker happened to be, and until one
   landed the backend went on answering down the tunnel that had just died.
   That was up to five seconds of frozen players on top of detection, and it
   was not in any setting. A prober also nudges itself on entry, so a fresh
   generation (a frontend restart mid-outage, a settings save, a redial) sends
   at once rather than after a full interval. Each switch and each generation
   start therefore costs one out-of-cadence probe per path, about 130 bytes
   each way, which the standby arithmetic above does not include and which is
   bounded by how often the system switches.

The backend keeps only the newest queued decision (`Agent.SetActivePath`
replaces `pending` only for a higher sequence). Its pre-filter reads `active`
and `lastSeq`, which the worker updates after its apply finishes, so while it
is inside `ip` a straggling probe from the abandoned tunnel carrying the
previous sequence still passes the filter. Unconditional, that straggler
overwrote the newer decision and the abandoned path was applied a second time.

Anything that changes an input to `selectPath` outside the tick wakes the
decision loop (`Engine.wakeDecision`) rather than waiting up to 500ms: a path
changing eligibility in either direction, the operator's pin, approve, revoke
and clear-quarantine actions, and a settings save. Recovery matters as much
as condemnation: with every path down the route is left on a dead tunnel and
the first path back is switched to with no hold-down, so the tick was the
whole of that delay. `Tracker.Usable` is the test, so up to suspect wakes
nothing. The tick remains for the purely time-based inputs: hold-down,
quarantine and grant expiry.

The entry nudge took away a delay that was doing a job. A send the kernel
refuses outright ends the socket and `Prober.Run` opens another, and that
cycle was throttled only by the first send waiting a full interval on the
ticker. Nudging on entry removed the wait and left the cycle with no delay at
all: a core spinning on dial-fail-redial, the sweep never reached, no loss
ever delivered, and `pending` growing until the sends came back and the
backlog was expired as one streak against a path that by then worked.
`sendFailed` books the failed probe as lost on the spot and `Prober.hold`
waits one interval before the next socket, which is what the dial-failure
path (`reportUnreachable`) always did. `hold` also runs the sweep before it
returns, and that is not tidiness: results leave in sequence order, a link
usually dies with a probe sent and unanswered, and only `expire` can resolve
that one. With no loop alive to tick the sweep, every later loss was booked
behind it and none was delivered.

### A usage delta

1. Backend samples `/sys/class/net/<iface>/statistics` every 10s.
2. Computes `Δbytes` and `Δpackets`. A negative delta means the interface was
   recreated - rebaseline, do not log.
3. Buffers the delta to disk with a per-path sequence number.
4. Ships batches up the control channel; the frontend dedupes on the sequence
   (`meta` key `usage_seq:<pathID>`) and folds them into the SQLite ledger,
   converting to billed bytes with `quota.Metered`. The watermark is written in
   the **same transaction** as the ledger insert: as two writes, a crash
   between them left a stale watermark that let the resent batch bill the same
   bytes twice.
5. The frontend acks the highest sequence per path that is durably in the
   ledger (`usage_ack`), and only then does the backend drop its buffered
   copy. A successful TCP write is not delivery - the batch in flight when the
   connection dies would otherwise be lost, and the connection dies at every
   failover, which is exactly when LTE usage is accruing. Anything unacked is
   resent on the next tick; the sequence dedupe makes the overlap free.

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

**Both ends of the control channel prove themselves, and a dialling agent acts
on nothing until the frontend has.** The handshake used to be one-sided: the
frontend challenged whoever dialled in, and the dialler never challenged back.
The reasoning was that the channel runs inside WireGuard, and for the backend
that holds, because its connection enters the tunnel on its own host. It does
not hold for a linker. A linker reaches the frontend by routing through the
backend as an ordinary LAN neighbour (`from <overlay> lookup <table>`, default
via the backend), so the first hop is plaintext TCP on somebody's office
network and only becomes WireGuard when the backend forwards it. Anything on
that segment could answer in the frontend's place, with no shared secret at
all, and what it would then be believed about is `LinkerConfig.EgressCIDRs` -
rules the linker loads into nftables as root.

`proto.SignAuth` and `proto.SignAuthAck` are the two halves. Both cover both
nonces, so neither end can choose the whole preimage, and they carry different
labels so the cheapest attack on a two-sided handshake - reflecting the
dialler's own proof back at it - does not work. The dialler checks the
frontend's half before it sends its `Hello`, so a peer that cannot prove itself
is not even told which overlay address the host holds.

**And the handshake alone is not enough, which is the part worth reading
twice.** It proves who the peer is at connect time and says nothing about who
is writing down the socket afterwards. The attacker above does not have to
impersonate the frontend: from the same position it can *relay* the handshake
to the real one, let both ends satisfy each other, and then send frames of its
own. Mutual authentication without per-frame authentication would have moved
the attack, not stopped it, and would have read in the diff as a fix.

`proto.Session` is what closes it. Every frame after the handshake carries a
MAC under a key derived from the pre-shared key and both nonces. A relay cannot
alter either nonce without breaking the handshake MACs, so it is forced to hand
both ends the same transcript, which means both ends derive the same key and
the relay - holding no pre-shared key - derives nothing. Each direction has its
own label, so a frame cannot be turned round at its sender, and its own counter,
checked exactly rather than as a floor: the transport is TCP, so a gap is not
late delivery, it is a frame somebody removed. What is left to an on-path
attacker is dropping frames, which is what cutting the cable already did.

`Session.WriteFrame` takes a lock across the counter and the write together,
and that is load-bearing rather than tidy: both the frontend and the backend
write from two goroutines (`pushLoop` beside the read loop's pong and usage
ack), and a sequence number that reached the wire out of order would be read as
tampering by a peer checking it exactly.

It sets the write deadline itself, inside that lock, and the callers no longer
do. Serialising the writes made a caller-side deadline wrong twice over: a
goroutine that set one and then waited out another's stalled write arrived at
the socket with the time already spent and failed instantly, and two goroutines
setting a deadline on one connection were overwriting each other's regardless,
because a deadline belongs to the connection and not to the write. The three
handshake frames still set their own - they are written from one goroutine,
before any session exists.

**A frame is bounded before it is read, and the bound is the frontend's, not
bufio's.** Every read here was `bufio.Reader.ReadBytes('\n')`, and the 4096-byte
reader in front of it was doing none of the work it looked like it was doing:
`ReadBytes` accumulates a line of any length into a fresh allocation, so a peer
that simply never sent a newline was handed as much of the frontend's memory as
it cared to ask for. On the frontend the first read happens *before* the
handshake, so no credential was needed at all, and the positions that can reach
that listener are exactly the ones `proto.Session` exists to defend against: a
linker's first hop is plaintext TCP on somebody's LAN. The cheaper attack was
one step ahead of the defence. `proto.MaxFrameBytes` and `proto.ReadFrame` are
the fix, shared by all three agents rather than copied into each, and
`Session.ReadFrame` reads through the same helper - the limit has to sit ahead
of the MAC check, because a limit applied after the frame is read is a limit on
memory already committed. A megabyte is about twenty times the largest frame
this protocol produces, which is a 500-delta usage batch, and
`proto_test.go` pins that ratio so shrinking one or growing the other has to be
a decision.

**The sender refuses an oversized frame too, and that is not symmetry for its
own sake.** The receiver drops one and closes, which from the sending side is
an ordinary disconnect - so a frame that outgrew the bound would present as a
reconnect loop with nothing anywhere naming the cause, and since the session
counter does not advance on a refused write, the reconnect would build the same
frame again. Nothing reaches it today; it is there for the change that raises
the usage batch's 500.

**And the sender's refusal has to be said out loud, or it moves the silence
rather than ending it.** Every writer here treats a failed write as an ordinary
disconnect and redials, which is right for a broken connection and wrong for
this one: the frame will never be deliverable, and since the session counter
does not advance over a refused write, the next connection builds the identical
frame and refuses it again. `ControlServer.warnUnsendable` and
`Agent.warnUnsendable` are the two ends of that, on the four writes that carry
anything an operator can grow - the config push, the linker push, the usage
batch and the link report - and they log at `Error`, because nothing here
recovers on its own.

**And a bound per frame is a bound on one multiplier.** `maxControlConns`
bounds the other: every accept used to start a goroutine with a reader behind
it and nothing said no. Refusing is a close rather than a queue, because a
caller made to wait is holding one of this host's sockets either way and every
honest peer redials. Sixty-four is far above one backend plus one connection
per linker, including the moment a silently dead session is still parked on its
read deadline while its replacement dials in.

**A total with nothing reserved in it is a pool the honest peer can lose,
which is why `maxPerSource` bounds one address to four of those sixty-four.**
Every connection claims from the pool before it has proved anything, so sixty-
four sockets from one machine - opened and left silent, or churned as their
ten-second handshake deadlines expire - held all of it, and the backend's
redial was closed on sight. The position that can do that is the one
`proto.Session` exists for: a linker reaches this listener as an ordinary LAN
neighbour routed through the backend, so the first hop is plaintext TCP on
somebody's office network, and the backend forwards the overlay range in both
directions. What it costs is not a portal that looks wrong - no usage delta
reaches the ledger, so LTE billing under-counts during exactly the window
quota enforcement exists for, and no configuration reaches the backend. The
per-address share is claimed before the pool slot, so a flood is turned away
without taking one even momentarily, and `releaseSource` deletes an empty
entry rather than leaving it at zero, because the keys are chosen by whoever
dials and a map that only grew would be a second unbounded resource behind the
limit meant to bound the first. It bounds one address and not an attacker with
a subnet to spend; the total is still what covers that.

That cap bounds how many connections are open at once and says nothing about
how fast they can be cycled, which is why the three reports a peer can drive
the rate of - rejected before authentication, no slot in the pool, one address
over its share - all go through `ControlServer`'s `throttle` at one report per
thirty seconds. A peer that cannot authenticate is a peer that redials, so one
`Warn` per attempt was unbounded journal output driven by a party that has
proved nothing, and pushing real entries out of the journal is a cheap way to
hide something. Thirty seconds still surfaces the case the log exists for,
because a genuinely misconfigured backend redials on a backoff that tops out at
exactly that.

**A throttle needs a trailing edge, and the first two hand-rolled copies of
this did not have one.** Each counted an event, reported when the window had
passed *since the last report*, and reset the counter - so a burst that stopped
inside the window was never reported at all. Five hundred failed
authentications over five seconds produced one line saying "1", and the other
four hundred and ninety-nine were counted into a window that never emitted,
because the peer driving it had stopped. The journal then records a single
rejected connection for a flood of five hundred, which is the opposite of what
the log is for. `throttle.flush`, ticked by `listen` for as long as the
listener lives, is what names them; it returns zero when nothing is owing, so a
quiet server still logs nothing. They are fields on the server rather than
locals in the accept loop because `listen` is re-entered after a failed bind,
and counters that reset there would forget a burst in progress.

The rejection log is also where `proto.ErrFrameTooLarge` is finally
distinguished from an authentication failure: the first read in `serve` used to
return in silence, so the one rejection that means "somebody sent something no
honest agent sends" produced no output at all.

`ControlServer.listen` fills that channel in when it finds it nil, as its first
statement and before the bind, and both halves are correctness rather than
tidiness. A nil channel does not weaken a select with a default arm, it inverts
it: the send never proceeds, `default` wins every time, and the server refuses
every connection it is ever offered, silently and for the life of the process.
`NewControlServer` sets it, but three tests build the struct literally, which is
exactly how a future caller arrives at a server that accepts nothing while
reporting itself healthy. Doing it ahead of the bind leaves no state of this
server in which the accept loop is reachable without a limit, and it is what
lets the test assert this without a sleep: once `listen` has returned, that
statement has run, whether the bind succeeded, failed, or was never attempted.

**A peer's role arrives in its own Hello, so the address it connects from is
what settles which half of the protocol it is served.** The handshake proves
the peer belongs to this deployment and nothing more, which is exactly the
reasoning already written for a linker's claimed overlay address. It was
applied to linkers and not to the backend: `serve` dispatched on
`hello.Role`, and anything that was not `"linker"` fell through to the backend
branch with no test of any kind. Omitting one JSON field was therefore enough
to be served as the backend, and an empty role is not an exotic frame, it is
what a backend from before linkers existed sends.

What that branch does is write the usage ledger, which is authoritative for
quota enforcement. Every host in the deployment holds the identical key,
because `Bootstrap.Key` is `sha256(psk)` whatever the role and
`install-linker.sh` takes the frontend's psk verbatim, so the peer best placed
to use this is a linker: the least trusted of the three by this system's own
reasoning, sitting on somebody's game server and reaching the listener over a
plaintext LAN hop.

`Engine.KnownBackend` is the check, and the address is what it checks because
the backend already proves it for free: `Agent.controlSession` binds its socket
to the overlay address, and the frontend's WireGuard peer only admits that
range. `KnownLinker` gained the matching half in the other direction, because
being on the configured list only says an address belongs to *some* linker: a
linker must also be connecting *from* the address it claims, or one of them
could name another and be handed that host's egress networks, which it loads
into nftables as root for a machine it is not. Neither needs a wire change and
neither costs more than a comparison.

It costs one thing, and it is worth knowing before an install goes wrong. A
backend whose bootstrap file disagreed with the frontend's about
`overlay.backend_ip` used to converge on its own: it was served, the push told
it which address it was, `Agent.Overlay` prefers the pushed value, and
`applyPlumbing` put that address on `dummy0`, so the next dial came from the
right place. That convergence is the hole, stated as a feature, so it is gone.
A fresh install with mismatched files now never connects at all, which is why
both `deploy/SETUP.md` and `install-backend.sh` name this among the reasons a
channel stays down. Two hosts that already agree see no change.

**This is a fence around a shared credential rather than a replacement for
one.** Every role derives the same key, so the address is doing work a
credential should be doing, and an address is a weaker thing to rest on than a
MAC: a root-compromised linker can add the backend's overlay address to its own
`dummy0` and dial from it, because `rp_filter` is 0 on both hosts by necessity
(§8) and the backend forwards the overlay range in both directions. What the
check buys is that the attack now needs root on that host and a deliberate
spoof, rather than one omitted JSON field. The real fix is a per-role key, some
`HKDF(psk, role)` with the role coming from each host's own bootstrap file
rather than from the Hello, which `proto` already has the label vocabulary for.
It is a wire break, because the frontend has to know which key to verify a
handshake against before the Hello has arrived, so it wants a `proto.Version`
bump and a coordinated upgrade. Not done here.

**A usage delta is bounded before it is billed, and every other value on this
channel already was.** The egress networks go through `EgressNetworks`, the
overlay address through `AddressLiteral`, the subnet through `NetworkLiteral`.
The numbers in a usage frame went through nothing, and they are not inert data:
a large one takes every metered path out of the selector while the links
themselves go on measuring perfectly, and a negative one erases the record the
data cap depends on. The second is the worse direction, because over-billing is
at least visible in the portal with an approve button beside it.

`ControlServer.checkDelta` clamps rather than refuses, and that is the design
rather than a shortcut. Refusing would leave the watermark where it was, so the
backend would resend the same delta on every tick and have it refused every
time: that path's accounting would stall for good, which is worse than billing
a bounded wrong number at `Error`. The ceilings are sanity bounds and not tight
ones, deliberately: `Meter` persists its per-interface baseline across restarts
so that usage accrued while the agent was stopped is still accounted for, which
means the first sample after an outage is a *single* delta covering the whole
of it. There is no interval here to multiply a line rate by, and a bound
derived from one would refuse exactly the delta that exists to survive a long
outage.

**The stamp is bounded in both directions, and the past side is the one that
happens by accident.** `AddUsage` picks the billing period from it, so a stamp
outside the window writes the bytes to a period nothing reads while the current
period stays where it was and the quota never trips. The future side is the
obvious half. The past side is reached by invariant 11's own scenario: the
house loses power, comes back with every link down, so there is no route to
NTP, so the backend's clock is stale, and it is the backend's clock that stamps
every delta. Such a host bills a month of metered LTE into 1970 with the portal
showing the period empty. The comparison is made on the raw seconds, not on
the `time.Time`, and that is the correct way round rather than the obvious one.
`time.Unix` overflows at both extremes and lands both in the same place:
`MinInt64` and `MaxInt64` alike render as the year 292277026596 and both compare
as *before* now. A `time.Time` comparison therefore misses `MaxInt64` in the
future branch entirely and catches it in the past branch, reporting a stamp
tens of billions of years ahead as one too far in the past to bill. Seconds do
not wrap.

The past window is a week, taken from the backlog rather than picked round. The
backend buffers at most `maxBuffered` deltas at one per path per ten seconds, so
the oldest an honest one can be is 5.8 days on a single-path site. A month, the
first value here, was five times that, and the slack was not free: a backend
whose clock is a week stale, which is an ordinary amount for an RTC after the
power cut invariant 11 describes, stamps current traffic a week back, lands it
in the previous billing period whenever the outage straddles a reset day, is
never reported because it is inside the window, and leaves the current period
reading empty while the cap is spent.

**The path id is dropped rather than clamped, and never acked.** It is one of
two fields that reach the database whatever else they say: `AddUsage` acks an id
it does not recognise on purpose, so deltas for a path the operator has just
removed stop being resent, and that ack is a row in `meta`, which has no
retention. Acking an id no configuration can hold is therefore a permanent row
per id with the key chosen by whoever is sending, so an id outside the range
`web.validate` allows is dropped before anything is read or written for it.
Clamping it onto a valid id would be worse than dropping: that bills one path's
traffic to another.

**The sequence is the other, and it is the field that does the most damage per
byte sent.** It is a per-path dedupe watermark: `applyUsage` skips anything not
strictly newer, writes the accepted value into `meta`, and acks it so the
backend may drop its buffered copy. All three are permanent. One delta carrying
a sequence near `MaxUint64` therefore parks the watermark where no honest delta
can ever follow, so every later delta for that path is skipped in silence, the
ack tells the backend its entire buffer is applied so the bytes are gone, and
the `meta` row survives every restart. That path is never billed again, the
quota never trips, all three paths go on measuring perfectly, and only editing
the database clears it. It is the one direction that is both silent and
unrecoverable, which is why `maxDeltaSequence` refuses rather than clamps and
does not ack: the resulting stall is deliberate, because a sender emitting such
a sequence has lost its meter state and there is no correct value to clamp to.
A sequence counts samples, so at the ten-second cadence the bound is about three
hundred thousand years of continuous sampling.

**An absolute bound alone does not close that, and reading it as though it did
is the trap.** `maxDeltaSequence` rules out only the top of the range. A
sequence of `1<<39` is comfortably inside it and just as far past an honest
counter of a few million, so it parks the watermark exactly as permanently, with
every consequence in the paragraph above intact. The damage is not a function of
how large the number is, it is a function of how far past the watermark it is,
so that is what `maxSequenceJump` bounds. Both are needed and neither subsumes
the other, though not in the way the first version of this assumed. It guarded
the relative check with `last > 0`, reasoning that a path with no watermark had
nothing to measure from, which handed a fresh database the absolute bound as its
only protection: one first-contact delta at `1<<40` was billed, became the
watermark, and left the path unbillable for good. Zero is a perfectly good base.
The relative bound applies to every delta, and `maxDeltaSequence` is what it
always should have been described as, a pre-filter that saves a database read
for a value no bound could accept. The slack is generous for one reason: the backend keeps sampling while the frontend is
unreachable and its sequence keeps advancing after `maxBuffered` has dropped the
oldest deltas off the front, so a legitimate jump is elapsed samples rather than
buffered ones. A bound derived from the buffer would refuse exactly the delta
that exists to survive a long outage. Forty years of continuous sampling is
still four orders of magnitude tighter than the absolute bound beside it.

**And the reference it is measured against has to be the watermark the batch
began with, not the running one.** The first version compared each delta against
`watermark[pathID]`, which `applyUsage` advances after every acceptance, so a
thousand deltas each sitting exactly at the limit were each admissible against
the delta before them: one frame walked the watermark a thousand jumps, and
eight frames reached `maxDeltaSequence`. A bound measured against a value the
thing being bounded moves is not a bound. `base` never moves for the life of the
batch and is what the jump is taken from; `seen` is the running high-water mark
and does only what it always did, deduplicate resends inside one frame.

**A refusal stalls one path, and that only holds because the backend's batch is
shared out.** `Meter.pending` is a single FIFO across every path, and
`PendingBatch` took a flat prefix of it. A delta the frontend refuses is never
acked, so it stays buffered and another arrives every sample interval: after
about five hundred samples the oldest of them fill a whole batch, every batch
from then on is deltas that will be refused again, and no delta for *any* path
reaches the ledger until `maxBuffered` evicts them days later. Every metered
byte in that window is lost and no quota can trip, which is the deployment-wide
version of the outcome the per-path stall is meant to be a recoverable
alternative to. `PendingBatch` now takes an equal share per path first and fills
the remainder from the front, so a single-path backlog still drains at the full
rate and the ordinary site is unchanged.

**One transaction per path per batch, not one per delta.** SQLite defaults to
`synchronous=FULL`, so every commit fsyncs the WAL, and `Store.Open` holds
`MaxOpenConns` at 1: a five hundred delta backlog was five hundred fsyncs with
every other reader in the process queued behind them, the portal's own API calls
included. A backlog is drained exactly when a failover has reconnected the
control channel, which is when somebody is most likely to be looking at the
portal. `store.AddUsageBatch` writes the rows and the watermark in one
transaction, which also replaces the `stalled` map the per-delta loop needed: if
one delta in a path's batch cannot be written, none of them is and the watermark
does not move, so the backend resends the lot.

What neither bounds is a sequence that has gone *backwards*, and that hole is
open. A backend that loses `meter-state.json` restarts at 1, every delta is at
or below the watermark, `applyUsage` skips them all, and the ack seeded from the
existing watermark tells the backend its buffer is applied, so `Meter.AckApplied`
drops them. That path bills nothing until the sequence climbs back past where it
was, which takes as long as the original run did. It is the same silent
under-billing reached from below, and closing it needs the backend to say that
its meter reset, which is a wire change.

**One usage batch is applied at a time, across every connection.** The
per-path watermark is memoised for the batch rather than re-read per delta, and
a memoised database read is only sound while this goroutine is the one moving
it. More than one connection from the backend is the ordinary case rather than
the exotic one: a silently dead session sits on its read deadline while its
replacement dials in, which is what `backendConns` and `maxPerSource` are both
written for, and the connection dies at every failover. The replacement resends
everything unacked, so two goroutines apply the same deltas, and the old one may
be several hundred transactions into a batch when the new one starts. Without
`ControlServer.usageMu` neither sees the other's commits and the whole batch is
billed twice. The per-delta read this replaced had the same race across one
delta; the lock closes it rather than narrowing it back.

**A bound on one delta is not a bound on the column it accumulates into, and
that gap was reachable inside a single frame.** SQLite does not error on integer
overflow: `bytes + excluded.bytes` silently becomes a REAL, and from then on
every `Scan` into an int64 fails with "converting driver.Value type float64 to a
int64". It is permanent, because the column now holds a float, and
`Engine.refreshQuota` carries the previous verdict forward on a read error, so
that path's quota freezes where it stood and only editing the database clears
it. Thirteen deltas clamped to the ceilings above reach it, well inside one
accepted frame. `store.MaxLedgerValue` saturates the sum in SQL, at 2^60, which
is an exbibyte and therefore never bites anything honest while staying low
enough that one more bounded delta on top of it cannot overflow.

**And that column has a floor as well as a ceiling, which took a second pass.**
The ceiling was written first, which left `store.AddUsage` advertising a bound
of its own and enforcing half of it: `MIN(bytes + excluded.bytes, ?)` caps only
upward, and the parameter check tested only the high side, so a negative delta
decremented a column that accumulates. That does not record a wrong figure for
one sample, it erases usage already billed, which is the silent direction and
the one the carrier's invoice is the first news of. Nothing reached it, because
`Engine.AddUsage` clamps first, and that is exactly what made it easy to miss:
the guarantee was living in a caller three files away while this method looked
complete. `clampLedger` and `MAX(MIN(...), 0)` make it total, on the parameters
and on the sum, for the reason `quota.saturatingAdd` carries the same note.

`usage_samples` is the same hazard reached through a read, and fixing only the
write half missed it. Its rows accumulate inside `SUM(bytes)` rather than in a
column, and SQLite does not promote an overflowing `SUM` the way it promotes a
bare `+`: it fails the statement outright, so one bucket past an int64 takes the
portal's usage graph off the air for that path until the rows age out, which is
thirteen months. The sum is taken over `REAL` there, which is right for a graph
and would be wrong in the ledger: this feeds a picture rather than an
enforcement decision, and float64 is exact to about 9e15, four orders of
magnitude above any bucket a deployment produces.

**What these bounds do not do is worth stating, because the temptation is to
read them as more.** A delta clamped to `maxDeltaBytes` and `maxDeltaPackets`
still exhausts any real quota thousands of times over, and that is deliberate
rather than an oversight: the two directions do not cost the same. Over-billing
is visible, since the portal names the blocked path and puts an approve button
beside it, while under-billing is silent until the carrier's invoice. So the
negative direction is refused outright and this one is only kept away from a
number that would overflow the arithmetic downstream. What keeps a hostile peer
away from the ledger is `KnownBackend`, not these.

**And the batch is bounded in count as well as each delta in value.** The
backend caps its own at 500, and the frontend enforced nothing: a frame is
bounded only by `proto.MaxFrameBytes`, and a delta is about a hundred bytes, so
one accepted frame can carry ten thousand. Each is a `Meta` read plus a full
transaction, run inline on the control read loop, which cannot answer a ping or
read the next frame while it works.

**Every one of these reports goes through `ControlServer.throttle`, and there is
one counter per remediation rather than one per family.** The count is chosen by the
peer, so a line per clamped delta is hundreds per frame, repeated on every send
tick: the same unbounded peer-driven journal volume the throttles were added
for, arriving through a new door. The oversized-batch report needed it most,
because the excess is never acked, so the sender rebuilds the identical frame on
every tick and the line repeats with it forever.

The split is not tidiness. A shared window is won by whichever reason fires
first, and every other one is folded into a generic count for thirty seconds, so
an operator with a mismatched `overlay.backend_ip` *and* a mislabelled linker is
told about one of them and the second is a number with no hint attached. Seven
counters now (`notBackend`, `unknownIP`, `wrongIP`, `clamped`, `badPath`,
`badSeq`, `oversized`), each with its own trailing edge in `flushThrottles`.

Remediation rather than reason is what draws the line, and the two places it
lands differently are worth naming. `badPath` and `badSeq` were one counter, and
they send an operator to different files with different hints, so a burst of
garbage path ids must not silence the line that says to go and look at
`meter-state.json`. `clamped` stays single although six conditions reach it,
because they all mean the same thing to whoever reads it and its line already
enumerates every one that fired for that delta: splitting it six ways would buy
nothing and cost the shape of the rule.

**The stamp window is deliberately asymmetric, and the future side is an hour
rather than five minutes.** What the window protects is which *period* a delta
lands in, and a period is a month, so an hour either side changes nothing except
within an hour of a boundary. Five minutes was too tight against the premise of
the past-side bound: a backend that may have no route to NTP, up for months,
drifts minutes. Every honest delta from such a host tripped the check and was
reported at `Error` with a hint saying no working backend emits this, which is
how an operator learns to ignore the one line that means the ledger was written
wrong.

`quota.Metered` is the second half and neither is redundant. It multiplies
every byte by two configuration values that had no ceiling of their own, and an
int64 that wraps does not announce itself: it produces a plausible number, or a
negative one that credits the month back. It now clamps both, saturates the
arithmetic and refuses a negative count outright. NaN is tested before the
ordered comparisons rather than after, because both of them are false for it:
a NaN calibration would sail through, stay NaN through the multiply, and reach
`int64(NaN)`, which on the deployment platform is `MinInt64`. `Engine.AddUsage`
clamps too, because `Metered` clamps only its own copy and the raw packet count
went on to the ledger's second column unchanged.

An out-of-range calibration falls back to 100 rather than to the nearest edge,
and the difference is the whole point of the floor. Clamping up to
`MinCalibration` left the case it was added for intact: a stored 1, a fraction
typed where a percent was wanted, became 10 and went on under-billing tenfold,
while a stored 0 took the neutral branch and billed correctly. Neutral is the
only fail-safe answer for a value that is not a calibration at all, and it errs
toward the visible direction.

The calibration is bounded on both sides, and only the ceiling existed at first.
That left the whole of the silent direction open: 100 typed as 10 bills a
gigabyte of LTE as a hundred megabytes, the ledger never approaches the cap, the
quota never trips, and the portal shows the path healthy and under quota
throughout. It is the same failure a negative byte count is refused for, reached
through the multiplier instead of the operand, so `quota.MinCalibration` refuses
it in the portal and clamps it at the boundary.

`web.validate` bounds the same values with a message an operator can act
on; the clamp is the boundary, for a value stored by an older build or arriving
from a socket, where there is nobody to tell.

Between those two sits the stored blob, and it is seen by neither.
`store.LoadConfig` unmarshals it, `model.Normalise` does not touch `Quota`, and
nothing re-validates it, so a config saved under a build whose only rule was
"above zero" carries a calibration the portal would now refuse. That is not
cosmetic, because `MinCalibration` is newer than the field it bounds: a site
storing 5 billed at 5% before it existed and bills at 100% after, a factor of
twenty from one restart to the next. `Engine.reportQuotaSubstitutions` says so
at load. It reports rather than repairs, deliberately: `Metered` already
substitutes, so rewriting the blob would change no billing and would take away
the save-time error that is how an operator learns which figure to correct. A
zero calibration is not reported, because `validate` has always read it as unset
and filled in 100, so it is a value nobody chose rather than one being ignored. It keys on `quota.MaxCalibration`
and `quota.MaxOverheadPerPacket` rather than on a copy of the numbers, the way
the region checks key on `sysx.GeoSetName`: raise one alone and the portal
accepts a figure the clamp silently reduces, which under-bills every metered
byte with nothing anywhere saying so.

**Everything this key authenticates carries a label, because two of them used
to be the same function.** The probe MAC covers the first 50 bytes of the
packet; the handshake MAC covered a nonce string the peer supplied. Same key,
nothing to say which was which. So a peer that could get a challenge answered
could send a probe body as the nonce and be handed a valid probe MAC instead -
and a probe body is entirely reachable from a JSON string, because every field
can be chosen to land below 0x80, `DecisionSeq` included at up to
`0x7f7f7f7f7f7f7f7f`, which beats the millisecond wall-clock seed by six orders
of magnitude. The forged probe pins the backend's reply path to a tunnel of the
attacker's choosing and no later decision can move it. `probeLabel`,
`controlLabel` and `controlAckLabel` are the fix; `controlMAC` also refuses a
nonce that is not the exact shape `RandomNonce` produces, so there is no chosen
preimage to reason about in the first place. A new use of this key gets its own
label, and no label is ever a prefix of another.

Both changes are wire breaks, which is why `proto.Version` is 2. `Unmarshal`
reports a version mismatch as `ErrProbeVersion` rather than folding it into
`ErrBadProbe`, and the responder logs it separately: the two faults send an
operator to look at completely different things, and "check that the shared
secret is identical" during a staged upgrade is the one thing that is fine.

**A network pushed down the control channel is re-parsed before it is written,
and what is written is what came back from the parse.** `sysx.EgressNetworks`
does it for `BuildBackendEgressRuleset` and `BuildLinkerEgressRuleset` alike.
`web.validate` already checks these, but that runs on a different host at save
time, so it cannot be the only check: what reaches the generator is whatever
the peer at the far end of a socket said. They were interpolated with `%s`,
unquoted, into a file loaded by `nft -f` as root, and a value carrying a
newline is not one bad rule but a free hand with the whole ruleset - a chain of
its own, a `dnat`, anything nft will load. Re-rendering rather than passing the
accepted string through is the half that makes it a boundary rather than a
filter: there is then no path by which an unexamined byte reaches the file.
`sysx.AddressLiteral` is the same treatment for the overlay address beside them,
which on the backend comes from the same pushed configuration and was the quiet
half of the same problem. It moves nothing for a configuration the portal
accepted, because `web.parseIPv4Network` already normalises to exactly this. A bad entry is
dropped rather than failing the batch, matching `mergeCIDRs`, because nft
rejects a whole table over one element and one unusable network must not take a
working ruleset down with it. The callers key their "nothing to install" branch
on what survives the parse, not on what arrived, or the mark rule goes in with
an empty ruleset behind it - which is the leak the rules-before-ruleset
ordering exists to prevent.

**And the third field on that message needed it too, which took a second pass to
notice.** `Overlay.Subnet` rides the same push as the networks and the address,
and it was still reaching the generated rules with a bare `%s` in
`BuildLinkerEgressRuleset` and, worse, reaching `nft insert rule` as an argv
element in `EnsureOverlayForwardExceptions`. A separate argv element is not the
protection it looks like: nft joins its own argv and re-lexes the result, so a
space in that value is a new rule token and a semicolon is a new rule, loaded
into `DOCKER-USER` as root. `sysx.NetworkLiteral` is the single-network half of
`EgressNetworks` and both now go through it. The two callers differ in what they
do with a value it refuses, and deliberately: the generator drops the subnet and
emits exactly what a site with no subnet gets, because one unusable value must
not reject a whole table, while the forward exceptions return an error, because
there is nothing left to install and the linker's control channel does not come
up without them. Host bits are masked rather than refused, matching
`web.parseIPv4Network` and the list beside it - nft answers `10.99.0.5/24` with
"Address has host bits set" and rejects the table with it.

The value is bootstrap-owned rather than operator-editable, so this is a
robustness boundary rather than a live hole once the handshake is mutual: what
reaches it is a typo, not an attacker. That is not a reason to leave it, because
the typo is the reachable case and `model.LoadBootstrap` was admitting it - see
§9.

**DNAT only, never SNAT.** Leaving the source address alone is the whole reason
srcds and the web server see real client IPs - for UDP as well as TCP, which no
proxy could do. The cost is that the backend must route replies from
`10.99.0.2` back out the tunnel (`ip rule from 10.99.0.2 lookup 100`) instead of
out pfSense. `sysx/nft_test.go` asserts the ruleset never contains a masquerade.

**The one source NAT is for traffic going the other way, and lives in its own
table.** `Frontend.BackendEgress` (off by default) makes connections the
*backend* originates from `10.99.0.2` leave by the frontend's public address.
That is not a weakening of the rule above: it applies to the opposite direction,
where there is no client address to preserve because there is no client. It
exists because a Source game server is listed in the server browser at the
address Steam observes its heartbeat coming from - there is no way to declare a
different one, deliberately, as anti-spoofing - so without it the server is
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
service on the backend host, and needs no backend rules at all - the existing
`ip rule from 10.99.0.2 lookup 100` already puts that traffic on the tunnel. A
container cannot do it: the overlay address does not exist in its network
namespace. Nor can it be identified by process - `meta skuid` and cgroup
matching work on locally *originated* packets, and a container's are *forwarded*
through the host, so there is no local socket to inspect. What is left is the
bridge network's address range, which is what `Egress.Sources` configures.

**And only the internet-bound part of it.** Both egress rulesets qualify the
source match with `ip daddr != { … }` over `sysx.nonInternetDestinations` -
RFC 1918, CGNAT, loopback, link-local, `0.0.0.0/8` and `224.0.0.0/3`. Matched on
source alone the mark stamped everything a container sent: its DNS queries to
the LAN resolver, its traffic to the host's own LAN address, to a database on
the next bridge, to the panel that manages it. All of it went down the tunnel to
a frontend that can do nothing with a private destination, and the symptom was
the containers going offline the moment their network was ticked - unable to
resolve a name or reach their panel, while their internet traffic was fine. The
frontend's NAT is an internet address; only internet traffic should seek it out.
On the linker the same set qualifies the SNAT too, because its one interface is
both its way to the backend and its way to everything else on the LAN - and the
linker additionally marks and translates traffic to the overlay subnet, because
its main table has no route there (only its own table does, selected by the
overlay source or by this mark), so a container on a linker talking to a
service bound to the backend's overlay address has no normal route to be left
on. The backend needs no such rule: its main table carries the route to the
frontend overlay and a host route to every linker.

Two rules on the backend, doing two jobs (`BuildBackendEgressRuleset`). The
prerouting `meta mark` diverts the traffic - a forwarded packet is routed after
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
the active tunnel - and LTE drops packets routinely. Sustained trouble is
caught two other ways: `FailThreshold` consecutive losses condemn the path, and
the loss/RTT thresholds block it as degraded. `Tracker.Usable()` is the
eligibility test; do not change it back to `Health() == HealthUp`.

**Failover is immediate, failback waits.** Moving to a worse path happens the
instant the current one is ineligible. Moving back to a better one requires an
unbroken clean streak of `HoldDownSec`. Any lost probe clears `cleanSince`, so a
marginal fixed line service that keeps half-recovering cannot drag traffic
back and forth.

**Quality selection only chooses between fallbacks, never against the preferred
path.** `Failover.Selection = "quality"` (off by default) changes exactly one
thing: once the preferred path is out, the replacement is the best-*measuring*
eligible path rather than simply the next one down the list - a clean LTE2 beats
an LTE1 dropping one packet in ten.

It is deliberately not "pick the best path". While the preferred path is usable
it keeps the traffic whatever the numbers say, and it wins the traffic back on
its clean streak alone. Priority order here is the *cost* order: the main link
is unmetered and the LTE services are capped, and LTE frequently measures better
than a congested fixed line. A selector that simply chased the lowest score
would park traffic on a metered link indefinitely and report itself as
optimising. `preferredPathID` is the guard; `qualityTarget` returns early on it.

Moving between two fallbacks needs both dampers, and neither is optional. The
candidate must beat the running path by `Quality.MarginPct` - measured against
the path actually carrying traffic, not against the one that is down, or a third
path could pull traffic off a second one it is no better than - and it must hold
that lead for `HoldDownSec`. Without the margin two similar links trade places on
measurement noise; every swap is a visible stall for connected players.
`Engine.beatenSince` times that hold-down against *the active path being beaten*
rather than against a particular challenger, because two candidates alternating
for the lead would otherwise restart the clock forever and the switch would
never happen however badly the active path was performing.

Because the margin applies in both directions there is a dead zone rather than a
threshold - moving A→B needs `score(B) < 0.75×score(A)`, moving back needs
`score(A) < 0.75×score(B)`, and both cannot hold at once - so oscillation on
noise is impossible rather than merely unlikely. What that does *not* bound is
how often a genuine alternation can switch: two links really taking turns being
much better, which is what a carrier working on a tower produces, would move
traffic every hold-down for as long as it lasted. `Quality.MinDwellSec` is the
floor under that, and it applies only to a choice between two working
fallbacks: it never delays leaving a path that has become unusable, nor a
failback to the preferred path.

The score is milliseconds-equivalent: `loss% × LossWeight + rtt × RTTWeight +
jitter × JitterWeight`. `LossWeight` defaults to 25 because for a game server a
clean 60ms link genuinely beats a lossy 30ms one. A flawless path scores zero
and cannot be displaced - the margin comparison is strict, so two idle tunnels
never swap.

**Detection speed is a portal preset, not a configuration field.** The
"Detection speed" dropdown (`model.DetectionPresets`: fast, standard, relaxed)
fills in four numbers, active interval, timeout, losses-before-down and window,
and the stored configuration carries only the numbers. The engine has never
heard of a preset, a site that never opens the dropdown is byte-identical, and
the numbers stay editable, so nothing new had to be validated or pushed. The
standard preset is pinned equal to `Defaults().Probe` so a fresh install reads
"Standard" and not "Custom".

Each preset carries its trade-off in `Note`, and the portal shows it beside the
choice together with the detection time the current fields give. That figure
is `ProbeConfig.DetectMs` in Go and a mirror of it in `app.js` (the page
recomputes as the operator types, and cannot call Go); keep the two in step.
That is the point of the feature, not decoration: a faster condemnation is
bought with false failovers on any link that drops bursts of packets, and every
false trip parks players on a metered path for the whole failback hold-down,
costs a visible switch each way, and counts towards quarantine. The fast
preset's 300ms timeout also has to stay above the worst round trip on the
slowest link or late replies are booked as losses, and since a reply slower
than the timeout is never measured, a Max RTT above it can no longer trip.
Probing at 100ms costs about 6.7 GB a month, both directions billed, while an
LTE path is the active one. Nothing else on the page says any of that, so the
dropdown has to. `DetectionPreset.Apply` (and the dropdown) lift the standby
interval to the new active one where needed, because validation refuses a
standby cadence faster than the active one and a preset the portal offers must
never produce a form it then refuses to save. The relaxed preset
exists for the opposite problem: a link that is condemned and recovers on its
own is one the standard tuning is too tight for, and the fix is a longer streak
and a longer timeout, not a lower loss threshold.

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
window is exactly when LTE data is burning hardest - a failover to LTE often
coincides with the frontend being unreachable. Dropping accounting then would
lose the usage that matters most.

**The portal lives on the frontend, not the backend.** When all three tunnels
are down, the backend is unreachable by definition - and that is precisely when
somebody needs to see why and click "use LTE2 anyway". The frontend is in a
datacentre on independent internet, so the portal survives a total path outage.

**The portal must never be able to take the agent down.** It binds an address on
the admin tunnel, and that address does not exist until `wg-quick` has brought
the interface up - unit ordering asks for that but cannot guarantee it, and an
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
current password, and drops every other session for that account - the usual
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
collisions - two boxes can both run 27015. It also carries the stable-address
property one hop further, so the linker's replies survive a failover for the
same reason everything else does. The backend needs one route to reach it and
its existing connection marking handles the replies unchanged.

The bigger payoff is egress selection. On the backend, binding a service to the
overlay address *is* the selector for leaving via the frontend's public address.
That holds one hop down: `srcds -ip 10.99.0.3` gets the server-browser heartbeat
right for free, while everything else on that box keeps its normal route. The
`Egress.Sources` CIDR list is not needed and should not be used there - it
exists for containers, which cannot bind an address that does not exist in their
namespace, and it catches every packet from the network it names.

**A linker is never told which tunnel is active, because it does not need to
be.** Its whole job is to put traffic sourced from its overlay address onto the
backend, and the backend already tracks the active path in table 100. That is
why there are no probes, no `decisionSeq`, and no metering in
`internal/linker`: not an unfinished agent, a complete one for a job that is
genuinely this small. Adding decision handling to it would create a second thing that has to
agree with the frontend, which is the failure mode §8 warns about for pfSense.

**A linker has no observe mode, and that is a decision.** The other two agents
need one because their rules move published traffic the moment they exist. The
linker's rules match only packets sourced from, or addressed to, its own overlay
address - and nothing on the box uses that address unless a service was
deliberately bound to it, or the frontend's DNAT points at it. So on a host
where nothing has opted in they are inert. What actually directs traffic to a
linker is that DNAT, which has an observe mode and is where the decision belongs.

**A linker's routing table is configurable, and that is not a nicety.** The
number belongs to the host's own namespace, not to this system. `DefaultLinkerTable`
is 200; the first real deployment landed on a machine already using 200 for its
second ISP, under the name `isp2`, and the agent wrote its own default route
straight over that host's - sending the operator's other traffic to the backend
with nothing anywhere reporting it. `Linker.Table` is set in the portal row and
must also appear in that host's bootstrap file, because the rule it names is what
carries the control channel: the agent cannot be told a value it needs in order
to be told anything. The agent reports back what it actually used so the two
cannot drift unnoticed.

**The linker reports `rp_filter` and never sets it.** The other two turn it off
because their tunnels carry no address of their own, which makes even "loose"
mode drop probe replies - broken by construction, as §8 explains at length. A
linker has an ordinary interface with an ordinary address, and on a host with
one route to the internet the reverse lookup lands on the arrival interface and
passes. Silently changing a system-wide sysctl on a machine that is somebody's
game server first is not this agent's business, so it warns and says when to
suspect it.

**Egress networks belong to exactly one host.** `EgressSource.Host` is not
tidiness. Docker's default bridge is `172.17.0.0/16` on every machine and the
allocator walks `172.18`, `172.19` and so on in the same order on each one, so
several hosts routinely hold the identical subnet. A global list would have
every agent installing every row - pulling containers onto the tunnel on hosts
the row was never meant to touch, silently, and billing them to the LTE quota.
The matching rule is the opposite of the one for paths: the same CIDR on two
hosts is normal and must stay legal, while a repeat within one host is rejected.

**Shaping is at both ends because a queue only controls the direction it sits
in front of.** `Path.Shape.ToBackendMbit` is the frontend's queue on that
tunnel - the house's download - and `ToFrontendMbit` is the backend's, the
house's upload. Only the second is sent down the control channel, because the
first is none of the backend's business. Both are zero by default and a site
that sets neither issues no `tc` command that changes anything.

The value belongs slightly *under* the measured line rate. At or above it the
queue forms in the carrier's buffer instead of ours, which is the entire thing
being fixed: that buffer is enormous, serves in arrival order, and puts seconds
of delay in front of a game packet stuck behind a download. CAKE rather than
fq_codel because it does the rate limiting itself rather than needing an htb or
tbf parent, and because its flow isolation gives sparse flows priority - which
is what keeps a 66-byte probe every 250ms out from behind a bulk transfer with
no classification to maintain. `ShapeOverheadBytes` is 80 because the shaper
counts the payload it is handed while the carrier bills what leaves the WAN.

Being able to shape the *download* direction at all is a property of owning both
ends. An ordinary home router can only drop traffic that has already crossed the
bottleneck; the frontend is upstream of it.

**TCP MSS is clamped on every SYN that leaves by a tunnel, on both hosts.**
The tunnels run at WireGuard's 1420 and everything either side of them at
1500, so a *forwarded* TCP connection - a player to a containerised server, a
container to the internet through the frontend - depended on path MTU
discovery: the host in front of the tunnel sending ICMP "fragmentation
needed" and the far end acting on it. Plenty of far ends never see that ICMP,
and Valve's servers are the canonical case: steamcmd from a container routed
out through the frontend completed its handshake and sat at "Retrying…"
forever, the first full-size segment from Steam dropped at the tunnel and
nothing telling Steam to send smaller ones, while the same container was fine
by the house's 1500-byte path. `writeMSSClamp` puts a forward chain in the
frontend's `failover` table and the backend's `failover_return` table:
`oifname { tunnels } tcp flags syn tcp option maxseg size set rt mtu`. `rt
mtu` is the leaving route's MTU, so the number tracks the tunnel rather than
being written here. Forwarded packets only - a connection a host originates on
its own address already sizes itself from the route - and it rides in the two
mode-gated tables, so observe mode touches nothing.

**Protection is a separate nftables table, and everything in it is off.** Same
reasoning as `failover_egress`: `NFTTable` carries the published services and is
asserted to contain no translation, this can be removed on its own, and a reader
can tell which rules publish from which rules drop. Two chains, because they
need different information - `raw` (-300) runs before conntrack, so the
blocklist and the malformed packets cost nothing to discard, and `filter` (-150)
runs after conntrack and before `dstnat` (-100), the only window where a rule
can know a packet's connection state and still stop it before it is translated
and sent down a tunnel.

**Every protection rule is scoped to the public interface, and that is a safety
property rather than an optimisation.** The system's own traffic - probes on
51999, the control channel on 51998, everything between overlay addresses -
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
and connection attempts carry and an in-game client never does - its packets are
sequence numbered. That is what makes a limit of two or three per second safe:
it cannot touch the traffic of a player already connected. Without the payload
match the same rule would throttle gameplay at a rate chosen for queries.

**Region locks are operator-declared network lists, not a GeoIP database.**
`Protect.Regions` is named lists of CIDRs; `Service.GeoRegions` locks a port to
their union, dropping everything else in the raw chain. A GeoIP database would
be a second external dependency with a licence and an update cadence, and a
stale copy fails in silence in whichever direction it happens to fail. The
lists arrive two ways and land in the same field: the portal's Fetch button
(`POST /api/geo/fetch`) has the frontend download the aggregated lists for a
set of ISO country codes, or the operator pastes them (`deploy/geo-zones.sh`
prints the same files offline). The fetch fills the settings form, never the
configuration - what came back still goes through the operator's eyes and
then through `PUT /api/config` like anything typed - and it happens only on a
click, never a schedule: an automatic refresh that half-succeeds at 3am would
replace a working allowlist with nobody watching, while staleness only costs
a few newly allocated networks. It is also whole-or-nothing (`fetchCountry`):
a truncated download is valid CIDRs all the way to the cut, so any bad line,
an empty list, or a response over the size cap fails the entire request
rather than becoming a plausible fragment of an allowlist. The caps are one
ordered story (`geoFetchMaxTotal` < `maxRegionsBytes` < `maxConfigBytes`):
what a fetch fills in must fit back through a save, or the button hands the
operator a form the save endpoint refuses with "request body too large" on
every save until the list is trimmed by hand - and
`deploy/geo-zones.sh` buffers for the same reason, printing nothing unless
every country fetched, because a redirect holding half a region is that same
fragment made by hand. Country codes are
checked against two-lowercase-letters before they go near the URL - every
code, in a first pass, so a bad one behind a good one is refused with zero
requests sent - and the fetches then run concurrently (bounded, and tied to
the request context so a closed tab cancels them) rather than eating a
timeout per code in series. Validation refuses anything nft would choke on;
what IPv4 means is defined once (`web.parseIPv4Network`, mask width included,
because a bare `To4` test admits an IPv4-mapped IPv6 network that saves,
generates nothing, and then blocks every later save when its stored form
fails to re-parse). Region names are folded to nft
identifiers at generation (`sysx.GeoSetName`, which validate also keys its
collision check on, so the two cannot disagree about which names are one set)
and each folded set name is emitted once, because
two names the fold makes identical are one set to nft and defining it twice
rejects the whole table; validate refuses that collision at save, the build
survives it in an older blob. The lockdown sets share that namespace, so a
region name folding onto `geo_lockdown_tcp/udp` is refused as reserved at
save, and the generator shifts a stale blob's region set aside rather than
defining the lock set twice with two types. The rules are stateless
and per-packet, deliberately: the set answer is fixed per address so an
allowed player can never be newly caught, an out-of-region flood costs no
conntrack entry, and a lock engaging also ends flows already in progress. The
lists are merged in Go before they reach the file (`mergeCIDRs`), because CIDR
blocks either nest or are disjoint and nft rejects the whole table over one
contained duplicate - a generous paste must not take every limit down.
A region is direction-neutral: `Service.GeoBlock` chooses per service between
admitting only the named regions (the default, negated lookups ANDed into one
rule) and dropping exactly them (one positive-match rule per region, because
"inside any of them" is an OR and a single rule ANDs its matches - two blocked
regions on one rule would drop only their intersection and silently admit
both). A reference that resolves to nothing fails open, and the open answer
differs by direction: `web.validate` refuses the dangling reference at save,
so meeting one means an older or hand-edited blob, and the build must not
take a published service off the air over it. On an allow lock any dangling
reference means no rule for that service - the rule is one AND of negated
lookups, so emitting it for just the references that resolve would silently
bar every player the missing region was meant to admit, a stricter lock than
was configured. On a block lock the resolved regions keep their rules and the
dangling one simply drops nothing, because there each region is its own rule
and dropping less is the open direction.

**The automatic region lock lives entirely in the kernel, like the parking
blocklist it copies.** `Service.GeoAutoPPS` makes the lock conditional: a
`limit rate over` trigger writes the port into a dynamic `geo_lockdown_<proto>`
set (timeout `GeoLockSeconds`, default 60s) and the drop rule matches only
while the port is in it - so the lock engages at line rate mid-flood with the
agent deciding nothing and polling nothing, holds while the flood lasts, and
releases on its own after it stops. The trigger rule runs *before* the drop
and takes no verdict, which is load-bearing: it must see the whole flood,
including the packets the drop is discarding, or the surviving in-region
traffic alone would fall under the threshold, the entry would expire
mid-attack, and a burst would get through every timeout. One lockdown set per
protocol, so a tcp flood cannot lock a udp service on the same port number.
The engaged locks are read back out of the kernel with the counters
(`ProtectState`) and said loudly in the portal, because an engaged lock looks
exactly like the service being down to everybody outside the region.

**Counters exist because a limiter nobody can see is worse than none.** "Some
players cannot connect" and "that threshold is too tight" look identical from
outside. Every drop rule carries a `counter` and a comment; `sysx.ProtectState`
reads them back out of the kernel with `nft -j`, because the numbers live in the
rules and reloading the table resets them. That is also why a save that leaves
the generated protection ruleset unchanged skips the reload (`Engine.
protectApplied`): the reload resets the counters, unparks every blocked source
and releases every engaged region lock, and an operator saving a probe interval
mid-flood must not hand the flood a clean slate. The portal shows the numbers
beside the parked sources. Whether a counter's packets were dropped is the
API's `ProtectCounter.Drops` flag, read from the rule's own drop verdict in
the same `nft -j` readback - the auto-lock trip counter carries none - so
neither the portal nor the parser infers semantics from a counter's name,
where "geo" being a prefix of "geo-trip" is a trap waiting for a `startsWith`. The lockdown sets are read
back by their two exact names, never by the `geo_lockdown_` prefix, because
region sets share that namespace and an operator's `lockdown_eu` must not be
scanned as engaged-lock state for a protocol called "eu".

**WireGuard handshake age never influences a decision.** It is collected and
displayed for context only. A WireGuard interface stays up long after the link
beneath it has died - catching that is the entire reason the probes are
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
   added lands *ahead* of the previous - and the backend adds the path rules
   first. That put the source rule on top and sent every probe reply down the
   active tunnel instead of its own: standby paths still got replies, so they
   read healthy while measuring a mix of two tunnels.

   **Both sides of that comparison must be pinned, not just one.** Fixing only
   the path rules leaves the same bug waiting for the next source rule anybody
   adds - which is exactly what happened when `overlay.subnet` introduced a
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
   route at all. `ensureProbeRules`, `EnsureControlRoute`, `EnsureEgressRule`
   and `EnsureReturnMarkRule` all install the pinned rule first and clear the
   strays afterwards.

   **And a path's rules fail closed, because a lookup rule on its own fails
   open.** A rule whose table holds no route for the destination is skipped,
   not terminal, so with the tunnel absent `fwmark 0x101 lookup 101` sends the
   probe on to the next rule that matches - on the frontend that is main and
   the public uplink, on the backend it is `from 10.99.0.2 lookup 100` and the
   active tunnel. Each path therefore carries a second rule, `fwmark 0x101
   unreachable` at `sysx.ProbeDenyRulePrefBase + id` (31001–31003), behind the
   lookup and ahead of everything else, so a marked packet with no route in its
   own table gets ENETUNREACH. That is the failure `Prober.sendFailed` and
   `hold` were written for and had never actually been reached on a host with
   a default route.

   The reason this is an invariant and not a tidy-up is conntrack. A frontend
   that boots before `wg-quick` has no probe routes, and its probes used to
   leave the datacentre addressed to `10.99.0.2`. On a site with backend egress
   on they matched `ip saddr 10.99.0.0/24 oifname eth0 snat` on the way out. A
   source NAT binding belongs to the connection, not to the interface, and the
   prober keeps one socket for as long as sends succeed - so once the tunnels
   came up every probe from that socket still carried the public address, the
   backend answered to the public address from an ephemeral port that matched
   no conntrack entry, and nothing was listening there. (That was the second
   fault in the boot report; the first was the reconciler never installing the
   route at all, see the never-created-table trap in §8. Either alone was
   enough to keep a path dead for the life of the process.) The rules go in for every path
   whether or not its interface exists yet (`EnsureProbeRoutes`), because the
   interface-less case is the one they are for, and the route follows from the
   reconciler when the tunnel appears. It is a rule rather than an
   `unreachable default` inside the table so the table carries only the one
   route this system installs - the number belongs to the host (invariant 8).

   **The band is the ownership line, in both directions.** A fwmark is only a
   number, and a host that already policy-routes may refuse on the same value
   for its own reasons, so a `fwmark … unreachable` outside 31001–31099 is
   neither "already installed" nor a stray and is never touched. Inside it,
   everything is this system's: `EnsureProbeRoutes` sweeps any refusal whose
   mark no path carries - a mark edited in the portal, or the shipped defaults
   a backend runs on until its first push - because unlike an orphaned lookup
   rule, which selects an empty table and does nothing, an orphaned refusal
   blackholes that mark for good. `RemoveProbeRoutes` clears the whole band,
   not just the configured marks, for the mark changed while the agent was
   stopped. `web.validate` bounds path ids below `sysx.ProbeDenyBandSize`
   (100), because both bands are derived from the id: at 100 the lookup lands
   on the egress rule's priority, and a large one carries the refusal past
   the source rules, where a probe would be routed before it was refused.

   **The two egress lookups carry the same backstop, for a worse version of
   the same reason.** `fwmark 0x300 lookup 100` on the backend and `fwmark
   0x301 lookup <table>` on a linker fail open the moment the table loses its
   default - the active tunnel deleted, the LAN route bounced - and a marked
   container packet then leaves by the host's own internet, where Docker's
   masquerade gives it that address. The binding belongs to the connection, so
   once the route is back the same flow is sent to the frontend carrying an
   address its NAT does not match, dead until the entry expires - never, for
   a UDP flow that keeps sending - and a heartbeat sent in the gap lists the
   server at the house's address, which is the one thing the feature exists to
   prevent. `EgressDenyRulePref` (31100) and `LinkerEgressDenyRulePref`
   (32403) sit behind their lookups; each is owned by its pinned priority
   alone, installed by `EnsureEgressRule` / `EnsureLinkerEgressRule` and
   removed by their counterparts. The source rules, the control rule and the
   return-mark rule deliberately get none: observe mode depends on the
   backend's control dial falling through table 100 to the seeded main route.
4. Probe results reach the tracker in sequence order. Out-of-order delivery
   scrambles the consecutive-loss counts that condemn a path.
5. Every probe and control frame is HMAC-authenticated. Nobody outside can
   forge path health or steer traffic.
6. Backend reply routing must match the frontend's choice. Asymmetric flows
   break pfSense state.
7. Observe mode must not move traffic - but it must still measure. The split is
   deliberately not "changes nothing": the overlay address, sysctls, per-path
   probe tables, fwmark rules and the backend's route to the frontend overlay
   are installed for real in both modes, because without them the probe sockets
   cannot bind and every path would follow the single active route, making the
   observation worthless. None of that moves traffic. Observe mode suppresses
   the main-table route to the backend, the DNAT ruleset, the backend's
   reply-path default route, and - added with them, for the same reason - the
   shapers and the protection rules. A queue discipline does not misdirect
   traffic the way a route does, but it decides what is dropped and when, and a
   rate limiter plainly does; observe mode's promise is that nothing the agent
   has done can be felt by a player. See `Engine.applySystemConfig` and
   `Agent.ApplyConfig`; `realRunner()` is the escape hatch.

   **It also loads no nftables table, on either host.** The backend's
   connection-marking table (`failover_return`) was installed as plumbing on
   the strength of being inert - the mark it restores selects table 100, whose
   default route observe mode never installs - and it is inert, but it was
   also a table sitting in `nft list ruleset` on a host whose portal said there
   was none. It now goes through the gated runner with the rest of the data
   plane: the file is written in both modes, loaded only when armed. The `ip
   rule` beside it stays plumbing, exactly like the probe rules - a rule into
   an empty table is nothing - and that is what lets arming take effect with
   one reload rather than a rule add that can fail.

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
   and it must be run second, with that host's unit stopped first (invariant
   12). Taking the reply path down while the frontend is still armed and DNATing
   breaks every published service on the spot: requests keep arriving down the
   tunnel and their replies leave by the LAN to pfSense, where the client's flow
   has no state.

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

   **And never start them twice from concurrent requests, which is the same
   fault from the other side.** `net/http` serves handlers concurrently, and
   both `PUT /api/config` and `POST /api/mode` call `Reconfigure`. Its
   `stopProbers` / `startProbers` pair is not atomic on its own, and the gap
   between them contains `applySystemConfig`, which shells out to `ip`, `nft`
   and `tc` - hundreds of milliseconds, wide open. Interleaved, the second
   caller's `stopProbers` found `proberCancel` already nil, cancelled nothing,
   and both callers then started a generation; the first `cancel` was
   overwritten and lost, and since the context descends from `baseCtx` that
   generation probed until the process was restarted.

   Nothing reported it, because every path went on measuring perfectly. The
   only symptom was a standby path on a 5000ms interval reporting every 2–3s -
   two tickers out of phase - with the metered quota billed twice for the
   privilege and `FailThreshold` consecutive losses reached in half the
   wall-clock time it was configured for. It compounded: each racing pair added
   another generation.

   Three things hold it now, and they are not redundant. `Reconfigure` takes
   `e.reconfMu` for its whole body - a separate lock from `e.mu` precisely
   because it must be held across `applySystemConfig`, which is far too slow to
   hold the state lock for. `startProbers` cancels any generation it finds
   still recorded rather than overwriting the handle, so no future caller can
   orphan one. And `stopProbers` **waits** on that generation's `WaitGroup`
   instead of merely cancelling: a cancelled prober still holds its marked
   socket and is still probing until its send loop reaches the select and its
   read deadline expires, so without the wait every settings save doubled the
   traffic on every path for a moment - briefly, but against the one
   measurement every failover decision is made from. Same reasoning as
   invariant 17.
10. **Commit state only after the system accepts the change.** Both
    `Engine.evaluate` and `Agent.SetActivePath` install routes first and record
    the new active path second. Recording first means a failed `ip route
    replace` is never retried, because the next pass sees the choice as already
    current - and the portal reports a path traffic is not using.
11. **`decisionSeq` must increase across a frontend restart.** The backend
    remembers the highest sequence it has seen and ignores anything lower. It is
    seeded from the wall clock in `New`; do not reset it to zero.

    **Seeded in milliseconds, and the backend admits an equal sequence.** To
    the second, a process that switched once and was restarted within that
    second handed its successor the same seed, and the successor's first
    switch the same number as the one it replaced, on a different path. That
    is reachable: `Restart=always` brings a crashed process back within the
    second, a fresh tracker is usable after one reply, and every prober sends
    on entry. `Agent.SetActivePath` refused to queue the equal number as a
    straggler, so the frontend routed down one tunnel while the backend
    replied down another, with no counter or log to show for it, until a
    later switch moved the number on. The guard is `>=`, matching
    `applyDecision`; a real straggler is always strictly lower.

    **And it is bounded above, because everything downstream compares
    sequences only against each other.** A number planted near the top of a
    uint64 is not a wrong decision that a right one corrects: it is a ceiling
    no honest decision can ever clear again, so the frontend routes down one
    tunnel while replies leave by another, all three paths go on measuring
    perfectly, and only restarting the backend clears it, because `lastSeq`
    lives in memory. It takes a peer holding the shared secret to send one
    deliberately; the cheaper reason to bound it is that no attacker is
    required, because the seed is a clock reading and a frontend booting with a
    wildly wrong clock plants the same ceiling by accident.

    **The backend's wall clock may widen that ceiling and may never narrow it,
    and getting the direction wrong is worse than the attack.** The first
    version of `plausibleDecisionSeq` compared against `time.Now()`
    on the backend and nothing else. A host whose clock is behind then computes a ceiling below
    every real sequence and refuses the lot - and such a host never installs a
    return path at all, because `active` is not persisted and
    `reassertReturnPath` returns early on zero, so the first accepted decision
    is what installs it. The route to a stale clock is the exact scenario this
    system exists for: the house loses power, comes back with every link down,
    so there is no route to NTP, so the clock stays stale, so the decision that
    would recover the site is refused. A hardening step must never be able to
    hold the recovery shut. `seqBase` is the frontend's own first sequence and
    `seqBaseAt` is a monotonic reading, so the ceiling grows at the rate real
    time passes whatever either host believes the date to be, and the anchor is
    never moved - re-anchoring on each decision would let a sequence walk the
    ceiling upward a step at a time. `decisionSeqHorizonMs` is the one bound that
    applies with no anchor yet, and it is deliberately absurd (the year 2100),
    because the unanchored case is the first decision a backend ever sees and
    refusing that one is refusing the thing that installs the return path.

    **The anchor alone cannot bound a frontend restart, and the second version
    found that out the hard way.** A sequence is `frontendStart << 16` plus one
    per switch, so it tracks when the frontend *started* rather than the
    passage of time, and a frontend that restarts reseeds by however long the
    previous process had been up. The anchor was stamped with that previous
    process's seed and this host has no idea how old it already was. So a
    backend restarting while the frontend had been running longer than
    `decisionSeqSkew` - which is `Restart=always` after a crash, and the
    documented "upgrade the backend first" order - anchored a fortnight behind,
    and when the frontend then restarted it refused every decision the new
    process ever sent. Permanently: the ceiling grows only at the rate real
    time passes, so catching up takes exactly the fortnight it is behind, and
    nothing re-anchors. `active` stays zero, the return path stays wherever
    `applyPlumbing` seeded it, all three paths measure perfectly, and one
    throttled log line every thirty seconds is the whole of the evidence -
    which is the failure this check exists to prevent, arrived at from the
    other side.

    The fix is to take the ceiling as the **higher** of two references: the
    anchor plus elapsed time, and the backend's own clock. A restarted frontend
    seeded itself from a clock no later than this host's, so the second
    reference covers it. Taking the maximum is what stops that reintroducing
    the fault it replaced: a clock that is behind loses to the anchor and can
    refuse nothing, and a clock that is ahead only widens, which at worst
    degrades the check to the horizon. There is no reading of this host's clock
    that makes the bound stricter, and that - rather than not reading it at all
    - is the property to preserve.

    That reference is bounded by the same horizon the sequences are, because
    the shift into the sequence's units can overflow. Past about the year 10889
    `ms << 16` no longer fits in a uint64, and taking the maximum does not make
    that safe: a low wrap harmlessly loses the comparison, but a high one
    widens the ceiling by an arbitrary amount, and a clock at the year 300000
    wraps to 7.6e18 - a ceiling that admits the very pin this refuses. A
    reading outside the horizon is not a reference at all.

    The refusal log names that ceiling. It used to blame "this host's clock" and
    send the operator to compare the two hosts, which cannot be the cause and
    whose second branch sent whoever read it hunting a forged-probe attack.
12. **Revert must also disarm.** The decision loop runs every 500ms. Removing
    the rules without dropping to observe means the very next tick sees no
    active path, picks one, and reinstalls the route - leaving the host half
    reverted, routing restored and nftables gone.

    **And it must exclude a settings save, for a worse version of the same
    reason.** `Revert` reads the configuration, spends a few hundred
    milliseconds tearing down a dozen things, and records `dataPlane = false`
    only at the end. A `Reconfigure` landing in that window runs
    `applySystemConfig` and puts the DNAT ruleset and the route straight back;
    revert then finishes and reports the system reverted. Unlike the disarm
    case, nothing corrects it afterwards - the engine believes there is nothing
    installed, so nothing tries. The rules stay live while the portal says they
    are gone, which is invariant 13 failing in the one direction it must not,
    on the one command that exists to be trusted. `Revert` takes `reconfMu` and
    `applyMu`, in that order.

    **Only the frontend can disarm itself, and the other two need the unit
    stopped instead.** `failoverctl revert` runs inside the engine, so setting
    observe mode is enough - but observe mode alone was not: its whole point is
    to keep measuring, so the reconciler went on repairing probe tables and
    rp_filter, and put back within one tick what the revert had just removed.
    `Engine.reverted` is the latch that stops it: set by `Revert` before the
    teardown, it stops the probers and holds the reconciler, the decision loop
    and the sample writer down until `Reconfigure` clears it. Without it,
    uninstalling the frontend was a race - the script stops the unit moments
    after the revert returns, and a reconcile tick landing in that gap stranded
    rules the about-to-be-deleted binary was the only thing able to remove.
    The latch is persisted alongside being set, and `Run`'s startup both checks
    it and holds `reconfMu`, because the same race had two more entrances: the
    unit restarts itself (`Restart=always`), so a crash in that window brought
    up a process that reinstalled everything unconditionally - and the
    failoverctl socket opens concurrently with startup, so a revert served
    mid-startup could be followed by the startup sequence putting the plumbing
    back and starting probers on a latched engine.
    `failover-backend -revert` and `failover-linker
    -revert` are separate processes, and a running agent's reconciler reinstalls
    the probe tables and their rules, the overlay route, the routes to every
    extra host, and the return path if the cached mode is still armed, within
    one ten-second tick. The nftables tables and the source rules stay gone, so
    what is left is a host that is half reverted and says it is clean, and
    `uninstall.sh` then deletes the binary that could have finished the job.
    That script stops the unit first for those two roles; the manual commands in
    §2 say to do the same.

    **And it must never be handed a request context.** `ExecRunner` builds every
    command with `exec.CommandContext`, so a cancelled context does not abort a
    revert - it makes each command fail instantly while `Revert`, which checks
    none of their errors, goes on to record `dataPlane = false` and answer
    "reverted". That is the same corrupt state as above, reached from the other
    side. Waiting on the two locks is what made it reachable: the wait is
    longest when a settings save is stuck on a slow `nft`, which is exactly when
    somebody reaches for this button, and `failoverctl` gives up after 15s.
    `web.handleRevert` detaches with `context.WithoutCancel`, and deliberately
    adds no timeout of its own - `ExecRunner` caps every command at 10s, so the
    whole thing is bounded by construction, and a ceiling low enough to matter
    could truncate a slow revert and reintroduce the fault in miniature.
    `engine/revert_context_test.go` pins the hazard rather than the handler,
    because the hazard is what a future edit has to keep in mind.
13. **Disarming is not a teardown.** Going armed → observe stops further
    changes but deliberately leaves installed rules in place, because deleting
    the DNAT table would drop every published service instantly. `Status.
    RulesActive` exists so the portal says this out loud; `revert` is the way to
    actually take them down.
14. **Overlay addressing is bootstrap-owned, never portal-editable.** Both hosts
    must agree on it, and a change would tear down the channel the change has to
    travel over. `handlePutConfig` overwrites whatever the client sent.
15. **The backend installs its plumbing at startup, before the responder and
    control client start** - overlay address, sysctls, per-path probe routes,
    return rule and the seeded route to the frontend overlay. It cannot wait
    for the frontend's first push: the push arrives over a TCP connection
    sourced from the overlay address and routed down a tunnel, so a backend
    that waits deadlocks - the responder cannot bind, the client cannot dial,
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
    channel is the normal healthy case - the frontend speaks only when it has
    something to say - so cancelling the context alone leaves the goroutine
    parked for up to `proto.ControlDeadline` (45s). `Agent.Run` waits on all
    four of its goroutines, the unit's `TimeoutStopSec` is 10s, and the result
    was that every backend restart ended in SIGKILL rather than a clean exit.
    The pattern is a `go func() { <-ctx.Done(); conn.Close() }()` beside the
    loop; `Responder.listen`, `Agent.runSession` and `ControlServer.serve` all
    carry it.

    **`Prober.loop` was the exception, and stayed one until something waited on
    it.** It relied on its one-second read deadline instead, which cost nothing
    while `stopProbers` merely cancelled. Once that started waiting - it has to,
    or a replaced generation goes on probing the same path as its replacement -
    the deadline became a second of latency on every settings save. It is
    invisible on a development machine, where the probe sockets cannot bind to
    the overlay address and there is no read loop to wait for at all, so
    `TestStopProbersDoesNotWaitOnTheReadDeadline` binds loopback sockets and
    points them at a listener that never answers. Every read loop here now
    carries the watcher; do not add one that does not.
18. **Per-interface state must be reconciled against the kernel, not just
    installed once.** Deleting an interface deletes every route that used it
    *and* resets its sysctls, and `wg-quick down` deletes the interface.
    Bringing the tunnel back restores neither, so `systemctl restart
    wg-quick@wg-main` leaves that path's probe table empty and its `rp_filter`
    back at the system default of 2 - either alone is enough to make the path
    read as down forever, while the tunnel recovers on the wire and never
    recovers in the portal. `Engine.reconcileRouting` and
    `Agent.reconcileRouting` re-read the kernel every 10s and reinstall only
    what is missing. Both run on the same goroutine as the code that installs
    routes (`Run`'s select, `applyLoop`), because a reconciler racing a switch
    in progress would read the kernel between the route going in and the
    decision being recorded, and undo it.

    **Sharing a goroutine only settles the writers that are on it, and there
    were others.** On the frontend, `applySystemConfig` re-asserts the route for
    the active path and runs on an HTTP handler's goroutine; `Revert` removes
    routes from another. On the backend, `ApplyConfig` re-asserts the return
    path from the control client's goroutine. Each is a third writer the
    same-goroutine argument never covered, and the collision is the one that
    argument describes: a settings save reads the outgoing path, `evaluate`
    installs the incoming one, and the save then writes the dead tunnel back
    over it - published traffic down a link that has just failed, portal showing
    the healthy one, until a reconciler notices up to 10s later. `Engine.applyMu`
    and `Agent.applyMu` serialise every route writer, so only one goroutine is
    ever inside `ip`. `internal/linker` had this from the start and is the
    model: one lock, taken by both the control session and the reconcile loop.

    **The runner swap is inside `applyMu` too, and that is not tidiness.**
    `evaluate` and `applyDecision` read the runner under the state lock at their
    start and then shell out for as long as `ip` takes. A swap outside the apply
    lock can therefore land in the middle of a decision that has already
    captured the previous runner - one route installed with the armed runner
    after the mode has gone to observe. `Agent.ApplyConfig` takes `applyMu`
    before the swap; `Engine.Reconfigure` takes it around the swap and releases
    it again immediately, because `applySystemConfig` takes it itself and these
    mutexes are not reentrant. A decision running in that gap sees the new
    configuration and is right to.

    **Frontend lock order is `reconfMu` then `applyMu`, never the reverse.**
    `Run`'s goroutine takes only `applyMu`, so there is no cycle. `applyMu` is
    deliberately not taken inside `applyActivePath` or `applyPlumbing`: their
    callers hold it across several groups of shell-outs precisely so a decision
    cannot land between them.

    **The queue discipline is on that list too.** A shaper belongs to the
    interface exactly as `rp_filter` does, so `wg-quick down` takes it with the
    device and the replacement comes back with the kernel default. Nothing
    reports it: traffic keeps flowing, unshaped, and the only symptom is that
    latency under load quietly gets bad again - the hardest kind of regression
    to attribute, weeks later. Both reconcilers call `sysx.EnsureQdisc` for any
    path with a rate, and neither runs `tc` at all for a path without one.
19. **Multi-host support must be invisible until it is configured.** With
    `overlay.subnet` empty - an older site, or one that opted out with
    `--subnet ''` - the generated rulesets and the `ip` commands must be
    byte-identical to a build with no linker support at all. This is a property
    of the code and does not change with what the installers write: they now
    default the field to the `/24` the overlay addresses sit in, because it
    cannot be set from the portal and a site without it has to be visited over
    SSH on both hosts before a linker can be added at all. The empty case stays
    supported, and stays tested. This is not neatness: a site with one
    host at the far end has no reason to have a range routed down its tunnel,
    its `DOCKER-USER` exceptions widened, or its egress NAT matching addresses
    nothing holds - and every one of those is a live rule on a working system.
    So nothing here is derived or inferred - not from whether any service names
    a target, not from anything else. `sysx/linker_test.go` pins the generated output; the real check is to
    diff it against the previous commit.
20. **`MatchPrefix` and `RoutePrefix` look redundant and are not.** nftables
    matched the backend on a bare address while `ip route` installed an
    explicit `/32`. Collapsing them into one helper changes whichever of the
    two you did not pick, on every existing deployment - equivalent to the
    kernel, and a diff in `ruleset.nft` on a host where nothing was meant to
    move. They return the same string once a subnet is set, which is what makes
    the duplication look pointless. Leave them.

    For the same reason, `sysx.RouteVia` takes the prefix that was **installed**
    rather than an address inside it. `ip route show` filters on an exact prefix
    - unlike `ip route get`, it will not report a `/24` when asked about a `/32`
    within it - so a caller that installs a range and reads back a host address
    sees "no route" on every tick and reinstalls what was already there. Each
    call site passes its own prefix so which one widens is visible where it is
    decided.
21. **A widened route must remove the one it superseded.** `ip route replace`
    writes the new prefix and leaves any other alone, so setting a subnet on a
    running site leaves both `10.99.0.2/32` and `10.99.0.0/24` installed - and
    the `/32` is more specific. The backend stays pinned to whichever tunnel
    was active at that moment while every later failover moves only the range.
    Nothing reports it: probes and the control channel are steered into their
    own tables by fwmark, so all three paths go on measuring perfectly.
    `Engine.dropSupersededHostRoute` removes it, on apply and on reconcile,
    and only in the widening direction - it has no record of a previous subnet
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
  ride the main link - three tunnels on one link, all probing healthy, no
  failover at all.

**`AllowedIPs` is asymmetric, and the backend's must be `0.0.0.0/0`.** It is a
filter as well as a route: WireGuard drops an inbound packet whose source falls
outside it. Published traffic carries the client's real address - the whole
point of DNAT without SNAT - so a backend peer limited to `10.99.0.1/32` drops
every request before it reaches the interface, and cannot send replies either.
Probes and the control channel keep working, because those genuinely do come
from the overlay address, so the portal shows three healthy paths while nothing
published works. `tcpdump` on the tunnel shows nothing at all, since the packet
never gets injected.

The frontend's side is `10.99.0.0/24` - the whole overlay range, not the
backend's `/32`. The `/32` is narrower and is what a backend-only site strictly
needs, but the default is the wider one because of the shape of the failure: the
day the site adds a second host at `10.99.0.3`, a peer pinned to the backend's
address silently refuses to transmit to it, and the only symptom is one
unreachable machine long after anybody last edited a WireGuard file. The range
is private, carries nothing but this system, and every channel on it is
separately authenticated - `Engine.KnownLinker` refuses an address that is not
configured whatever key the peer holds - so the wider filter gives away very
little. Deliberately narrowing it on a site that will only ever have one backend
is a reasonable hardening step and is documented as one.

**Docker rewrites the packet filter on whichever host runs it.** On the
frontend it sets the FORWARD policy to drop, which discards DNAT'd traffic; the
agent inserts exceptions into `DOCKER-USER` (`sysx.EnsureForwardExceptions`),
matched by destination and connection state, never by source - a reply's source
is rewritten back before the forward hook runs.

**The backend needs the same treatment the moment a linker exists behind it,
and for a long time it did not have it.** Until then the backend terminated
everything and forwarded nothing, so a drop-policy forward chain had nothing of
its to drop. With a linker, every packet in both directions is forwarded
through it, and on a backend that runs containers they were all dropped -
routing correct on all three hosts, `ip route get` answering perfectly, and the
linker's control channel timing out with nothing in any log.
`sysx.EnsureOverlayForwardExceptions` accepts the overlay range in both
directions, and both are needed: the request carries the linker's address as
the destination and every answer carries it as the source. Nothing here is
translated, which is why matching on source is right here and wrong on the
frontend. Installed only where linkers are configured. On the backend a container on a
bridge network defeats the source-based return rule, because the reply is
routed while it still carries the container's address; `sysx.BuildReturnRuleset`
marks connections arriving from a tunnel and restores the mark on replies only.
Restoring it in both directions sends incoming requests back out their own
tunnel.

**Restarting a tunnel silently empties its routing table.** `wg-quick down`
runs `ip link delete`, and the kernel discards every route pointing at that
device - the path's probe/reply route in table 10x, and, if it was the active
tunnel, the main-table route and the return-path default too. `wg show` looks
perfect afterwards (a handshake seconds ago) while the path probes as 100%
loss, because the packets have nowhere to go. The reconcilers exist for this;
see invariant 18. To confirm it by hand: `ip route show table 101` should name
the tunnel, and an empty result is the bug.

**A tunnel that was absent at startup is a different case, and it was not
repaired.** A table that has never held a route does not exist to the kernel,
and `ip route show … table 101` answers with `Error: ipv4: FIB table does not
exist` (exit 2) rather than an empty listing. A table emptied by a restart
still exists and lists as empty. `RouteVia` and `DefaultVia` used to pass that
error up, and both reconcilers skip a path on error - so a frontend rebooted
ahead of `wg-quick` never created the tables for the tunnels that came up
after it and never repaired them, every tick, for the life of the process. The
fingerprint: `wg show` with one tunnel carrying kilobytes and the others at 92
bytes sent - one handshake response and not a single probe - and a service
restart fixing it instantly, because by then every interface existed before
the routes were installed. Every route readback now goes through
`sysx.showRoutes`, which reports a nonexistent table as the empty listing it
is; any other failure is still a failure. It is one helper rather than a check
at each site because the answer was first missed in three: `RouteVia`,
`DefaultVia`, `LinkerRouteVia` (a linker whose LAN was down at agent start
never created its table and its reconciler returned on the error every tick)
and `cleanAbandonedTable`, where the error kept a stray rule into a table that
never existed as a "retry marker" forever, through the revert included.

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
which inherits `net.ipv4.conf.default.rp_filter` - systemd ships that as 2 -
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
ip route get 10.99.0.3 from 10.99.0.1 iif wg-main
```

Answering with the tunnel rather than the LAN is the bug.

**An overlay address must exist on exactly one host, and a revert deliberately
leaves it behind.** Swapping two hosts' roles - the box that was the linker
becoming the backend, the old backend becoming the linker - leaves each one
holding the address it used to have. Neither `Revert` nor `uninstall.sh` removes
it without `--overlay`, and that default is right for the case it was written
for: something may be bound to the address, and on the backend binding to it is
the entire egress selector, so dropping it would take a running game server's
socket with it. The result of the swap is a new backend carrying `10.99.0.3` on
`dummy0` beside its own `10.99.0.2`, answering for a host it is supposed to be
routing to.

The displaced host then reaches nothing, and the error is a first-hop one:
`connect: no route to host` from the control channel, `ip neigh` showing the
backend's LAN address `FAILED`, and a tcpdump on the backend showing the ARP
requests arriving and never being answered. That is not a firewall. Linux
route-checks an ARP request before replying to it - `arp_process` calls
`ip_route_input`, which calls `__fib_validate_source` - and a request whose
*sender* address is one of the receiver's own resolves to `RTN_LOCAL`, which is
`e_inval` unless `accept_local` is set. That branch runs ahead of the rp_filter
branch, so `rp_filter = 0` does not rescue it as it does elsewhere in this
system: the backend will simply not answer ARP for a peer claiming an address it
holds itself.

Everything else reads healthy, which is what makes it expensive. The frontend
pings the linker and gets a reply - from the backend. Traffic published to the
linker is answered by the backend, because `local` is rule 0 and shadows the
`10.99.0.3 via <lan>` route the agent installed. All three paths measure
perfectly throughout. The only number that gives it away is the round trip: the
backend pinging the "linker" answers in about 0.02ms, which is not a LAN hop.

Two commands on the backend, and both are worth running after any role change:

```sh
ip -br addr show dummy0
ip route get 10.99.0.3
```

`dummy0` must carry this host's own overlay address and nothing else, and the
route must name the LAN neighbour rather than `local`. A `dummy0` address does
not survive a reboot, so this clears on its own and comes back the moment
somebody re-adds it by hand - which is not a reason to leave it. When a host is
changing role rather than leaving the deployment, `uninstall.sh --overlay` is
what takes the old address with it.

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
converted the return rules and the linker's, and left `ensureProbeRules`,
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

**Frontend** - SQLite at `/var/lib/failover/failover.db`:

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

**The state directory is 0700, and the database is 0600 inside it.** Session
tokens are stored in the clear beside the password hashes, so a world-readable
database is a world-readable login to the thing that arms the data plane,
serves the shared secret over `/api/psk` and reverts the system: the credential
is not the database, it is every credential in the system. SQLite creates its
files honouring the umask, which under systemd is 022, so they landed at 0644
in a directory systemd had made 0755. The mode is set in three places and none of them
is redundant, because each covers a moment the others miss:
`install-frontend.sh` creates the directory 0700 and, because `install -d`
applies a mode to a directory that already exists, corrects an install made
before this was understood; `StateDirectoryMode=0700` covers a directory
systemd creates itself; and a `chmod` in `cmd/failover-frontend` covers every
start after that. Beside them `store.restrict` takes the bits off the database,
its WAL pair and its rollback journal, which catches a `db_path` pointed
outside the state directory - while the directory mode is what covers those
files whenever SQLite recreates them after a checkpoint. What it could not do
is reported rather than swallowed (`Store.PermissionWarnings`, logged by
`cmd/failover-frontend`): this is a security property, not a tidy-up, and a
`chmod` that silently did nothing - a filesystem that ignores it, an export
where this process does not own the file - leaves live thirty-day session
tokens world-readable while the journal says the frontend started normally. It
is still not fatal, because a database that opened is one the frontend can run
on and refusing to start over a mode bit trades the hardening step for the
outage it exists to prevent. `perms_test.go` runs on tmpfs, where the failure
cannot happen, which is exactly why the warning has to exist. The backend's and the
linker's state directories stay 0755 deliberately: they hold no secret, and
narrowing them would be a change to behaviour with nothing behind it. Nothing outside the process reads any of
it: the portal serves embedded assets, `ruleset.nft` is a record for somebody
who is already root, and the failoverctl socket has its own 0700 directory
below this one.

Also on disk: `ruleset.nft` (the generated DNAT ruleset, left in place as a
readable record), `egress.nft` (the source NAT for backend-originated traffic,
written only when `Frontend.BackendEgress` is on), `protect.nft` (the rate
limiting and edge filtering, written only when protection is on and something in
it is configured) and `ctl.sock` (the failoverctl socket, mode 0600).

**Backend** - no database. `backend-config.json` (cached pushed config, so a
frontend outage does not leave it unable to route replies after a restart),
`usage-buffer.jsonl` (undelivered deltas), `meter-state.json` (counter
baselines and sequence numbers - persisting the baseline means usage during
agent downtime is still accounted for).

**Bootstrap files** (`/etc/failover/{frontend,backend}.json`) hold only the
shared secret, state paths and overlay addressing. Everything else is in the
portal, on purpose: there is one place to manage the system from.

**Linker** - no database and no state files at all. `/etc/failover/linker.json`
carries the shared secret, the overlay addressing, and the two things the
frontend has no way to discover: this host's own overlay address and the
backend's address on the local network. `LoadBootstrap` refuses a linker config
missing either, because an agent that starts with neither installs a rule for
traffic that will never arrive and reports itself perfectly healthy. It refuses
one that does not *parse* for a sharper version of the same reason: both
addresses end up in generated nftables rules, and a generator handed an address
it cannot use renders nothing at all. An empty ruleset is a zero-byte file that
`nft -f` loads without complaint, so a typo bought a linker that started, logged
its egress networks as installed, and had no table. The agents check the same
thing again where they build (`sysx.AddressLiteral`, and the empty-ruleset guard
in `Linker.installEgress`), because an empty file is not self-announcing and a
caller that passes one on reports success.

**"Parses" means what the generators can actually use, which is narrower than
`net.ParseIP`.** Every one of them is IPv4 only, so an IPv6 address parsed
perfectly, passed the check, and then rendered nothing - the check was catching
the typo that does not parse and missing the one that parses into something
unusable, which is the same silent-empty-ruleset failure it was written to
prevent. `model.ipv4Literal` and `model.ipv4Network` are what it uses now, and
the normalised form is stored back into the `Bootstrap`, so what the generators
see is what was checked. They mirror `sysx.AddressLiteral` and
`sysx.NetworkLiteral` by hand because `sysx` imports `model` and the dependency
cannot run the other way; if the rule moves in one, move it in the other.

**The marking table and its mark rule go in as a pair, in both writers.**
Nothing sets that mark unless the table is loaded, so the rule on its own
selects a table for traffic that can never carry it: plumbing that reads as
correct in `ip rule` while the thing it serves was never built. Guarding that in
`apply` alone was worth nothing, because `reconcile` installed the rule
unconditionally on its next tick, so the guard held for ten seconds. The inverse
was the worse half of the same gap: `reconcile` never retried the *table*, so a
load that failed at boot was never reinstalled while its rule was kept
perpetually fresh. `Linker.ensureReturnPath` is the single writer both call, and
`returnOK` is recorded only once `nft -f` has taken it, exactly as `egressOK` is
- so a refused load is retried rather than believed. `reconcile` reloads nothing
when that flag is set: an nftables table is not lost with an interface the way a
rule or a route is, so there is nothing to repair in the ordinary case.

---

## 10. Configuration model

**Adding a field to `model.Config` does not give existing deployments its
default.** The whole config is one JSON blob in SQLite, so a config written by
an older build unmarshals with every newer field at its zero value, and
`Defaults()` only ever runs on a first start. Shipping the quality weights
without accounting for that gave every upgraded system a scoring function where
all weights were zero and the portal a form full of zeros. `model.Normalise` is
where that is repaired, and it is called on load and on save. It fills in a
group only when every field in it is zero - which cannot be deliberate - so an
individually chosen zero, a margin or a dwell of none, survives.


**Five fields exist only for multi-host sites, and empty means "the backend"
for all of them.** That is what keeps them invisible: an older config
unmarshals with every one at its zero value and behaves exactly as it did.
`Normalise` deliberately leaves them alone - there is nothing to repair,
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
| `Protect.Regions`, `Service.GeoRegions` | no region locks; reachable from anywhere | portal |
| `Service.GeoAutoPPS` | a lock with regions set is unconditional | portal |

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
linker that actually exists - being inside the subnet only proves the *frontend*
can route it.

`Config.BackendLAN` routes nothing. It is the one fact a linker's own bootstrap
file needs that nothing else here carries, and holding it is what lets the portal
generate that file instead of the operator assembling it by hand.

`Overlay.Subnet` is bootstrap-owned rather than portal-editable for the reason
in invariant 14, plus one of its own: it has to be covered by `AllowedIPs` on
the frontend's peers, and the portal cannot edit a WireGuard config. The shipped
setup puts the whole range there from the start precisely so that this is
normally already true - see the `AllowedIPs` trap for why the narrower value is
the more dangerous default.

`model.Config` is the whole user-editable surface. The portal `PUT`s it whole;
`web.validate` normalises and rejects it; `Engine.Reconfigure` persists it,
restarts the probers, reapplies system config, and bumps `cfgVersion`. The
control server notices the version change within 2s and pushes the backend's
subset down.

Defaults (`model.Defaults()`) match the intended deployment: main/LTE1/LTE2 at
priorities 1/2/3, tables 101/102/103, marks `0x101`/`0x102`/`0x103`, 250ms
active and 5s standby probing, 8 losses to condemn (~2.6s detection), 90s
failback hold-down, 60 GB and 20 GB quotas resetting on the 1st in
`model.DefaultTimezone` (`Australia/Melbourne`), and **observe mode**. The six example services -
`http 80/tcp`, `https 443/tcp`, `pterodactyl-sftp 2022/tcp`, `pterodactyl-wings
8080/tcp`, `source 27015–27030/udp`, `minecraft 25565/tcp` - ship **disabled**:
a row is a DNAT rule, and a fresh install must not publish a port on the
strength of nobody having deleted it. Arming is when the shipped list would
have gone live, which is why observe mode is not the answer to this on its own.
A row added in the portal starts at `5000/tcp`, a port nothing here listens on,
so a row saved before it was edited publishes nothing that exists.

The one shipped egress source, `pterodactyl` on `172.18.0.0/16`, is disabled
for the same reason and needs it more: enabled, it would pull every container
on that bridge onto the tunnel and bill them to the LTE quota. It is there
because it is the row this deployment adds by hand every time, and because a
CIDR somebody has to go and look up is a CIDR that gets typed wrong.
`model/defaults_test.go` pins both.

Ports in use: probe `51999/udp`, control `51998/tcp`, tunnels
`51820`/`51821`/`51822` (distinct so pfSense can policy-route by source port),
admin tunnel `51830/udp`, portal `10.98.0.2:8088`.

---

## 11. Testing

Tests are pure and fast - no network, no root, no sockets. They cover the parts
where a subtle regression would be invisible in production until an outage:

- `engine/select_test.go` - the whole selection policy: priority, immediate
  failover, hold-down failback, quota skip, held states, dead-man, pinning.
- `engine/quality_test.go` - quality selection: that it never displaces the
  preferred path however much better a fallback measures, that priority mode is
  untouched, that loss outranks latency, that the margin and hold-down both
  apply between fallbacks, that identical paths never swap, that a change of
  challenger does not restart the clock, and that the dead-man and pinning
  still win.
- `engine/tracker_test.go` - health transitions, the suspect-stays-usable rule,
  clean-streak reset, circuit breaker and its backoff, degraded thresholds.
- `quota/quota_test.go` - billing period boundaries including short-month
  clamping, metered-byte reconstruction, grants expiring by time and by bytes,
  ceiling overriding a grant.
- `proto/proto_test.go` - round trip, and rejection of wrong keys, tampering,
  wrong sizes and replayed challenges. Also the two properties the handshake
  exists for: that the dialler's proof and the frontend's are not
  interchangeable, so reflecting one back is not enough; and that the handshake
  cannot be talked into signing a probe, pinned twice over - the nonce shape is
  refused before the key is touched, and each MAC is checked against the bare
  HMAC it used to be. `agent/shutdown_test.go` holds the other end of it: a
  session is refused, and the hello never goes out, against a peer with no
  proof, a made-up MAC, a proof under the wrong key, and the dialler's own
  proof reflected back. And the session the handshake establishes: a relay that
  passed the handshake through, so it holds both nonces and no key, cannot write
  a frame either end will read; a frame cannot be reflected at its sender,
  replayed, reordered or relabelled; and a frame with no MAC at all is refused.
  `engine/linker_session_test.go` holds the frontend's end of that over a real
  socket, which is what proves the server actually reads through the session
  rather than beside it. Back in `proto/proto_test.go`, that every frame gets
  its own write deadline, which is what stops a writer queued behind a stalled
  one reaching the socket with the time already spent.
- `sysx/nft_test.go` - the published ruleset never masquerades; atomic replace;
  a pushed egress network carrying nftables syntax and a newline never reaches
  the generated file while the usable network beside it still does, a network
  the parse cannot use renders nothing at all rather than an empty ruleset over
  a table that is already loaded, and one the portal accepted is not moved by a
  byte; the overlay address beside them gets the same treatment, so a generator
  handed one it cannot parse renders nothing rather than a file with it in;
  `linker/linker_test.go` holds that a push with nothing usable in it takes the
  rules down instead of installing the mark rule, and that an install which
  would render no ruleset at all is not recorded as applied, so the retry that
  exists for a refused install still covers it;
  both mode-gated tables clamp the TCP MSS on SYNs leaving by a tunnel, scoped
  to the tunnels, and render no clamp with no tunnels;
- `linker/linker_test.go` also holds that the egress rules go in before the
  ruleset that starts marking packets, because the backend does it that way
  round for a reason: a marked packet with no lookup and no refusal leaves by
  the host's own internet and Docker's masquerade binds the flow there.
  the egress mark leaves private, link-local and multicast destinations on
  their normal route (and `sysx/linker_test.go` holds the same for a linker's
  mark and its SNAT);
  the egress source NAT stays in its own table, stays scoped to the public
  interface, and renders nothing at all when it is off; the two forward-exception
  comments cannot match each other; the backend egress SNAT stays ahead of
  Docker's masquerade and never fires off the tunnels; no two fwmarks collide;
  return marking is limited to connections that originated from a tunnel.
- `proto/proto_test.go` also holds the size bound: an oversized frame is
  refused rather than buffered, on the handshake reader and on the
  session's alike, and refused with a bounded amount consumed rather than
  merely refused eventually; the reader in that test is deliberately finite,
  so reverting the bound fails the test instead of hanging it. Beside them,
  that a full 500-delta usage batch - the largest frame this protocol
  produces - fits inside the bound with an order of magnitude to spare, and
  that a frame just under it still reads, because the check runs per chunk
  and an off-by-one there rejects frames that fit.
- `proto/proto_test.go` also holds the write side: a frame past the bound is
  refused by its sender, nothing partial reaches the buffer, and the session
  counter does not advance over the refusal - which matters because the peer
  checks that number exactly, so a gap there would be read as tampering.
- `engine/control_limit_test.go` - the connection limit admits to its bound,
  refuses past it, and gives a slot back when a connection finishes (a limit
  that never released one would refuse everything after the first sixty-four
  callers, which is a worse outage than the one it prevents). And that `listen`
  fills in a limit it was not given, driven through the real accept loop on
  loopback: nil there would have refused every connection rather than erroring,
  so this is pinned rather than left to the constructor. And that
  pre-authentication rejections are throttled, counted through a log handler
  rather than by reading the code, with the throttle proved to reopen after its
  interval so a standing misconfiguration is not reported once and never again.
  And its trailing edge: a burst that stops inside the window is still named
  rather than swallowed, a flush inside the window adds no line, and a flush
  with nothing owing is silent. And the per-address share: one address is
  admitted to `maxPerSource` and refused past it while a second address is
  unaffected, a finished connection gives its share back, and the map is empty
  again once they have - the keys are chosen by whoever dials.
- `store/perms_test.go` - the database and its journal carry no group or world
  bits. They hold live session tokens, so this is the file mode standing
  between a local account and the portal.
- `store/usage_saturation_test.go` - the ledger column survives at both ends:
  forty saturated deltas leave it readable and capped rather than promoted to a
  REAL, and a negative delta neither drives it below zero nor takes the packet
  column with it. The floor is pinned here rather than only in the engine
  because `Engine.AddUsage` clamps first, so an engine-level test passes whether
  or not this method holds its own bound.
- `engine/quota_report_test.go` - a stored calibration outside the range this
  build accepts is named at load, with the path in the line, and a configuration
  the portal would accept produces no line at all. Zero is pinned as one of the
  quiet cases: `validate` reads it as unset, so reporting it would fire on every
  path of any deployment predating the field and bury the line that matters. A
  negative value is pinned beside it for a sharper reason: `validate` normalises
  anything at or below zero to 100 before its range check, so it saves cleanly,
  and the first version of this report fired on it with a hint saying the form
  would refuse to save.
- `agent/meter_buffer_test.go` also holds the batch's fair share: a path with
  thousands of unackable deltas at the front of the buffer cannot crowd two
  other paths out of a batch, the leftover is still filled from it so a genuine
  single-path backlog drains at the full rate, per-path order is preserved
  because the frontend's watermark requires it, and a buffer holding one path
  still comes off the front as the flat prefix it always was.
- `agent/decision_test.go` also holds the sequence bound: an implausible
  sequence is refused *and does not become the ceiling*, which is the half
  that matters, while a real one still lands; the ceiling grows with elapsed
  time from the anchor, so a frontend restart and a clock corrected days
  forward both pass while a month-sized jump in a minute does not; the very
  first decision is bounded only by the horizon, because there is nothing to
  measure from and refusing it would refuse the decision that installs the
  return path; that a frontend restarting after a fortnight of uptime is not
  refused as a pin, which the anchor alone could not do and which left a
  restarted backend unable to route a reply for as long as it ran; that a clock
  past the horizon is ignored rather than trusted, since the shift into the
  sequence's units wraps there and a high wrap would widen the ceiling to
  admit anything, while a clock inside it widens without lifting the horizon
  with it; and a wildly wrong wall clock cannot refuse a real decision,
  which is the property the first version of this check got backwards.
- `web/validate_test.go` also holds the public address: the wrong family is
  refused, an IPv4-mapped one is flattened rather than refused - matching
  `sysx.AddressLiteral`, since To4 on a bare address yields a usable dotted
  quad where a mapped *network* would not - and a valid one saves normalised.
- `web/password_test.go` - a password can be changed, doing so logs out every
  other session while keeping the caller signed in, the current password is
  required, an unauthenticated request cannot change one, the local socket can
  reset a forgotten one, and a very short password is refused.
- `sysx/protect_test.go` - protection off generates no table at all, and the
  switch on with no thresholds generates none either; every chain excludes
  non-public traffic in its first rule; the system's own ports and overlay
  addresses never appear; the table never translates an address; the chains run
  before dstnat; sources are parked only when a block time is set; the blocklist
  is consulted first; query limiting matches only connectionless packets and
  needs a service to opt in; every drop is counted; the blocklist set is dynamic
  and bounded; two services on one port still produce a set nftables will
  accept; and the counters and blocklist parse back out of `nft -j`.

  The region locks are pinned in the same file: a lock alone activates the
  table, matches statelessly before conntrack, and its set carries `flags
  interval`; overlapping and duplicate networks in a pasted list are merged
  (nft rejects the table over one contained duplicate); several regions on a
  service AND their negated lookups into one rule, which is the union as an
  allowlist; the block direction matches positively and puts each region on
  its own rule, so several blocked regions drop their union rather than their
  intersection, with the auto variant conditional on the lockdown set like
  the allow one; a dangling region reference locks nothing rather than dropping
  everything, and a partly dangling allow lock locks nothing too while a
  partly dangling block lock keeps its resolved regions, because the open
  direction differs by rule shape; the automatic lock's trigger precedes its
  drop so a locked flood
  keeps refreshing the lock, its lockdown set is dynamic and per protocol, and
  the release lag is configurable with zero meaning the shipped minute; region
  names are folded to loadable set names whatever the blob holds, two
  names that fold together emit one set rather than a rejected table, and a
  region folding onto a lockdown set's name is shifted aside rather than
  defining that set twice; and engaged locks parse back out of `nft -j` with
  the rest, matched by the two exact lockdown names so an operator's
  `lockdown_eu` region is never read as lock state, with the trip counter
  flagged as observing rather than dropping.
  `web/protect_validate_test.go` holds the fail-closed half: a lock on an
  undefined or empty region is refused, so is an auto threshold with no
  regions, a network that does not parse, an IPv6 network in an ip-family
  table, an IPv4-mapped one whose stored form would fail to re-parse (for a
  region and for an egress source, which share the helper), a name outside
  the slug the set name needs, a name reserved by the lockdown sets, and two
  names that fold to one set - keyed on `sysx.GeoSetName` itself, so validate
  and generation cannot drift; while a valid lock saves with bare addresses
  widened to /32 and host-part CIDRs masked to their network.
  `web/geofetch_test.go` pins the fetch endpoint against a local fake host:
  the merged lists and per-country counts come back in request order whatever
  order the concurrent fetches finish in, a list
  with anything that is not an IPv4 network in it fails whole with no partial
  data, a missing or empty list is refused, a bad country code is refused
  before any request leaves - in any position, because the codes are checked
  as a whole first pass - an oversized response is a loud error rather
  than a silently shorter list, the endpoint requires a session, and a
  region's remembered country codes are validated to the same shape the
  endpoint demands.

  The last two are load failures, not cosmetic ones, and both were found by
  reading the generated ruleset rather than by any test passing. A set that is
  not `dynamic` refuses every `add` from the packet path, and a set literal with
  a repeated or overlapping element is rejected outright - in each case nft
  rejects the **whole table**, so one duplicated service port would have taken
  every limit down with it. Generated nftables is worth reading by eye before
  trusting: the tests can only assert what somebody thought to assert.
- `sysx/shape_test.go` - an unshaped path installs nothing, the configured rate
  reaches the kernel with the overhead, an intact shaper is left alone, one lost
  with its interface is restored, clearing the rate removes it, a queue
  discipline this agent did not install is never removed, and tc's units are
  read back whichever it chose to print.
- `engine/protect_test.go`, and the shaping cases in `agent/reconcile_test.go` -
  observe mode neither shapes nor loads a limiter, disabling protection removes
  the table, shaping lost with a tunnel is restored while an intact one is left
  alone, an unshaped site never runs `tc` in the reconciler, and revert removes
  only the shapers this agent installed.
- `sysx/route_test.go` - that a table with a name in `rt_tables` does not hide
  the agent's own rules from it, that the control and return-mark rules carry an
  explicit priority ahead of the probe band, that moving a rule to its pinned
  priority adds before it deletes, the control rule selects on mark not addresses,
  rp_filter is off rather than loose, the path rules are pinned ahead of the
  return rule, a purged table reads back as no interface rather than an
  error, and so does a table that never existed while any other `ip` failure
  is still one. Also that a path's rules go in without its interface and the
  unreachable backstop lands behind the lookup, that a backstop at the wrong
  priority is moved with the add before the delete, that a refusal for a mark
  no path carries is swept while a host's own refusal outside the band is
  left alone, that revert clears the band, and that the egress lookup carries
  its own refusal, owned by its priority alone and removed with the lookup
  (`sysx/linker_test.go` holds the same for a linker's).
- `engine/reconcile_test.go`, `agent/reconcile_test.go` - what a tunnel restart
  leaves behind gets repaired, a probe table that was never created (the
  tunnel absent at startup, which the kernel reports as an error rather than
  an empty table) is repaired too, an intact system is left completely alone, a
  tunnel that has not come back is skipped, and observe mode repairs
  measurement without installing anything that moves traffic.
- `engine/detection_test.go`: a new prober generation sends at once and a
  decision change sends again at once rather than on the standby ticker, both
  proved from outside by watching a loopback socket; a nudge with no loop to
  receive it never blocks; a path being condemned wakes the decision loop
  exactly once while a loss that changes nothing does not wake it at all, with
  the channel drained between checks so the negative assertions can fail; a
  path recovering wakes it once too, as does a fresh tracker's first reply,
  while a reply on a path already up and a single loss demoting up to suspect
  do not; pin, approve, revoke, clear-quarantine and a settings save each wake
  it; and a send the kernel refuses is booked as a loss and held for one
  interval rather than spun on, proved with a udp4 socket pointed at an IPv6
  address so it needs no routing and fails the same way on every platform.
- `model/presets_test.go`: the standard preset applied to the defaults changes
  nothing, the presets are ordered by detection time and each note quotes the
  time `DetectMs` gives for its numbers, applying a preset lifts a standby
  interval the new active one would overtake and leaves a slower one alone,
  and `DetectMs` counts the streak plus the last timeout.
- `web/validate_test.go` also runs every preset through `validate`, on the
  shipped configuration and on one with a short standby interval, because a
  copy of the bounds would keep passing after the real rule moved.
- `agent/decision_test.go`: a stale decision arriving after a newer one is
  queued cannot replace it, while a newer one still can; an equal sequence on
  another path, which is a restarted frontend's first switch, is still queued;
  and, with the worker actually running, the newest decision is applied, a
  straggler never reaches the kernel, and the equal-sequence decision lands.
- `engine/prober_lifecycle_test.go` - one generation of probers, always: a
  replaced generation is cancelled rather than orphaned, `stopProbers` returns
  only once the old goroutines are gone, and eight concurrent `Reconfigure`
  calls leave exactly one prober per path. These run the probers as real
  goroutines rather than stubs - their sockets cannot bind on a development
  machine, which is the intended shape, because `Prober.Run` then sits in its
  dial/`reportUnreachable` cycle holding a context exactly like a working one.
  `Engine.liveProbers` exists so this is assertable at all: from outside, a
  duplicate generation is invisible except as a path probing faster than its
  configured interval. On the original code the last of these reported 24
  goroutines where three were wanted.
- `engine/apply_serialise_test.go`, `agent/apply_serialise_test.go` - no two
  goroutines are ever inside a system command at once. Both drive every route
  writer concurrently against a runner that reports the peak number of
  overlapping calls, which is the property that matters: each fault in this
  family is two goroutines writing the same route, and which one lands last is
  a matter of timing. On the unguarded code they report four and three.
- `engine/revert_context_test.go` - a revert handed a cancelled context runs no
  commands at all and still reports the rules gone, which is why
  `web.handleRevert` detaches the request context; and the same revert with a
  live one does the work.
- `engine/revert_latch_test.go` - the revert latch survives a restart: a fresh
  process on the same database starts held, its startup installs nothing and
  starts no probers, and a settings save releases both the in-memory flag and
  the persisted copy.
- `sysx/linker_test.go` - that a site with no subnet generates byte-identical
  rules, that the two prefix helpers agree once one is set, that a service
  target moves only the DNAT, and that the source rules stay behind the
  per-path rules and get moved when found elsewhere. Also the ownership line
  the sweeps hold: a mark rule in another table is swept only when it sits at
  the pinned priority - the mark constants are this system's but a fwmark is
  only a number, and a host that already policy-routes may select on the same
  value for its own tables (invariant 8) - while the source rule may claim
  every match, because nothing but this system holds the overlay address. And
  that a table abandoned by a change of `linker.table` is relieved of this
  system's `default via <backend>` when its stray rule is swept, on ensure and
  on revert, gateway-qualified so a default the operator has put back is never
  the one removed - with the route deleted *before* the rule, and the rule
  kept whenever the table could not be confirmed clean. The stray rule is the
  only evidence the table was ever this system's, so it is the marker the next
  reconcile tick retries from; deleting it first would turn any failure in the
  gap into a permanent, invisible misroute. And the subnet's own re-parse: one
  the generator cannot use is dropped, leaving exactly the ruleset a site with
  no subnet gets rather than a table nft would reject whole, while one carrying
  host bits is masked so the overlay rules a linker needs are still emitted.
- `agent/revert_test.go` - the backend takes down what it installed: both return
  sources, the mark rule, the marking and egress tables, the routes to extra
  hosts, the probe tables and the overlay route; that it deletes table 100's
  default route rather than flushing the table; that it removes only the shapers
  it installed; that it acts in observe mode; and, the one guarding every
  existing site, that a site with no subnet and no linkers reverts nothing that
  mentions either.
- `linker/linker_test.go` - an egress install the kernel refused is not recorded
  as applied and is retried on the next reconcile tick, an unchanged push costs
  nothing, a host the frontend has never spoken to has its egress left alone,
  an intact linker is left alone, the route lost with
  the LAN interface is restored, revert leaves the overlay address in place, the
  agent writes no sysctls, and it loads exactly one nftables table of its own
  which never translates an address. Also that marking happens before dstnat and
  only in the original direction, which is what makes it match the overlay
  address rather than the container's. And the return path's pairing, in both
  writers: reconcile withholds the mark rule while the table it selects is not
  loaded, retries a table the kernel refused, and reloads nothing once one is
  in - the three cases that were a guard in `apply` undone by `reconcile` a tick
  later, and a refused load nothing ever came back for.
- `engine/linker_registry_test.go` - each linker receives only its own networks,
  an unowned row never leaks to one, nothing is pushed while the egress master
  switch is off, only configured linkers are accepted, and a configured host
  that has never connected still reports as down rather than vanishing.
- `engine/linker_session_test.go` - the control channel end to end over a real
  socket: authentication, the first push, liveness registration, a linker
  claiming an address nobody configured being refused, and a roleless hello
  still being understood as the backend.
- `engine/control_identity_test.go` - which half of the protocol a peer is
  served is decided by where it connects from, not by what it says it is: a
  configured linker sending a roleless hello is refused rather than served as
  the backend, a linker naming another linker's address is refused rather than
  handed that host's networks, and the real backend dialling from the overlay
  address with no role at all is still served exactly as it was. Plus
  `KnownBackend` itself, so an unset address cannot become a wildcard.
  A refusal is asserted as a *closed connection* rather than as a read that did
  not finish, and that distinction is the test: `pushLoop` has no immediate
  push the way `pushLinkerLoop` does, so a served backend sends nothing for two
  seconds, and any deadline near that passes against unguarded code on a busy
  machine. A timeout is reported as inconclusive rather than as success.
- `engine/usage_bounds_test.go` - the ledger is not writable to arbitrary
  values by whatever reaches this socket: a delta past the ceiling is clamped
  rather than billed as sent, a negative one cannot credit the ledger, a
  stamp in the future is pulled back to now while a backdated one keeps its own
  billing period, and a clamped delta still advances the watermark, because a
  refusal would have the backend resend it forever and stall that path's
  accounting for good. The one that guards every working deployment is that an
  ordinary delta is not moved by a byte, including the single large one a
  restart after a long outage legitimately produces. Then the four the first
  version of the bound missed: a stamp before the window is billed to the
  current period rather than into 1970, which is where a backend with a stale
  clock puts a month of LTE; both overflowing stamps are clamped and
  named for the direction they came from; a path id
  outside any valid configuration never touches the database, since acking one
  is a permanent `meta` row keyed by whatever the sender chose; and an
  oversized batch is truncated, because a frame bounded only by
  `proto.MaxFrameBytes` can carry ten thousand transactions onto the read loop.
  Then the one that outranks all of them, because it is silent *and*
  unrecoverable: an implausible sequence cannot become the watermark, since one
  that did would end that path's accounting for good and survive every restart,
  with the companion case pinning that an ordinary sequence, ten years of
  sampling deep, is still accepted. Then the same hazard measured the way it
  actually bites: a sequence well inside the absolute bound but hundreds of
  millions of samples past the watermark is refused and does not become it,
  while the path still bills the next honest delta - and a jump of a year's
  sampling, which is what a backend that kept metering through a long frontend
  outage produces, is billed rather than refused. Beside them, that the same
  batch applied on four goroutines at once is billed once: two backend sessions
  is what a failover produces, and the per-batch watermark memo is a database
  read held across five hundred transactions. Then the two the bound itself got
  wrong: a frame of deltas each sitting exactly at the jump limit cannot walk
  the watermark past one jump, which is what measuring against a running
  reference allowed, and a first-contact delta on a path with no watermark is
  bounded too rather than falling back on the absolute limit, with the companion
  case pinning that a backend four years deep still bills against a fresh
  database. And that a batch interleaving three paths acks each at its own
  high-water mark, which is what the per-delta `stalled` map used to hold. Then the two the pass after that found: a
  frame of clamped deltas cannot overflow the ledger column into a SQLite REAL,
  which no per-delta bound could have prevented and which breaks every later
  read of that row; and both overflowing stamps are clamped *and named
  correctly*, `MaxInt64` as the future and `MinInt64` as the past, which a
  `time.Time` comparison gets wrong in exactly one of the two directions. Beside them, that every clamp reason reaches
  the log rather than only the last, that the reporting is throttled like every
  other peer-driven line in that file, and that `quota.Metered` saturates rather
  than wrapping, since an int64 that wraps here credits the month back.
- `web/validate_test.go` also holds the high side of the two quota multipliers,
  and it has to: the reason validate keys on `quota.MaxCalibration` and
  `quota.MaxOverheadPerPacket` is that the portal's refusal and `Metered`'s
  clamp must not drift, and without a test here loosening either leaves the
  suite green. The clamp's own boundary still saves, so the message cannot be
  reached by a value the clamp would have left alone, and a NaN calibration is
  refused rather than saved: every ordered comparison is false for it, so it
  slips past the low check and the high one alike and is then silently turned
  into 100 by the clamp. Nothing can deliver one today - JSON has no NaN
  literal, so neither a PUT body nor the stored blob decodes into one, and
  `json.Marshal` refuses to write one - and the guard is kept for the shape of
  the comparison rather than for a reachable input, which is what the next float
  bound added beside it will inherit.
  The backdated case anchors its stamp an hour before the current period's own
  boundary rather than reaching a fixed span into the past, so it is a
  different billing period without sitting on the age bound and becoming a
  question about the calendar.
- `sysx/forward_test.go` - the Docker forward exceptions widen when the overlay
  subnet is set, leave an already-correct chain alone, and never touch a rule
  they do not own. Also that the prefix is re-parsed before it is handed to
  `nft`: a value carrying a second rule, a bare address or the wrong family is
  refused with nothing inserted, while one that is a network written untidily is
  normalised and installed. nft joins its own argv and re-lexes it, so a
  separate argv element is not the protection it looks like.
- `model/bootstrap_test.go` - an address that is present but is not an address
  is refused at load: a hostname, a typo, a network where an address belongs.
  And the narrower rule the generators actually impose: an address that parses
  but is not IPv4 is refused too, for the overlay pair and the linker pair
  alike, because that one used to pass and then render nothing; a subnet
  carrying host bits is masked rather than refused, since nft rejects the whole
  table over the unmasked form; and an absent subnet is still left empty, which
  is invariant 19.
  The linker's two, and the overlay pair on every role, since all of them reach
  a generator that answers an unparseable address with an empty file. A config
  naming none of them still loads on its defaults, so the check cannot become a
  reason to write them out.
- `web/linker_config_test.go` also covers the routing table: out of range,
  colliding with a table this system uses at the far end, and zero meaning the
  default.
- `engine/superseded_test.go` - the `/32` a widened route replaced is removed
  once, not repeatedly, never without a subnet, and never in observe mode.
- `engine/egresshost_test.go` - each agent receives only its own egress
  networks, and an unowned row still means the backend.
- `agent/linker_test.go` - the backend installs a route per linker, repairs one
  lost with the LAN interface, corrects one pointing at the wrong host, leaves
  an intact one alone, withdraws one that was removed, and - the one that
  guards every existing site - issues no `via` route at all when no linker is
  configured.
- `web/linker_config_test.go` - the fail-closed rules: no linkers without a
  subnet, no two on one address, none outside the subnet or colliding with the
  frontend or backend, no publishing to an address no linker holds.
- `engine/linker_push_test.go` - only enabled linkers reach the backend, and a
  site with none sends nothing.
- `agent/agent_test.go` - an overlay address the generator cannot use leaves the
  egress rules alone rather than removing them, because an empty ruleset means
  two different things and only one of them is an instruction; an empty network
  list still removes them, which is the case that branch must not break. The
  same fault reached through the other input: a push where no network survives
  the parse renders that same empty ruleset, and it leaves the rules alone too,
  while one usable entry beside a bad one is still installed. Also
  observe mode loads no nftables table: the marking
  table's file is written, `nft -f` is not run, the return-mark rule still goes
  in as plumbing, and arming loads it.
- `model/defaults_test.go` - the shipped service rows are this deployment's
  ports, and nothing in the shipped configuration is live: the
  mode is observe, no example service is enabled, backend egress is off and the
  shipped egress row is disabled. A fresh install must not publish a port or
  divert a container network because nobody deleted a row.
- `web/validate_test.go` - a path mark colliding with any of the five the system
  reserves, duplicate marks/tables, contradictory ceilings,
  unknown timezones, and a blank timezone taking the deployment's own zone
  rather than UTC, which would draw the billing boundary ten hours from where
  the carrier draws it.

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
  long after it comes back - on top of the probes needed to prove it healthy.
  Subscribing to `RTM_NEWLINK` would make it immediate, at the cost of the
  first netlink dependency in a codebase that deliberately shells out.
- Egress selection is by overlay source address (host services, via `-ip`) or by
  source network (`Egress.Sources`, for containers). There is no per-process
  selector. A host service that opens an unbound socket - a Lua `http.Fetch`, a
  workshop download - picks its source from the route to the destination and
  still leaves via pfSense, and `-ip` does not change that. Covering it would
  mean `meta skuid` or cgroup matching in an output chain, which is not built.
  The container case has the opposite property: the network match catches
  every internet-bound packet from that network, wanted or not. Only the
  destination is considered, never which process sent it.
- The reconcilers repair routes and `rp_filter`. Anything else the kernel
  attaches to an interface - a queue discipline, an nftables device set - would
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
