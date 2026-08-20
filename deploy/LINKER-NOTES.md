# Linker bring-up: what happened, and where it stands

Working notes from the first real linker deployment, 2026-08-19/20. Read this
before touching `internal/linker`, `sysx/linker.go`, or anything about extra
hosts. `CLAUDE.md` has the design reasoning; this is the field record — what
broke, in what order, and what it looked like at the time.

The theme is worth stating once, because every fault here shared it: **on this
path, nothing announces itself.** A misrouted reply, a dropped forward, a rule
that lost a race — all of them present as a timeout, and a timeout reads as
"the far host is down". The far host was almost never down.

---

## The site

| | |
|---|---|
| frontend | `dedi`, public `51.161.196.207`, overlay `10.99.0.1`, public iface `eno1` |
| backend | `debian`, overlay `10.99.0.2`, LAN `10.1.1.3` |
| linker | `flux`, overlay `10.99.0.3`, LAN `10.1.1.4`, LAN iface `br0`, table **220** |
| overlay subnet | `10.99.0.0/24`, set in both bootstrap files |

`flux` runs Docker and a llama-server on `:8088`, and — this matters — already
policy-routed for a second ISP before any of this existed.

---

## Where it stands

Working and verified end to end:

- Backend's route to the linker, installed from the portal row and reconciled.
- Publishing to a **host** service bound to `10.99.0.3`.
- Publishing to a **container** on a bridge network with `-p`.
- Container egress SNAT to the overlay address (verified on a real kernel with
  Docker's own masquerade in place).
- Stale-rule cleanup, table configurability, alias-proof readbacks.

**The control channel fault is found and fixed** (`baa3c1f`), but had not been
confirmed on the live site at the time of writing — deploy backend and linker and
check the portal's **Extra hosts** section. It is fault 8 below.

Because the channel had never come up, the egress networks have never actually
been pushed to `flux` in the field. The mechanism is unit-tested and verified
against a real kernel, but delivery end to end is unproven. See **Next steps**.

Note what *does* work regardless: published traffic does not depend on the
control channel at all. The backend's route and the linker's own rules are
installed and reconciled independently, which is why the site kept serving
throughout all of this.

---

## The faults, in the order they were found

Each of these cost real time. They are recorded because the next one will
probably rhyme with one of them.

### 1. `docker run -host` is not `--network host`

`-host` parses as `-h ost` — it sets the container's *hostname*. The container
ran happily on the default bridge with no published port, and `ss -lntp | grep
':80'` looked plausible because it matched `8080`, `8081`, `8088`. Nothing was
listening on 80 at all.

*Lesson:* match ports exactly — `ss -lntp '( sport = :80 )'`.

### 2. The frontend's `DOCKER-USER` rule never widened

`EnsureForwardExceptions` returned as soon as it found its own comment, so the
accept rule was written once — when the site had no overlay subnet — and never
revisited. It still said `ip daddr 10.99.0.2 accept` while the route and egress
NAT had both widened to `/24`. With Docker's `FORWARD policy drop`, traffic to
`10.99.0.3` was DNAT'd correctly, routed correctly, then dropped on the way out
of the frontend.

Fixed in `4acd1a2`: the helpers now reconcile against the *prefix*, not the
presence of the comment, and delete a stale rule by handle.

*Fingerprint:* timeout from outside; backend and linker both completely clean.

### 3. Container replies missed the source rule

A bridge container's reply comes back carrying its `172.x` address and is routed
in that state — the reverse translation has not happened yet — so
`from 10.99.0.3 lookup <table>` never matched.

Fixed in `f8fd7fc` with `BuildLinkerReturnRuleset`: mark connections *addressed
to* the overlay address at mangle priority (ahead of dstnat, so the address is
still on the packet), restore the mark on replies, route marked replies to the
linker's table. This is the backend's own trick with the discriminator changed
from "arrived on a tunnel" to "was addressed to me", because everything reaches
a linker on one interface.

### 4. `ip rule show` prints table *names*

`flux` had `200 isp2` in `/etc/iproute2/rt_tables`, so every
`strings.Contains(rules, "lookup 200")` in the package failed. The agent could
not recognise rules it had installed seconds earlier, re-added them every tick,
and logged `File exists` forever — while the rules sat in the listing in front
of it.

Fixed in `031d6c9`: `listRulesInTable` asks the kernel to filter by number. An
alias changes how a rule is *printed*, never how it is *selected*.

### 5. Table 200 was somebody else's

The deeper half of #4. `flux` was already using table 200 for its second ISP, and
the agent wrote `ip route replace default via 10.1.1.3 table 200` straight over
the operator's default route. Their `from 10.100.1.4` traffic went to the backend
instead, silently.

Fixed in `031d6c9`: `Linker.Table` in the portal row, defaulting to 200, refusing
the numbers this system uses at the far end and 253-255 outright. It must also be
in the host's bootstrap file — the rule it names carries the control channel, so
the agent cannot be told a value it needs in order to be told anything. The agent
reports back what it actually used so the two cannot drift unseen.

**`failover-linker -revert` on a shared table flushes it entirely.** On `flux`
that would have taken the operator's isp2 routes. Stop the unit instead.

### 6. A stale rule outlived the table change

Changing the table left the old build's unpinned rule behind, pointing at 200.
It was matched on source exactly like the new one and sat at **priority 0**, so
it won: everything `flux` sent from `10.99.0.3` went out the second ISP.
Published traffic was unaffected — inbound never matches a source rule — so
nothing looked wrong from outside.

Fixed in `364bdd0`: the agent reads the full rule list as well as its own
table's, and withdraws any rule for its address that is not the one it wants.
Deletion carries the full selector and the table token exactly as printed —
`ip rule del pref 0` alone matches the *local* table's rule, which shares that
priority, and would take the host's address resolution with it. That was
verified by accident during debugging; do not shorten it.

### 7. Two hand-made leftovers from the original deployment

A `failover-egress` table (**hyphen**; the agent uses an underscore) and an
uncommented `ip saddr 10.99.0.2 accept` in `DOCKER-USER`. Neither was created or
managed by any version of this software — they were hand-applied before the
features existed. Before assuming a rule is the agent's, check for a hyphenated
or uncommented twin.

### 8. The backend bounced overlay-to-overlay traffic back down the tunnel

The one that actually broke the control channel, and the best example of the
theme. The backend's return rule matches on **source**, and once a subnet is
configured that range is the whole overlay — including the frontend. So a packet
the frontend sent to a linker arrived at the backend, matched
`from 10.99.0.0/24 lookup 100`, and was routed by a table whose default points
back down the tunnel it had just come out of. The frontend's SYN-ACK went
straight back to the frontend.

Nothing about it was visible. Published traffic was untouched — a client's source
is a public address, so it never matches the return rule and is forwarded to the
linker normally. Every published service kept working while the only thing broken
was overlay hosts talking to *each other*, which in practice is exactly the
control channel. Routing looked correct at every hop on every host, because
individually it was: the fault only exists in the combination.

Fixed in `baa3c1f`: one rule sending overlay-destined traffic to `main`,
immediately ahead of the source rules it is an exception to. The main table
already knows how to reach every overlay host — the backend's own address is
local, the frontend is out the active tunnel, each linker is a neighbour — so the
fix is simply to let it answer.

The command that shows it, run on the backend:

```sh
ip route get 10.99.0.3 from 10.99.0.1 iif <tunnel>
```

Answering with the tunnel rather than the LAN is the bug. This is the single most
useful diagnostic on this path, because it asks the kernel the forwarding
question directly instead of inferring it from a failed connection.

---

## Next steps

1. **Deploy `baa3c1f` to the backend and the linker** and check the portal's
   **Extra hosts** section. `flux` should read connected, with its build and
   uptime. If it does not, the diagnostic in fault 8 is where to start.
2. **Prove egress delivery.** Add the container's bridge network under **Backend
   networks routed out through the frontend** with **On host** = `10.99.0.3`,
   confirm `nft list table ip failover_linker_egress` appears on `flux`, and
   check the address Steam sees for the game server.
3. **Confirm failover survival** with a connection held open to a service on the
   linker while forcing a path change from the portal. It should stall for a
   second or two and continue, not drop.

**Ruled out already**, so nobody repeats it: the linker's own rules; the
backend's route to the linker and its forwarding of published traffic; the
frontend's reply routing for a linker address (a reply carrying `ControlMark`
falls through table 100 to `main` and resolves correctly — verified); and the
socket's source binding.

**Still open by design:** the linker reports no usage, and its liveness must
never reach `engine/tracker.go` — a game server rebooting is not a path problem,
and treating it as one would move traffic onto a metered link.

---

## Debugging this path

One command, read-only, run on any of the three hosts — it detects the role:

```sh
sudo sh <<'EOF'
R=none; for f in frontend backend linker; do [ -f /etc/failover/$f.json ] && R=$f; done
echo "===== $(hostname)  role=$R ====="
[ "$R" != none ] && { command -v failover-$R >/dev/null && failover-$R -version; echo "service: $(systemctl is-active failover-$R 2>/dev/null)"; }
grep -Eo '"(frontend_ip|backend_ip|subnet|device|overlay_ip|backend_lan|table)"[^,}]*' /etc/failover/$R.json 2>/dev/null
ip rule show
for t in 100 101 102 103 200 220; do echo "table $t: $(ip route show table $t 2>/dev/null | tr '\n' ' ')"; done
ip -brief addr show dummy0 2>/dev/null
ip route show | grep -E '10\.99\.'
for i in $(wg show interfaces 2>/dev/null); do echo "  $i: $(wg show $i allowed-ips 2>/dev/null | awk '{$1=""; print}' | tr '\n' ' ')"; done
sysctl -n net.ipv4.conf.all.rp_filter
nft list tables 2>/dev/null
EOF
```

**Refused means something answered; timed out means something dropped.** That
distinction pointed at the right hop every single time here — it is the fastest
thing to establish before forming any other theory.

Check the full error, not the truncated one. `systemctl status` clips at
terminal width and the useful part — the command's own stderr — is at the *end*:

```sh
sudo journalctl -u failover-linker -n 30 --no-pager -o cat | grep -o '"err":"[^"]*"' | sort -u
```

Everything here was reproduced first in a network namespace with `unshare -rn`
(add `-m` and remount `/sys` when `IfaceExists` matters, or bind-mount
`/etc/iproute2/rt_tables` to test aliases). It needs no root and cannot touch
the host — it is how the container reply path, the egress SNAT ordering against
Docker's masquerade, and the table-alias fault were all confirmed before
shipping.
