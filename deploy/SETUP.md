# Setting up the underlying network

The agents do not create WireGuard tunnels and do not touch pfSense. They
assume both are already correct. This document is what "correct" means.

Get this part wrong and the software will still appear to work while silently
testing the same link three times.

Everything below has been done on Debian 13 and Ubuntu 24.04 and nowhere else.
The agents shell out to `ip`, `nft`, `wg` and `sysctl` rather than using
anything distribution-specific, so another systemd distribution will most likely
work, but nobody has tried one.

---

## 1. Overlay addresses — handled for you

Both hosts carry a stable address on a dummy interface: `10.99.0.1/32` on the
frontend, `10.99.0.2/32` on the backend.

**The agents create these themselves** on every start, so there is nothing to
configure and nothing to make persistent. For reference, it is equivalent to:

```sh
ip link add dummy0 type dummy
ip addr add 10.99.0.1/32 dev dummy0
ip link set dummy0 up
```

The device name is the `overlay.device` field of the bootstrap file on each
host, in case `dummy0` is already taken. It is deliberately *not* editable in
the portal: both hosts have to agree on the overlay, and the change would have
to travel over the channel it tears down. `handlePutConfig` overwrites whatever
the client sends with the bootstrap value.

The address lives on a dummy interface rather than on a tunnel because it must
survive any tunnel going down — if it lived on `wg-nbn`, it would vanish with
the link. Failover then changes only the outgoing interface: the source and
destination addresses never move, conntrack keeps its entries, and a player's
UDP flow or a browser's TCP connection carries on after a brief stall instead
of dropping.

This is set up even in observe mode, because without it nothing can be probed
at all.

---

## 2. WireGuard tunnels

Use a **separate keypair per tunnel**. Three tunnels sharing one keypair works
but leaves you unable to revoke a single path, and makes `wg show` ambiguous.

### Backend (home) — dials out, one listen port per path

The distinct source ports are what pfSense uses to pin each tunnel to its own
WAN. They are not cosmetic.

`/etc/wireguard/wg-nbn.conf`:

```ini
[Interface]
PrivateKey = <backend nbn private key>
ListenPort = 51820
Table = off

[Peer]
PublicKey = <frontend nbn public key>
AllowedIPs = 10.99.0.1/32
Endpoint = <frontend public IP>:51820
PersistentKeepalive = 15
```

`wg-lte1.conf` is the same with `ListenPort = 51821` and `:51821`,
`wg-lte2.conf` with `ListenPort = 51822` and `:51822`.

Two settings matter:

- **`Table = off`** — without it `wg-quick` installs its own route for
  `10.99.0.1/32` and all three tunnels fight over the same destination. The
  agent owns those routes.
- **`PersistentKeepalive = 15`** — the LTE services are behind CGNAT, so the
  frontend can never initiate. Keepalive holds the NAT binding open on the two
  standby tunnels, so failing over to LTE2 costs one route change rather than a
  route change plus a fresh handshake at the worst possible moment. Two idle
  tunnels cost roughly 3 MB/month each in keepalive.

### Frontend (datacentre) — responds only

`/etc/wireguard/wg-nbn.conf`:

```ini
[Interface]
PrivateKey = <frontend nbn private key>
ListenPort = 51820
Table = off

[Peer]
PublicKey = <backend nbn public key>
AllowedIPs = 10.99.0.0/24
```

No `Endpoint`: the backend's public address is dynamic and behind CGNAT, so the
frontend learns it from the first valid handshake and updates it as it roams.

The whole overlay range rather than the backend's single address, so that adding
a second host behind the backend later needs no edit here. See below.

### AllowedIPs is not symmetric

On the **backend**, every tunnel's peer must be:

```ini
AllowedIPs = 0.0.0.0/0
```

Not `10.99.0.1/32`. `AllowedIPs` is a filter as much as a route: WireGuard
discards an inbound packet whose source is outside it, and refuses to send to a
destination outside it. Published traffic arrives carrying the *client's real
address* - that is the whole point of DNAT without SNAT - so a backend that
only allows the frontend's overlay address drops every request before it
reaches the interface, and cannot send the replies either.

The symptom is brutal to diagnose: probes and the control channel work
perfectly, because those really do come from the overlay address, so the portal
shows three healthy paths while nothing published works at all. `tcpdump` on the
backend's tunnel shows nothing, because the packet is dropped before it is ever
injected into the interface.

This is safe because `Table = off` means wg-quick installs no routes from it,
so `AllowedIPs` acts purely as the crypto filter and routing stays under the
agent's control.

On the **frontend**, use the whole overlay range:

```ini
AllowedIPs = 10.99.0.0/24
```

The narrowest value that works for a backend-only site is `10.99.0.2/32`, and
that is the more secure one — a compromised backend key then cannot present any
source address but the one. It is not the default here because of how it fails.
The day this site publishes from a second host, that `/32` silently drops every
packet for `10.99.0.3`: `AllowedIPs` is a filter in both directions, so the
frontend will not even transmit to an address outside it, nothing logs the
refusal, `wg show` looks perfect, and the tunnel carries the backend's traffic
exactly as before. The failure appears months after the file was written, in a
place nobody would think to look.

The range is private, is used by nothing but this system, and every channel
riding it is separately authenticated — a peer that could claim `10.99.0.3` is
still refused by the control server unless that address is configured and it
holds the shared key. So the wider value costs very little.

**Narrowing it is worth doing if this site will only ever have the one backend**,
and it is a two-line edit whenever you decide: set each peer to `10.99.0.2/32`
and restart the tunnels. Just note it down beside the decision, because widening
it again is the step that gets forgotten.

Enable all three on both hosts:

```sh
systemctl enable --now wg-quick@wg-nbn wg-quick@wg-lte1 wg-quick@wg-lte2
```

### Admin tunnel (frontend only)

The portal binds here, which is why there are no certificates to manage.

`/etc/wireguard/wg-admin.conf`:

```ini
[Interface]
PrivateKey = <frontend admin private key>
Address = 10.98.0.2/24
ListenPort = 51830

[Peer]
# laptop
PublicKey = <laptop public key>
AllowedIPs = 10.98.0.10/32

[Peer]
# phone
PublicKey = <phone public key>
AllowedIPs = 10.98.0.11/32
```

On the laptop or phone, `AllowedIPs = 10.98.0.2/32` routes only the portal
through the tunnel, so bringing it up does not disturb anything else.

---

## 3. pfSense

pfSense holds the three WAN links. Its only job here is to send each tunnel out
a fixed WAN and then stay out of the way.

### Policy routing rules

On the interface facing the backend, three rules — order matters, put them
above any general allow rule:

| Source | Protocol | Source port | Destination | Gateway |
|---|---|---|---|---|
| backend LAN IP | UDP | 51820 | any | `NBN_GW` |
| backend LAN IP | UDP | 51821 | any | `LTE1_GW` |
| backend LAN IP | UDP | 51822 | any | `LTE2_GW` |

Source port is under **Advanced Options → Source port range** on the rule.
Gateway is under **Advanced Options → Gateway**.

### The two settings that will bite you

**Use single gateways, never a gateway group.** If pfSense also fails traffic
over, two systems are making the same decision from different information and
they will fight. You get flapping neither one can explain.

**Stop pfSense from withdrawing the rules.** By default, when pfSense decides a
gateway is down it removes the policy-routing rules that use it, and the
traffic falls through to the default gateway. That would send the "LTE1 tunnel"
out over NBN — you would have three tunnels all riding one link, all probing
healthy, and no failover at all when NBN died.

So, for each of the three gateways in **System → Routing → Gateways**, tick
**Disable Gateway Monitoring Action**. pfSense will still show you the gateway
status, but it will not act on it.

Leave **System → Advanced → Miscellaneous → Skip rules when gateway is down**
unchecked. With it unchecked, a tunnel whose WAN is dead simply fails — which
is exactly what the probes need to see.

---

## 4. If either host runs Docker

Docker rewrites the host's packet filter, and two of its defaults interact with
this system. The agents handle both automatically - this section is here so the
behaviour is not a mystery, and so a hand-rolled equivalent can be recognised.

**On the frontend, Docker sets the FORWARD policy to drop.** Published traffic
is DNAT'd and therefore forwarded, so it is discarded no matter how correct the
routing is. nftables offers no way to override that from another table: an
accept is final only within its own chain, a drop is final everywhere. The
frontend agent therefore inserts two rules into `DOCKER-USER`, the chain Docker
publishes for exactly this purpose and never flushes:

```
ip daddr 10.99.0.2 accept
ct state established,related accept
```

They match on destination and connection state, never on source: a reply has
its source rewritten back to the public address before the forward hook sees
it, so a source match never fires. `failoverctl revert` removes them again,
identified by their comment.

**On the backend, a container on a bridge network breaks reply routing.** The
backend normally routes replies with `ip rule from 10.99.0.2 lookup 100`. That
stops working as soon as anything DNATs further, because the reply is routed
*before* its source is rewritten back to the overlay address - at that moment it
still carries the container's address, matches no rule, and leaves by the LAN
default route. The backend agent therefore also marks connections arriving from
a tunnel and restores that mark on their replies:

```
table ip failover_return {
    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;
        iifname { "wg-nbn", "wg-lte1", "wg-lte2" } ct direction original ct mark set 0x200
        ct direction reply meta mark set ct mark
    }
}
```

with `ip rule add fwmark 0x200 lookup 100` beside it. Routing by connection
survives any number of translations.

Both `ct direction` qualifiers are load-bearing, in opposite directions.

On the reply line, restoring the mark on *every* packet sends the incoming
request straight back out the tunnel it arrived on instead of to the container.

On the marking line, `ct direction original` limits the stamp to connections
whose *first* packet came from a tunnel. Without it this also stamps
connections the backend *started* down a tunnel — the egress traffic in section
5 — because their replies arrive on a tunnel too. Those replies would then be
routed by table 100 and sent back out the tunnel rather than to the container
waiting for them.

`--network host` avoids the second problem entirely, and is the better fit
anyway - the design exists to preserve real client IPs, and a bridge network
puts another NAT in front of them.

---

## 5. Backend-originated traffic — the egress feature

Off by default. Turn it on only if something on the backend has to *appear* at
the published address rather than at the house's own internet service.

The case it exists for is Source engine server registration. A server is listed
in the browser at the address Steam observes its heartbeat coming from, and
there is no way to declare a different one — deliberately, as anti-spoofing.
Without this the heartbeat leaves by pfSense and the server is advertised at the
home WAN address: no port forward behind it, changes when the service does, and
unreachable entirely while a CGNAT'd LTE path is carrying traffic. Players who
found the server through the browser would bypass the failover completely.

This is the one source NAT in the system, and it does not contradict the
DNAT-only rule. That rule is about *published* traffic, where rewriting the
source would destroy the real client address. Here the direction is reversed and
there is no client address to preserve, because there is no client.

**It is opt-in for a reason.** Everything else the backend sends from the
overlay address goes the same way, and therefore through the LTE quota during a
failover.

### On the frontend

Portal → Frontend. Set **Public interface** correctly; the default is `eth0` and
a datacentre box may well name it something else.

```sh
ip route get 1.1.1.1        # the dev it names is the public interface
```

Getting it wrong does not fail loudly — the rule simply never matches, and the
heartbeat keeps leaving by pfSense. **Public IP** is optional; left empty the
rule masquerades to whatever address the interface holds.

The rule is scoped to `oifname <public>` on purpose. Unscoped it would also
match traffic leaving down a tunnel — which is a reply on its way to a player —
and rewriting that source is exactly what the whole design forbids. It lives in
its own `failover_egress` table so the published ruleset never contains a
masquerade and the feature can be removed on its own.

### On the backend, choosing what goes

Two mechanisms, because a container cannot use the first one.

**A service running on the backend host:** bind it to the overlay address.

```sh
srcds_run -ip 10.99.0.2 ...
```

Nothing else is needed. The existing `ip rule from 10.99.0.2 lookup 100` already
puts that traffic on the active tunnel.

**A container:** it cannot bind `10.99.0.2` — the address does not exist in its
network namespace — and it cannot be matched by uid or cgroup either, because a
container's packets are *forwarded* through the host rather than locally
originated, so there is no local socket to inspect. What is left is the bridge
network's address range. Add it in the portal under **Egress → Sources**:

```sh
docker network inspect <name> -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}'
```

Be aware this catches *everything* on that network, wanted or not.

The backend then installs, for each configured network:

```
table ip failover_egress {
    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;
        ip saddr 172.18.0.0/16 meta mark set 0x300
    }
    chain postrouting {
        type nat hook postrouting priority -10; policy accept;
        ip saddr 172.18.0.0/16 oifname { "wg-nbn", "wg-lte1", "wg-lte2" } snat to 10.99.0.2
    }
}
```

with `ip rule add fwmark 0x300 lookup 100` beside it.

The two rules do two different jobs. The prerouting mark is what *diverts* the
traffic: a forwarded packet is routed after that hook, so the mark is what sends
it to table 100 instead of out to pfSense — and table 100 already tracks the
active tunnel, so this follows failover for free. The postrouting SNAT is what
makes the frontend's rule match and gives the reply somewhere to come back to;
without it the packet reaches the frontend carrying a private container address
that nothing downstream can answer.

That SNAT sits at priority `-10`, ahead of `srcnat` (100) where Docker installs
its masquerade. Allowed to run first, Docker would rewrite the source to an
address on the output interface — and the tunnels have none.

### Checking it

```sh
# backend
nft list table ip failover_egress
ip rule show | grep 0x300

# frontend
nft list table ip failover_egress
```

The portal warns if egress networks are configured while the frontend toggle is
still off, since that combination silently does nothing.

---

## 6. Verify before arming

**Handshakes on all three, from the backend:**

```sh
wg show
```

Every tunnel should show a recent handshake. If only one does, the pfSense
policy rules are not matching — check the source ports.

**Each tunnel is genuinely on its own WAN.** On pfSense, look at
**Diagnostics → States** and filter for each source port. `51820` should show
against the NBN interface, `51821` LTE1, `51822` LTE2. If two share an
interface, the rules are wrong and the whole exercise is pointless.

**Reverse-path filtering is off, on both hosts:**

```sh
sysctl net.ipv4.conf.all.rp_filter          # must be 0
```

The agents set this themselves, but a `/etc/sysctl.d/` drop-in that puts it
back to 1 or 2 will break two of the three paths and nothing will say why - the
tunnels carry no address of their own, and on such an interface even "loose"
filtering drops any packet whose reverse route names a different device. Only
one path can ever satisfy that.

**The per-path probe routing works, from the frontend once the agent has run
once:**

```sh
ip rule show
ip route show table 101
ip route get 10.99.0.2 mark 0x102
```

The last command should report `dev wg-lte1`. If it reports the active tunnel
instead, the mark rule is missing.

**End-to-end through one specific path:**

```sh
ping -I 10.99.0.1 10.99.0.2
```

---

## 7. Bootstrap files must be owned by root

Every unit runs as root but drops all but the capabilities it needs -
`CAP_NET_ADMIN` and `CAP_NET_RAW` for the two agents, `CAP_NET_ADMIN` alone
for a linker. None of them keep `CAP_DAC_OVERRIDE`, so root gets no DAC bypass
and can only read a 0600 file it genuinely owns. Copying the bootstrap file up
as an ordinary user leaves it owned by that user, and the agent restart-loops
on `permission denied` while `sudo cat` on the same file works fine.

```sh
sudo chown root:root /etc/failover/frontend.json
sudo chmod 0600 /etc/failover/frontend.json
```

The same applies to `backend.json` and, on an extra host, `linker.json`.
Annotated examples of all three are in this directory as `*.json.example`;
the install scripts write these files for you, so you only need them if you
are configuring a host by hand.

---

## 8. Rolling it out

1. Bring up all three tunnels and verify the checks above. Nothing else works
   until this does.
2. Install both agents, on their own hosts, from a clone of the repo:

   ```sh
   sudo ./deploy/install-frontend.sh                  # datacentre box
   sudo ./deploy/install-backend.sh --psk <as shown>  # box at the house
   ```

   The frontend script generates the shared secret and prints it; the backend
   needs that same value. Both are idempotent, so re-running them is also how
   you upgrade. They ship in **observe mode**: they probe, decide and log, but
   change nothing.

   Re-running to upgrade never rewrites an existing bootstrap file. If you do
   pass `--force-config` on the backend, pass `--psk` with it — the secret is
   the one thing on that host that cannot be recovered from anywhere else.
3. Log in and change the password. The first-run one is generated on first
   start and written to this host's journal in the clear, where it stays for as
   long as the journal is kept:

   ```sh
   journalctl -u failover-frontend | grep 'portal account created'
   ```

   **Settings → Portal account** changes it, and logs out every other session
   for that account. If you never wrote it down, `sudo failoverctl passwd` on
   the frontend sets a new one and prints it — it asks for no old password,
   because anyone who can run it is already root on the box.
4. Leave it for a few days. Watch the portal. You are looking for paths that
   flap, quotas that count at a plausible rate, and a decision history that
   matches what actually happened.
5. Compare the metered figures against your carrier's own portal and adjust the
   per-path **calibration %** until they agree.
6. Arm it from the portal, or `failoverctl mode armed`.

If anything goes wrong, `failoverctl revert` removes the nftables tables and
every policy route the *frontend* installed, including the egress table from
section 5. The WireGuard tunnels are untouched, because the agent never created
them.

Then, on the backend, `failover-backend -revert`. It is a separate command
because it is a separate host, and it goes second on purpose: it takes down the
reply path, and while the frontend is still armed and DNATing that breaks every
published service instantly. The requests keep arriving down the tunnel and the
replies leave by the LAN to pfSense, where the client's flow has no state. It
leaves the overlay address in place, because a service may still be bound to it.

Neither command is a teardown of the tunnels, and neither needs to be undone:
restarting the agent reinstalls everything.

Extra hosts behind the backend, if you have any, come last — after the two
agents above are armed and working. See section 10.

---

## 9. Optional: choosing the fallback by measurement

Selection is **priority** by default: when the preferred path is out, traffic
goes to the next one down the list. Switching Portal → Failover → Selection to
**quality** changes exactly one thing — the replacement is then the
best-*measuring* eligible path rather than simply the next one down. A clean
LTE2 beats an LTE1 dropping one packet in ten.

It is deliberately not "always pick the best path". While the preferred path is
usable it keeps the traffic whatever the numbers say, and it wins the traffic
back on its clean streak alone. Priority order here is the **cost** order — NBN
is unmetered, the LTE services are capped — and LTE frequently measures better
than a congested fixed line. A selector that simply chased the lowest score
would park traffic on a metered link indefinitely and report itself as
optimising.

The score is milliseconds-equivalent:

```
loss% × LossWeight + rtt × RTTWeight + jitter × JitterWeight
```

Shipped weights are `25 / 1 / 3`. Loss is weighted heavily because for a game
server a clean 60ms link genuinely beats a lossy 30ms one. A flawless path
scores zero and cannot be displaced.

Three dampers govern a move between two working fallbacks, and none of them is
optional:

| Setting | Default | What it prevents |
|---|---|---|
| **Margin %** | 25 | Two similar links trading places on measurement noise. Because it applies in both directions there is a dead zone, not a threshold: A→B needs `score(B) < 0.75 × score(A)` and the move back needs the mirror image, and both cannot hold at once. |
| **Hold-down** | 90s | A momentary lead counting as a verdict. Timed against the *active path being beaten*, not against a particular challenger, so two candidates alternating for the lead cannot restart the clock forever. |
| **Min dwell** | 300s | A *genuine* alternation — a carrier working on a tower — moving traffic every hold-down for as long as it lasts. Every move is a visible freeze for connected players. |

None of the three ever delays leaving a path that has become unusable, nor a
failback to the preferred path. They apply only to a choice between two
fallbacks that both work.

Worth watching in observe mode for a while before arming: the decision history
shows what quality selection *would* have done, at no cost.

---

## 10. Optional: publishing from more than one host

**Skip this section unless a site needs it.** Most do not. The default is one
backend at the far end of the tunnels, and everything below is off until you
deliberately turn it on — a site that never sets `overlay.subnet` generates
byte-identical rules and routes to one that has never heard of the feature.

Use it when the boxes doing the work are not the box terminating the tunnels: a
small dedicated backend that only routes, with the game servers and the websites
on separate machines behind it, chosen for their own CPUs.

### The addressing

Each extra host gets its own overlay address on its own `dummy0` — `10.99.0.3`,
`10.99.0.4`, and so on — and the range gets a name:

```json
"overlay": {
  "frontend_ip": "10.99.0.1",
  "backend_ip": "10.99.0.2",
  "subnet": "10.99.0.0/24"
}
```

Set it identically in **both** bootstrap files. It is bootstrap-owned rather
than portal-editable for the same reason as the addresses themselves: both ends
have to agree, and the change would have to travel over the channel it tears
down.

Setting it changes two things on the frontend. It routes the whole range down
the active tunnel instead of the backend's `/32`, and its egress source NAT and
`DOCKER-USER` exceptions cover the range rather than the single address.

### Check AllowedIPs on the frontend before going further

Every one of the frontend's peers needs to cover the range:

```sh
wg show wg-nbn  allowed-ips
wg show wg-lte1 allowed-ips
wg show wg-lte2 allowed-ips
```

Each must list `10.99.0.0/24`, which is what section 2 sets up. If one still
says `10.99.0.2/32` — an older install, or a host that was deliberately
hardened — widen it and restart that tunnel, because `AllowedIPs` is a filter as
well as a route and the frontend will not even transmit to `10.99.0.3` through a
peer that excludes it. Nothing reports the refusal: the tunnel keeps carrying
the backend's traffic perfectly, and only the linker is unreachable.

The backend side is already `0.0.0.0/0` and needs no change.

The subnet is still opt-in rather than derived, for the reason in section 2's
note: it widens the route the frontend installs, and a site with one host at the
far end should not have a range routed down its tunnel for no reason.

### Publishing a service to one of them

In the portal, **Published services** now has a **Published to** column. Leave it
blank and the service goes to the backend, which is what every service did
before and what most still do. Put an overlay address in it and the frontend
DNATs that port there instead.

Nothing else changes: still destination NAT only, still no source rewriting, so
the far host sees real client IPs. And because each host has its own address,
two of them can both listen on 27015 with nothing to translate.

The portal rejects a target outside the overlay subnet, and rejects one at all
if no subnet is configured — a DNAT to an address the frontend cannot route
would swallow every request, and a published port that accepts nothing looks
exactly like the service being down at the far end.

### Egress networks belong to one host

**Backend networks routed out through the frontend** now has an **On host**
column. Leave it blank for the backend.

Fill it in for anything else, because Docker uses the same bridge subnets on
every machine — `172.17.0.0/16` is the default everywhere, and the allocator
walks `172.18`, `172.19` and so on in the same order on each one. A row with no
owner is sent to every agent, so one entry would pull containers onto the tunnel
on hosts it was never meant to touch, silently, and through the LTE quota.

The same network on two different hosts is normal and allowed. The same network
twice on one host is rejected.

### Installing the agent on the extra host

Each extra host runs `failover-linker`. It holds the overlay address, routes
anything sent from it to the backend, and does nothing else — no tunnels, no
probes, no decisions.

```sh
sudo ./deploy/install-linker.sh --psk <the frontend's psk> \
     --overlay-ip 10.99.0.3 --backend-lan 192.168.1.2
```

Or paste the config the portal generated for this host into
`/etc/failover/linker.json` and start the unit — the installer is doing the same
thing with a little more checking.

`--backend-lan` is the backend's address on **this** network, not its overlay
address: overlay traffic reaches the backend as a neighbour on the LAN, and the
backend is what puts it on a tunnel. The installer rejects the overlay address
there, because the two names invite the mistake.

It installs exactly two things, which are the mirror of what the backend
installs for itself:

```sh
ip rule  add from 10.99.0.3 lookup 200
ip route replace default via 192.168.1.2 table 200
```

Check them with `ip rule show | grep 10.99.0.3` and `ip route show table 200`.

There is no observe mode and none is needed. Only packets sourced from the
overlay address match that rule, and nothing on the box uses that address unless
a service was deliberately bound to it — so until something opts in, the rules
are inert. What actually directs traffic to this host is the frontend's DNAT,
which has its own observe mode.

`failover-linker -revert` removes both rules and deliberately leaves the overlay
address in place, so anything bound to it keeps listening.

### Declare the linker in the portal first

**Settings → Linkers.** Fill in the backend's address on that network once, then
add a row per extra host: a name, its overlay address (`10.99.0.3`), its LAN
address (`10.1.1.4`), and the routing table it should use.

**Check the table before accepting the default.** It is 200 unless you change
it, and that number belongs to the host's own namespace, not to this system. A
machine that already policy-routes — a second ISP, a VPN — may well be using it,
and two systems writing one table fight over its default route: the loser's
traffic goes somewhere nobody intended, silently. On the host:

```sh
ip rule show
cat /etc/iproute2/rt_tables
```

Anything listed there is taken. Pick a free number and set it in the row. It must
also appear in that host's `linker.json` — the rule it names is what carries the
control connection, so the agent needs it before it can be told anything. The
generated config below has it, and the dashboard warns if the host reports using
a different one.

That row is what tells the backend how to reach it. Saving pushes the list down
the existing control channel, and the backend agent installs
`ip route replace 10.99.0.3/32 via 10.1.1.4` and reconciles it every 10s like
every other route it owns. **Nothing has to be run on the backend by hand**, and
nothing is lost at a reboot.

Without that row the frontend would DNAT a published port to `10.99.0.3`, the
packet would arrive at the backend, and the backend would have nowhere to send
it — the service timing out with nothing in any log to say why. So the portal
refuses to publish a service to an address no linker holds, rather than letting
you build that silence.

Unticking a linker withdraws its route as well as its publishing, so taking a
host out of service is one checkbox.

The section also generates that host's `/etc/failover/linker.json`, ready to
copy. The shared secret is deliberately left as a placeholder — the frontend
holds only the key derived from it, never the passphrase, and plumbing the raw
secret into the portal so it could be displayed would be a real downgrade for
one saved paste. Fill it in from `/etc/failover/frontend.json`.

### Binding services on the extra host

Bind to the overlay address, the same as on the backend:

```sh
srcds_run -ip 10.99.0.3 -port 27015 ...
```

That single flag does two jobs. It makes the service reachable at the address
the frontend publishes to, and it is what sends the outbound half — the
server-browser heartbeat — through the frontend's public address, provided
**Backend egress via this address** is ticked in the portal. Everything else the
box does keeps its normal route out through pfSense and never touches a tunnel.

Containers are the exception, and the reason is the same one as in section 4:
the overlay address does not exist inside a container's network namespace, so
`-ip 10.99.0.3` is not available to one.

**Publishing to a container works anyway.** Run it the way containers are
normally published — `docker run -p 80:80 …` on a bridge network — and the
linker marks the connection on the way in so the reply is routed back to the
backend even though it comes out of the container carrying a `172.x` address.
Without that marking the request arrives, the container answers, and the answer
leaves by the host's own default route: a timeout, which reads as the container
being down.

**Outbound from a container works too, with one switch.** Add the container's
bridge network under **Backend networks routed out through the frontend**, with
**On host** set to that linker's overlay address, and tick **Backend egress via
this address** in the Frontend section. Its traffic then leaves by the
frontend's public address, which is what gets a containerised game server listed
in the browser at the published address rather than the house's.

The portal refuses a network assigned to a host that is not a configured linker,
because that row would be delivered nowhere and the operator would see rules
they configured having no effect on any machine.

All of that network's internet traffic takes this route, so it counts against
the LTE quota during a failover. Give the service its own Docker network if the
bridge carries anything you would rather leave on the local service.

### What you do get in the portal

A linker dials the frontend the way the backend does, so the dashboard shows it
under **Extra hosts**: whether it is connected, its hostname and build, and how
long it has been up. A linker that is configured but has never checked in reads
as *not connected* rather than being absent, which is the difference between a
host that is down and one nobody configured.

Note what that liveness does **not** do: it never reaches the path trackers. A
game server box rebooting is not a tunnel problem, and treating it as one would
move traffic to a metered link for no reason.

Published traffic does not depend on the control channel. The backend's route to
the linker and the linker's own rules are installed and reconciled
independently, so a frontend restart does not interrupt anything already
serving.

It can still be checked from its own shell:

```sh
systemctl status failover-linker
ip rule show | grep 10.99.0.3
ip route show table 200
```

---

## 11. Rebuilding a host from scratch

Wiping a host and re-running its install script is a good way to prove the
scripts work, and the frontend carries three things a fresh install will not
give you back.

**The shared secret.** `install-frontend.sh` generates a new one when there is
no config to read. Every other host then fails authentication. Either keep the
old value and pass it back in, or reinstall every host together:

```sh
sudo grep psk /etc/failover/frontend.json      # before you wipe anything
```

**The overlay subnet**, if this site runs linkers. It is not stored anywhere but
the bootstrap files, so pass it to both agents or the frontend goes back to
routing a `/32` and every linker becomes unreachable:

```sh
sudo ./deploy/install-frontend.sh --psk <old> --subnet 10.99.0.0/24
sudo ./deploy/install-backend.sh  --psk <old> --subnet 10.99.0.0/24
```

**The database**, and this is the one that actually costs something.
`/var/lib/failover/failover.db` holds the whole configuration — services,
quotas, thresholds, selection mode, egress networks, portal users — and the
**usage ledger**. Losing the ledger resets metered-byte accounting to zero
mid-period, so both LTE paths believe they have a full month of headroom, and
the calibration percentages you spent a month tuning go with it.

```sh
sudo systemctl stop failover-frontend
sudo cp /var/lib/failover/failover.db /root/failover.db.bak
```

Restore it by copying it back before starting the new agent. If you deliberately
want a clean slate, note the calibration percentages and current usage first.

**What survives regardless:** the WireGuard configuration. The agents never
created those interfaces and no install or revert touches `/etc/wireguard`.

**One thing that will look wrong and is not.** A fresh install starts in observe
mode, and observe mode deliberately leaves existing rules in place rather than
tearing them down — so published services keep working off the nftables table
the old agent installed, while the portal says nothing is armed. That is
invariant 13 behaving correctly. Run `failoverctl revert` before wiping if you
want a genuinely bare frontend to test against, and `failover-backend -revert`
on the backend for the same reason: its reply rules and marking table survive a
disarm too.
