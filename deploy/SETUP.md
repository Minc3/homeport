# Installing homeport

A step by step install, start to finish. Every item here is something to do,
type or check.

Nothing here explains how the system works or why it is built this way. That is
[REFERENCE.md](../REFERENCE.md) for the behaviour and [CLAUDE.md](../CLAUDE.md)
for the internals. If a step looks arbitrary, the reason is in one of those two.

**In a hurry, on the shipped defaults, with nothing optional?**
[SIMPLE-SETUP.md](SIMPLE-SETUP.md) is the same install in a tenth of the words.
It works in the same order as this guide, so you can start there and come
back here the moment something needs checking or explaining.

Done on Debian 13 and Ubuntu 24.04. Any other systemd distribution will
probably work and has not been tried.

## Order of work

| Step | On | What |
|---|---|---|
| 1 | both hosts | Prerequisites |
| 2 | both hosts | WireGuard tunnels |
| 3 | pfSense | Pin each tunnel to its own WAN |
| 4 | frontend | Install the agent |
| 5 | backend | Install the agent |
| 6 | laptop | First login, change the password |
| 7 | portal | Publish your services |
| 8 | both hosts | Verify |
| 9 | portal | Arm it |

Steps 10 to 14 are optional features. Steps 15 to 18 are day to day operations:
updating, reverting, uninstalling, rebuilding.

Do not skip ahead to step 4. The agents assume the tunnels already exist and
will happily report three healthy paths that are all riding one link.

---

## 1. Prerequisites

### 1.1 Two hosts

| Role | Where | Needs |
|---|---|---|
| frontend | datacentre or VPS | a static public IP, root |
| backend | the house | terminates the tunnels, root |

### 1.2 Packages

On the frontend:

```sh
apt install iproute2 nftables procps openssl wireguard-tools
```

On the backend, the same list without `openssl`:

```sh
apt install iproute2 nftables procps wireguard-tools
```

The installers check for these and name anything missing before they change
anything.

### 1.3 Ports open to the frontend's public IP

| Port | Purpose |
|---|---|
| 51820, 51821, 51822 /udp | the three tunnels |
| 51830/udp | admin tunnel, for the portal |
| each service port you intend to publish | e.g. 27015/udp, 80/tcp, 443/tcp |

The probe port (51999/udp) and control port (51998/tcp) run inside the tunnels
and need nothing opened.

### 1.4 Addresses used throughout

These are the shipped defaults. Change them only if they clash with something
you already run.

| Thing | Value |
|---|---|
| Frontend overlay address | `10.99.0.1` |
| Backend overlay address | `10.99.0.2` |
| Overlay subnet | `10.99.0.0/24` |
| Admin tunnel, frontend side | `10.98.0.2/24` |
| Portal | `10.98.0.2:8088` |
| Routing tables used | 100, 101, 102, 103 |
| Firewall marks used | `0x101`, `0x102`, `0x103`, `0x200`, `0x300` |

If either host already policy routes, check those table numbers are free before
you start:

```sh
ip rule show
cat /etc/iproute2/rt_tables
```

### 1.5 Note the frontend's public interface

```sh
ip route get 1.1.1.1        # the "dev" it names is the public interface
```

Write it down. The installer detects it and asks you to confirm, and a wrong
name silently matches nothing later.

---

## 2. WireGuard tunnels

The agents never create, modify or remove tunnels. Build them by hand, here.

### 2.1 Generate one keypair per tunnel

Use a separate keypair per tunnel, on each host. Sharing one works but leaves
you unable to revoke a single path.

```sh
umask 077
cd /etc/wireguard
for t in main lte1 lte2; do wg genkey | tee $t.key | wg pubkey > $t.pub; done
```

On the frontend also generate an admin keypair, plus one keypair per phone or
laptop that will reach the portal.

### 2.2 Backend tunnel configs

`/etc/wireguard/wg-main.conf`:

```ini
[Interface]
PrivateKey = <backend main private key>
ListenPort = 51820
Table = off

[Peer]
PublicKey = <frontend main public key>
AllowedIPs = 0.0.0.0/0
Endpoint = <frontend public IP>:51820
PersistentKeepalive = 15
```

Copy it to `wg-lte1.conf` with `ListenPort = 51821` and `:51821`, and to
`wg-lte2.conf` with `ListenPort = 51822` and `:51822`.

Four things must be exactly as written:

- `Table = off`, or wg-quick installs its own routes and the three tunnels
  fight over one destination.
- `AllowedIPs = 0.0.0.0/0`, **not** the frontend's overlay address. It is a
  filter as well as a route, and published traffic arrives carrying the
  client's real IP.
- `PersistentKeepalive = 15`, because the LTE services are behind CGNAT and the
  frontend can never dial in.
- A different `ListenPort` per tunnel. pfSense pins each tunnel to a WAN by
  source port.

### 2.3 Frontend tunnel configs

`/etc/wireguard/wg-main.conf`:

```ini
[Interface]
PrivateKey = <frontend main private key>
ListenPort = 51820
Table = off

[Peer]
PublicKey = <backend main public key>
AllowedIPs = 10.99.0.0/24
```

Again copy to `wg-lte1.conf` (51821) and `wg-lte2.conf` (51822).

No `Endpoint` here: the frontend learns the backend's address from the first
handshake.

`AllowedIPs` is the whole `/24`, so that adding a host behind the backend later
needs no edit. `10.99.0.2/32` is the tighter value and is safe if this site
will only ever have one backend; note the decision down somewhere, because
widening it again is the step that gets forgotten.

### 2.4 Admin tunnel, frontend only

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

On the laptop and phone, set `AllowedIPs = 10.98.0.2/32` so bringing the tunnel
up routes only the portal and disturbs nothing else.

### 2.5 Bring them up

Frontend:

```sh
systemctl enable --now wg-quick@wg-main wg-quick@wg-lte1 wg-quick@wg-lte2 wg-quick@wg-admin
```

Backend:

```sh
systemctl enable --now wg-quick@wg-main wg-quick@wg-lte1 wg-quick@wg-lte2
```

### 2.6 Check

On the backend:

```sh
wg show
```

All three tunnels must show a recent handshake. If only one does, step 3 is not
done or its source ports are wrong.

---

## 3. pfSense

Skip this step if the backend's tunnels do not pass through pfSense. On any
other router the requirement is the same: pin each source port to a fixed WAN,
and stop the router from failing traffic over on its own.

### 3.1 Policy routing rules

On the interface facing the backend, add three rules, above any general allow
rule:

| Source | Protocol | Source port | Destination | Gateway |
|---|---|---|---|---|
| backend LAN IP | UDP | 51820 | any | `MAIN_GW` |
| backend LAN IP | UDP | 51821 | any | `LTE1_GW` |
| backend LAN IP | UDP | 51822 | any | `LTE2_GW` |

Source port is under **Advanced Options, Source port range**. Gateway is under
**Advanced Options, Gateway**.

Use a **single gateway** on each rule. Never a gateway group.

### 3.2 Stop pfSense acting on gateway status

**System, Routing, Gateways**, and for each of the three gateways tick
**Disable Gateway Monitoring Action**.

Without this, pfSense withdraws the policy rule for a gateway it thinks is
down, the traffic falls through to the default gateway, and the "LTE1 tunnel"
quietly rides the main link.

### 3.3 Leave one box unticked

**System, Advanced, Miscellaneous, Skip rules when gateway is down** must stay
unchecked.

### 3.4 Confirm each tunnel is on its own WAN

**Diagnostics, States**, filtered by source port. `51820` should show against
the main WAN, `51821` LTE1, `51822` LTE2. If two share an interface, fix
the rules before going further.

---

## 4. Install the frontend

Run this on the datacentre box.

### 4.1 Confirm the admin tunnel is up first

```sh
ip -4 addr show wg-admin        # expect 10.98.0.2
```

The installer reads the portal's listen address off this interface. With the
interface down it falls back to `127.0.0.1:8088`, which is a file edit and a
restart to correct afterwards.

### 4.2 Run the installer

```sh
git clone https://github.com/Minc3/homeport.git && cd homeport
sudo ./deploy/install-frontend.sh
```

It detects the public interface and asks you to confirm it, then prints:

- the **shared secret**, needed verbatim in step 5,
- the **portal address**,
- the **first-run password**, read back out of the journal.

Copy all three somewhere before you close the terminal.

Useful flags:

| Flag | Use |
|---|---|
| `--public-iface ens3` | give the interface outright instead of confirming |
| `--no-ask` | never prompt, take the detected value (for scripted runs) |
| `--portal 10.98.0.2:8088` | set the portal address explicitly |
| `--psk <hex>` | reuse an existing secret instead of generating one |
| `--subnet ''` | opt out of the overlay subnet |
| `--force-config` | rewrite an existing bootstrap file |

### 4.3 Check it started

```sh
systemctl status failover-frontend
failoverctl status
```

It starts in **observe mode**: it probes, decides and logs, and changes
nothing.

### 4.4 If the portal fell back to loopback

```sh
ip -4 addr show wg-admin                     # e.g. 10.98.0.2
sudo editor /etc/failover/frontend.json      # "portal_listen": "10.98.0.2:8088"
sudo systemctl restart failover-frontend
```

Re-running the installer with `--portal` will not do this for you: an existing
bootstrap file is never rewritten without `--force-config`.

---

## 5. Install the backend

Run this on the box at the house, with the secret step 4 printed.

```sh
git clone https://github.com/Minc3/homeport.git && cd homeport
sudo ./deploy/install-backend.sh --psk <the value the frontend printed>
```

Then check both ends:

```sh
systemctl status failover-backend            # on the backend
failoverctl status                           # on the frontend
```

The frontend's status should show the backend connected and three paths being
probed within a few seconds.

If it does not, the secret is the first thing to check: it must be
byte identical on both hosts.

---

## 6. First login

Bring the admin tunnel up on your laptop or phone, then open:

```
http://10.98.0.2:8088
```

Log in with the password step 4 printed, then change it immediately in
**Settings, Portal account**. It was written to the frontend's journal in the
clear and stays there as long as the journal is kept.

If you did not keep it:

```sh
journalctl -u failover-frontend | grep 'portal account created'
```

Or set a new one from the frontend's shell, which asks for no old password:

```sh
sudo failoverctl passwd
```

---

## 7. Publish your services

**Settings, Published services** ships six example rows - http 80/tcp, https
443/tcp, pterodactyl-sftp 2022/tcp, pterodactyl-wings 8080/tcp, source
27015-27030/udp and minecraft 25565/tcp - and every one of them is
**disabled**.

1. Tick the rows this site actually serves, or add your own.
2. Delete the examples you do not want.
3. Save.

Each row is a DNAT rule. Nothing is published until you tick it, and nothing
takes effect at all until step 9.

While you are here, check **Settings, Frontend, Public interface** matches what
you noted in step 1.5.

---

## 8. Verify before arming

Work through all of these. Each one has caught a real fault.

**Handshakes on all three, from the backend:**

```sh
wg show
```

**Reverse path filtering off, on both hosts:**

```sh
sysctl net.ipv4.conf.all.rp_filter          # must be 0
```

The agents set this themselves. A drop-in under `/etc/sysctl.d/` that puts it
back to 1 or 2 breaks two of the three paths and nothing says why.

**Per path probe routing, on the frontend:**

```sh
ip rule show
ip route show table 101
ip route get 10.99.0.2 mark 0x102
```

The last command must report `dev wg-lte1`. If it reports the active tunnel
instead, the mark rule is missing.

**End to end over the overlay:**

```sh
ping -I 10.99.0.1 10.99.0.2
```

**The portal agrees:** three paths probing, RTT and loss figures that look
plausible for each service, and a backend that is connected.

---

## 9. Arm it

1. Leave it in observe mode for a few days. Watch the portal for paths that
   flap, quota counters moving at a plausible rate, and a decision history that
   matches what actually happened on those links.
2. Check **Reset day** and **Timezone** on each metered path in **Settings,
   Paths** against where your carrier actually draws the billing boundary. The
   defaults are the 1st, counted in `Australia/Melbourne`.
3. Compare the metered figures against your carrier's own portal and adjust the
   per path **Calibration %** in the same table until they agree.
4. Arm it, from the portal or from the frontend's shell:

   ```sh
   failoverctl mode armed
   ```

That is the install finished. Everything below is optional or operational.

---

## 10. Optional: outbound traffic through the frontend

Turn this on only if something at the far end has to appear at the frontend's
public address rather than the house's WAN IP. The case it exists for is a
Source engine server's heartbeat, which decides the address the server browser
lists.

It is off by default because everything the backend sends from the overlay
address then goes the same way, and therefore through the LTE quota during a
failover.

### 10.1 On the frontend

**Settings, Frontend**: confirm **Public interface**, then tick **Backend
egress via this address**. **Public IP** is optional and only needed if that
interface holds several addresses.

### 10.2 Pick what goes, on the backend

**A service on the backend host:** bind it to the overlay address. Nothing else
is needed.

```sh
srcds_run -ip 10.99.0.2 ...
```

**A container:** it cannot bind an address that does not exist in its
namespace, so it is selected by its network instead. Find the subnet:

```sh
docker network inspect <name> -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}'
```

Add it under **Settings, Backend networks routed out through the frontend**,
leaving **On host** blank for the backend. A `pterodactyl` row for
`172.18.0.0/16` ships there already, disabled: tick it if that is your bridge,
correct the CIDR if it is not.

This catches every internet-bound packet from that network, so give the
service its own Docker network if the bridge carries anything else. Traffic to
private, link-local and multicast addresses - the LAN, the host, the resolver,
another bridge - is left on its normal route, because the frontend's public
address can do nothing with a private destination.

### 10.3 Check

```sh
# backend
nft list table ip failover_egress
ip rule show | grep 0x300

# frontend
nft list table ip failover_egress
```

The portal warns if networks are configured while the frontend toggle is still
off, because that combination does nothing.

---

## 11. Optional: choose the fallback by measurement

Selection is **priority** by default: when the preferred path is out, traffic
goes to the next one down the list.

**Settings, Failover, Selection**, set to **quality**. That changes one thing:
the replacement is then the best measuring eligible path rather than the next
one down. It never displaces the preferred path, and never delays leaving a
path that has failed.

Three dampers govern a move between two working fallbacks, under **Choosing
between fallbacks**:

| Setting | Default | Raise it if |
|---|---|---|
| Margin % | 25 | similar links trade places |
| Hold-down | 90s | brief leads are counting as verdicts |
| Min dwell | 300s | a genuinely alternating pair is switching too often |

Watch it in observe mode first. The decision history shows what quality
selection would have done at no cost.

---

## 12. Optional: traffic shaping

Only worth doing if latency under load is a problem. Both fields default to 0,
which runs no `tc` at all.

1. Confirm the kernel has CAKE on both hosts:

   ```sh
   modprobe sch_cake
   ```

2. Measure each link's real throughput in each direction.
3. **Settings, Paths**, per path:
   - **Down Mbit/s** is what the frontend sends into that tunnel, the house's
     download.
   - **Up Mbit/s** is what the backend sends into it, the house's upload.
4. Set each slightly **under** the measured rate. At or above it the queue
   forms in the carrier's buffer instead of ours and the setting does nothing.

---

## 13. Optional: edge protection

Rate limiting and filtering on the frontend's public interface, off by default.
It needs **Settings, Frontend, Public interface** set first; the portal refuses
to enable it otherwise.

**Settings, Protection (rate limiting and edge filtering)**, tick **Enabled**,
then set only the thresholds you want. Each is off at 0.

| Setting | Notes |
|---|---|
| New connections per second | per source |
| Concurrent connections per source | per source |
| UDP packets per second per source | per source |
| Block a tripping source for (s) | 0 means drop the packet but do not park the source |
| Drop invalid, bogus TCP flags, spoofed sources | cheap, safe to leave on |
| Drop legacy Source queries | the two dead query types (GETCHALLENGE, A2A_PING); needs a **Source engine** tick below or it drops nothing |

For a Source game port, tick **Source engine** on that service row. It limits
only connectionless packets, so it cannot touch a connected player - but a
server-browser refresh sends three A2S queries at once, so keep the limit at
10 a second or more (the presets' floor): a single-digit limit parks a player
who refreshes twice in a second, and everybody behind their carrier NAT with
them. **Ceiling pps** caps one service across every client.

Every drop is counted, and the counters show in the portal beside the parked
sources. Start loose and tighten while watching them.

### Region locks

Lock a published port to part of the world, `25565` to Oceania say. Protection
must be enabled for any of this to exist.

1. **Settings, Protection, Regions**: add a row, name it (`oceania`), enter
   ISO country codes (`au, nz`) and click **Fetch**. The frontend downloads
   the current aggregated lists into the box for you to review. Or paste
   networks by hand, one per line; `deploy/geo-zones.sh au nz` prints the same
   data offline.
2. On the service row, set **Region** to `only oceania` and save. Everything
   arriving from outside the region is now dropped before it is translated.
   The same dropdown offers `block oceania`, which is the inverse: that
   region is dropped and the rest of the world admitted.
3. Optional, instead of a permanent lock: set **Auto-lock pps** on the row.
   The port stays open to the world until its traffic exceeds that rate; the
   lock then engages in the kernel, holds while the flood lasts, and releases
   about a minute after it stops (**Auto-lock release** tunes that). Set the
   threshold above the busiest legitimate moment you have measured, because
   in-region traffic counts towards it too. Engaged locks are announced on the
   dashboard. Saving a change to the protection settings reloads the rules,
   which releases an engaged lock until the flood trips it again - like the
   counters resetting, a property of the reload. A save that leaves
   protection untouched skips the reload, so editing an unrelated setting
   mid-attack costs nothing.

It matches where an address is allocated, not where a player is: a VPN
endpoint inside the region walks straight through. It keeps a server regional
and thins a flood; it is not an access control.

After the first save that uses a lock, parse-check the generated file once:

```sh
nft -c -f /var/lib/failover/protect.nft
```

Silence is a pass. It proves this host's nft accepts every construct the lock
generates (the negated interval-set match and the dynamic port set), without
touching the kernel. The file is written in observe mode too, so this works
before arming.

### Blocklist

A threat feed in front of every published TCP port, refreshed on a timer. It
is independent of everything above: it works with protection switched off
entirely, and it lives in an nftables table of its own.

**Settings, Blocklist**, tick **Enabled** and save. It needs the public
interface set, for the same reason protection does, and it takes effect when
armed. That is the whole of the setup: the feed, FireHOL level1, is built in.

| Setting | Notes |
|---|---|
| Refresh interval (hours) | empty means 4; the feed republishes daily and the request is conditional |
| Exceptions | networks never dropped, one per line; a bare address is taken as a /32 |

What it does and deliberately does not do:

- TCP only. A false positive on a UDP game port would drop a player
  mid-match; on TCP it is a connection that does not open.
- Public interface only, like the protection chains, so it can never see a
  probe or the control channel.
- It cannot lock you out of the portal. The portal is on the admin WireGuard
  tunnel, over UDP, so no rule here is consulted for it.
- Private, reserved and carrier-grade NAT space is stripped from the feed
  before anything is loaded. A feed listing a slice of `100.64/10` would drop
  a large number of real mobile players at once.
- A failed or implausibly short fetch keeps the list that is already loaded.
  The last good copy is on disk, so a restart while the feed is unreachable
  still comes up protected.

The dashboard card shows the list size, its age, and what it has dropped. The
age is the number worth watching: a list that has stopped refreshing keeps
working and keeps dropping, so nothing else says it has gone stale.

If somebody cannot reach a service and you suspect this list, check the card
first, then add their network to **Exceptions** rather than switching the
feature off. To see whether an address is listed:

```sh
grep -w 203.0.113.7 /var/lib/failover/blocklist-feed.nft
```

Refreshing the list never touches a rule, so it resets no counter and releases
nothing the protection table is holding. Saving a change to the blocklist
settings does rebuild its table, which resets its own drop counter.

After the first save with it enabled, parse-check the generated files once:

```sh
nft -c -f /var/lib/failover/blocklist.nft
```

Silence is a pass, in the same way as for the protection file above.

---

## 14. Optional: publishing from more than one host

Skip this unless the machines doing the work are not the machine terminating
the tunnels. Each extra host runs `failover-linker`, holds its own overlay
address, and routes traffic sent from that address to the backend.

### 14.1 Confirm the overlay subnet is set on both hosts

A current install already has it. An older one has it empty, and the portal
refuses to configure a linker until both hosts agree:

```sh
sudo ./deploy/install-frontend.sh --subnet 10.99.0.0/24     # on the frontend
sudo ./deploy/install-backend.sh  --subnet 10.99.0.0/24     # on the backend
```

Each patches that one field and restarts its own agent. Both must end up with
the identical string.

### 14.2 Confirm AllowedIPs covers the range

On the frontend:

```sh
wg show wg-main  allowed-ips
wg show wg-lte1 allowed-ips
wg show wg-lte2 allowed-ips
```

Each must list `10.99.0.0/24`. If one still says `10.99.0.2/32`, widen it and
restart that tunnel, or the frontend will not transmit to `10.99.0.3` at all
and nothing will report the refusal.

The backend side is `0.0.0.0/0` already and needs no change.

### 14.3 Pick a routing table for the extra host

The default is 200, and that number belongs to the host's own namespace. On
that host:

```sh
ip rule show
cat /etc/iproute2/rt_tables
```

Anything listed is taken. Pick a free number.

### 14.4 Declare the host in the portal

**Settings, Linkers (extra hosts behind the backend)**:

1. Fill in the backend's address on that LAN, once.
2. Add a row: a name, the host's overlay address (`10.99.0.3`), its LAN address
   (`10.1.1.4`), and the table number from 14.3.
3. Save.

Saving pushes the list to the backend, which installs and reconciles the route
to that host. Nothing has to be run on the backend by hand.

### 14.5 Install the agent on the extra host

Expand **Set up &lt;name&gt;** under the Linkers table. It prints the exact
install command for that host with every value filled in, and the
`/etc/failover/linker.json` it would write for a host with no clone of the
repo. Both contain the real secret, so read before pasting.

By hand:

```sh
sudo ./deploy/install-linker.sh --psk <the frontend's psk> \
     --overlay-ip 10.99.0.3 --backend-lan 192.168.1.2 \
     --subnet 10.99.0.0/24 --table 200
```

`--backend-lan` is the backend's address on **this** network, not its overlay
address. The installer rejects the overlay address there.

Check:

```sh
ip rule show | grep 10.99.0.3
ip route show table 200
```

There is no observe mode and none is needed; the rules match only the overlay
address, which nothing uses until you bind to it.

### 14.6 Point services at it

**Settings, Published services**, set **Published to** to `10.99.0.3` on the
rows that belong to this host. Blank still means the backend. Two hosts can
both listen on 27015 with nothing to translate.

Bind the service on the extra host the same way as on the backend:

```sh
srcds_run -ip 10.99.0.3 -port 27015 ...
```

Containers cannot do that, and do not need to: publish them normally with
`docker run -p 80:80`, and the linker marks the connection so the reply routes
back. For container **outbound** traffic, add its network under **Backend
networks routed out through the frontend** with **On host** set to
`10.99.0.3`, and tick **Backend egress via this address** in the Frontend
section.

### 14.7 If the backend runs Docker

An up to date backend handles this itself. On an older one, the symptom is the
extra host being unreachable while `ip route get` answers correctly on all
three machines:

```sh
sudo nft insert rule ip filter DOCKER-USER ip daddr 10.99.0.0/24 accept
sudo nft insert rule ip filter DOCKER-USER ip saddr 10.99.0.0/24 accept
```

---

## 15. Updating a host

Re-run its install script. No arguments are needed: an existing bootstrap file
is left alone.

**Upgrade the backend first and the frontend straight after.** The wire version
is 2 and hosts do not interoperate across it, so there is a window between the
two in which the frontend measures 100% loss on every path. The order is what
decides whether the journal explains that window or misdirects you: only the
newer host can recognise the older one's probes as a version mismatch rather
than as a failed authentication. A backend upgraded first logs `dropping probes
from a different wire version; upgrade both hosts to the same build`, which is
the truth. A frontend upgraded first leaves the old backend reporting a bad
shared secret for the whole window, sending you to check the one thing that is
fine.

Three dead paths in the portal during the gap are that, not a fault, and not a
reason to reach for `revert`: the dead-man behaviour keeps the installed route
where it is and published traffic carries on over whichever tunnel was already
active. Linkers can follow at leisure - an un-upgraded one keeps routing what it
was already routing and simply receives no egress pushes until it is updated.

```sh
cd /path/to/homeport && git pull
sudo ./deploy/install-backend.sh           # box at the house, first
sudo ./deploy/install-frontend.sh          # datacentre box, straight after
sudo ./deploy/install-linker.sh            # each extra host, at leisure
```

Do not copy the binary over the running one by hand. The scripts install
alongside and rename into place, and they refresh the systemd unit, which a
hand copy skips.

From a workstation instead, without a clone on the host:

```sh
make test
make deploy-frontend FRONTEND_HOST=root@dc.example.net
make deploy-backend  BACKEND_HOST=root@home.example.net
make deploy-linker   LINKER_HOST=root@gs1        # one host at a time
```

Confirm it took:

```sh
failover-frontend -version
failover-backend -version
failover-linker -version
```

A version that has not moved usually means `build/` was stale on a host with no
Go toolchain. Refresh it with `make build linker` on a machine that has one and
commit the result.

What a restart costs: the frontend stops probing for a second or two and keeps
its installed route and rules. The backend stops answering on all three paths
at once, which produces a "no usable path" alert and leaves the route where it
was; standby paths read `down` for up to a minute afterwards while they re-earn
their recovery count. A linker costs nothing at all.

---

## 16. Reverting

Removes the routing and nftables changes, leaves the tunnels and the overlay
address alone. Restarting the agent puts everything back.

**Frontend first, with its agent running:**

```sh
failoverctl revert
```

**Then the backend, with its unit stopped:**

```sh
systemctl stop failover-backend
failover-backend -revert
```

**Then each extra host, same way:**

```sh
systemctl stop failover-linker
failover-linker -revert
```

Two rules, both load bearing:

- **That order.** Taking the backend's reply path down while the frontend is
  still armed and translating breaks every published service instantly.
- **The unit state differs by role.** The frontend's revert goes through the
  running engine and needs it up. The other two are separate processes, and a
  running agent puts back what they remove within ten seconds.

---

## 17. Uninstalling

```sh
sudo ./deploy/uninstall.sh              # frontend
sudo ./deploy/uninstall.sh              # then the backend
sudo ./deploy/uninstall.sh              # then each linker
```

Same order and for the same reason as step 16. The script works out which agent
this host runs, reverts first while the binary that knows what it installed is
still present, then removes the unit, the binaries, the bootstrap file and the
state directory. It refuses to remove anything if the revert fails.

| Flag | Effect |
|---|---|
| `--keep-config` | leave the bootstrap file, and with it the shared secret |
| `--keep-state` | leave the state directory, which on the frontend is the database |
| `--no-backup` | do not copy `failover.db` aside first |
| `--overlay` | also remove this host's overlay address |
| `--force` | continue even if the revert failed |
| `--yes` | do not ask for confirmation |

WireGuard is never touched, on any host, with any flag. Routing entries this
system did not install are never removed, so a box that already policy routes
keeps its own rules in 100, 200 and 101 to 103.

By hand, if the script is not available:

```sh
# on the backend or a linker, stop the unit first
failoverctl revert                       # or failover-{backend,linker} -revert
systemctl disable --now failover-frontend
rm /etc/systemd/system/failover-frontend.service && systemctl daemon-reload
rm /usr/local/bin/failover-frontend /usr/local/bin/failoverctl
```

---

## 18. Rebuilding a host from scratch

Before you wipe the frontend, save three things a fresh install will not give
back.

**The shared secret**, or every other host fails authentication:

```sh
sudo grep psk /etc/failover/frontend.json
```

**The database**, which holds the whole configuration and the usage ledger.
Losing the ledger resets metered accounting mid period, so both LTE paths
believe they have a full month of headroom:

```sh
sudo systemctl stop failover-frontend
sudo cp /var/lib/failover/failover.db /root/failover.db.bak
```

**The overlay subnet**, if this site runs linkers. It lives only in the
bootstrap files.

Reinstall passing the old values back:

```sh
sudo ./deploy/install-frontend.sh --psk <old> --subnet 10.99.0.0/24
sudo ./deploy/install-backend.sh  --psk <old> --subnet 10.99.0.0/24
```

Copy the database back before starting the new agent. If you want a genuinely
bare host to test against, run the reverts in step 16 **before** wiping:
observe mode deliberately leaves existing rules in place, so published services
keep working off the old agent's rules while the portal says nothing is armed.

---

## Troubleshooting

| Symptom | Check | Usual cause |
|---|---|---|
| Only one tunnel handshakes | `wg show` on the backend | pfSense source port rules (step 3.1) |
| All three paths healthy but nothing published works | `AllowedIPs` on the backend's peers | not `0.0.0.0/0` (step 2.2) |
| Two paths read 100% loss | `sysctl net.ipv4.conf.all.rp_filter` | a sysctl drop-in resetting it (step 8) |
| A path stays down after a tunnel restart | `ip route show table 101` empty | wait 10s for the reconciler; if it persists, check the agent is running |
| Probes measure the wrong tunnel | `ip route get 10.99.0.2 mark 0x102` | a duplicate fwmark or table between paths |
| All three tunnels probe healthy but never fail over | pfSense gateway monitoring | monitoring action not disabled (step 3.2) |
| Agent restart loops on permission denied | `ls -l /etc/failover/*.json` | not owned by root; `chown root:root`, `chmod 0600` |
| Portal unreachable, agent otherwise fine | `grep portal_listen /etc/failover/frontend.json` | fell back to loopback (step 4.4) |
| Rules configured in the portal do nothing | `nft list table ip failover_egress` | still in observe mode (step 9) |
| Extra host unreachable, routing correct everywhere | `iptables -S FORWARD` on the backend | Docker's drop policy (step 14.7) |
| Agent logs `File exists` for rules that are present | the table has a name in `rt_tables` | a table number this system uses is already taken (step 1.4) |
| Backend never connects; frontend logs `claimed to be the backend from an address that is not the backend's` | `grep backend_ip /etc/failover/*.json` on both hosts | `overlay.backend_ip` differs between them. The frontend serves the backend half of the control protocol only to the address it has configured, so a peer holding the shared secret cannot talk its way into it. This does not resolve itself. The frontend's copy is the authority, since it is what the DNAT rules point at and what its WireGuard peers admit, so correct the backend to match it and restart that unit. |
| Linker never connects; frontend logs `claimed an address it is not connecting from` | `grep overlay_ip /etc/failover/linker.json`, then `ip -br addr show dummy0` on that host | `linker.overlay_ip` is not the address that host actually holds, so its socket binds elsewhere. Being on the portal's Linkers list is not enough: a linker must connect from the address it claims, or one could be handed another's egress networks. |

## Reference

Bootstrap files live in `/etc/failover/{frontend,backend,linker}.json` and must
be owned by `root:root` mode `0600`. The units drop `CAP_DAC_OVERRIDE`, so root
cannot read a 0600 file it does not own, and the agent restart loops while
`sudo cat` on the same file works. Annotated examples of all three are in this
directory as `*.json.example`; the install scripts write them for you.

- [REFERENCE.md](../REFERENCE.md), how the system behaves and why
- [CLAUDE.md](../CLAUDE.md), design reasoning, invariants and traps
