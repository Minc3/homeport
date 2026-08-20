# homeport

Homeport is a traffic steering and failover system for self-hosted services
behind one or more WAN connections.

It uses WireGuard tunnels you have already configured between a cheap VPS and
your home network to give services at home a stable public address. It publishes
your ports from the VPS, measures the health of every tunnel end to end, moves
traffic to a healthy one when the current one fails, and handles the forwarding
and return-path routing that makes that work, all while preserving the client's
real IP address, on UDP as much as on TCP.

**Homeport does not configure WireGuard, pfSense, or your WAN connections.**
Those are deliberately left to you. It assumes the tunnels exist and are correct,
and steers traffic across them.

![The portal dashboard: three tunnels with live RTT, loss and jitter, the
active one marked, data used against each quota, and an extra host checked
in below](dashboard.png)

## What it is, and what it is not

**Homeport is:**

- A traffic steering and failover layer for inbound connections
- Built for self-hosted services: game servers, web apps, anything on a port
- Built around WireGuard connectivity you already have
- Able to measure real path health end to end, not just whether an interface is up
- Responsible for forwarding, return-path routing and the policy routing around it
- Aware of data caps, so a failover to a metered link does not quietly cost you money

**Homeport is not:**

- A WireGuard configuration manager
- A VPN provider
- A replacement for pfSense, or for your firewall
- A reverse proxy, or anything that terminates your traffic
- A zero-configuration "expose my homelab" tool

## The architecture

```
                            Internet
                               │
                    FRONTEND · any cheap VPS
                               │   publishes your ports, measures every
                               │   tunnel, decides which one carries traffic
          ┌────────────────────┼────────────────────┐
      wg-tunnel-1         wg-tunnel-2         wg-tunnel-3     one, or several
          └────────────────────┼────────────────────┘
                               │
                     BACKEND · your box at home
                               │   terminates the tunnels, answers probes
              ┌────────────────┴────────────────┐
           LINKER                            LINKER           optional, and
          10.99.0.3                         10.99.0.4         most setups
          game host                      web server host      have none
```

Two Go agents and a web portal, plus an optional third agent for extra hosts.
The frontend is authoritative for everything: the backend makes no decisions and
never needs to be logged into. There is no proxy, no dynamic DNS, and nothing
forwarded on your home router.

## Who this is for

Home labbers who want a public address for something they host themselves and
do not want to pay for a real server to run it on. The cheapest VPS you can find
is enough: it never touches your data, it only forwards packets. Everything that
actually needs CPU, disk or a GPU stays on the hardware you already own.

It is also for anyone whose home connection cannot accept inbound traffic at
all: CGNAT, a locked-down router, a landlord's internet. The tunnel is dialled
out from home, so nothing has to be forwarded to you.

It assumes you are comfortable configuring WireGuard yourself and reading
routing tables when something is wrong. If you want something that sets up the
tunnel for you, this is the wrong tool.

## What you need before installing

- **A VPS with a public IPv4 address.** The cheapest tier is enough.
- **A Linux box at home** to terminate the tunnels. It can also be the machine
  running your services. Most setups are exactly that.
- **WireGuard tunnels already up between the two**, one per internet connection.
  Homeport does not create them. [deploy/SETUP.md](deploy/SETUP.md) is what
  "correct" means: get it wrong and the software will appear to work while
  silently testing the same link three times.
- **A separate admin WireGuard tunnel to the VPS.** The portal binds to that
  instead of a public port, so there are no certificates and no public login.
- **If you have more than one WAN**, a router that can pin each tunnel to one
  fixed WAN. pfSense is the reference setup, and two of its settings will
  otherwise defeat the whole design. Both are in SETUP.md.
- **Root and systemd on each host**, plus `iproute2`, `nftables`, `procps`,
  `openssl` and `wireguard-tools`. Only the frontend needs `openssl`. Each
  installer checks and names anything missing before it changes a thing.
- **Debian 13 or Ubuntu 24.04.** That is what has been tested, on both ends.
  Every change to the system is made by shelling out to `ip`, `nft`, `wg` and
  `sysctl` rather than through anything distribution-specific, so another
  systemd distribution will most likely work, but that is an expectation, not a
  report. If you try one, the parts most likely to differ are the nftables
  version and whether `sch_cake` is built.
- **Go 1.25+ only if you are building from source.** The installers use a
  prebuilt binary in `build/` when there is no toolchain on the host.

## Why it routes instead of proxying

The usual way to do this is a reverse proxy on the VPS. That works for HTTP and
falls apart everywhere else: every connection arrives at your backend from the
VPS's address, so your logs, your bans and your rate limits are all useless, and
UDP is not really covered at all.

Homeport routes instead. The VPS rewrites the destination of an incoming packet
and nothing else, so your backend sees the client's real address, for UDP exactly
as much as for TCP. Nothing needs `X-Forwarded-For` and nothing needs to
understand the PROXY protocol.

That is also what makes failover invisible. Only the outgoing interface changes,
so the addresses either end of a connection never move: conntrack keeps its
entries and a player's UDP flow or a browser's TCP connection stalls for a
couple of seconds and carries on, instead of dropping.

## The pieces

**`failover-frontend`** runs on the VPS and is the only part that makes
decisions. It publishes your ports to the internet, sends them down a tunnel,
measures each tunnel end to end, and serves the portal you manage everything
from. It holds all the configuration.

**`failover-backend`** runs on the machine at home that terminates the tunnels.
It answers health probes, keeps its return routing pointing at whichever tunnel
the frontend chose, and meters usage on any connection you have marked as
metered. It makes no decisions, has no web interface, and never needs to be
logged into.

**`failover-linker`** is optional, and most setups never need it. It exists for
the case where the box terminating the tunnels is *not* the box running your
services. See below.

## Extra hosts: what a linker is for

Start without one. The backend can perfectly well be the machine that runs your
services, and if it is, you are done.

You want a linker once that stops being true. The box terminating the tunnels
might be a small always-on router or NAS, with the things you actually publish
living on other machines behind it: a game server host, a web VM, a box with the
GPU in it. The obvious fix is to forward again on the backend and demultiplex by
port, and it goes wrong quickly. A second layer of translation loses the client
IP you installed this to keep, and two machines can no longer both use port
27015.

A linker avoids both. Each extra host gets its own address on the internal
overlay (`10.99.0.3`, `10.99.0.4`) and you publish ports straight to it from
the portal. There is no second translation, no port demux, and no collisions
between hosts. Client IPs survive the extra hop, and so does failover: the
backend still owns the decision about which tunnel is live, and the linker
simply hands it everything, so it never has to agree with anyone about anything.

You configure it entirely from the frontend's portal: the name, its overlay
address, and where it sits on your LAN. The portal generates the small bootstrap
file that host needs, and the backend installs and maintains the route to it, so
nothing is ever set up by hand on the linker itself.

Adding one changes the WireGuard configuration slightly, so do it after the
other two are working and read [SETUP.md](deploy/SETUP.md) section 10 first:

```sh
sudo ./deploy/install-linker.sh --psk <the frontend's psk> \
     --overlay-ip 10.99.0.3 --backend-lan 192.168.1.2
```

## You do not need more than one tunnel

Failover is the headline feature, but it is not the reason most people will
install it. Run it with a single tunnel and you still get:

- **Real client IPs** at the backend, on UDP and TCP alike.
- **All the awkward networking handled for you.** Policy routing, reverse-path
  filtering, the return path, Docker's forward rules, the routing that breaks
  every time a tunnel restarts. The agents install all of it, read it back out
  of the kernel, and put it right when something takes it away.
- **A portal** to publish and unpublish ports, and to see whether the link is
  actually healthy rather than whether the interface is merely up.
- **Observe mode**, so you can watch it decide for a few days before you let it
  touch anything.

Add a second connection later and the failover starts working. Nothing about the
single-tunnel setup changes.

## Quick start

Read [deploy/SETUP.md](deploy/SETUP.md) first. The agents assume the WireGuard
tunnels already exist, and if you are routing them through pfSense there are two
settings that will silently defeat the whole design.

On the VPS:

```sh
sudo ./deploy/install-frontend.sh
```

It prints a shared secret, the portal address and a one-time admin password.
Then at home:

```sh
sudo ./deploy/install-backend.sh --psk <the value it printed>
```

Both start in **observe mode**: they probe, decide and log, and change nothing
until you arm them from the portal. Both are safe to re-run, which is how you
upgrade.

## Building from source

To build you need **Go 1.25 or newer** and `git`. Debian 13 ships `golang-go`
1.24, which is older than the `go` line in `go.mod` and will refuse the build.
Take the tarball from [go.dev/dl](https://go.dev/dl/), or build on another
machine and copy the tree across. The installers use a prebuilt binary in
`build/` when there is no toolchain on the host, so a box that only ever
receives artefacts is a supported case rather than a workaround.

One command builds all four binaries into `build/`:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -ldflags="-s -w -X main.version=$(git describe --tags --always --dirty 2>/dev/null || echo dev)" \
  -o build/ ./cmd/...
```

`CGO_ENABLED=0` is not optional: the only dependency is `modernc.org/sqlite`,
which is pure Go, and keeping cgo off is what makes the binaries static and
independent of the target's libc. The trailing slash on `-o build/` is what lets
one invocation write several binaries, each named after its directory under
`cmd/`.

`make build` does the same for the three binaries every site runs. It leaves out
`failover-linker` deliberately, because most deployments have no extra hosts and
building it by default invites installing it by default. The command above
includes it, which costs nothing so long as you only copy it to a host that
really is a linker.

### Packages on the hosts

The agents shell out to ordinary system commands, so what they need is what
those commands come in. On the frontend:

```sh
apt install iproute2 nftables procps openssl wireguard-tools
```

The backend and any linker need the same minus `openssl`, which only the
frontend uses, to generate the shared secret and the first-run password.
`procps` is there for `sysctl` and `wireguard-tools` for `wg`; `systemd` is
assumed. Each installer checks for these before it changes anything and names
the missing ones.

The tunnels themselves are yours to create and are not installed here; see
[deploy/SETUP.md](deploy/SETUP.md). If you want traffic shaping, the `sch_cake`
module must load (`modprobe sch_cake`); it is in Debian's stock kernel. Leaving
shaping unconfigured runs no `tc` at all, so a kernel without it is only a
problem if you ask for the feature.

## Documentation

- **[REFERENCE.md](REFERENCE.md)** covers the full detail: how failover stays
  invisible, how health is measured, the selection policy, data quotas,
  outbound traffic, multi-host setups, the CLI and the safety behaviour.
- **[deploy/SETUP.md](deploy/SETUP.md)** is installation start to finish:
  WireGuard, pfSense, the portal, arming it.
- **[deploy/LINKER-NOTES.md](deploy/LINKER-NOTES.md)** holds field notes from
  the first multi-host deployment, and how to debug that path.
- **[CLAUDE.md](CLAUDE.md)** has the design reasoning, the invariants and the
  traps. Read it before changing the code.
