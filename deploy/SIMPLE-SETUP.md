# homeport, the short version

The bare minimum: two Debian boxes, shipped defaults, nothing optional.
Every step here is explained in [SETUP.md](SETUP.md); if anything looks
arbitrary or goes wrong, switch to it.

Needs: a frontend (VPS, static public IP, root) and a backend (the house,
root). Open on the frontend: 51820-51822/udp, 51830/udp, and your service
ports.

## 1. Packages, both hosts

```sh
apt install iproute2 nftables procps openssl wireguard-tools
```

## 2. Tunnels, by hand

Keys, on each host:

```sh
umask 077; cd /etc/wireguard
for t in main lte1 lte2; do wg genkey | tee $t.key | wg pubkey > $t.pub; done
```

Backend `/etc/wireguard/wg-main.conf` (copy to `wg-lte1`/`wg-lte2` with ports
51821/51822):

```ini
[Interface]
PrivateKey = <backend main key>
ListenPort = 51820
Table = off

[Peer]
PublicKey = <frontend main pub>
AllowedIPs = 0.0.0.0/0
Endpoint = <frontend public IP>:51820
PersistentKeepalive = 15
```

Frontend `wg-main.conf` (again copy for 51821/51822):

```ini
[Interface]
PrivateKey = <frontend main key>
ListenPort = 51820
Table = off

[Peer]
PublicKey = <backend main pub>
AllowedIPs = 10.99.0.0/24
```

Frontend `wg-admin.conf`, plus a key for your laptop:

```ini
[Interface]
PrivateKey = <frontend admin key>
Address = 10.98.0.2/24
ListenPort = 51830

[Peer]
PublicKey = <laptop pub>
AllowedIPs = 10.98.0.10/32
```

Bring up: `systemctl enable --now wg-quick@wg-main wg-quick@wg-lte1
wg-quick@wg-lte2` on both, plus `wg-quick@wg-admin` on the frontend.

Do not change `Table = off`, `AllowedIPs = 0.0.0.0/0`, or the keepalive.

Check `wg show` on the backend: three recent handshakes.

## 3. Install

Frontend (admin tunnel up first: `ip -4 addr show wg-admin`):

```sh
git clone https://github.com/Minc3/homeport.git && cd homeport
sudo ./deploy/install-frontend.sh
```

Keep the three things it prints: shared secret, portal address, password.

Backend:

```sh
git clone https://github.com/Minc3/homeport.git && cd homeport
sudo ./deploy/install-backend.sh --psk <the secret>
```

Check from the frontend: `failoverctl status` shows the backend connected and
three paths probing.

## 4. Portal

Admin tunnel up on your laptop, open `http://10.98.0.2:8088`, log in, change
the password. In **Settings**: enable the service rows you actually serve,
and confirm **Frontend, Public interface**.

## 5. Arm

It starts in observe mode, measuring but changing nothing. Watch it for a few
days, verify with SETUP.md step 8, then:

```sh
failoverctl mode armed
```

Done. Quotas, shaping, protection, region locks and extra hosts: SETUP.md
steps 10-14.
