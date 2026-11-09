# Architecture

How CTF Lab is put together, for people who want to change it or to judge how safe it is. User documentation is in the [README](../README.md).

## Overview

```
 your computer (host)
 ┌──────────────────────────────────────────────────────────────────────────────────────────┐
 │                                                                                          │
 │  other computers ──► Caddy :8443 (HTTPS + password) ─┬─► panel.py 127.0.0.1:8765          │
 │  (browser)                                           ├─► /kali  QEMU VNC-websocket :5700  │
 │                                                      └─► /term  ttyd :7681 ──ssh──► Kali  │
 │                                                                                          │
 │  you ──► ctf (bash CLI) ◄── panel.py runs `ctf …` for every action                       │
 │             │                                                                            │
 │             ├── docker mode ─► your Docker, ports bound to 127.0.0.1                     │
 │             └── libvirt / QEMU (runs as your user)                                       │
 │                   ├─ virbr-ctf     192.168.100.0/24  isolated, no gateway                │
 │                   │     Kali .10 · targets .20 · boot2root VMs .100-.200 · VPN peers .210-.250
 │                   └─ virbr-ctfnat  192.168.150.0/24  NAT: internet only (Kali, targets)  │
 │                                                                                          │
 │  WireGuard wg-ctf :51820/udp ──► peers appear inside 192.168.100.0/24 (proxy ARP)        │
 └──────────────────────────────────────────────────────────────────────────────────────────┘
```

The design rule: **the CLI holds all the logic.** The panel is a thin web layer that validates its input and runs `ctf <action>`; the flag checker (`progress.py`) is the only logic shared in-process by the CLI and the panel.

## Components

| Path | Role |
|---|---|
| `.system/bin/ctf` | The CLI (bash). Catalog loading, VM install/convert/define, start/stop/reset, web-lab runtime, import (`drop-here`), remote access, VPN, bootstrap |
| `.system/bin/panel.py` | Web panel. Python standard library only (`http.server`), one HTML page with inline JS, JSON API |
| `.system/bin/progress.py` | Flag verification (SHA-256) and task bookkeeping; also a small CLI (`ctf flag/done/undo/info/progress`) |
| `.system/bin/gen_challenges.py` | Deterministic generator of the crypto/forensics/pwn challenges (fixed seed); writes `flags.sha256` and `generated.psv` |
| `.system/bin/gen_archive_index.py` | Writes `INDEX.md` for each real-CTF archive |
| `.system/bin/compose_bind.py` | Docker mode: rewrites `ports:` in compose files to bind one address |
| `.system/bin/host-setup.sh` | The only script that needs root: packages, libvirt, polkit rule, firewall service, networks, WireGuard helper |
| `.system/bin/ctf-firewall.sh` | iptables rules (idempotent, rebuilt on every run) |
| `.system/bin/ctf-vpn-helper` | Root-owned, input-validating helper that `ctf vpn` calls through one `sudoers` rule |
| `.system/bin/kali-setup.sh` | Runs *inside* Kali (as root, through the QEMU guest agent) to install tools |
| `.system/catalog/` | `labs.psv` (the lab list), `learn/{en,tr}/*.json`, `i18n/*.json`, `flags.sha256`, `generated.psv` |
| `.system/labs/<id>/` | Compose file or `start.sh`/`stop.sh` of a web lab |
| `.system/templates/targets/` | cloud-init files of the targets VM |
| `.system/xml/ctf-lab.xml`, `ctf-nat.xml` | The two libvirt networks |

## Networks and firewall

| Network | Bridge | libvirt mode | Purpose |
|---|---|---|---|
| `ctf-lab` | `virbr-ctf` | `open` (libvirt adds no firewall rules) | Isolated lab network. DHCP gives **no default gateway** (`dhcp-option=3`) |
| `ctf-nat` | `virbr-ctfnat` | `nat` | Internet for Kali and the targets VM (apt, image pulls) |

`ctf-lab` is in `open` mode on purpose: libvirt's own isolated/NAT modes would also install rules and would conflict with the WireGuard peers living inside the same subnet. Instead `ctf-firewall.sh` owns the policy, in three chains:

- `CTF-LAB-IN` (INPUT, from `virbr-ctf+`): the lab can reach DHCP/DNS/ping on the bridge address and nothing else on the host.
- `CTF-WG-IN` (INPUT, from `wg-ctf`): peers reach only `8443/tcp` and ping.
- `CTF-LAB-FWD` (FORWARD, also hooked into `DOCKER-USER`): `virbr-ctf` ⇄ `virbr-ctf` and `wg-ctf` ⇄ `virbr-ctf` are accepted; everything else from or to either interface is dropped; `virbr-ctfnat` may only reach non-private addresses (so not your LAN, hotspot or Docker networks).

The jump is installed in both `FORWARD` and `DOCKER-USER`, so isolation holds with or without Docker. `net.ipv4.conf.virbr-ctf.proxy_arp=1` makes the host answer ARP for the peers' addresses, which is what lets targets treat a VPN peer as a neighbour (reverse shells work).

## The two web-lab runtimes

Web and API labs are Docker Compose projects. They run in one of two places (`WEB_MODE` in `config.env`):

| | `vm` | `docker` |
|---|---|---|
| Where | Ubuntu cloud-image VM `ctf-targets` (`192.168.100.20`), Docker inside | The host's Docker |
| Isolation | Own kernel, isolated network | Shared kernel; ports on `127.0.0.1` |
| Reached from | Kali (`http://targets:<port>`), the host, VPN peers | The host only |
| Files | rsynced to `/opt/labs/<id>` in the VM | rsynced to `.system/runtime/labs/<id>` |

All the code paths go through four small functions: `web_sh` (run a command there), `web_put` (copy the lab there), `web_up` (make sure the runtime is ready) and `web_env` (environment for start scripts). In docker mode `web_put` additionally runs `compose_bind.py` over every compose file, and replaces the VM address inside them with `127.0.0.1`.

**Fail closed.** The port rewriter cannot understand every compose syntax (variables, long form). So after every docker-mode start, `docker_exposure_check` inspects each container that belongs to the lab (identified by its compose working directory or the `ctf-lab` label, so your own containers are never touched) and **stops it if `docker port` shows `0.0.0.0` or `[::]`**. A lab that cannot be bound safely refuses to run instead of running exposed.

## Remote access

`ctf remote enable` generates `.system/remote/Caddyfile` and three systemd *user* units (`ctf-panel`, `ctf-caddy`, `ctf-ttyd`).

- **Caddy** listens on `:8443` with its internal CA, requires HTTP basic auth (user `ctf`, bcrypt hash in `.system/remote/remote.env`, mode 600), and proxies `/` to the panel, `/kali/websockify` to QEMU's built-in VNC websocket (path rewritten to `/`), `/kali/*` to the noVNC files, and `/term/*` to ttyd.
- **The panel stays on `127.0.0.1`.** Direct requests must carry a matching `Host` header (DNS-rebinding protection) and, for the API, the per-start token in `X-Token` (CSRF protection). Requests coming through Caddy are recognised by a secret `X-CTF-Proxy` header Caddy adds; the panel only honours it while remote access is enabled, then hands the page its token. `/files/…` (read-only downloads) needs the cookie set with the page when reached directly (proxied requests are already password-protected), only serves `0N-*` category folders, rejects dot-paths and re-checks `realpath` containment (symlinks cannot escape).
- **Kali's VNC** is a second `<graphics>` element listening on `127.0.0.1:5910` with the websocket on `5700`, next to SPICE (which keeps the local window working).
- **ttyd** runs `ctf-kali-shell` on the host (starts Kali if needed, then `ssh kali@192.168.100.10` with the lab key). Nothing new listens inside the guest.

## WireGuard

`ctf vpn add <name>` generates the peer's key pair, picks a free address in `192.168.100.210–250`, writes the client config, and calls `sudo ctf-vpn-helper sync` with the peer table on stdin. The helper (root-owned, `/usr/local/bin`) validates every field (names, addresses, key format, count), rewrites `/etc/wireguard/wg-ctf.conf`, and applies it with `wg syncconf` (or starts `wg-quick@wg-ctf`). The server key never leaves `/etc/wireguard`. The client config contains `AllowedIPs = 192.168.100.0/24` (a split tunnel) and the host's address as `Endpoint`.

## Data formats

**`catalog/labs.psv`**: `id | type | category | level | name | source | extra | description` (`|` separated, `#` comments). `type`: `vm`, `iso`, `docker`, `repo`, `files`, `local`, `vulhub`. `extra` is `key=value;key=value` (VM: `ram vcpu bus nic mac nic_slot nohotplug kargs fname wait static_ip kali_alias experimental login`; Docker: `port url login setup`).

**`catalog/learn/<lang>/<category>.json`**: `{ "<lab-id>": { "learn": [..], "vulns": [{"id","name","desc","task"?}], "tasks": [{"id","name"}]? } }`. Ids are language-independent and identical in `en` and `tr`; only the text differs. When a lab has no explicit `tasks`, they are derived: a lone flag, `user`+`root` for VMs, or one task per vulnerability.

**`flags.sha256`**: `<sha256>  <lab>` or `<sha256>  <lab>#<task>`; only hashes are stored.

**`progress.json`** (private): `{ "v": 2, "labs": { "<lab>": { "<task>": { "state": "verified|claimed", "t": <unix>, "note"? } } } }`, written atomically under a file lock with mode 600.

## What is private or generated (never committed)

`.system/ssh/` (lab SSH key) · `.system/remote/` (gateway password hash, proxy secret, WireGuard keys and peer configs) · `.system/logs/` (includes the panel token) · `.system/config.env` · `.system/progress.json` · `.system/vm/`, `.system/downloads/`, `.system/runtime/` · the numbered category folders · launchers.

## Non-goals

No Windows/macOS host support, no multi-user accounts (everyone behind the gateway shares one user and one Kali), no attempt to hide the lab from a determined local user on the same computer: the isolation is between the vulnerable software and your network, not between you and your own lab.
