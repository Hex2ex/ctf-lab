# CTF Lab

A self-hosted CTF practice lab you run on your own Linux computer: **83 labs** from "first nmap scan" to real Google CTF finals, one panel to run them, progress tracking, and optional isolated VMs with a browser-based Kali.

- **Everything is optional and modular.** Start with files only (no VM, no Docker), add web labs in Docker, add KVM virtual machines later. Nothing is all-or-nothing.
- **Safe by design.** Vulnerable software never listens on your network: VMs live on an isolated virtual network; Docker mode binds every port to `127.0.0.1` and refuses to keep a lab running if it is reachable from outside.
- **Use it from anywhere.** Open the panel and a full Kali desktop in a browser from another computer, or join the lab network from your own machine over WireGuard.
- **English and Turkish** panel and docs (`EN | TR` switch). Türkçe: [README.tr.md](README.tr.md)

> **Legal / safety.** This lab contains deliberately vulnerable software and exploit practice material. Use it only on your own machine and networks. Never expose the lab (or Docker-mode apps) to the internet. See [Security model](#security-model) and [Disclaimer](#disclaimer).

---

## Contents

1. [What is inside](#what-is-inside)
2. [Choose your setup](#choose-your-setup)
3. [Requirements](#requirements)
4. [Quick start](#quick-start)
5. [Using the lab](#using-the-lab)
6. [Web Kali and remote access](#web-kali-and-remote-access)
7. [Join from your own machine (WireGuard)](#join-from-your-own-machine-wireguard)
8. [Security model](#security-model)
9. [Configuration](#configuration)
10. [Command reference](#command-reference)
11. [Troubleshooting](#troubleshooting)
12. [FAQ](#faq)
13. [Repository layout](#repository-layout) · [Contributing](#contributing) · [Credits](#credits) · [Disclaimer](#disclaimer) · [License](#license)

---

## What is inside

| Folder (created by `ctf init`) | What | Needs |
|---|---|---|
| `01-web` | 12 web apps (DVWA, bWAPP, Mutillidae, WebGoat, SQLi-Labs, Upload-Labs, DSVW, Juice Shop, DVNA, Hackazon, WrongSecrets, NodeGoat) + **Vulhub** (300+ real CVE environments) | Docker or targets VM |
| `02-linux` | 29 boot2root machines: Metasploitable 2/3, Kioptrix, Mr-Robot, DC-1…9, Stapler, Raven, Symfonos, Brainpan, Nebula… | KVM |
| `03-windows` | Metasploitable 3 (Windows Server 2008 R2) | KVM |
| `04-pwn-rev` | 4 generated crackme/pwn challenges, **ROP Emporium**, **Nightmare**, **how2heap**, plus Protostar / Phoenix / Fusion VMs | files / KVM |
| `05-crypto` | 12 generated challenges: Caesar, XOR, Vigenère, hash cracking, RSA (small e, Fermat, Wiener, Håstad), two-time pad, JWT | nothing |
| `06-forensics` | 12 generated challenges: strings, EXIF, QR, zip passwords, LSB stego, pcap, logs, deleted files, Morse, Brainfuck, layered encodings | nothing |
| `07-api` | VAmPI, DVGA (GraphQL), crAPI | Docker or targets VM |
| `08-archives` | Real competition challenges: **CTF Wiki** (118), **DownUnderCTF 2025** (64), **Google CTF 2017–2026** (344), each with an `INDEX.md` by category | files (downloaded on demand) |
| `09-custom` | CTFs you drop into `drop-here/` | depends |

Levels inside each folder are `1-easy`, `2-medium`, `3-hard`. Every lab has a `README.md` (or `LAB.md` when the upstream project ships its own README); generated challenges have `CHALLENGE.md`.

Also included: a **web panel** (start/stop/reset labs, learning notes, vulnerabilities per lab, flag submission, progress), a **flag checker** (SHA-256 hashes only; the flags are never stored), a **drop-here** folder that sets up any CTF you throw at it, a **browser Kali**, and **WireGuard** access.

---

## Choose your setup

Pick the smallest path that gives you what you want. You can add the next one at any time.

| Path | You get | You need | Commands |
|---|---|---|---|
| **A. Files only** | crypto, forensics, pwn/rev challenges, CTF archives, panel, progress tracking | Linux, Python 3, p7zip, e2fsprogs | `ctf init` |
| **B. + Web labs in Docker** | + the 15 web/API labs and Vulhub, on `127.0.0.1` only | + Docker with the compose plugin | `ctf bootstrap docker` |
| **C. + KVM virtual machines** | + 33 boot2root/pwn VMs, isolated lab network, the *targets VM* (web labs in a VM, safest), the *Kali VM*, browser Kali, WireGuard | + KVM/libvirt, ~45 GB free, 16 GB RAM recommended | `host-setup.sh`, `ctf bootstrap targets`, `ctf bootstrap kali` |

Notes:

- **In Docker mode you attack from your own computer** (browser, Burp, your own tools): the apps listen on `127.0.0.1` only, so a Kali VM cannot reach them. If you want a Kali VM to attack the web labs, use the targets VM (path C).
- **You do not need to install the Kali VM.** If you already have Kali/Parrot/anything, skip `bootstrap kali` and join the lab network with WireGuard (`ctf vpn add`).
- boot2root machines (DC-1, Metasploitable…) are complete operating systems, so they always need KVM, but neither of the two helper VMs.

---

## Requirements

Developed and tested on **Arch Linux**. Paths A and B only use common tools and should work on any Linux; path C's helper script installs packages with `pacman`. On other distributions install the equivalents yourself and run `host-setup.sh --no-packages` (package names below are best-effort and untested).

**Path A** (all paths)

| Tool | Arch | Debian / Ubuntu | Fedora |
|---|---|---|---|
| Python 3.9+ | `python` | `python3` | `python3` |
| 7z | `p7zip` | `p7zip-full` | `p7zip p7zip-plugins` |
| mkfs.ext4, debugfs | `e2fsprogs` | `e2fsprogs` | `e2fsprogs` |
| rsync, curl, git, ssh | `rsync curl git openssh` | `rsync curl git openssh-client` | `rsync curl git openssh-clients` |
| *optional* qrencode, ImageMagick, gcc | `qrencode imagemagick gcc` | `qrencode imagemagick gcc` | `qrencode ImageMagick gcc` |

**Path B:** Docker + compose plugin (`docker docker-compose` on Arch, `docker.io docker-compose-v2` on Debian/Ubuntu). Your user must be able to run `docker` (usually: be in the `docker` group). The first start of each lab downloads its image.

**Path C**

- A CPU with virtualization (Intel VT-x / AMD-V) enabled in the BIOS/UEFI, and `/dev/kvm`.
- Packages (Arch names; `host-setup.sh` installs them): `qemu-desktop libvirt virt-install virt-manager virt-viewer edk2-ovmf swtpm dnsmasq dmidecode libisoburn rsync sshpass inotify-tools caddy ttyd wireguard-tools qrencode`. Also `libarchive` (`bsdtar`) for `.ova` files.
- Disk: ~45 GB free for Kali + the targets VM. Each boot2root VM adds 1–5 GB; downloading **everything** is about 200 GB.
- RAM: the Kali VM gets up to 8 GB and the targets VM up to 8 GB (scaled down on smaller machines; see [Configuration](#configuration)). 16 GB total is comfortable, 32 GB is better when you run several VMs at once.

---

## Quick start

```bash
git clone https://github.com/Hex2ex/ctf-lab.git
cd ctf-lab
.system/bin/ctf init        # path A: generates the challenges, folders, launchers; adds `ctf` to ~/.local/bin
ctf list                    # every lab and its state
ctf panel                   # the web panel
```

> The code lives in the hidden `.system/` folder (show hidden files in your file manager: Ctrl+H). Everything works from any directory; there is nothing to configure.

**Path B, web labs in Docker**

```bash
ctf bootstrap docker
ctf start dvwa              # → http://127.0.0.1:8081   (admin / password, then open /setup.php once)
ctf stop dvwa
```

**Path C, VMs**

```bash
sudo bash .system/bin/host-setup.sh     # once: packages, firewall, lab networks, WireGuard (asks for your sudo password)
ctf bootstrap targets                   # web labs in a VM (~0.6 GB download, ~5 min)
ctf bootstrap kali                      # Kali VM (~3.6 GB download), then installs the CTF tools (takes a while)
ctf start dc1                           # a boot2root machine; its IP is reported when it is up
ctf kali                                # opens the Kali window (user kali / password kali)
```

In Kali: `nmap -sn 192.168.100.0/24`, then `nmap -sC -sV -p- <ip>`. Broke something? `ctf reset dc1` returns the VM to its first state.

`ctf bootstrap status` shows what is set up on your computer, and `ctf bootstrap` explains every option.

---

## Using the lab

### The panel

`ctf panel` (or the **Lab Panel** launcher) opens it on `http://127.0.0.1:8765` in your browser. Each lab card has **Start / Stop / Reset**, **Details** (what you will learn, the vulnerabilities, and the tasks), and, for file-based labs, **Files**. The header shows Kali, the web-lab runtime and your overall progress. The **EN | TR** button switches the language. Search understands vulnerability names: type `sql injection`, `ssrf`, `rop`…

### Flags and progress

Open **Details** on a lab and type the flag into a task's box.

| Badge | Meaning |
|---|---|
| ✓ **Verified** | The system checked the flag (generated crypto, forensics and pwn/rev challenges). Only the right flag completes the task. |
| ◐ **Claimed** | Flags of VMs and web labs are not stored anywhere, so they cannot be verified. You mark the task done yourself (with the flag or a note). Claimed tasks are counted separately and never mixed with verified ones. |

Generated challenges use the format `CTFLAB{...}`. From a terminal: `ctf info <id>`, `ctf flag <id> [task] '<flag>'`, `ctf done <id> <task> [note]`, `ctf undo <id> <task>`, `ctf progress`, `ctf solution <id>` (spoiler!). Progress is stored in `.system/progress.json`; copy that file to back it up.

> Spoilers: the generator source (`.system/bin/gen_challenges.py`) contains the solutions of the generated challenges. Don't read it until you are done.

### boot2root VMs

```bash
ctf list linux              # all Linux machines
ctf start dc1               # installs on first use (downloads and converts the image), then boots; prints the IP
ctf info dc1                # what you will learn, vulnerabilities, tasks
ctf console dc1             # VM console window
ctf compat dc1              # the VM gets no IP? tries other NIC / disk controller combinations automatically
ctf reset dc1               # back to the first state
```

`ctf install all` downloads and prepares every VM (about 36 GB of downloads).

### Real CTF archives

```bash
ctf install ctfwiki ductf25 google     # shallow clones, `.git` removed; each gets an INDEX.md listing every challenge by category
```

Browse `08-archives/*/*/INDEX.md`. Run binaries inside Kali, not on your host. `ctf sync` copies the files into Kali at `~/CTF/<category>/`.

### drop-here: add your own CTF

Drop a file or folder into `drop-here/` and the lab does the rest. Turn the background watcher on once with `ctf watch --install` (a systemd user service), or import a single item by hand with `ctf import <path>`.

| You drop | What happens |
|---|---|
| `.ova` `.vmdk` `.vdi` `.qcow2` `.iso`, or a `.zip/.7z/.rar` containing one | installed as a VM on the isolated network, started, IP reported. No IP? It tries NIC/disk combinations by itself |
| a folder or archive with `docker-compose.yml` / `Dockerfile` | built and run with Docker (VM or Docker mode, ports bound as usual) |
| a `.tar` made with `docker save` | `docker load`ed |
| anything else (pwn binary, pcap, image, zip…) | copied into Kali at `~/CTF/inbox/` |

Remove one of yours with `ctf remove custom-<name>`.

---

## Web Kali and remote access

With the Kali VM set up you can use it from a browser, on this computer or from any computer on your network.

```bash
ctf remote enable           # asks for a web password; starts the panel service, HTTPS gateway and web terminal
```

Then open **`https://<this-computer>:8443/`** and sign in as user **`ctf`** with that password. The certificate is self-signed, so the browser warns once; accept it.

| Address | What |
|---|---|
| `/` | the panel (same as locally) |
| `/kali` | the full Kali desktop (noVNC), keyboard and mouse included |
| `/term/` | a Kali terminal in the browser |
| `/files/…` | read-only download of challenge files (the **Files** button on a card) |

Everyone who connects shares the same Kali desktop. The **Desktop (web)** and **Terminal (web)** buttons in the panel start Kali first if it is off. `ctf remote status | password | disable` manage it; `ctf web-kali --open` is the shortcut.

How it works and why it is safe: a Caddy reverse proxy terminates HTTPS and requires the password; the panel itself stays bound to `127.0.0.1` and accepts proxied requests only with a secret header; Kali's VNC display listens on `127.0.0.1` only. Details in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Join from your own machine (WireGuard)

Prefer your own tools? Create a WireGuard peer and your computer joins the **lab network** directly, with no Kali VM involved.

```bash
ctf vpn add laptop          # prints the config and a QR code (also: panel → Remote access)
ctf vpn list
ctf vpn remove laptop
```

Import the config on the other machine (WireGuard app on Windows/macOS/Android/iOS, or `sudo wg-quick up ./laptop.conf` on Linux). The machine gets a lab address (`192.168.100.210–250`) and can reach every target. **Reverse shells work**, since targets can reach your peer address. Only lab traffic (`192.168.100.0/24`) goes through the tunnel; the rest of your traffic is untouched. The panel is then also at `https://192.168.100.1:8443/`.

Over the internet: forward **UDP 51820** on your router to this computer and create the peer with `CTF_VPN_ENDPOINT=<your public address> ctf vpn add laptop`. Keep the peer list short and remove peers you no longer use.

---

## Security model

| Thing | Exposure |
|---|---|
| Lab network `192.168.100.0/24` (Kali `.10`, targets `.20`, boot2root `.100–.200`, VPN peers `.210–.250`) | Isolated: no internet, no home LAN. VMs get no default gateway. The firewall (`ctf-firewall.sh`) lets them talk to each other and to VPN peers only, and reach nothing on your computer except DHCP/ping on the bridge address |
| Kali / targets internet access | A separate NAT network: internet only; the firewall blocks every private range (your LAN, hotspot, Docker networks) |
| Vulnerable web labs, VM mode | Inside the targets VM, on the isolated network |
| Vulnerable web labs, Docker mode | Every published port is rewritten to `127.0.0.1`; after each start `ctf` checks the running containers and **stops any lab reachable on all interfaces** |
| Panel | `127.0.0.1:8765`; a per-start token and a `Host` check protect it against other websites in your browser |
| HTTPS gateway (`ctf remote enable`) | `0.0.0.0:8443`, password protected, self-signed TLS. **Only this port and WireGuard (51820/udp) are meant to be reachable from other computers** |
| VPN peers | Lab network and the gateway only; they cannot reach your LAN or the internet through your computer |
| QEMU | Runs as your user, not root |

Default credentials you should know about: Kali VM `kali` / `kali` (console and auto-login; `ctf` also installs its own SSH key there); targets VM `lab` / `lab` (console only, SSH needs the key). The VMs are not reachable from outside the isolated network, but **change these if you ever change that**. The web gateway user is `ctf` with the password you chose. The vulnerable labs keep their own (public) default logins, shown in each lab's `README.md`.

Do not forward port 8443 to the internet unless you are comfortable exposing a password-protected shell into your lab; prefer WireGuard.

---

## Configuration

`.system/config.env` (created on demand; plain `KEY=value` lines):

| Key | Default | Meaning |
|---|---|---|
| `WEB_MODE` | `auto` | `vm`, `docker`, or `auto` (the targets VM if it exists, else Docker). Change with `ctf mode vm|docker|auto` |
| `KALI_TIMEZONE` | the host's | time zone for Kali and the targets VM |
| `KALI_KEYMAP` | `us` (`tr,us` on a Turkish locale) | keyboard layout in Kali; two layouts switch with Alt+Shift |
| `KALI_RAM_MB`, `KALI_VCPUS` | ⅓ of host RAM (3–8 GB), ½ of the CPUs (2–6) | Kali VM size, used when it is created |
| `TARGETS_RAM_MB`, `TARGETS_VCPUS`, `TARGETS_DISK_GB` | ⅕ of host RAM (2–8 GB), ¼ of the CPUs (2–4), 60 | targets VM size, used when it is created |
| `CTF_VPN_ENDPOINT` (environment) | this computer's LAN address | address written into new WireGuard configs |

Ports: panel `8765` (localhost), gateway `8443` (network), WireGuard `51820/udp`, Kali VNC `5910` / `5700` and web terminal `7681` (localhost only); web labs use `3000`, `4000`, `5000`, `5013`, `8025`, `8080–8091`, `8888` and `9090`.

---

## Command reference

`ctf help` prints the full list. The most useful:

| Command | What |
|---|---|
| `ctf init` · `ctf bootstrap status\|docker\|targets\|kali\|all` · `ctf mode` | set things up |
| `ctf list [category]` · `ctf status [--json]` | what exists, what runs |
| `ctf start <id> [--open]` · `stop` · `reset` · `ip` · `console` · `compat` | run labs |
| `ctf kali [start\|stop\|setup\|backup\|reset --yes]` · `ctf ssh [kali\|targets]` | the Kali VM (`backup` saves the current state as "clean"; `reset` returns to it) |
| `ctf info` · `flag` · `done` · `undo` · `progress` · `solution` | learning and progress |
| `ctf install <id>\|all` · `ctf remove custom-<name>` · `ctf import <path>` · `ctf watch` | add and remove |
| `ctf send <file…>` · `ctf sync` | move files into Kali |
| `ctf vulhub search\|read\|start\|stop` | Vulhub environments |
| `ctf remote …` · `ctf vpn …` · `ctf web-kali` | remote access |
| `ctf pull` | pre-download web-lab images |
| `ctf layout` | regenerate folders, READMEs and launchers |

---

## Troubleshooting

| Problem | Try |
|---|---|
| `ctf: command not found` | `ctf init` links it to `~/.local/bin/ctf`; add that folder to `PATH`, or run `.system/bin/ctf` |
| `ctf init` says tools are missing | install them from the [requirements](#requirements) table |
| A boot2root VM gets no IP | `ctf compat <id>`; many old VMs only boot with an IDE disk and an old NIC model |
| Old VM, SSH "no matching key exchange method" | see the `ssh -o HostKeyAlgorithms=+ssh-rsa …` line in that lab's `README.md` |
| `ctf bootstrap …` says the networks are missing | run `sudo bash .system/bin/host-setup.sh` once |
| Docker mode: "Docker is not running" | `sudo systemctl enable --now docker`; add your user to the `docker` group and log in again |
| Docker mode: "refusing: … published on ALL interfaces" | working as intended: that lab's compose file uses a port syntax the rewriter can't change. Use the targets VM for it, or open an issue |
| Web Kali: "Failed to connect to server" | Kali is off or still booting; start it (`ctf kali`, or the panel's button) and press Connect again |
| `https://…:8443` shows a certificate warning | expected (self-signed); accept it once |
| Browser can't reach `https://<ip>:8443` from another computer | `ctf remote status`; check your firewall allows 8443/tcp from the LAN |
| Kali setup stuck or failed | `ctf kali-log`; it is safe to run `ctf kali setup` again |
| A lab folder or README is missing | `ctf layout` regenerates them |

Logs live in `.system/logs/` (import log, per-VM `virt-install` output, install logs). `journalctl --user -u ctf-caddy -u ctf-panel -u ctf-ttyd` for the remote-access services.

---

## FAQ

**Do I have to install the Kali VM?** No. See [Choose your setup](#choose-your-setup): use your own machine over WireGuard (`ctf vpn add`), or attack Docker-mode labs from your host.

**Why is there a "targets" VM at all?** To keep deliberately vulnerable web apps off your host kernel and network. Docker mode trades that isolation for simplicity.

**Can I run it on Windows or macOS?** Not supported. It relies on Linux, KVM/libvirt and iptables. Paths A and B (files, Docker) can work in WSL2 or similar, but this is untested.

**Is my progress safe if I update the repository?** Yes: `progress.json`, `config.env`, your VMs and downloads are git-ignored.

**How do I add a lab?** See [Contributing](#contributing).

**Where does the vulnerable software come from?** It is downloaded when you first start a lab, from its own publisher (Docker Hub, GitHub, VulnHub, Kali and Ubuntu mirrors). This repository contains only the glue code.

**How do I remove everything?** `ctf kali stop`, `virsh -c qemu:///system undefine <ctf-…> --nvram` for each `ctf-*` domain, `ctf remote disable`, `ctf vpn remove` each peer, then delete the folder and `/usr/local/bin/ctf-*`, `/etc/systemd/system/ctf-firewall.service`, `/etc/sudoers.d/ctf-vpn`, `/etc/sysctl.d/90-ctf-lab.conf`, `/etc/wireguard/wg-ctf.*`, `/etc/polkit-1/rules.d/50-ctf-lab.rules` and `virsh net-undefine ctf-lab ctf-nat`.

---

## Repository layout

```
.system/
  bin/            ctf (the CLI), panel.py, progress.py, gen_challenges.py, gen_archive_index.py, compose_bind.py,
                  host-setup.sh, kali-setup.sh, ctf-firewall.sh, ctf-vpn-helper, helpers
  catalog/        labs.psv (the lab list), learn/{en,tr}/ (learning notes), i18n/ (panel strings, Turkish lab texts), flags.sha256
  labs/           compose files / start scripts of the web labs
  templates/      cloud-init files of the targets VM
  tests/          unit tests (no VM or network needed)
  xml/            the two libvirt network definitions
docs/ARCHITECTURE.md
```

Everything else (`0*-…` folders, `.system/vm`, downloads, logs, private keys, `config.env`, progress) is generated or private and git-ignored.

Run the tests: `python3 -I -m unittest discover -s .system/tests -v`.

## Contributing

Issues and pull requests are welcome. To add a lab:

1. Add a row to `.system/catalog/labs.psv` (format documented at the top of the file).
2. Web lab: add `.system/labs/<id>/docker-compose.yml` (or a `start.sh`/`stop.sh` pair that honours `LABS_DIR` and `LISTEN_IP`).
3. Add its learning notes in `.system/catalog/learn/en/<category>.json` **and** `…/tr/…` (same ids and order), and its Turkish name/description in `.system/catalog/i18n/tr-labs.json`. `test_catalog.py` checks all of this.
4. Run the tests, then `ctf layout`.

Please keep new text in English first; translations are welcome but optional.

## Credits

This project only automates downloading and running other people's work. All the vulnerable applications, virtual machines and challenge collections belong to their authors and keep their own licenses: DVWA, bWAPP, Mutillidae, OWASP WebGoat/Juice Shop/NodeGoat/crAPI/WrongSecrets, SQLi-Labs, Upload-Labs, Hackazon, VAmPI, DVGA, DVNA, DSVW, **Vulhub**, **VulnHub** machines (DC series, Kioptrix, Mr-Robot, Stapler, …), Rapid7 Metasploitable, Exploit Education, ROP Emporium, Nightmare, how2heap, CTF Wiki, DownUnderCTF, Google CTF, Kali Linux, Ubuntu cloud images, noVNC, Caddy, ttyd, WireGuard and libvirt/QEMU. Thank you.

## Disclaimer

This software is provided for **education and authorized testing**. It deliberately runs vulnerable software and teaches attack techniques. You are responsible for where and how you use it: attack only systems you own or have written permission to test, keep the lab off untrusted networks, and do not expose it to the internet. The authors accept no liability for damage or misuse. See the [license](LICENSE).

## License

[MIT](LICENSE). The third-party material listed under [Credits](#credits) is **not** part of this repository and is covered by its own licenses.
