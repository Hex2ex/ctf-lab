# Online CTF / practice platforms

The Kali VM has internet access, so you can connect to these directly from inside Kali
(for the ones that need a VPN, run `sudo openvpn file.ovpn`; the VPN traffic stays inside Kali).

| Platform | What for | Level |
|---|---|---|
| OverTheWire — Bandit, Natas, Leviathan… (overthewire.org/wargames) | Linux and web basics over SSH | Easy |
| picoCTF / picoGym (picoctf.org) | Teaching challenges in every category | Easy → Medium |
| TryHackMe (tryhackme.com) | Guided rooms, OpenVPN | Easy → Medium |
| PortSwigger Web Security Academy (portswigger.net/web-security) | Web vulnerabilities, excellent labs (with Burp) | Easy → Hard |
| CryptoHack (cryptohack.org) | Cryptography | Easy → Hard |
| HackTheBox (hackthebox.com) | Machines and challenges, OpenVPN | Medium → Hard |
| pwn.college (pwn.college) | Binary exploitation / systems security curriculum | Easy → Hard |
| Root-Me (root-me.org) | Mixed challenges | Every level |

Do **not** expose the vulnerable lab itself to an outside network: only the HTTPS entry point (8443, password-protected)
and WireGuard (51820/udp) are meant to be reachable from other computers. See README.md → "Using the lab from other computers".
