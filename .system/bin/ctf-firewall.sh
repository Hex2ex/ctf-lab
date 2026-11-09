#!/bin/sh
# CTF-Lab: firewall rules for the libvirt bridges (virbr-ctf, virbr-ctfnat) and the WireGuard interface (wg-ctf).
# - Lets lab traffic through despite Docker's FORWARD DROP policy, and isolates it even when Docker is absent.
# - The NAT network (Kali/targets) only reaches the internet; never the home LAN/hotspot/Docker networks.
# - Lab VMs cannot reach services on this machine; only DHCP/DNS/ping.
# - WireGuard peers reach the lab network and the panel (8443) only; not the LAN, not the internet.
# Rules live in CTF-LAB-* chains and are rebuilt from scratch on every run (idempotent).

for IPT in iptables ip6tables; do
  command -v "$IPT" >/dev/null 2>&1 || continue

  # --- INPUT: lab -> this machine ---
  $IPT -N CTF-LAB-IN 2>/dev/null || $IPT -F CTF-LAB-IN
  $IPT -A CTF-LAB-IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  if [ "$IPT" = iptables ]; then
    # DHCP/DNS/ping only to the bridge's own address (or DHCP broadcast); not to the host's other IPs
    for DST in 192.168.100.1 192.168.150.1 255.255.255.255; do
      $IPT -A CTF-LAB-IN -d "$DST" -p udp -m multiport --dports 53,67 -j ACCEPT
      $IPT -A CTF-LAB-IN -d "$DST" -p tcp --dport 53 -j ACCEPT
      $IPT -A CTF-LAB-IN -d "$DST" -p icmp -j ACCEPT
    done
  else
    $IPT -A CTF-LAB-IN -p ipv6-icmp -j ACCEPT
    $IPT -A CTF-LAB-IN -p udp --dport 547 -j ACCEPT
  fi
  $IPT -A CTF-LAB-IN -j DROP
  $IPT -C INPUT -i virbr-ctf+ -j CTF-LAB-IN 2>/dev/null || $IPT -I INPUT 1 -i virbr-ctf+ -j CTF-LAB-IN

  # --- INPUT: WireGuard peers -> this machine (panel/web Kali on 8443 and ping only) ---
  $IPT -N CTF-WG-IN 2>/dev/null || $IPT -F CTF-WG-IN
  $IPT -A CTF-WG-IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  $IPT -A CTF-WG-IN -p tcp --dport 8443 -j ACCEPT
  if [ "$IPT" = iptables ]; then $IPT -A CTF-WG-IN -p icmp -j ACCEPT; else $IPT -A CTF-WG-IN -p ipv6-icmp -j ACCEPT; fi
  $IPT -A CTF-WG-IN -j DROP
  $IPT -C INPUT -i wg-ctf -j CTF-WG-IN 2>/dev/null || $IPT -I INPUT 1 -i wg-ctf -j CTF-WG-IN

  # --- FORWARD (IPv4 only); hooked into FORWARD itself and into DOCKER-USER ---
  if [ "$IPT" = ip6tables ]; then
    $IPT -C FORWARD -i wg-ctf -j DROP 2>/dev/null || $IPT -I FORWARD 1 -i wg-ctf -j DROP
    continue
  fi
  $IPT -N CTF-LAB-FWD 2>/dev/null || $IPT -F CTF-LAB-FWD
  # NAT network: no private/LAN destinations; the rest (internet) is allowed
  for NET in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10; do
    $IPT -A CTF-LAB-FWD -i virbr-ctfnat -d "$NET" -j DROP
  done
  $IPT -A CTF-LAB-FWD -i virbr-ctfnat -j ACCEPT
  $IPT -A CTF-LAB-FWD -o virbr-ctfnat -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  # Isolated lab network: only inside itself (bridged traffic lands here because of br_netfilter) ...
  $IPT -A CTF-LAB-FWD -i virbr-ctf -o virbr-ctf -j ACCEPT
  # ... and to/from WireGuard peers (reverse shells to a peer work too)
  $IPT -A CTF-LAB-FWD -i wg-ctf -o virbr-ctf -d 192.168.100.0/24 -j ACCEPT
  $IPT -A CTF-LAB-FWD -i virbr-ctf -o wg-ctf -s 192.168.100.0/24 -j ACCEPT
  $IPT -A CTF-LAB-FWD -i wg-ctf -j DROP
  $IPT -A CTF-LAB-FWD -o wg-ctf -j DROP
  $IPT -A CTF-LAB-FWD -i virbr-ctf -j DROP
  $IPT -A CTF-LAB-FWD -o virbr-ctf -j DROP
  $IPT -C FORWARD -j CTF-LAB-FWD 2>/dev/null || $IPT -I FORWARD 1 -j CTF-LAB-FWD
  $IPT -N DOCKER-USER 2>/dev/null || true
  $IPT -C DOCKER-USER -j CTF-LAB-FWD 2>/dev/null || $IPT -I DOCKER-USER 1 -j CTF-LAB-FWD
done
# WireGuard peers live inside 192.168.100.0/24: the host answers ARP for them on the lab bridge
[ -d /proc/sys/net/ipv4/conf/virbr-ctf ] && sysctl -qw net.ipv4.conf.virbr-ctf.proxy_arp=1
exit 0
