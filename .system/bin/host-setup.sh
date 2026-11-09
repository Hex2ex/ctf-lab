#!/bin/bash
# CTF-Lab host setup — the ONLY step that needs sudo. Safe to rerun.
#   sudo bash .system/bin/host-setup.sh [--no-packages]
set -euo pipefail

[ "$EUID" -eq 0 ] || { echo "Run this script with sudo:  sudo bash $0"; exit 1; }
LABUSER="${SUDO_USER:-}"
[ -n "$LABUSER" ] && [ "$LABUSER" != root ] || { echo "Run it with sudo from your normal user (not as root)."; exit 1; }
SYS="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
export LIBVIRT_DEFAULT_URI=qemu:///system

step "1/8  Packages (QEMU/KVM + libvirt + virt-manager, Caddy, ttyd, WireGuard)"
PKGS="qemu-desktop libvirt virt-install virt-manager virt-viewer edk2-ovmf swtpm dnsmasq dmidecode libisoburn rsync sshpass inotify-tools caddy ttyd wireguard-tools qrencode"
if [ "${1:-}" = --no-packages ]; then
  echo "  skipped (--no-packages): install the equivalents of these yourself first: $PKGS"
elif command -v pacman >/dev/null 2>&1; then
  pacman -S --needed --noconfirm $PKGS
else
  echo "This script installs packages with pacman (Arch Linux). On another distribution install the equivalents of:"
  echo "  $PKGS"
  echo "then run:  sudo bash $0 --no-packages   (see README → Requirements for Debian/Ubuntu and Fedora package names)"
  exit 1
fi

step "2/8  QEMU VMs run as '$LABUSER' (not root)"
if ! grep -q '^# CTF-Lab' /etc/libvirt/qemu.conf; then
  cat >> /etc/libvirt/qemu.conf <<EOF

# CTF-Lab: VMs run as an unprivileged user (even if a vulnerable VM escapes, it is not root)
user = "$LABUSER"
group = "kvm"
EOF
fi

step "3/8  libvirt services"
if systemctl list-unit-files 'virtqemud.socket' 2>/dev/null | grep -q virtqemud; then
  # modular libvirt (newer versions)
  for s in virtqemud virtnetworkd virtstoraged virtnodedevd virtsecretd virtinterfaced virtlogd virtlockd; do
    systemctl enable --now "$s.socket" 2>/dev/null || systemctl enable "$s.socket" 2>/dev/null || true
  done
  systemctl enable --now virtqemud.service virtnetworkd.service virtstoraged.service 2>/dev/null || true
else
  systemctl enable --now virtlogd.socket libvirtd.service
fi
usermod -aG libvirt,kvm "$LABUSER"

step "4/8  polkit: '$LABUSER' manages VMs without a password (no re-login needed)"
cat > /etc/polkit-1/rules.d/50-ctf-lab.rules <<EOF
// CTF-Lab: $LABUSER may manage libvirt without a password
polkit.addRule(function(action, subject) {
    if ((action.id == "org.libvirt.unix.manage" || action.id == "org.libvirt.unix.monitor") &&
        subject.user == "$LABUSER") {
        return polkit.Result.YES;
    }
});
EOF

step "5/8  Firewall rules (Docker/hotspot compatible, closed to the LAN)"
if systemctl list-unit-files ctf-lab-forward.service >/dev/null 2>&1 && [ -f /etc/systemd/system/ctf-lab-forward.service ]; then
  systemctl disable --now ctf-lab-forward.service 2>/dev/null || true
  rm -f /etc/systemd/system/ctf-lab-forward.service /usr/local/bin/ctf-lab-forward.sh   # old (Turkish) name
fi
install -m 755 "$SYS/bin/ctf-firewall.sh"      /usr/local/bin/ctf-firewall.sh
install -m 644 "$SYS/bin/ctf-firewall.service" /etc/systemd/system/ctf-firewall.service
cat > /etc/sysctl.d/90-ctf-lab.conf <<'EOF'
# CTF-Lab: routing for WireGuard peers that live inside the lab network (192.168.100.210-250)
net.ipv4.ip_forward = 1
net.ipv4.conf.virbr-ctf.proxy_arp = 1
EOF
systemctl daemon-reload
systemctl enable --now ctf-firewall.service

step "6/8  Virtual networks: ctf-lab (isolated, 192.168.100.0/24) and ctf-nat (internet only, 192.168.150.0/24)"
for i in $(seq 1 20); do virsh list >/dev/null 2>&1 && break; sleep 1; done   # wait for the modular daemons' sockets
for n in ctf-lab ctf-nat; do
  if virsh net-info "$n" >/dev/null 2>&1; then
    if [ "$n" = ctf-lab ] && ! virsh net-dumpxml --inactive ctf-lab | grep -q "mode='open'"; then
      if virsh list --name | grep -q '^ctf-'; then
        echo "  ctf-lab needs to be redefined (open mode for WireGuard), but lab VMs are running. Stop them and rerun this script."
      else
        echo "  ctf-lab: switching to open mode (no libvirt rules; ctf-firewall.sh isolates it)"
        virsh net-destroy ctf-lab >/dev/null 2>&1 || true
        virsh net-undefine ctf-lab >/dev/null   # a definition without the old UUID cannot replace it in place
        virsh net-define "$SYS/xml/ctf-lab.xml" >/dev/null
      fi
    else echo "  $n is already defined"; fi
  else
    virsh net-define "$SYS/xml/$n.xml"
  fi
  virsh net-autostart "$n" >/dev/null
  virsh net-start "$n" 2>/dev/null || true
done
sysctl -q --system >/dev/null 2>&1 || true
systemctl restart ctf-firewall.service

step "7/8  WireGuard server (wg-ctf, UDP 51820) + passwordless helper for 'ctf vpn'"
install -o root -g root -m 755 "$SYS/bin/ctf-vpn-helper" /usr/local/bin/ctf-vpn-helper
cat > /etc/sudoers.d/ctf-vpn <<EOF
# CTF-Lab: '$LABUSER' may manage WireGuard peers through the root-owned, input-validating helper only
$LABUSER ALL=(root) NOPASSWD: /usr/local/bin/ctf-vpn-helper
EOF
chmod 440 /etc/sudoers.d/ctf-vpn
visudo -cf /etc/sudoers.d/ctf-vpn >/dev/null
PEERS="$SYS/remote/wg/peers.tsv"
if [ -f "$PEERS" ]; then /usr/local/bin/ctf-vpn-helper sync < "$PEERS"; else /usr/local/bin/ctf-vpn-helper sync < /dev/null; fi

step "8/8  Lab user services"
sudo -u "$LABUSER" XDG_RUNTIME_DIR="/run/user/$(id -u "$LABUSER")" systemctl --user daemon-reload 2>/dev/null || true

echo
virsh net-list --all
echo
echo "Setup complete. KVM: $(ls -l /dev/kvm | awk '{print $1}')  | libvirt: $(virsh --version)"
echo "Next (as your normal user):  ctf remote enable   → panel + web Kali on https://<this-pc>:8443"
echo "                             ctf vpn add <name>  → join the lab network from another machine"
echo "Note: the 'libvirt' group takes effect at your next login; the polkit rule lets you work right away."
