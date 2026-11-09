#!/bin/bash
# Kali CTF setup — runs INSIDE the VM as root (`ctf kali setup` sends it with ctf-guest-exec).
# Safe to rerun. Log: /var/log/ctf-setup.log
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
LOG=/var/log/ctf-setup.log
exec >>"$LOG" 2>&1
step() { echo; echo "===== $(date +%T) $* ====="; }
PUBKEY='@@PUBKEY@@'
TZ_NAME='@@TZ@@'          # filled in by `ctf kali setup` from .system/config.env (KALI_TIMEZONE)
KEYMAP='@@KEYMAP@@'      # e.g. us  or  tr,us   (KALI_KEYMAP)
XKBOPT='@@XKBOPT@@'      # e.g. grp:alt_shift_toggle when there are two layouts
KU=kali

step "Time zone, keyboard layout, hosts"
timedatectl set-timezone "$TZ_NAME" || true
localectl set-x11-keymap "$KEYMAP" pc105 "" "$XKBOPT" || true
sed -i "s/^XKBLAYOUT=.*/XKBLAYOUT=\"$KEYMAP\"/; s/^XKBOPTIONS=.*/XKBOPTIONS=\"$XKBOPT\"/" /etc/default/keyboard
grep -q ' targets' /etc/hosts || echo '192.168.100.20 targets hedefler' >> /etc/hosts

step "SSH (key login)"
apt-get install -y openssh-server >/dev/null
install -d -m 700 -o $KU -g $KU /home/$KU/.ssh
grep -qF "$PUBKEY" /home/$KU/.ssh/authorized_keys 2>/dev/null || echo "$PUBKEY" >> /home/$KU/.ssh/authorized_keys
chown $KU:$KU /home/$KU/.ssh/authorized_keys; chmod 600 /home/$KU/.ssh/authorized_keys
systemctl enable --now ssh

step "apt: fast official mirror (kali.download), no Contents or translation files"
echo 'Acquire::IndexTargets::deb::Contents-deb::DefaultEnabled "false";' > /etc/apt/apt.conf.d/99-ctf-fast
echo 'Acquire::Languages "none";' >> /etc/apt/apt.conf.d/99-ctf-fast
echo 'Acquire::Retries "5";' >> /etc/apt/apt.conf.d/99-ctf-fast
sed -i -E 's#URIs: https?://[^ ]+#URIs: http://kali.download/kali/#' /etc/apt/sources.list.d/kali.sources
step "apt update"
apt-get update
pkgs() {  # installs the packages that exist, logs the ones that don't
  local ok=() p
  for p in "$@"; do
    if apt-cache show "$p" >/dev/null 2>&1; then ok+=("$p"); else echo "NO SUCH PACKAGE (skipped): $p"; fi
  done
  [ ${#ok[@]} -gt 0 ] || return 0
  if ! apt-get install -y --no-install-recommends "${ok[@]}"; then
    echo "WARNING: bulk install failed, trying one by one"
    for p in "${ok[@]}"; do apt-get install -y --no-install-recommends "$p" || echo "FAILED: $p"; done
  fi
}

step "SPICE (shared clipboard + automatic resolution)"
pkgs spice-vdagent qemu-guest-agent
systemctl enable --now spice-vdagentd 2>/dev/null || true

step "Compilers / basic tools"
pkgs build-essential gcc-multilib g++-multilib make cmake git curl wget rsync tmux vim neovim tree jq xxd \
       python3-pip python3-venv pipx python3-dev ruby ruby-dev libssl-dev libffi-dev \
       unzip p7zip-full zip unrar-free libarchive-tools zbar-tools libgmp-dev libmpfr-dev libmpc-dev netcat-traditional ncat socat openvpn wireguard-tools \
       proxychains4 sshuttle chisel php-cli nodejs npm

step "Binary exploitation / reverse engineering"
pkgs gdb gdb-multiarch gdbserver pwncat python3-pwntools python3-ropgadget ropper checksec nasm \
       strace ltrace patchelf upx-ucl libc6-dbg qemu-user-static binutils-multiarch \
       ghidra radare2 rizin cutter jadx apktool dex2jar python3-z3 python3-capstone python3-keystone \
       python3-unicorn python3-angr seccomp-tools one-gadget kali-tools-reverse-engineering

step "Web"
pkgs kali-tools-web seclists wordlists ffuf feroxbuster gobuster dirsearch sqlmap wfuzz nikto whatweb wpscan \
       nuclei zaproxy commix jwt-tool httpie cewl hydra sslscan dalfox arjun

step "Crypto / stego / forensics / passwords"
pkgs kali-tools-crypto-stego kali-tools-forensics python3-pycryptodome python3-gmpy2 python3-sympy hashid \
       hash-identifier john hashcat fcrackzip steghide stegseek stegsnow outguess zsteg binwalk foremost \
       libimage-exiftool-perl pngcheck imagemagick sox ffmpeg tshark wireshark tcpdump volatility3 sleuthkit \
       testdisk scalpel bulk-extractor qpdf pdf-parser oletools xortool

step "Network / server exploitation / privilege escalation"
pkgs kali-tools-exploitation kali-tools-passwords nmap masscan smbclient smbmap enum4linux-ng netexec \
       python3-impacket impacket-scripts evil-winrm responder bloodhound.py exploitdb peass \
       linux-exploit-suggester metasploit-framework

step "GEF (gdb plugin), RsaCtfTool, gem tools"
for g in zsteg one_gadget seccomp-tools; do command -v "${g//_/-}" >/dev/null 2>&1 || command -v "$g" >/dev/null 2>&1 || gem install --no-document "$g" || echo "FAILED(gem): $g"; done
if [ ! -f /home/$KU/.gdbinit-gef.py ]; then
  curl -fsSL https://raw.githubusercontent.com/hugsy/gef/main/gef.py -o /home/$KU/.gdbinit-gef.py \
    && echo 'source ~/.gdbinit-gef.py' > /home/$KU/.gdbinit && chown $KU:$KU /home/$KU/.gdbinit /home/$KU/.gdbinit-gef.py
fi
if [ ! -d /opt/RsaCtfTool ]; then
  git clone --depth 1 https://github.com/RsaCtfTool/RsaCtfTool.git /opt/RsaCtfTool \
   && python3 -m venv /opt/RsaCtfTool/venv \
   && /opt/RsaCtfTool/venv/bin/pip install -q -r /opt/RsaCtfTool/requirements.txt \
   && printf '#!/bin/sh\nexec /opt/RsaCtfTool/venv/bin/python /opt/RsaCtfTool/RsaCtfTool.py "$@"\n' > /usr/local/bin/RsaCtfTool \
   && chmod +x /usr/local/bin/RsaCtfTool || echo "WARNING: RsaCtfTool could not be installed"
fi

step "Tools installed with pip (not in apt): volatility3, xortool, jwt_tool"
export PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin
for t in volatility3 xortool; do command -v "$t" >/dev/null 2>&1 || command -v vol >/dev/null 2>&1 && [ "$t" = volatility3 ] || pipx install "$t" || echo "FAILED(pipx): $t"; done
if [ ! -d /opt/jwt_tool ]; then
  git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool && python3 -m venv /opt/jwt_tool/venv \
   && /opt/jwt_tool/venv/bin/pip install -q -r /opt/jwt_tool/requirements.txt \
   && printf '#!/bin/sh\nexec /opt/jwt_tool/venv/bin/python /opt/jwt_tool/jwt_tool.py "$@"\n' > /usr/local/bin/jwt_tool && chmod +x /usr/local/bin/jwt_tool || echo "WARNING: jwt_tool could not be installed"
fi
[ -x /usr/local/bin/RsaCtfTool ] || { rm -rf /opt/RsaCtfTool; git clone --depth 1 https://github.com/RsaCtfTool/RsaCtfTool.git /opt/RsaCtfTool && python3 -m venv /opt/RsaCtfTool/venv && /opt/RsaCtfTool/venv/bin/pip install -q -r /opt/RsaCtfTool/requirements.txt && printf '#!/bin/sh\nexec /opt/RsaCtfTool/venv/bin/python /opt/RsaCtfTool/RsaCtfTool.py "$@"\n' > /usr/local/bin/RsaCtfTool && chmod +x /usr/local/bin/RsaCtfTool || echo "WARNING: RsaCtfTool could not be installed"; }

step "Auto login + screen lock off (isolated lab machine)"
install -d /etc/lightdm/lightdm.conf.d
printf '[Seat:*]\nautologin-user=%s\nautologin-user-timeout=0\n' "$KU" > /etc/lightdm/lightdm.conf.d/50-ctf-autologin.conf
cat > /etc/xdg/autostart/ctf-no-lock.desktop <<'EOT'
[Desktop Entry]
Type=Application
Name=CTF disable screen lock
Exec=sh -c 'xset s off -dpms; xfconf-query -c xfce4-screensaver -p /saver/enabled -n -t bool -s false; xfconf-query -c xfce4-screensaver -p /lock/enabled -n -t bool -s false; xfconf-query -c xfce4-power-manager -p /xfce4-power-manager/dpms-enabled -n -t bool -s false'
NoDisplay=true
EOT

step "CTF working directory"
for d in web linux windows pwn crypto forensics api archives inbox work; do install -d -o $KU -g $KU /home/$KU/CTF/$d; done
[ -f /usr/share/wordlists/rockyou.txt.gz ] && [ ! -f /usr/share/wordlists/rockyou.txt ] && gunzip -k /usr/share/wordlists/rockyou.txt.gz
cat > /home/$KU/CTF/README.txt <<'EOT'
CTF workspace
  inbox/    : non-VM files you drop into the desktop drop-here folder land here
  work/     : your own notes and exploits
  web/ linux/ pwn/ ... : challenge files kept in sync with the desktop library (ctf sync)
Target network: 192.168.100.0/24  →  nmap -sn 192.168.100.0/24   (find the targets' IPs)
Web labs: http://targets  (192.168.100.20)  — which lab is on which port: ctf status
Keyboard layout: see /etc/default/keyboard (set with KALI_KEYMAP in .system/config.env).
EOT
chown -R $KU:$KU /home/$KU/CTF

step "Cleanup"
apt-get -y autoremove >/dev/null 2>&1; apt-get clean
step "READY"
echo READY > /var/lib/ctf-setup.state
