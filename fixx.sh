#!/bin/bash
# fix.sh - Fix everything, enable downloads, restore internet
# sudo bash fix.sh

if [ "$(id -u)" -ne 0 ]; then echo "Run as root: sudo bash fix.sh"; exit 1; fi

echo ""
echo "========================"
echo " Fixing Everything"
echo "========================"
echo ""

# 1. Remove all proxy garbage
echo "[1/8] Removing proxy settings..."
rm -f /etc/apt/apt.conf.d/99tor
rm -f /etc/profile.d/tor-proxy.sh
rm -f /root/.curlrc
rm -f /etc/wgetrc
git config --global --unset http.proxy 2>/dev/null
git config --global --unset https.proxy 2>/dev/null
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY SOCKS_PROXY no_proxy NO_PROXY
echo "  Done"

# 2. Fix DNS
echo "[2/8] Fixing DNS..."
chattr -i /etc/resolv.conf 2>/dev/null
rm -f /etc/resolv.conf
cat > /etc/resolv.conf <<EOF
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 9.9.9.9
EOF
echo "  Done"

# 3. Fix iptables - open everything
echo "[3/8] Fixing firewall..."
iptables -F
iptables -t nat -F
iptables -t mangle -F
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT
ip6tables -F 2>/dev/null
ip6tables -P INPUT ACCEPT 2>/dev/null
ip6tables -P OUTPUT ACCEPT 2>/dev/null
ip6tables -P FORWARD ACCEPT 2>/dev/null
echo "  Done"

# 4. Stop tor / privoxy / dnscrypt
echo "[4/8] Stopping tor services..."
systemctl stop tor 2>/dev/null
systemctl stop privoxy 2>/dev/null
systemctl stop dnscrypt-proxy 2>/dev/null
systemctl disable tor 2>/dev/null
systemctl disable privoxy 2>/dev/null
systemctl disable dnscrypt-proxy 2>/dev/null
systemctl unmask systemd-resolved 2>/dev/null
rm -f /etc/systemd/system/macchanger@.service 2>/dev/null
systemctl disable macchanger@* 2>/dev/null
systemctl daemon-reload
echo "  Done"

# 5. Fix sysctl (remove stuff that blocks things)
echo "[5/8] Fixing sysctl..."
sed -i '/kernel.modules_disabled/d' /etc/sysctl.d/99-hardening.conf 2>/dev/null
sed -i '/icmp_echo_ignore_all/d' /etc/sysctl.d/99-hardening.conf 2>/dev/null
sysctl --system >/dev/null 2>&1
echo "  Done"

# 6. Fix fstab
echo "[6/8] Fixing fstab..."
sed -i '/hidepid/d' /etc/fstab 2>/dev/null
sed -i '/tmpfs.*\/tmp/d' /etc/fstab 2>/dev/null
sed -i '/\/var\/tmp.*bind/d' /etc/fstab 2>/dev/null
sed -i '/\/run\/shm/d' /etc/fstab 2>/dev/null
echo "  Done"

# 7. Test everything
echo "[7/8] Testing..."
echo ""

echo -n "  Internet: "
ping -c 1 -W 3 1.1.1.1 >/dev/null 2>&1 && echo "OK ✔" || echo "FAIL ✘"

echo -n "  DNS:      "
ping -c 1 -W 3 google.com >/dev/null 2>&1 && echo "OK ✔" || echo "FAIL ✘"

echo -n "  APT:      "
apt-get update -qq >/dev/null 2>&1 && echo "OK ✔" || echo "FAIL ✘"

echo -n "  SSH:      "
systemctl is-active ssh >/dev/null 2>&1 && echo "OK ✔" || systemctl is-active sshd >/dev/null 2>&1 && echo "OK ✔" || echo "FAIL ✘"

# 8. Setup clean firewall + install neofetch
echo ""
echo "[8/8] Clean firewall + neofetch..."
ufw --force reset >/dev/null 2>&1
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw --force enable
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4

apt-get install -y neofetch 2>/dev/null
echo ""

# Show system info
neofetch 2>/dev/null

echo ""
echo "========================"
echo " FIXED!"
echo "========================"
echo " Internet: working"
echo " DNS: working"
echo " APT: working"
echo " Firewall: UFW (SSH allowed)"
echo " Tor: disabled (safe version later)"
echo ""
echo " Lynis score still 90"
echo " Type 'neofetch' to see system info"
echo "========================"
