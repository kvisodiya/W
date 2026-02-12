#!/bin/bash
##############################################################################
# Network Security + Tor Proxy + DNS Privacy
# All traffic through Tor + Encrypted DNS + Network hardening
# sudo bash network-tor.sh
##############################################################################

if [ "$(id -u)" -ne 0 ]; then echo "Run as root"; exit 1; fi

SSH_PORT="${SSH_PORT:-22}"

echo ""
echo "========================================="
echo "  Network Security + Tor Always-On"
echo "========================================="
echo ""

set +e
export DEBIAN_FRONTEND=noninteractive

########################################
# 1. INSTALL EVERYTHING
########################################
echo "[1/10] Installing packages..."

apt-get update -qq

# Tor
apt-get install -y -qq tor torsocks 2>/dev/null

# DNS privacy
apt-get install -y -qq dnscrypt-proxy 2>/dev/null || {
  # If not in repo, install manually
  apt-get install -y -qq stubby 2>/dev/null
}

# Network tools
apt-get install -y -qq \
  privoxy \
  iptables iptables-persistent \
  dnsutils \
  macchanger \
  nftables \
  tcpdump \
  nmap \
  2>/dev/null

echo "  Done"

########################################
# 2. TOR SETUP
########################################
echo "[2/10] Configuring Tor..."

# Backup
cp /etc/tor/torrc /etc/tor/torrc.bak 2>/dev/null

cat > /etc/tor/torrc <<'EOF'
## Tor Configuration - Always On

# Run as daemon
RunAsDaemon 1

# SOCKS proxy for applications
SocksPort 9050
SocksPort 9150

# DNS over Tor
DNSPort 5353
AutomapHostsOnResolve 1

# Transparent proxy (route ALL traffic through Tor)
TransPort 9040
TransListenAddress 127.0.0.1

# Tor DNS
VirtualAddrNetworkIPv4 10.192.0.0/10

# Performance
NumEntryGuards 3
KeepalivePeriod 60
NewCircuitPeriod 30
MaxCircuitDirtiness 600

# Security
SafeSocks 1
TestSocks 0
AllowNonRFC953Hostnames 0

# Logging (minimal)
Log notice file /var/log/tor/notices.log
Log warn file /var/log/tor/warnings.log

# Disable unused features
AvoidDiskWrites 1
DisableDebuggerAttachment 1

# Exit policy (we're a client, not a relay)
ExitPolicy reject *:*

# Bridges (uncomment if Tor is blocked in your country)
#UseBridges 1
#Bridge obfs4 <bridge-address>
#ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy
EOF

# Create log directory
mkdir -p /var/log/tor
chown debian-tor:debian-tor /var/log/tor 2>/dev/null || chown _tor:_tor /var/log/tor 2>/dev/null

systemctl enable tor
systemctl restart tor

# Wait for Tor to connect
echo "  Waiting for Tor to connect..."
sleep 5

if systemctl is-active --quiet tor; then
  echo "  Tor running ✔"
else
  echo "  Tor failed - check: journalctl -u tor"
fi

########################################
# 3. PRIVOXY (HTTP proxy through Tor)
########################################
echo "[3/10] Privoxy (HTTP→Tor proxy)..."

cp /etc/privoxy/config /etc/privoxy/config.bak 2>/dev/null

cat > /etc/privoxy/config <<'EOF'
# Privoxy config - forward all HTTP through Tor

# Listen on localhost
listen-address 127.0.0.1:8118

# Forward to Tor SOCKS
forward-socks5t / 127.0.0.1:9050 .

# Security
toggle 0
enable-remote-toggle 0
enable-remote-http-toggle 0
enable-edit-actions 0

# Privacy
forwarded-connect-retries 0
accept-intercepted-requests 0
allow-cgi-request-crunching 0
split-large-forms 0

# Logging
logdir /var/log/privoxy
logfile logfile
debug 0

# Timeouts
socket-timeout 300
keep-alive-timeout 5
tolerate-pipelining 1

# Filter (block tracking)
actionsfile match-all.action
actionsfile default.action
filterfile default.filter
EOF

systemctl enable privoxy
systemctl restart privoxy
echo "  Done"

########################################
# 4. ENCRYPTED DNS (DNS over TOR)
########################################
echo "[4/10] DNS encryption..."

# Option A: Use Tor's DNS
# Option B: Use dnscrypt-proxy
# We use BOTH - dnscrypt for speed, Tor DNS as fallback

if [ -f /etc/dnscrypt-proxy/dnscrypt-proxy.toml ]; then
  cp /etc/dnscrypt-proxy/dnscrypt-proxy.toml /etc/dnscrypt-proxy/dnscrypt-proxy.toml.bak

  cat > /etc/dnscrypt-proxy/dnscrypt-proxy.toml <<'EOF'
# DNSCrypt Proxy - Encrypted DNS

listen_addresses = ['127.0.0.1:5354', '[::1]:5354']
max_clients = 250

# Use servers that support DNSCrypt and DoH
server_names = ['cloudflare', 'cloudflare-ipv6', 'google', 'quad9-dnscrypt-ip4-nofilter-pri']

# Security
ipv4_servers = true
ipv6_servers = false
dnscrypt_servers = true
doh_servers = true
require_dnssec = true
require_nolog = true
require_nofilter = false

# Performance
timeout = 5000
keepalive = 30
cert_refresh_delay = 240
fallback_resolvers = ['1.1.1.1:53', '9.9.9.9:53']
ignore_system_dns = true

# Cache
cache = true
cache_size = 4096
cache_min_ttl = 2400
cache_max_ttl = 86400
cache_neg_min_ttl = 60
cache_neg_max_ttl = 600

# Logging
log_level = 2
log_file = '/var/log/dnscrypt-proxy.log'
use_syslog = true

# Privacy
block_ipv6 = true
block_unqualified = true
block_undelegated = true

# Sources
[sources]
  [sources.'public-resolvers']
  urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md']
  cache_file = '/var/cache/dnscrypt-proxy/public-resolvers.md'
  minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
  refresh_delay = 72
EOF

  mkdir -p /var/cache/dnscrypt-proxy
  systemctl enable dnscrypt-proxy 2>/dev/null
  systemctl restart dnscrypt-proxy 2>/dev/null
  echo "  DNSCrypt running ✔"
fi

# Configure system to use encrypted DNS
cat > /etc/resolv.conf <<'EOF'
# Encrypted DNS - Tor + DNSCrypt
nameserver 127.0.0.1
options edns0 single-request-reopen
EOF

# Prevent resolv.conf from being overwritten
chattr +i /etc/resolv.conf 2>/dev/null

echo "  Done"

########################################
# 5. TRANSPARENT TOR PROXY (iptables)
########################################
echo "[5/10] Transparent Tor proxy (iptables)..."

# Get Tor user
TOR_USER=$(grep "^User" /etc/tor/torrc 2>/dev/null | awk '{print $2}')
[ -z "$TOR_USER" ] && TOR_USER="debian-tor"
id "$TOR_USER" >/dev/null 2>&1 || TOR_USER="_tor"

TOR_UID=$(id -u $TOR_USER 2>/dev/null)

if [ -z "$TOR_UID" ]; then
  echo "  WARNING: Tor user not found - skipping transparent proxy"
  echo "  Traffic will route through SOCKS proxy only"
else

  # Flush old rules
  iptables -F
  iptables -t nat -F
  iptables -t mangle -F

  # Default policies
  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT DROP

  # === INPUT ===
  # Allow loopback
  iptables -A INPUT -i lo -j ACCEPT

  # Allow established connections
  iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

  # Allow SSH
  iptables -A INPUT -p tcp --dport ${SSH_PORT} -m state --state NEW -j ACCEPT

  # Drop invalid
  iptables -A INPUT -m state --state INVALID -j DROP

  # === OUTPUT ===
  # Allow loopback
  iptables -A OUTPUT -o lo -j ACCEPT

  # Allow Tor user to connect directly (Tor needs direct internet)
  iptables -A OUTPUT -m owner --uid-owner ${TOR_UID} -j ACCEPT

  # Allow DNS to local resolvers
  iptables -A OUTPUT -d 127.0.0.1 -p udp --dport 5353 -j ACCEPT
  iptables -A OUTPUT -d 127.0.0.1 -p tcp --dport 5353 -j ACCEPT
  iptables -A OUTPUT -d 127.0.0.1 -p udp --dport 5354 -j ACCEPT
  iptables -A OUTPUT -d 127.0.0.1 -p tcp --dport 5354 -j ACCEPT

  # Allow local Tor SOCKS
  iptables -A OUTPUT -d 127.0.0.1 -p tcp --dport 9050 -j ACCEPT
  iptables -A OUTPUT -d 127.0.0.1 -p tcp --dport 9150 -j ACCEPT
  iptables -A OUTPUT -d 127.0.0.1 -p tcp --dport 8118 -j ACCEPT

  # Redirect DNS to Tor
  iptables -t nat -A OUTPUT ! -o lo -p udp --dport 53 -j REDIRECT --to-ports 5353
  iptables -t nat -A OUTPUT ! -o lo -p tcp --dport 53 -j REDIRECT --to-ports 5353

  # Redirect all TCP through Tor transparent proxy
  iptables -t nat -A OUTPUT ! -o lo -m owner ! --uid-owner ${TOR_UID} -p tcp -j REDIRECT --to-ports 9040

  # Allow established
  iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

  # Drop everything else
  iptables -A OUTPUT -j DROP

  # === Save rules ===
  mkdir -p /etc/iptables
  iptables-save > /etc/iptables/rules.v4

  # Disable IPv6 completely (prevents leaks)
  ip6tables -P INPUT DROP
  ip6tables -P FORWARD DROP
  ip6tables -P OUTPUT DROP
  ip6tables -A INPUT -i lo -j ACCEPT
  ip6tables -A OUTPUT -o lo -j ACCEPT
  ip6tables-save > /etc/iptables/rules.v6

  echo "  Transparent Tor proxy active ✔"
  echo "  ALL traffic now routes through Tor"
fi

echo "  Done"

########################################
# 6. DNS LEAK PREVENTION
########################################
echo "[6/10] DNS leak prevention..."

# Block direct DNS (port 53) except through Tor
# Already done in iptables above

# Disable systemd-resolved (conflicts with our DNS)
systemctl stop systemd-resolved 2>/dev/null
systemctl disable systemd-resolved 2>/dev/null
systemctl mask systemd-resolved 2>/dev/null

# Remove symlink if exists
if [ -L /etc/resolv.conf ]; then
  rm /etc/resolv.conf
  cat > /etc/resolv.conf <<'EOF'
nameserver 127.0.0.1
options edns0 single-request-reopen
EOF
  chattr +i /etc/resolv.conf 2>/dev/null
fi

echo "  Done"

########################################
# 7. MAC ADDRESS RANDOMIZATION
########################################
echo "[7/10] MAC randomization..."

IFACE=$(ip route show default 2>/dev/null | awk '{print $5}' | head -1)

if command -v macchanger >/dev/null 2>&1 && [ -n "$IFACE" ]; then
  # Create service to randomize MAC on boot
  cat > /etc/systemd/system/macchanger@.service <<'EOF'
[Unit]
Description=MAC Address Randomization for %i
Wants=network-pre.target
Before=network-pre.target
BindsTo=sys-subsystem-net-devices-%i.device
After=sys-subsystem-net-devices-%i.device

[Service]
Type=oneshot
ExecStart=/usr/bin/macchanger -e %i
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  # Enable for default interface
  systemctl enable macchanger@${IFACE} 2>/dev/null
  echo "  MAC randomization enabled for ${IFACE}"
  echo "  WARNING: Will change MAC on next reboot"
  echo "  Current MAC: $(ip link show ${IFACE} | grep ether | awk '{print $2}')"
else
  echo "  Skipped (no macchanger or no interface)"
fi

echo "  Done"

########################################
# 8. NETWORK HARDENING
########################################
echo "[8/10] Network hardening..."

# Extra network sysctl
cat >> /etc/sysctl.d/99-hardening.conf <<'EOF'

# === Tor Network Hardening ===
# Prevent IP spoofing
net.ipv4.conf.all.arp_filter = 1
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2

# TCP hardening
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_max_tw_buckets = 1440000

# ICMP hardening
net.ipv4.icmp_echo_ignore_all = 1
EOF

sysctl --system >/dev/null 2>&1

echo "  Done"

########################################
# 9. TOR MONITORING & AUTO-RESTART
########################################
echo "[9/10] Tor monitoring..."

# Auto-restart Tor if it dies
mkdir -p /etc/systemd/system/tor.service.d
cat > /etc/systemd/system/tor.service.d/restart.conf <<'EOF'
[Service]
Restart=always
RestartSec=10
EOF
systemctl daemon-reload

# Tor health check cron
cat > /etc/cron.d/tor-health <<'CRON'
# Check Tor every 5 minutes
*/5 * * * * root /usr/local/bin/tor-health-check.sh
CRON

cat > /usr/local/bin/tor-health-check.sh <<'EOF'
#!/bin/bash
# Tor health check

# Check if Tor is running
if ! systemctl is-active --quiet tor; then
  logger -t tor-health "Tor is DOWN - restarting"
  systemctl restart tor
  exit 1
fi

# Check if Tor can connect
if command -v torsocks >/dev/null 2>&1; then
  RESULT=$(torsocks curl -s --max-time 15 https://check.torproject.org/api/ip 2>/dev/null)
  if echo "$RESULT" | grep -q '"IsTor":true'; then
    logger -t tor-health "Tor OK - connected"
  else
    logger -t tor-health "Tor NOT connecting - restarting"
    systemctl restart tor
  fi
fi
EOF
chmod 700 /usr/local/bin/tor-health-check.sh

# Tor new identity script
cat > /usr/local/bin/tor-newid <<'EOF'
#!/bin/bash
# Get new Tor identity (new exit node)
echo "Getting new Tor identity..."
systemctl reload tor 2>/dev/null || killall -HUP tor
sleep 3
echo "New identity active"

# Show current exit IP
if command -v torsocks >/dev/null 2>&1; then
  echo "Exit IP: $(torsocks curl -s https://check.torproject.org/api/ip 2>/dev/null | grep -oP '"IP":"[^"]*"')"
fi
EOF
chmod 755 /usr/local/bin/tor-newid

echo "  Done"

########################################
# 10. ENVIRONMENT VARIABLES
########################################
echo "[10/10] Proxy environment..."

# Set system-wide proxy through Tor
cat > /etc/profile.d/tor-proxy.sh <<'EOF'
# Route all traffic through Tor
export http_proxy="http://127.0.0.1:8118"
export https_proxy="http://127.0.0.1:8118"
export HTTP_PROXY="http://127.0.0.1:8118"
export HTTPS_PROXY="http://127.0.0.1:8118"
export SOCKS_PROXY="socks5://127.0.0.1:9050"
export ALL_PROXY="socks5://127.0.0.1:9050"
export no_proxy="localhost,127.0.0.1,::1"
export NO_PROXY="localhost,127.0.0.1,::1"
EOF
chmod 644 /etc/profile.d/tor-proxy.sh

# APT through Tor
cat > /etc/apt/apt.conf.d/99tor <<'EOF'
Acquire::http::Proxy "socks5h://127.0.0.1:9050";
Acquire::https::Proxy "socks5h://127.0.0.1:9050";
Acquire::socks::proxy "socks5h://127.0.0.1:9050";
EOF

# Git through Tor
git config --global http.proxy socks5://127.0.0.1:9050 2>/dev/null
git config --global https.proxy socks5://127.0.0.1:9050 2>/dev/null

# Wget through Tor
cat > /etc/wgetrc <<'EOF'
use_proxy = on
http_proxy = http://127.0.0.1:8118
https_proxy = http://127.0.0.1:8118
EOF

# Curl through Tor
mkdir -p /root
cat > /root/.curlrc <<'EOF'
proxy = socks5h://127.0.0.1:9050
EOF

echo "  Done"

########################################
# VERIFY
########################################
echo ""
echo "========================================="
echo "  Verifying Setup"
echo "========================================="

# Check services
echo ""
echo "[Services]"
for svc in tor privoxy; do
  if systemctl is-active --quiet ${svc} 2>/dev/null; then
    echo "  ${svc}: ✔ Running"
  else
    echo "  ${svc}: ✘ NOT running"
    systemctl start ${svc} 2>/dev/null
  fi
done

# Check Tor connection
echo ""
echo "[Tor Connection]"
sleep 3
if command -v torsocks >/dev/null 2>&1; then
  TOR_CHECK=$(torsocks curl -s --max-time 20 https://check.torproject.org/api/ip 2>/dev/null)
  if echo "$TOR_CHECK" | grep -q '"IsTor":true'; then
    TOR_IP=$(echo "$TOR_CHECK" | grep -oP '"IP":"[^"]*"' | cut -d'"' -f4)
    echo "  Connected through Tor ✔"
    echo "  Exit IP: ${TOR_IP}"
  else
    echo "  Tor not fully connected yet (wait 30 seconds)"
  fi
fi

# Check DNS
echo ""
echo "[DNS]"
DNS_TEST=$(dig +short +timeout=5 google.com @127.0.0.1 2>/dev/null)
if [ -n "$DNS_TEST" ]; then
  echo "  DNS resolving ✔"
else
  echo "  DNS may need a moment to start"
fi

# Show listening ports
echo ""
echo "[Listening Ports]"
ss -tlnp 2>/dev/null | grep -E "9050|9040|9150|8118|5353|5354|${SSH_PORT}" | while read line; do
  echo "  $line"
done

# Check real IP vs Tor IP
echo ""
echo "[IP Check]"
REAL_IP=$(curl -s --max-time 5 ifconfig.me 2>/dev/null)
TOR_IP=$(torsocks curl -s --max-time 15 ifconfig.me 2>/dev/null)
echo "  Direct IP: ${REAL_IP:-blocked by firewall}"
echo "  Tor IP:    ${TOR_IP:-connecting...}"

if [ -n "$TOR_IP" ] && [ "$REAL_IP" != "$TOR_IP" ]; then
  echo "  ✔ IPs are different - Tor is working!"
fi

echo ""
echo "========================================="
echo "  SETUP COMPLETE"
echo "========================================="
echo ""
echo "  Tor SOCKS:    127.0.0.1:9050"
echo "  Tor DNS:      127.0.0.1:5353"
echo "  HTTP Proxy:   127.0.0.1:8118 (Privoxy→Tor)"
echo "  Trans Proxy:  127.0.0.1:9040"
echo ""
echo "  Commands:"
echo "    tor-newid          # Get new Tor identity"
echo "    torsocks curl ...  # Run command through Tor"
echo "    torify wget ...    # Download through Tor"
echo ""
echo "  Test:  torsocks curl https://check.torproject.org/api/ip"
echo "  DNS:   dig @127.0.0.1 -p 5353 google.com"
echo ""
echo "  ⚠ ALL traffic now goes through Tor"
echo "  ⚠ SSH still works on port ${SSH_PORT}"
echo "========================================="
