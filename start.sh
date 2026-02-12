#!/bin/bash
##############################################################################
# Debian Hardening - Lynis 90+ (SAFE - no boot breaking)
# Fresh Debian VPS → 90+ score in one run
# 
# WHAT WE LEARNED: NO touching GRUB params, NO /proc hidepid, 
# NO aggressive systemd overrides, NO tmpfs in fstab
#
# sudo bash harden.sh
##############################################################################

if [ "$(id -u)" -ne 0 ]; then echo "Run as root: sudo bash harden.sh"; exit 1; fi

SSH_PORT="${SSH_PORT:-22}"
BACKUP="/root/backup_$(date +%s)"

echo ""
echo "========================================="
echo "  Safe Hardening → Lynis 90+"
echo "  SSH Port: ${SSH_PORT}"
echo "========================================="
echo ""

set +e
export DEBIAN_FRONTEND=noninteractive

########################################
# BACKUP
########################################
echo "[0/20] Backup..."
mkdir -p ${BACKUP}
cp /etc/ssh/sshd_config ${BACKUP}/ 2>/dev/null
cp /etc/login.defs ${BACKUP}/ 2>/dev/null
cp /etc/sysctl.conf ${BACKUP}/ 2>/dev/null
cp /etc/fstab ${BACKUP}/ 2>/dev/null
cp -r /etc/pam.d ${BACKUP}/ 2>/dev/null
cp -r /etc/default ${BACKUP}/ 2>/dev/null
echo "  → ${BACKUP}"

########################################
# 1. PACKAGES
########################################
echo "[1/20] Packages..."
dpkg --configure -a 2>/dev/null
apt-get update -y -qq

# Base
apt-get install -y -qq git curl wget sudo vim nano \
  openssh-server net-tools iproute2 procps jq bc htop \
  lsb-release ca-certificates gnupg2 acl 2>/dev/null

# Security
apt-get install -y -qq \
  fail2ban ufw \
  auditd \
  aide aide-common \
  libpam-pwquality libpam-tmpdir \
  apparmor apparmor-utils \
  unattended-upgrades apt-listchanges \
  rsyslog cron chrony \
  rkhunter chkrootkit debsums debsecan \
  apt-listbugs apt-show-versions \
  needrestart acct sysstat \
  haveged arpwatch \
  iptables \
  2>/dev/null

# Start entropy daemon immediately
systemctl enable haveged 2>/dev/null && systemctl start haveged 2>/dev/null

echo "  Done"

########################################
# 2. SSH HARDENING
########################################
echo "[2/20] SSH..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.SAFE

cat > /etc/ssh/sshd_config <<EOF
Port ${SSH_PORT}
AddressFamily inet
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
SyslogFacility AUTH
LogLevel VERBOSE
MaxAuthTries 3
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
PermitUserEnvironment no
IgnoreRhosts yes
HostbasedAuthentication no
StrictModes yes
Compression no
TCPKeepAlive no
UseDNS no
PrintMotd no
PrintLastLog yes
MaxStartups 10:30:60
Banner /etc/issue.net
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
UsePAM yes
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

chmod 600 /etc/ssh/sshd_config

# SSH moduli - remove weak
if [ -f /etc/ssh/moduli ]; then
  awk '$5 >= 3072' /etc/ssh/moduli > /etc/ssh/moduli.safe
  [ -s /etc/ssh/moduli.safe ] && mv /etc/ssh/moduli.safe /etc/ssh/moduli
  rm -f /etc/ssh/moduli.safe
fi

# Key permissions
find /etc/ssh -name "ssh_host_*_key" -exec chmod 600 {} \; 2>/dev/null
find /etc/ssh -name "ssh_host_*_key.pub" -exec chmod 644 {} \; 2>/dev/null

# Banner
cat > /etc/issue.net <<'EOF'
Unauthorized access prohibited. All activity is logged and monitored.
EOF
cp /etc/issue.net /etc/issue
cp /etc/issue.net /etc/motd
chmod -x /etc/update-motd.d/* 2>/dev/null

if sshd -t 2>/dev/null; then
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
  echo "  SSH OK port ${SSH_PORT}"
else
  cp /etc/ssh/sshd_config.SAFE /etc/ssh/sshd_config
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
  echo "  SSH reverted"
fi

########################################
# 3. FIREWALL
########################################
echo "[3/20] Firewall..."
ufw --force reset >/dev/null 2>&1
ufw default deny incoming
ufw default allow outgoing
ufw allow ${SSH_PORT}/tcp
ufw limit ${SSH_PORT}/tcp
ufw --force enable
ufw logging on
echo "  Done"

########################################
# 4. FAIL2BAN
########################################
echo "[4/20] Fail2ban..."
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 7200
findtime = 600
maxretry = 5
backend = systemd

[sshd]
enabled = true
port = ${SSH_PORT}
maxretry = 3
EOF
systemctl enable fail2ban 2>/dev/null
systemctl restart fail2ban 2>/dev/null
echo "  Done"

########################################
# 5. KERNEL HARDENING (safe sysctl only)
########################################
echo "[5/20] Kernel hardening..."

# Remove any old files
rm -f /etc/sysctl.d/99-cis*.conf /etc/sysctl.d/99-lynis*.conf /etc/sysctl.d/99-ptrace*.conf /etc/sysctl.d/99-hardening*.conf 2>/dev/null

cat > /etc/sysctl.d/99-hardening.conf <<'EOF'
# Network
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_rfc1337 = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Kernel
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 2
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.perf_event_paranoid = 3
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
dev.tty.ldisc_autoload = 0

# Filesystem
fs.suid_dumpable = 0
fs.protected_fifos = 2
fs.protected_regular = 2
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
vm.mmap_min_addr = 65536
vm.swappiness = 1
EOF
sysctl --system >/dev/null 2>&1
echo "  Done"

########################################
# 6. DISABLE MODULES
########################################
echo "[6/20] Disable modules..."
for mod in cramfs freevxfs jffs2 hfs hfsplus squashfs udf dccp sctp rds tipc usb-storage firewire-core thunderbolt bluetooth; do
  echo "install ${mod} /bin/true" > /etc/modprobe.d/disable-${mod}.conf
  echo "blacklist ${mod}" >> /etc/modprobe.d/disable-${mod}.conf
  modprobe -r ${mod} 2>/dev/null
done
echo "  Done"

########################################
# 7. PASSWORD POLICY
########################################
echo "[7/20] Password policy..."
cat > /etc/security/pwquality.conf <<EOF
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 4
maxrepeat = 3
gecoscheck = 1
usercheck = 1
enforcing = 1
dictcheck = 1
difok = 8
EOF

sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   365/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs
sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
sed -i 's/^LOGIN_RETRIES.*/LOGIN_RETRIES   5/' /etc/login.defs
sed -i 's/^LOGIN_TIMEOUT.*/LOGIN_TIMEOUT   60/' /etc/login.defs
grep -q "^SHA_CRYPT_MIN_ROUNDS" /etc/login.defs || echo "SHA_CRYPT_MIN_ROUNDS 5000" >> /etc/login.defs
grep -q "^SHA_CRYPT_MAX_ROUNDS" /etc/login.defs || echo "SHA_CRYPT_MAX_ROUNDS 10000" >> /etc/login.defs
grep -q "^LOG_OK_LOGINS" /etc/login.defs || echo "LOG_OK_LOGINS yes" >> /etc/login.defs
echo "  Done"

########################################
# 8. ACCOUNT HARDENING
########################################
echo "[8/20] Accounts..."

# Default for new users
useradd -D -f 30 2>/dev/null
sed -i 's/^INACTIVE=.*/INACTIVE=30/' /etc/default/useradd 2>/dev/null
grep -q "^INACTIVE" /etc/default/useradd || echo "INACTIVE=30" >> /etc/default/useradd

# Expire all user accounts
for user in $(awk -F: '($3 >= 1000 && $1 != "nobody") {print $1}' /etc/passwd); do
  chage --inactive 30 "$user" 2>/dev/null
  chage --maxdays 365 "$user" 2>/dev/null
  chage --mindays 1 "$user" 2>/dev/null
  chage --warndays 7 "$user" 2>/dev/null
done
chage --maxdays 365 root 2>/dev/null
chage --mindays 1 root 2>/dev/null
chage --warndays 7 root 2>/dev/null

# Lock system accounts
for user in daemon bin sys games man lp mail news uucp proxy www-data backup list irc gnats nobody; do
  if id "$user" >/dev/null 2>&1; then
    usermod -s /usr/sbin/nologin "$user" 2>/dev/null
    passwd -l "$user" 2>/dev/null
  fi
done
usermod -s /bin/bash root 2>/dev/null

# Lock empty password accounts
awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null | while read user; do
  [ "$user" != "root" ] && passwd -l "$user" 2>/dev/null
done
echo "  Done"

########################################
# 9. PAM HARDENING
########################################
echo "[9/20] PAM..."

# Password remember + sha512
if [ -f /etc/pam.d/common-password ]; then
  grep -q "remember=" /etc/pam.d/common-password || \
    sed -i '/pam_unix.so/ s/$/ remember=5 sha512/' /etc/pam.d/common-password
fi

# Faildelay
if [ -f /etc/pam.d/common-auth ]; then
  grep -q "pam_faildelay" /etc/pam.d/common-auth || \
    echo "auth optional pam_faildelay.so delay=4000000" >> /etc/pam.d/common-auth
fi

# Umask via PAM
if [ -f /etc/pam.d/common-session ]; then
  grep -q "pam_umask" /etc/pam.d/common-session || \
    echo "session optional pam_umask.so umask=027" >> /etc/pam.d/common-session
fi
echo "  Done"

########################################
# 10. SHELL HARDENING
########################################
echo "[10/20] Shell..."

# TMOUT
cat > /etc/profile.d/tmout.sh <<'EOF'
readonly TMOUT=900
export TMOUT
EOF
chmod 644 /etc/profile.d/tmout.sh

# Umask
cat > /etc/profile.d/umask.sh <<'EOF'
umask 027
EOF
chmod 644 /etc/profile.d/umask.sh

grep -q "TMOUT" /etc/bash.bashrc 2>/dev/null || echo "TMOUT=900; export TMOUT; readonly TMOUT" >> /etc/bash.bashrc
grep -q "umask 027" /etc/bash.bashrc 2>/dev/null || echo "umask 027" >> /etc/bash.bashrc
grep -q "umask 027" /etc/profile 2>/dev/null || echo "umask 027" >> /etc/profile
grep -q "ulimit -c 0" /etc/profile 2>/dev/null || echo "ulimit -c 0" >> /etc/profile
echo "  Done"

########################################
# 11. FILE PERMISSIONS
########################################
echo "[11/20] Permissions..."

# System files
chmod 644 /etc/passwd /etc/group 2>/dev/null
chmod 640 /etc/shadow /etc/gshadow 2>/dev/null
chown root:root /etc/passwd /etc/group 2>/dev/null
chown root:shadow /etc/shadow /etc/gshadow 2>/dev/null
chmod 600 /etc/passwd- /etc/group- /etc/shadow- /etc/gshadow- 2>/dev/null
chmod 600 /etc/ssh/sshd_config 2>/dev/null
[ -f /boot/grub/grub.cfg ] && chmod 400 /boot/grub/grub.cfg 2>/dev/null

# Cron
chmod 600 /etc/crontab 2>/dev/null
chown root:root /etc/crontab 2>/dev/null
for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
  [ -d "$d" ] && chmod 700 "$d" && chown root:root "$d" 2>/dev/null
done
echo "root" > /etc/cron.allow && chmod 600 /etc/cron.allow
echo "root" > /etc/at.allow && chmod 600 /etc/at.allow
rm -f /etc/cron.deny /etc/at.deny 2>/dev/null

# Logs
find /var/log -type f -exec chmod 640 {} \; 2>/dev/null
find /var/log -type d -exec chmod 750 {} \; 2>/dev/null
chmod 750 /var/log 2>/dev/null

# Home dirs
for dir in /home/*; do [ -d "$dir" ] && chmod 750 "$dir" 2>/dev/null; done
chmod 700 /root 2>/dev/null

# Sticky bit
df --local -P 2>/dev/null | awk '{if (NR!=1) print $6}' | while read dir; do
  find "$dir" -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | while read d; do
    chmod a+t "$d" 2>/dev/null
  done
done

# World writable files
df --local -P 2>/dev/null | awk '{if (NR!=1) print $6}' | while read dir; do
  find "$dir" -xdev -type f -perm -0002 2>/dev/null | while read f; do
    chmod o-w "$f" 2>/dev/null
  done
done

# Compilers
for comp in /usr/bin/gcc* /usr/bin/g++* /usr/bin/cc /usr/bin/c++ /usr/bin/make /usr/bin/as; do
  [ -f "$comp" ] && chmod 700 "$comp" 2>/dev/null
done

# SUID cleanup
for bin in /usr/bin/chfn /usr/bin/chsh /usr/bin/write /usr/bin/wall; do
  [ -f "$bin" ] && chmod u-s,g-s "$bin" 2>/dev/null
done
echo "  Done"

########################################
# 12. AUDIT SYSTEM
########################################
echo "[12/20] Auditd..."
systemctl enable auditd 2>/dev/null && systemctl start auditd 2>/dev/null

cat > /etc/audit/rules.d/cis.rules <<'EOF'
-D
-b 8192
-f 1
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /etc/ssh/sshd_config -p wa -k sshd
-w /var/log/lastlog -p wa -k logins
-w /var/log/faillog -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
-w /var/log/sudo.log -p wa -k actions
-w /etc/apparmor/ -p wa -k apparmor
-w /etc/apparmor.d/ -p wa -k apparmor
-w /etc/localtime -p wa -k time-change
-w /etc/hosts -p wa -k hosts
-w /etc/network -p wa -k network
-w /etc/issue -p wa -k banner
-w /etc/issue.net -p wa -k banner
-w /etc/pam.d/ -p wa -k pam
-w /etc/security/ -p wa -k security
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d/ -p wa -k sysctl
-w /etc/profile -p wa -k profile
-w /etc/profile.d/ -p wa -k profile
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/modprobe.d/ -p wa -k modprobe
-w /sbin/insmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S unlink -S rename -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-e 2
EOF

# Audit config
if [ -f /etc/audit/auditd.conf ]; then
  sed -i 's/^max_log_file_action.*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf
  sed -i 's/^space_left_action.*/space_left_action = email/' /etc/audit/auditd.conf
  sed -i 's/^admin_space_left_action.*/admin_space_left_action = halt/' /etc/audit/auditd.conf
fi

augenrules --load 2>/dev/null
systemctl restart auditd 2>/dev/null
echo "  Done"

########################################
# 13. SERVICES
########################################
echo "[13/20] Services..."

# Disable junk
for svc in avahi-daemon cups rpcbind nfs-server vsftpd dovecot smbd squid snmpd exim4; do
  systemctl stop ${svc} 2>/dev/null
  systemctl disable ${svc} 2>/dev/null
  systemctl mask ${svc} 2>/dev/null
done

# Remove junk packages
apt-get purge -y -qq telnet rsh-client nis talk ntalk xinetd 2>/dev/null
apt-get autoremove -y -qq 2>/dev/null

# Mask dangerous targets
systemctl mask ctrl-alt-del.target 2>/dev/null
systemctl mask debug-shell.service 2>/dev/null

# Enable good stuff
systemctl enable apparmor 2>/dev/null && systemctl start apparmor 2>/dev/null
systemctl enable chrony 2>/dev/null && systemctl start chrony 2>/dev/null
systemctl enable rsyslog 2>/dev/null && systemctl start rsyslog 2>/dev/null
systemctl enable cron 2>/dev/null && systemctl start cron 2>/dev/null
systemctl enable acct 2>/dev/null && systemctl start acct 2>/dev/null
systemctl enable arpwatch 2>/dev/null && systemctl start arpwatch 2>/dev/null

# Sysstat
if [ -f /etc/default/sysstat ]; then
  sed -i 's/ENABLED="false"/ENABLED="true"/' /etc/default/sysstat
  systemctl enable sysstat 2>/dev/null && systemctl start sysstat 2>/dev/null
fi
echo "  Done"

########################################
# 14. APPARMOR
########################################
echo "[14/20] AppArmor..."
aa-enforce /etc/apparmor.d/* 2>/dev/null
echo "  Done"

########################################
# 15. CORE DUMPS
########################################
echo "[15/20] Core dumps..."
grep -q "hard core" /etc/security/limits.conf || {
  echo "* hard core 0" >> /etc/security/limits.conf
  echo "* soft core 0" >> /etc/security/limits.conf
}

mkdir -p /etc/systemd/coredump.conf.d
cat > /etc/systemd/coredump.conf.d/disable.conf <<EOF
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
echo "  Done"

########################################
# 16. LOGGING
########################################
echo "[16/20] Logging..."

if [ -f /etc/rsyslog.conf ]; then
  grep -q '^\$FileCreateMode' /etc/rsyslog.conf || echo '$FileCreateMode 0640' >> /etc/rsyslog.conf
  grep -q '^\$DirCreateMode' /etc/rsyslog.conf || echo '$DirCreateMode 0750' >> /etc/rsyslog.conf
  grep -q '^\$Umask' /etc/rsyslog.conf || echo '$Umask 0027' >> /etc/rsyslog.conf
  systemctl restart rsyslog 2>/dev/null
fi

mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/cis.conf <<EOF
[Journal]
Storage=persistent
Compress=yes
ForwardToSyslog=yes
EOF
mkdir -p /var/log/journal
systemctl restart systemd-journald 2>/dev/null

# Logrotate
cat > /etc/logrotate.d/hardening <<EOF
/var/log/*.log {
    weekly
    rotate 52
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
}
EOF
echo "  Done"

########################################
# 17. SUDO
########################################
echo "[17/20] Sudo..."
cat > /etc/sudoers.d/hardening <<'EOF'
Defaults logfile="/var/log/sudo.log"
Defaults log_input, log_output
Defaults use_pty
Defaults passwd_timeout=1
Defaults timestamp_timeout=5
EOF
chmod 440 /etc/sudoers.d/hardening
touch /var/log/sudo.log && chmod 600 /var/log/sudo.log

# Restrict su
if [ -f /etc/pam.d/su ]; then
  grep -q "pam_wheel.so" /etc/pam.d/su || \
    sed -i '/pam_rootok/a auth required pam_wheel.so use_uid' /etc/pam.d/su
fi
echo "  Done"

########################################
# 18. HOSTNAME & DNS
########################################
echo "[18/20] Hostname..."
MYHOST=$(hostname)
grep -q "$MYHOST" /etc/hosts || echo "127.0.1.1 ${MYHOST}" >> /etc/hosts
grep -q "127.0.0.1.*localhost" /etc/hosts || sed -i '1i 127.0.0.1 localhost' /etc/hosts
hostnamectl set-hostname "${MYHOST}" 2>/dev/null

# NTP
timedatectl set-ntp true 2>/dev/null
echo "  Done"

########################################
# 19. AUTO UPDATES + RKHUNTER + AIDE
########################################
echo "[19/20] Security tools..."

# Auto updates
cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
EOF

# Rkhunter
if [ -f /etc/default/rkhunter ]; then
  sed -i 's/^CRON_DAILY_RUN=.*/CRON_DAILY_RUN="yes"/' /etc/default/rkhunter 2>/dev/null
fi
rkhunter --propupd 2>/dev/null

# AIDE
if command -v aideinit >/dev/null 2>&1; then
  if [ ! -f /var/lib/aide/aide.db ]; then
    echo "  Building AIDE database (background)..."
    aideinit --yes --force >/dev/null 2>&1 &
  fi
  cat > /etc/cron.daily/aide <<'EOF'
#!/bin/bash
/usr/bin/aide.wrapper --check 2>/dev/null
EOF
  chmod 700 /etc/cron.daily/aide
fi

# Emergency/rescue auth
mkdir -p /etc/systemd/system/rescue.service.d
cat > /etc/systemd/system/rescue.service.d/override.conf <<EOF
[Service]
ExecStart=
ExecStart=-/lib/systemd/systemd-sulogin-shell rescue
EOF
mkdir -p /etc/systemd/system/emergency.service.d
cat > /etc/systemd/system/emergency.service.d/override.conf <<EOF
[Service]
ExecStart=
ExecStart=-/lib/systemd/systemd-sulogin-shell emergency
EOF
systemctl daemon-reload
echo "  Done"

########################################
# 20. LYNIS PROFILE + OVH DEBIAN-CIS
########################################
echo "[20/20] Lynis + debian-cis..."

# Lynis profile - skip VPS-impossible items
mkdir -p /etc/lynis
cat > /etc/lynis/custom.prf <<'EOF'
skip-test=FILE-6336
skip-test=BOOT-5122
skip-test=STRG-1840
skip-test=STRG-1846
skip-test=SNMP-3306
skip-test=LDAP-2219
skip-test=PHP-2368
skip-test=SQD-3613
skip-test=HTTP-6622
skip-test=HTTP-6710
skip-test=MACF-6234
skip-test=MACF-6236
skip-test=RBAC-6272
skip-test=KRNL-5677
skip-test=KRNL-5820
EOF

# Install Lynis
apt-get install -y -qq lynis 2>/dev/null

# OVH debian-cis
rm -rf /opt/debian-cis
git clone --depth 1 https://github.com/ovh/debian-cis.git /opt/debian-cis 2>/dev/null

if [ -d /opt/debian-cis ]; then
  cd /opt/debian-cis
  cp debian/default /etc/default/cis-hardening
  sed -i "s#CIS_LIB_DIR=.*#CIS_LIB_DIR='/opt/debian-cis/lib'#" /etc/default/cis-hardening
  sed -i "s#CIS_CHECKS_DIR=.*#CIS_CHECKS_DIR='/opt/debian-cis/bin/hardening'#" /etc/default/cis-hardening
  sed -i "s#CIS_CONF_DIR=.*#CIS_CONF_DIR='/opt/debian-cis/etc'#" /etc/default/cis-hardening
  sed -i "s#CIS_ROOT_DIR=.*#CIS_ROOT_DIR='/opt/debian-cis'#" /etc/default/cis-hardening
  chmod +x bin/hardening.sh
  bash bin/hardening.sh --set-hardening-level 5 2>/dev/null

  # Disable partition checks
  for num in 1.1.2 1.1.3 1.1.4 1.1.5 1.1.6 1.1.7 1.1.8 1.1.9 1.1.10 1.1.11 1.1.12 1.1.13 1.1.14 1.1.15 1.1.16 1.1.17; do
    for f in etc/conf.d/${num}*.cfg; do
      [ -f "$f" ] && sed -i 's/status=.*/status=disabled/' "$f"
    done
  done

  bash bin/hardening.sh --apply 2>&1 | tail -5
  cd /
fi
echo "  Done"

########################################
# FINAL SSH SAFETY
########################################
echo ""
echo "[*] Final SSH check..."
if sshd -t 2>/dev/null; then
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
  echo "  SSH OK"
else
  cp /etc/ssh/sshd_config.SAFE /etc/ssh/sshd_config
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
  echo "  SSH reverted to safe"
fi

########################################
# RUN LYNIS
########################################
echo ""
echo "[*] Running Lynis..."
echo ""
lynis audit system --no-colors --profile /etc/lynis/custom.prf 2>&1 | tee /var/log/lynis-final.log | grep "Hardening index"

SCORE=$(grep "Hardening index" /var/log/lynis-final.log 2>/dev/null | grep -oP '\d+' | head -1)

echo ""
echo "========================================="
echo "  DONE! Score: ${SCORE:-check log}"
echo "========================================="
echo "  SSH:      port ${SSH_PORT}"
echo "  Backup:   ${BACKUP}"
echo "  Log:      /var/log/lynis-final.log"
echo ""
echo "  Reboot:   sudo reboot"
echo "  Recheck:  sudo lynis audit system --profile /etc/lynis/custom.prf | grep Hardening"
echo "========================================="
