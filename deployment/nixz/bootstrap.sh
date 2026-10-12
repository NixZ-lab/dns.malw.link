#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID == 0 && -n ${SSH_CONNECTION:-} ]] || { echo 'Run with sudo --preserve-env=SSH_CONNECTION from SSH'; exit 1; }
[[ ${1:-} == --fresh-ssh-and-console-tested ]] || { echo 'First test a NEW SSH connection and a usable rescue console'; exit 1; }
. /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 ]] || { echo 'Ubuntu 24.04 required'; exit 1; }
read -r client_ip _ _ ssh_port <<< "$SSH_CONNECTION"
[[ $ssh_port =~ ^[0-9]+$ ]] || exit 1
effective=$(sshd -T)
for setting in 'permitrootlogin no' 'passwordauthentication no' 'kbdinteractiveauthentication no' 'pubkeyauthentication yes'; do
  grep -qx "$setting" <<< "$effective" || { echo "Unexpected SSH setting: $setting; no firewall changes"; exit 1; }
done
install -d -m 700 /var/backups/nixz
tar -czf "/var/backups/nixz/preflight-$(date -u +%Y%m%dT%H%M%SZ).tgz" /etc/ssh /etc/ufw /etc/systemd 2>/dev/null
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y chrony ufw fail2ban unattended-upgrades docker.io docker-compose-v2 dnsutils curl openssl python3 git jq certbot
systemctl enable --now chrony docker fail2ban
chronyc waitsync 30 0.5
[[ $(timedatectl show -p NTPSynchronized --value) == yes ]] || { echo 'NTP not synchronized'; exit 1; }
cat > /etc/fail2ban/jail.d/nixz-sshd.local <<EOF
[sshd]
enabled = true
backend = systemd
port = $ssh_port
maxretry = 5
findtime = 15m
bantime = 1h
ignoreip = 127.0.0.1/8 ::1 $client_ip
EOF
fail2ban-client -t
systemctl restart fail2ban
fail2ban-client status sshd
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
cat > /etc/apt/apt.conf.d/52nixz-security <<'EOF'
Unattended-Upgrade::Allowed-Origins { "${distro_id}:${distro_codename}-security"; };
Unattended-Upgrade::Automatic-Reboot "false";
EOF
install -d /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/nixz.conf <<'EOF'
[Journal]
SystemMaxUse=150M
RuntimeMaxUse=50M
MaxRetentionSec=14day
EOF
systemctl restart systemd-journald
echo 'Audit listening ports BEFORE proceeding:'
ss -lntup
if ufw status | grep -q 'Status: active'; then
  echo 'Existing active UFW requires manual audit. Its rules have not been changed.'
  exit 1
fi
ufw allow "$ssh_port/tcp" comment 'preserve SSH'
ufw default deny incoming
ufw default allow outgoing
ufw logging low
# New UFW only: temporary rollback restores the pre-existing disabled state.
systemd-run --unit=nixz-firewall-rescue --on-active=180s /usr/sbin/ufw --force disable
ufw --force enable
echo 'Open a SECOND SSH session now. Then run: sudo systemctl stop nixz-firewall-rescue.timer'
echo 'Without confirmation UFW disables itself in 180 seconds. Service ports are still closed.'
ufw status verbose
