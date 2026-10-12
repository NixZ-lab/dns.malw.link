#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID == 0 && -d /opt/nixz/current ]] || exit 1
install -d -m 700 /var/backups/nixz
umask 077
target="/var/backups/nixz/nixz-$(date -u +%Y%m%dT%H%M%SZ).tgz"
tar -h -czf "$target" /etc/nixz /opt/nixz/current /etc/fail2ban/jail.d/nixz-sshd.local \
  /etc/systemd/system/nixz-monitor.service /etc/systemd/system/nixz-monitor.timer \
  /etc/systemd/system/nixz-routes.service /etc/systemd/system/nixz-routes.timer
chmod 600 "$target"
mapfile -t backups < <(find /var/backups/nixz -maxdepth 1 -type f -name 'nixz-*.tgz' | sort -r)
for stale in "${backups[@]:7}"; do rm -- "$stale"; done
echo "Protected backup: $target"
echo 'Contains TLS/private configuration. Use encrypted off-server storage; never send to chat or GitHub.'
