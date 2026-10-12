#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID == 0 ]] || exit 1
[[ $(readlink -f "$(dirname "$0")") == /opt/nixz/repo/deployment/nixz ]] || { echo 'Install repo to /opt/nixz/repo first'; exit 1; }
[[ -d /opt/nixz/current ]] || { echo 'Deploy and locally verify first'; exit 1; }
cat > /etc/systemd/system/nixz-monitor.service <<'EOF'
[Unit]
Description=NixZ DNS and SNI real health probes
After=docker.service network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/nixz/repo/deployment/nixz/probe.py --release /opt/nixz/current
ExecStartPost=/bin/sh -c 'test $(df --output=pcent / | tail -1 | tr -dc 0-9) -lt 85'
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
TimeoutStartSec=180
EOF
cat > /etc/systemd/system/nixz-monitor.timer <<'EOF'
[Unit]
Description=NixZ health every five minutes
[Timer]
OnBootSec=2m
OnUnitActiveSec=5m
[Install]
WantedBy=timers.target
EOF
cat > /etc/systemd/system/nixz-routes.service <<'EOF'
[Unit]
Description=NixZ validated route-only deployment
After=docker.service network-online.target
[Service]
Type=oneshot
ExecStart=/bin/bash /opt/nixz/repo/deployment/nixz/routes-sync.sh --apply
TimeoutStartSec=600
UMask=0022
EOF
cat > /etc/systemd/system/nixz-routes.timer <<'EOF'
[Unit]
Description=Refresh approved routes and pinned public SNI upstreams
[Timer]
OnBootSec=10m
OnUnitActiveSec=4h
RandomizedDelaySec=5m
Persistent=true
[Install]
WantedBy=timers.target
EOF
install -d /etc/letsencrypt/renewal-hooks/{pre,post,deploy}
cat > /etc/letsencrypt/renewal-hooks/pre/50-nixz <<'EOF'
#!/bin/sh
/usr/sbin/ufw allow 80/tcp comment 'nixz-acme-temporary'
EOF
cat > /etc/letsencrypt/renewal-hooks/post/50-nixz <<'EOF'
#!/bin/sh
/usr/sbin/ufw --force delete allow 80/tcp
EOF
cat > /etc/letsencrypt/renewal-hooks/deploy/50-nixz <<'EOF'
#!/bin/sh
cd /opt/nixz/repo/deployment/nixz
# Preserve active routes while refreshing certificates.
NIXZ_ROUTES_FILE=/opt/nixz/current/routes.json /bin/bash deploy.sh --apply
EOF
chmod 700 /etc/letsencrypt/renewal-hooks/{pre,post,deploy}/50-nixz
systemctl daemon-reload
systemctl enable --now nixz-monitor.timer
echo 'Route auto-deployment is installed, DISABLED by default. Enable after PR merge and external acceptance:'
echo 'sudo systemctl enable --now nixz-routes.timer'
echo 'After TLS enabled: sudo systemctl enable --now certbot.timer; sudo certbot renew --dry-run'
