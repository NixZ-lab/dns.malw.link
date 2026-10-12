#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID == 0 && ${1:-} == --fresh-ssh-and-console-tested ]] || exit 1
ufw status | grep -q 'Status: active' || { echo 'Run bootstrap and verify new SSH first'; exit 1; }
systemctl is-active --quiet nixz-firewall-rescue.timer && { echo 'Confirm second SSH login and stop rescue timer first'; exit 1; }
python3 "$(dirname "$0")/nixz.py" validate --node /etc/nixz/node.json
# Host-network containers have no Docker published ports or DNAT. UFW INPUT applies.
python3 - <<'PY'
import json, subprocess
node = json.load(open('/etc/nixz/node.json'))
for cidr in node['client_cidrs']:
    for port in ['443', '853'] if node['tls'] else ['443']:
        subprocess.run(['ufw', 'allow', 'from', cidr, 'to', 'any', 'port', port,
                        'proto', 'tcp', 'comment', 'nixz-clients'], check=True)
PY
ufw status numbered
echo 'No 53/UDP or 443/UDP rules added. Remove obsolete client rules manually by their current number.'
