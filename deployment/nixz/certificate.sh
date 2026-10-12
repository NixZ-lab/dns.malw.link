#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID == 0 ]] || exit 1
cd "$(dirname "$0")"
install -d -m 700 /etc/nixz
if [[ ! -f /etc/nixz/domain-proof ]]; then
  openssl rand -hex 24 > /etc/nixz/domain-proof
  chmod 600 /etc/nixz/domain-proof
fi
hostname=$(python3 -c 'import json; print(json.load(open("/etc/nixz/node.json"))["hostname"])')
[[ -n $hostname ]] || { echo 'Set your real hostname in /etc/nixz/node.json first'; exit 1; }
if [[ ${1:-} != --issue ]]; then
  printf 'In the DNS zone you control, add TXT _nixz-owner.%s with value: ' "$hostname"
  cat /etc/nixz/domain-proof
  echo 'Also add A for this hostname to your node IPv4. Leave AAAA absent until IPv6 verified.'
  echo 'After propagation: sudo bash certificate.sh --issue (prompts for ACME contact email)'
  exit
fi
python3 - <<'PY'
from nixz import load, resolve_json
from pathlib import Path
routes, node, _, _ = load('routes.json', '/etc/nixz/node.json')
expected = routes['nodes'][node['node']]
proof = Path('/etc/nixz/domain-proof').read_text().strip()
for response in resolve_json('_nixz-owner.' + node['hostname'], 'TXT'):
    values = {x['data'].strip('"') for x in response.get('Answer', []) if x['type'] == 16}
    if proof not in values:
        raise SystemExit('Domain-control TXT not verified by both independent resolvers')
for response in resolve_json(node['hostname'], 'A'):
    values = {x['data'] for x in response.get('Answer', []) if x['type'] == 1}
    if values != {expected['ipv4']}:
        raise SystemExit('Public A must point only to this node')
for response in resolve_json(node['hostname'], 'AAAA'):
    values = {x['data'] for x in response.get('Answer', []) if x['type'] == 28}
    wanted = {expected['ipv6']} if node['ipv6_verified'] else set()
    if values != wanted:
        raise SystemExit('Unexpected AAAA; remove it or verify IPv6 first')
PY
ss -lnt | grep -qE ':80[[:space:]]' && { echo 'Port 80 occupied'; exit 1; }
ufw status | grep -q 'Status: active' || exit 1
read -r -p 'ACME email (stored only on VPS): ' email
python3 - "$email" <<'PY'
import re
import sys

address = sys.argv[1]
if not (address.isascii() and address.isprintable()
        and re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', address)):
    raise SystemExit('Invalid ACME email: type an ASCII address without spaces or hidden characters.')
PY
# Keep renewal restricted to standalone HTTP-01 on 80; no broad firewall reset.
ufw allow 80/tcp comment 'nixz-acme-temporary'
trap 'ufw --force delete allow 80/tcp' EXIT
certbot certonly --standalone --non-interactive --agree-tos --email "$email" -d "$hostname"
echo 'Certificate issued. Set tls=true locally, run deploy dry-run/apply, then firewall.sh.'
echo 'Run install-services.sh to install renewal hooks and monitoring.'
