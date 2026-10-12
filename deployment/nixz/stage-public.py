#!/usr/bin/env python3
"""Preflight public mode without modifying production settings or firewall."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path('/opt/nixz/repo/deployment/nixz')


def main():
    if os.geteuid() != 0 or Path(__file__).resolve().parent != ROOT:
        raise SystemExit('Run with sudo from the reviewed /opt/nixz/repo checkout')
    code = Path(__file__).stat()
    if code.st_uid != 0 or code.st_mode & 0o022:
        raise SystemExit('Reviewed code must be root-owned and not group/world-writable')
    node = json.loads(Path('/etc/nixz/node.json').read_text())
    if not node['tls'] or node['ipv6_verified']:
        raise SystemExit('Trusted production TLS and IPv4-only configuration required')
    node.update(access_mode='public', public_access_ack=True)
    with tempfile.TemporaryDirectory(prefix='nixz-public-stage-') as temp:
        path = Path(temp)
        config = path / 'node.json'
        config.write_text(json.dumps(node, indent=2) + '\n')
        config.chmod(0o600)
        values = dict(line.split('=', 1) for line in Path('/opt/nixz/current/images.env').read_text().splitlines()
                      if line and not line.startswith('#'))
        values['NGINX_IMAGE'] = 'nginx:1.31.6-alpine'
        images = path / 'images.env'
        images.write_text('\n'.join(f'{k}={v}' for k, v in values.items()) + '\n')
        images.chmod(0o600)
        env = dict(os.environ, NIXZ_NODE_FILE=str(config), NIXZ_IMAGES_FILE=str(images),
                   NIXZ_ROUTES_FILE='/opt/nixz/current/routes.json')
        subprocess.run(['bash', str(ROOT / 'deploy.sh'), '--dry-run'], env=env, check=True)
    print('PUBLIC PREFLIGHT PASSED. Live node settings, containers and firewall were not changed.')


if __name__ == '__main__':
    main()
