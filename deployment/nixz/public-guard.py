#!/usr/bin/env python3
"""Explicit public ingress activation with a persistent, fail-closed traffic guard."""
import argparse
import fcntl
import hashlib
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

STATE_DIR = Path('/var/lib/nixz-public')
STATE = STATE_DIR / 'guard.json'
SCRIPT = Path('/opt/nixz/repo/deployment/nixz/public-guard.py')


def evaluate(state, rx, tx, boot, day):
    if state.get('latched'):
        return state, 'already stopped'
    if boot != state['boot'] or rx < state['rx'] or tx < state['tx']:
        return state, 'reboot or interface counter reset'
    used = state['used'] + rx - state['rx'] + tx - state['tx']
    # Charge the whole sampling interval before resetting a day, conservatively.
    reason = 'daily traffic budget reached' if used >= state['budget'] else None
    new = dict(state, rx=rx, tx=tx, used=used, day=day)
    if day != state['day'] and not reason:
        new['used'] = 0
    return new, reason


def save(state):
    fd, name = tempfile.mkstemp(dir=STATE_DIR, prefix='.guard-')
    try:
        with os.fdopen(fd, 'w') as out:
            json.dump(state, out, indent=2)
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, STATE)
    finally:
        Path(name).unlink(missing_ok=True)


def sample(interface):
    if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,32}', interface):
        raise ValueError('Invalid interface')
    base = Path('/sys/class/net') / interface / 'statistics'
    return (int((base / 'rx_bytes').read_text()), int((base / 'tx_bytes').read_text()),
            Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            datetime.now(timezone.utc).strftime('%Y-%m-%d'))


def rule(action, port, dry_run=False):
    if action not in ('allow', 'delete') or port not in (443, 853):
        raise ValueError('Only guarded TCP443/853 rules are permitted')
    command = ['ufw']
    if dry_run:
        command += ['--dry-run']
    if action == 'delete':
        command += ['--force', 'delete']
    command += ['allow', 'from', '0.0.0.0/0', 'to', 'any',
                'port', str(port), 'proto', 'tcp']
    subprocess.run(command, check=True, timeout=15)


def stop(state, reason):
    state.update(latched=True, reason=reason)
    save(state)
    # Stop existing tunnels too, not just new connections. SSH and dnsdist are untouched.
    subprocess.run(['docker', 'stop', '--timeout', '2', 'nixz-nginx-1'], check=True, timeout=15)
    status = subprocess.check_output(['ufw', 'status'], text=True)
    for port in (443, 853):
        if re.search(r'^\s*' + str(port) + r'/tcp\s+ALLOW IN\s+Anywhere\s*$', status, re.M):
            rule('delete', port)
    print('Public ingress stopped:', reason, '; restore private mode via reviewed deploy.sh')


def arm(interface, budget, fresh):
    if not fresh:
        raise ValueError('Fresh key SSH and working provider console must be confirmed')
    if STATE.exists():
        raise ValueError('Guard state already exists; do not silently reset the budget/latch')
    code = SCRIPT.stat()
    if code.st_uid != 0 or code.st_mode & 0o022:
        raise ValueError('Install guard in the root-owned reviewed repo first')
    node = json.loads(Path('/opt/nixz/current/node.json').read_text())
    if node.get('access_mode') != 'public' or node.get('public_access_ack') is not True:
        raise ValueError('Deploy and verify the public candidate before opening ingress')
    local = Path('/opt/nixz/current/local-evidence.json')
    if not local.exists():
        raise ValueError('Missing local acceptance evidence')
    evidence = json.loads(local.read_text())
    manifest = hashlib.sha256(Path('/opt/nixz/current/manifest.json').read_bytes()).hexdigest()
    if evidence.get('test_ca') is not False or evidence.get('manifest_sha256') != manifest:
        raise ValueError('Trusted local acceptance must match the active release')
    status = subprocess.check_output(['ufw', 'status'], text=True)
    if 'Status: active' not in status:
        raise ValueError('UFW must already be active')
    if re.search(r'^\s*(443|853)/tcp\s+ALLOW IN\s+Anywhere', status, re.M):
        raise ValueError('Pre-existing public rule: inspect ownership instead of replacing it')
    # Validate actual UFW command parsing before state, timers or ingress change.
    for port in (443, 853):
        rule('allow', port, dry_run=True)
    for cidr in node['client_cidrs']:
        ipaddress.ip_network(cidr, strict=True)
    rx, tx, boot, day = sample(interface)
    state = dict(interface=interface, budget=budget, used=0, rx=rx, tx=tx,
                 boot=boot, day=day, latched=False)
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    save(state)
    service = '''[Unit]
Description=NixZ public traffic budget guard
After=docker.service network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/nixz/repo/deployment/nixz/public-guard.py --check
UMask=0077
TimeoutStartSec=45
'''
    timer = '''[Unit]
Description=Check NixZ public traffic budget every 15 seconds
[Timer]
OnBootSec=5s
OnUnitActiveSec=15s
AccuracySec=1s
[Install]
WantedBy=timers.target
'''
    Path('/etc/systemd/system/nixz-public-guard.service').write_text(service)
    Path('/etc/systemd/system/nixz-public-guard.timer').write_text(timer)
    try:
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        subprocess.run(['systemctl', 'enable', '--now', 'nixz-public-guard.timer'], check=True)
        subprocess.run(['systemctl', 'is-active', '--quiet', 'nixz-public-guard.timer'], check=True)
        for port in (443, 853):
            rule('allow', port)
    except Exception:
        stop(state, 'incomplete activation')
        raise
    print('Public IPv4 TCP443/853 enabled; daily RX+TX budget:', budget, 'bytes')


def main():
    p = argparse.ArgumentParser()
    m = p.add_mutually_exclusive_group(required=True)
    m.add_argument('--arm', action='store_true')
    m.add_argument('--check', action='store_true')
    m.add_argument('--close', action='store_true')
    m.add_argument('--firewall-preflight', action='store_true')
    p.add_argument('--interface', default='ens3')
    p.add_argument('--budget-gib', type=int, default=2, choices=range(1, 11))
    p.add_argument('--fresh-ssh-and-console-tested', action='store_true')
    a = p.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('sudo required')
    if a.firewall_preflight:
        for port in (443, 853):
            rule('allow', port, dry_run=True)
        print('UFW syntax preflight passed. No rules, timers or containers changed.')
        return
    lock = open('/run/nixz-public.lock', 'a')
    fcntl.flock(lock, fcntl.LOCK_EX)
    if a.arm:
        arm(a.interface, a.budget_gib * 1024 ** 3, a.fresh_ssh_and_console_tested)
        return
    try:
        node = json.loads(Path('/opt/nixz/current/node.json').read_text())
        if node.get('access_mode', 'private') != 'public':
            print('Private release active; guard does not stop private service')
            return
        state = json.loads(STATE.read_text())
        current, reason = evaluate(state, *sample(state['interface']))
        if reason or a.close:
            stop(current, reason or 'operator requested closure')
        else:
            save(current)
            print('Traffic:', current['used'], '/', current['budget'])
    except Exception:
        subprocess.run(['docker', 'stop', '--timeout', '2', 'nixz-nginx-1'], timeout=15)
        raise


if __name__ == '__main__':
    main()
