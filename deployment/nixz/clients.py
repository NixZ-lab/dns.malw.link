#!/usr/bin/env python3
"""Generate clients only after trusted, recent external evidence for this release."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import plistlib
import uuid
from nixz import load


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--release', required=True, type=Path)
    p.add_argument('--evidence', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    a = p.parse_args()
    routes, node, _, _ = load(a.release / 'routes.json', a.release / 'node.json')
    e = json.loads(a.evidence.read_text())
    address = routes['nodes'][node['node']]['ipv4']
    age = datetime.datetime.now(datetime.timezone.utc) - datetime.datetime.fromisoformat(e['utc'])
    manifest = hashlib.sha256((a.release / 'manifest.json').read_bytes()).hexdigest()
    if (not node['tls'] or not e['external'] or e['test_ca'] or e['hostname'] != node['hostname']
            or e['address'] != address or not 0 <= age.total_seconds() < 86400
            or e['manifest_sha256'] != manifest or {x['transport'] for x in e['dns']} != {'doh', 'dot'}):
        raise SystemExit('Recent trusted external acceptance for this exact release is required')
    host = node['hostname']
    url = f'https://{host}/dns-query'
    profile = {
        'PayloadType': 'Configuration', 'PayloadVersion': 1,
        'PayloadIdentifier': f'net.nixz.dns.{node["node"]}', 'PayloadUUID': str(uuid.uuid4()),
        'PayloadDisplayName': f'NixZ DNS {node["node"]}', 'PayloadRemovalDisallowed': False,
        'PayloadContent': [{
            'PayloadType': 'com.apple.dnsSettings.managed', 'PayloadVersion': 1,
            'PayloadIdentifier': f'net.nixz.dns.{node["node"]}.settings', 'PayloadUUID': str(uuid.uuid4()),
            'PayloadDisplayName': 'NixZ encrypted DNS',
            'DNSSettings': {'DNSProtocol': 'HTTPS', 'ServerURL': url, 'ServerAddresses': [address]},
            'OnDemandRules': [{'Action': 'Connect'}]
        }]
    }
    a.out.mkdir(parents=True, exist_ok=False)
    (a.out / 'NixZ-DNS.mobileconfig').write_bytes(plistlib.dumps(profile))
    instructions = f'''Windows 11: DNS IPv4 {address}, DoH template {url}, encrypted only (no plaintext fallback).
Android: Private DNS provider hostname {host}. No URL, no port.
Apple: install NixZ-DNS.mobileconfig only for the personal-device test; remove or switch DNS profile to return to NextDNS.
Current node count: 1. There is no automatic failover yet.
Source CIDR must be allowed on the VPS. Test iPhone with all VPNs OFF, over Wi-Fi and cellular separately.
Client acceptance remains PENDING even after these server tests.
'''
    (a.out / 'connection.txt').write_text(instructions)
    print(a.out)


if __name__ == '__main__':
    main()
