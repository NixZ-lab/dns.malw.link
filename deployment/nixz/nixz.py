#!/usr/bin/env python3
"""Validate routes and compile an immutable release; no production API writes."""
import argparse
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import struct
import urllib.parse

ROOT = Path(__file__).resolve().parent
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def domain(value):
    if not isinstance(value, str) or value != value.lower() or len(value) > 253:
        raise ValueError(f"Invalid domain: {value!r}")
    if len(value.split('.')) < 2 or not all(LABEL.fullmatch(x) for x in value.split('.')):
        raise ValueError(f"Exact ASCII FQDN required: {value!r}")
    return value


def public_ip(value, family=None):
    ip = ipaddress.ip_address(value)
    if not ip.is_global or ip.is_multicast or (family and ip.version != family):
        raise ValueError(f"Non-public or wrong-family IP: {value}")
    return str(ip)


def load(routes_path, node_path):
    routes = json.loads(Path(routes_path).read_text())
    node = json.loads(Path(node_path).read_text())
    if routes.get('schema') != 1:
        raise ValueError('Unsupported schema')
    for name, entry in routes['nodes'].items():
        if not re.fullmatch(r'[a-z0-9-]+', name):
            raise ValueError('Invalid node name')
        public_ip(entry['ipv4'], 4)
        if entry.get('ipv6'):
            public_ip(entry['ipv6'], 6)
    selected = routes['nodes'][node['node']]
    if type(node['tls']) is not bool or type(node['ipv6_verified']) is not bool:
        raise ValueError('Boolean flags required')
    if node.get('hostname'):
        domain(node['hostname'])
    if node['tls'] and not node.get('hostname'):
        raise ValueError('TLS requires a real hostname')
    if node['ipv6_verified'] and not selected.get('ipv6'):
        raise ValueError('IPv6 flag requires node IPv6')
    if not node['client_cidrs']:
        raise ValueError('Set client_cidrs locally; refuse an open service')
    for cidr in node['client_cidrs']:
        net = ipaddress.ip_network(cidr, strict=True)
        public_ip(str(net.network_address))
        public_ip(str(net.broadcast_address))
        if net.prefixlen < (24 if net.version == 4 else 64):
            raise ValueError('Client CIDR too broad; prefer /32 or /128')
    if type(node['ttl']) is not int or not 30 <= node['ttl'] <= 300:
        raise ValueError('TTL must be 30..300')
    for domains in routes['groups'].values():
        for item in domains:
            domain(item)
        if len(domains) != len(set(domains)):
            raise ValueError('Duplicate domain within a group')
    exclude = {domain(d) for d in routes['exclude']}
    blocked = {domain(d) for d in routes['blocked']}
    proxy = set()
    for group in routes['enabled_groups']:
        proxy.update(routes['groups'][group])
    proxy -= exclude
    if not proxy or len(proxy) > 100:
        raise ValueError('Proxy list empty or exceeds the v1 safety limit')
    records = routes['records'].copy()
    for name, addresses in records.items():
        domain(name)
        if not addresses:
            raise ValueError('Empty static record')
        for address in addresses:
            public_ip(address)
    if blocked & (proxy | set(records)) or proxy & set(records):
        raise ValueError('Contradictory route/block/static record')
    if node.get('hostname'):
        if node['hostname'] in proxy | blocked | set(records):
            raise ValueError('DNS hostname overlaps another rule')
        records[node['hostname']] = [selected['ipv4']]
        if node['ipv6_verified']:
            records[node['hostname']].append(selected['ipv6'])
    return routes, node, sorted(proxy), records


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, hostname, address, port=443, context=None):
        super().__init__(hostname, port, timeout=10, context=context)
        self.address = address

    def connect(self):
        raw = socket.create_connection((self.address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def resolve_json(name, qtype):
    results = []
    for host, ip, path in [('dns.google', '8.8.8.8', '/resolve'),
                           ('cloudflare-dns.com', '1.1.1.1', '/dns-query')]:
        conn = PinnedHTTPS(host, ip)
        try:
            query = urllib.parse.urlencode({'name': name, 'type': qtype})
            conn.request('GET', path + '?' + query, headers={'Accept': 'application/dns-json'})
            response = conn.getresponse()
            if response.status != 200:
                raise ValueError(f'{host}: HTTP {response.status}')
            data = json.loads(response.read(65536))
            if data['Status'] not in [0, 3]:
                raise ValueError(f'{host}: DNS status {data["Status"]} for {name}')
            results.append(data)
        finally:
            conn.close()
    return results


def resolve_public(name):
    answers = set()
    for data in resolve_json(name, 'A'):
        current = {public_ip(rr['data'], 4) for rr in data.get('Answer', []) if rr['type'] == 1}
        if data['Status'] != 0 or not current:
            raise ValueError(f'No public A answer for {name}')
        answers.update(current)
    return sorted(answers)


def verify_peer(name, address, port=443, ca=None):
    context = ssl.create_default_context(cafile=ca)
    with socket.create_connection((address, port), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=name) as peer:
            return {'name': name, 'address': address, 'tls': peer.version(),
                    'certificate_sha256': hashlib.sha256(peer.getpeercert(binary_form=True)).hexdigest()}


def compile_release(routes, node, proxy, records, pins, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    selected = routes['nodes'][node['node']]
    own_ips = {ip for n in routes['nodes'].values() for ip in (n['ipv4'], n.get('ipv6')) if ip}
    if set(pins) != set(proxy):
        raise ValueError('Pin set must exactly match enabled proxy domains')
    for name, addresses in pins.items():
        if not addresses or len(addresses) > 32:
            raise ValueError('Invalid upstream pin count')
        for ip in addresses:
            public_ip(ip, 4)
            if ip in own_ips:
                raise ValueError(f'DNS loop: {name} resolves to our VPS')
    allow = ['allow 127.0.0.1;', 'allow ::1;']
    allow += [f'allow {cidr};' for cidr in node['client_cidrs']]
    allow += ['deny all;']
    upstreams, mapping = [], []
    for index, name in enumerate(proxy):
        backend = f'service_{index}'
        upstreams.append('upstream ' + backend + ' {\n' + '\n'.join(
            f'    server {ip}:443 max_fails=2 fail_timeout=10s;' for ip in pins[name]) + '\n}')
        mapping.append(f'    {name} {backend};')
    if node['tls']:
        mapping.append(f'    {node["hostname"]} 127.0.0.1:8443;')
    listen6 = '\n        listen [::]:443 ipv6only=on;' if node['ipv6_verified'] else ''
    dot6 = '\n        listen [::]:853 ipv6only=on;' if node['ipv6_verified'] else ''
    dot = ''
    if node['tls']:
        dot = f'''    server {{
        listen 0.0.0.0:853;{dot6}
        include /config/clients.conf;
        limit_conn per_client 32;
        proxy_pass 127.0.0.1:8853;
        proxy_connect_timeout 5s;
        proxy_timeout 60s;
    }}'''
    nginx = '''user nginx;
worker_processes 1;
pid /tmp/nginx.pid;
error_log /dev/stderr warn;
events { worker_connections 1024; }
stream {
    log_format route '$time_iso8601 $remote_addr $ssl_preread_server_name $upstream_addr $status $session_time';
    access_log /dev/stdout route;
    limit_conn_zone $binary_remote_addr zone=per_client:1m;
''' + '\n'.join(upstreams) + '''
    map $ssl_preread_server_name $target {
        default 127.0.0.1:9444;
''' + '\n'.join(mapping) + '''
    }
    server { listen 127.0.0.1:9444; return ""; }
    server {
        listen 0.0.0.0:443;''' + listen6 + '''
        include /config/clients.conf;
        ssl_preread on;
        preread_timeout 10s;
        limit_conn per_client 32;
        proxy_pass $target;
        proxy_connect_timeout 5s;
        proxy_timeout 300s;
    }
''' + dot + '\n}\n'
    lua = ['setLocal("127.0.0.1:5300")', 'setACL({"127.0.0.1/32", "::1/128"})',
           'setSecurityPollSuffix("")', 'setMaxTCPClientThreads(2)',
           'setMaxTCPQueuedConnections(128)',
           'setMaxTCPConnectionsPerClient(64)',
           'addAction(AllRule(), QPSAction(200))',
           'addAction(QTypeRule(DNSQType.ANY), RCodeAction(DNSRCode.REFUSED))',
           'newServer({address="1.1.1.1:853", tls="openssl", subjectName="cloudflare-dns.com", validateCertificates=true})',
           'newServer({address="9.9.9.9:853", tls="openssl", subjectName="dns.quad9.net", validateCertificates=true})',
           'getPool(""):setCache(newPacketCache(10000, {maxTTL=300, temporaryFailureTTL=5, staleTTL=0}))']
    if node['tls']:
        lua += ['addDOHLocal("127.0.0.1:8443", "/config/certs/fullchain.pem", "/config/certs/privkey.pem", {"/dns-query"})',
                'addTLSLocal("127.0.0.1:8853", "/config/certs/fullchain.pem", "/config/certs/privkey.pem")']
    for name in sorted(routes['blocked']):
        lua.append(f'addAction(QNameRule("{name}"), RCodeAction(DNSRCode.NXDOMAIN))')
    redirect = records.copy()
    for name in proxy:
        redirect[name] = [selected['ipv4']]
        if node['ipv6_verified']:
            redirect[name].append(selected['ipv6'])
    for name, addresses in sorted(redirect.items()):
        for version, qtype in [(4, 'A'), (6, 'AAAA')]:
            ips = [ip for ip in addresses if ipaddress.ip_address(ip).version == version]
            action = ('SpoofAction({' + ','.join(json.dumps(ip) for ip in ips) +
                      '}, {ttl=' + str(node['ttl']) + ', ad=false})') if ips else 'RCodeAction(DNSRCode.NOERROR)'
            lua.append(f'addAction(AndRule({{QNameRule("{name}"), QTypeRule(DNSQType.{qtype})}}), {action})')
        if name in proxy:
            for qtype in [64, 65]:
                lua.append(f'addAction(AndRule({{QNameRule("{name}"), QTypeRule({qtype})}}), RCodeAction(DNSRCode.NOERROR))')
    hosts = '# NixZ own routes only. No NextDNS write authorization.\n'
    hosts += ''.join(f'{ip} {name}\n' for name, ips in sorted(redirect.items()) for ip in ips)
    hosts += ''.join(f'0.0.0.0 {name}\n' for name in sorted(routes['blocked']))
    adguard = ''.join(f'||{name}^$dnsrewrite=NOERROR;{"AAAA" if ":" in ip else "A"};{ip}\n'
                      for name, ips in sorted(redirect.items()) for ip in ips)
    files = {'nginx.conf': nginx, 'clients.conf': '\n'.join(allow) + '\n',
             'dnsdist.conf': '\n'.join(lua) + '\n', 'hosts': hosts, 'adguard.txt': adguard,
             'pins.json': json.dumps(pins, indent=2) + '\n',
             'routes.json': json.dumps(routes, indent=2) + '\n',
             'node.json': json.dumps(node, indent=2) + '\n'}
    for name, content in files.items():
        (output / name).write_text(content)
    manifest = {name: hashlib.sha256(content.encode()).hexdigest() for name, content in files.items()}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['validate', 'render'])
    parser.add_argument('--routes', default=ROOT / 'routes.json', type=Path)
    parser.add_argument('--node', default=ROOT / 'node.json', type=Path)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    routes, node, proxy, records = load(args.routes, args.node)
    print(json.dumps({'node': node['node'], 'tls': node['tls'], 'proxy': proxy, 'blocked': routes['blocked']}, indent=2))
    if args.action == 'render':
        if not args.out:
            parser.error('--out required')
        pins = {name: resolve_public(name) for name in proxy}
        for name, ips in pins.items():
            for ip in ips:
                verify_peer(name, ip)
        compile_release(routes, node, proxy, records, pins, args.out)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError) as error:
        raise SystemExit(str(error)) from error
