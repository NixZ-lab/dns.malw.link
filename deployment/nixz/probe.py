#!/usr/bin/env python3
"""Real DNS/TLS probes. curl must support HTTP/2. No certificate bypass."""
import argparse
import base64
import datetime
import json
from pathlib import Path
import secrets
import socket
import ssl
import struct
import subprocess
import tempfile
from nixz import ROOT, load, verify_peer


def query(name, qtype=1):
    ident = secrets.randbelow(65536)
    wire = struct.pack('!6H', ident, 0x0100, 1, 0, 0, 0)
    wire += b''.join(bytes([len(label)]) + label.encode('ascii') for label in name.split('.'))
    return wire + b'\0' + struct.pack('!2H', qtype, 1)


def skip_name(data, offset):
    for _ in range(128):
        size = data[offset]
        if size & 0xc0 == 0xc0:
            return offset + 2
        if size & 0xc0:
            raise ValueError('Invalid DNS label')
        offset += size + 1
        if size == 0:
            return offset
    raise ValueError('Invalid DNS name')


def parse(data, request):
    ident, flags, questions, answers, _, _ = struct.unpack('!6H', data[:12])
    if ident != struct.unpack('!H', request[:2])[0] or not flags & 0x8000 or flags & 0x0200:
        raise ValueError('Invalid, truncated, or mismatched DNS response')
    pos = 12
    for _ in range(questions):
        pos = skip_name(data, pos) + 4
    ips = []
    for _ in range(answers):
        pos = skip_name(data, pos)
        qtype, cls, ttl, size = struct.unpack('!HHIH', data[pos:pos + 10])
        pos += 10
        raw = data[pos:pos + size]
        if qtype == 1 and cls == 1 and size == 4:
            ips.append(socket.inet_ntop(socket.AF_INET, raw))
        if qtype == 28 and cls == 1 and size == 16:
            ips.append(socket.inet_ntop(socket.AF_INET6, raw))
        pos += size
    return {'rcode': flags & 15, 'answers': answers, 'ips': sorted(ips), 'ad': bool(flags & 0x20)}


def receive(sock, count):
    result = b''
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise ValueError('Premature EOF')
        result += part
    return result


def dns_query(name, qtype, mode, address, hostname, ca=None):
    request = query(name, qtype)
    if mode == 'udp':
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)
            sock.connect((address, 5300))
            sock.send(request)
            response = sock.recv(65535)
    elif mode == 'dot':
        ctx = ssl.create_default_context(cafile=ca)
        with socket.create_connection((address, 853), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as sock:
                sock.sendall(struct.pack('!H', len(request)) + request)
                response = receive(sock, struct.unpack('!H', receive(sock, 2))[0])
    else:
        dns = base64.urlsafe_b64encode(request).rstrip(b'=').decode()
        cmd = ['curl', '--noproxy', '*', '--http2', '--fail', '--silent', '--show-error',
               '--connect-timeout', '5', '--max-time', '15', '--resolve',
               f'{hostname}:443:{"[" + address + "]" if ":" in address else address}',
               '-H', 'Accept: application/dns-message']
        if ca:
            cmd += ['--cacert', ca]
        response = subprocess.check_output(cmd + [f'https://{hostname}/dns-query?dns={dns}'])
    return parse(response, request)


def require(condition, text):
    if not condition:
        raise ValueError(text)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--release', type=Path, required=True)
    parser.add_argument('--address', default='127.0.0.1')
    parser.add_argument('--external', action='store_true')
    parser.add_argument('--ca', help='CI-only test CA; never install on production devices')
    parser.add_argument('--skip-upstream', action='store_true', help='CI only; no production evidence')
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    routes, node, proxy, records = load(args.release / 'routes.json', args.release / 'node.json')
    require(not args.external or (args.address != '127.0.0.1' and not args.ca and not args.skip_upstream),
            'External evidence requires public address, trusted TLS and upstream checks')
    require(node['tls'] or not args.external, 'External acceptance requires TLS')
    modes = ['doh', 'dot'] if node['tls'] else ['udp']
    if not args.external:
        modes.append('udp') if 'udp' not in modes else None
    result = {'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'external': args.external, 'address': args.address, 'hostname': node['hostname'],
              'test_ca': bool(args.ca), 'dns': [], 'sni': [], 'client_test': 'PENDING',
              'manifest_sha256': __import__('hashlib').sha256((args.release / 'manifest.json').read_bytes()).hexdigest()}
    expected4 = routes['nodes'][node['node']]['ipv4']
    expected6 = [routes['nodes'][node['node']]['ipv6']] if node['ipv6_verified'] else []
    for mode in modes:
        for name in proxy:
            for qtype, expected in [(1, [expected4]), (28, expected6), (64, []), (65, [])]:
                answer = dns_query(name, qtype, mode, args.address, node['hostname'], args.ca)
                require(answer['rcode'] == 0 and answer['ips'] == expected and not answer['ad'],
                        f'{mode} wrong rewrite: {name}/{qtype} {answer}')
                if qtype in [64, 65] or (qtype == 28 and not expected6):
                    require(answer['answers'] == 0, 'SVCB/HTTPS or IPv6 bypass')
                result['dns'].append({'transport': mode, 'name': name, 'qtype': qtype, **answer})
        for name in routes['blocked']:
            require(dns_query(name, 1, mode, args.address, node['hostname'], args.ca)['rcode'] == 3,
                    'Block rule failed')
        if not args.skip_upstream:
            answer = dns_query('example.org', 1, mode, args.address, node['hostname'], args.ca)
            require(answer['rcode'] == 0 and answer['ips'] and expected4 not in answer['ips'], 'Recursion failed')
            result['dns'].append({'transport': mode, 'name': 'example.org', **answer})
    for name in proxy:
        result['sni'].append(verify_peer(name, args.address))
        cmd = ['curl', '--noproxy', '*', '--silent', '--show-error', '--max-time', '15',
               '--resolve', f'{name}:443:{args.address}', '--output', '/dev/null',
               '--write-out', '%{http_code}', f'https://{name}/']
        result['sni'][-1]['http_status'] = subprocess.check_output(cmd).decode()
    for name in ['example.org', 'localhost', '169.254.169.254', 'chatgpt.com.evil.invalid']:
        # Negative test: detect ANY completed handshake, even with a wrong certificate.
        negative = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        negative.check_hostname = False
        negative.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((args.address, 443), timeout=5) as raw:
                with negative.wrap_socket(raw, server_hostname=name):
                    pass
        except (OSError, ssl.SSLError):
            pass
        else:
            raise ValueError(f'Unauthorized SNI accepted: {name}')
    with socket.create_connection((args.address, 443), timeout=5) as raw:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        try:
            with ctx.wrap_socket(raw, server_hostname=None):
                raise ValueError('Missing SNI accepted')
        except (OSError, ssl.SSLError):
            pass
    if args.external:
        try:
            with socket.create_connection((args.address, 53), timeout=3):
                raise ValueError('Public TCP 53 open')
        except OSError:
            pass
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.sendto(query('example.org'), (args.address, 53))
            try:
                sock.recvfrom(65535)
                raise ValueError('Public UDP 53 responded')
            except OSError:
                pass
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
