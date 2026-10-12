#!/usr/bin/env python3
"""Real isolated source-identity, DNS rate, connection and header-forgery checks."""
import json
from pathlib import Path
import socket
import ssl
import struct
import sys
import httpx
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from probe import query, parse, receive

release = Path(sys.argv[1])
host = json.loads((release / 'node.json').read_text())['hostname']
ctx = ssl.create_default_context(cafile=str(release / 'certs/fullchain.pem'))
ctx.set_alpn_protocols(['h2'])
name = 'chatgpt.com'


def dot(source):
    raw = socket.socket()
    raw.settimeout(5)
    raw.bind((source, 0))
    raw.connect(('127.0.0.1', 853))
    return ctx.wrap_socket(raw, server_hostname=host)


def send_dns(peer, request):
    peer.sendall(struct.pack('!H', len(request)) + request)
    response = receive(peer, struct.unpack('!H', receive(peer, 2))[0])
    return parse(response, request)


def doh(source):
    request = query(name)
    transport = httpx.HTTPTransport(local_address=source, http1=False, http2=True,
                                    verify=ctx, trust_env=False)
    with httpx.Client(transport=transport, timeout=5, trust_env=False) as client:
        response = client.post('https://127.0.0.1/dns-query', content=request,
                               headers={'Host': host, 'Content-Type': 'application/dns-message',
                                        'X-Forwarded-For': '192.0.2.99'},
                               extensions={'sni_hostname': host})
        assert response.status_code == 200 and response.http_version == 'HTTP/2'
        return parse(response.content, request)


with dot('127.0.0.2') as peer:
    requests = [query(name) for _ in range(500)]
    peer.sendall(b''.join(struct.pack('!H', len(q)) + q for q in requests))
    replies = [parse(receive(peer, struct.unpack('!H', receive(peer, 2))[0]), q) for q in requests]
    assert any(r['rcode'] == 5 for r in replies), 'Source query flood was not limited'
    # Same IP and a new connection must not reset the limit; the forged HTTP header must not help.
    assert doh('127.0.0.2')['rcode'] == 5, 'DoH did not share the actual-source limit'
    assert doh('127.0.0.3')['rcode'] == 0, 'Independent source was charged as loopback/flood source'
    with dot('127.0.0.3') as other:
        assert send_dns(other, query(name))['rcode'] == 0
print('PROXYv2 identity, per-source rate and cross-transport isolation passed')

for port in (443, 853):
    with socket.socket() as raw:
        raw.settimeout(3)
        raw.bind(('127.0.0.5', 0))
        raw.connect(('127.0.0.1', port))
        fake = b'\r\n\r\n\x00\r\nQUIT\n' + b'\x21\x11\x00\x0c'
        fake += socket.inet_aton('127.0.0.1') + socket.inet_aton('127.0.0.1') + struct.pack('!HH', 12345, port)
        raw.sendall(fake)
        try:
            peer = ctx.wrap_socket(raw, server_hostname=host)
        except (OSError, ssl.SSLError):
            pass
        else:
            peer.close()
            raise AssertionError('External forged PROXY header accepted')
print('External forged PROXY header rejection passed')

held = []
try:
    for _ in range(16):
        held.append(dot('127.0.0.4'))
    try:
        extra = dot('127.0.0.4')
    except (OSError, ssl.SSLError):
        pass
    else:
        extra.close()
        raise AssertionError('Per-source connection cap not enforced')
finally:
    for peer in held:
        peer.close()
print('Per-source concurrent TLS connection cap passed')
