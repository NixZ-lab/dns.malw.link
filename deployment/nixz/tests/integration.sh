#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
temp=$(mktemp -d)
export RELEASE_DIR="$temp/release"
cleanup() {
  docker compose -f compose.yaml logs --tail=40 || true
  docker compose -f compose.yaml down || true
  sudo rm -rf "$temp"
}
trap cleanup EXIT
python3 - "$temp/node.json" <<'PY'
import json, sys
from pathlib import Path
data = json.loads(Path('node.json.example').read_text())
data.update(hostname='dns.nixz-ci.invalid', tls=True, client_cidrs=['8.8.8.8/32'])
Path(sys.argv[1]).write_text(json.dumps(data))
PY
python3 nixz.py render --node "$temp/node.json" --out "$RELEASE_DIR"
mkdir "$RELEASE_DIR/certs"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=dns.nixz-ci.invalid' \
  -addext 'subjectAltName=DNS:dns.nixz-ci.invalid' \
  -keyout "$RELEASE_DIR/certs/privkey.pem" -out "$RELEASE_DIR/certs/fullchain.pem" 2>/dev/null
chmod 755 "$temp" "$RELEASE_DIR"
sudo chown -R 65532:65532 "$RELEASE_DIR/certs"
sudo chmod 700 "$RELEASE_DIR/certs"
sudo chmod 400 "$RELEASE_DIR/certs/privkey.pem"
docker compose -f compose.yaml config --quiet
docker compose -f compose.yaml pull
docker compose -f compose.yaml run --rm --no-deps nginx -c /config/nginx.conf -t
docker compose -f compose.yaml run --rm --no-deps dnsdist --check-config -C /config/dnsdist.conf
docker compose -f compose.yaml up -d
pass=false
for i in 1 2 3 4 5; do
  echo "Integration attempt $i"
  # Real public SNI peers; self-signed cert is accepted only for our isolated DNS fixture.
  if sudo python3 probe.py --release "$RELEASE_DIR" --ca "$RELEASE_DIR/certs/fullchain.pem" --out "$temp/evidence.json"; then pass=true; break; fi
  sleep 3
done
[[ $pass == true ]]
# Exercise the exact curl-free path used by native Windows acceptance.
sudo python3 probe.py --release "$RELEASE_DIR" --ca "$RELEASE_DIR/certs/fullchain.pem" \
  --native-http --out "$temp/native-evidence.json"
python3 - <<'PY'
import socket, ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
for port in [443, 853]:
    raw = socket.socket()
    raw.settimeout(5)
    raw.bind(('127.0.0.2', 0))
    try:
        raw.connect(('127.0.0.1', port))
        peer = ctx.wrap_socket(raw, server_hostname='dns.nixz-ci.invalid')
    except (OSError, ssl.SSLError):
        pass
    else:
        peer.close()
        raise SystemExit(f'Unlisted source IP accepted on {port}')
    finally:
        raw.close()
print('Unlisted source-IP rejection passed')
PY
if sudo python3 clients.py --release "$RELEASE_DIR" --evidence "$temp/evidence.json" --out "$temp/clients"; then
  echo 'BUG: client profiles accepted test-CA/local evidence'; exit 1
fi
echo 'Isolated Docker integration passed. This does NOT verify node1 VPS or iPhone.'
