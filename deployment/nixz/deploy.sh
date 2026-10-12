#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID == 0 ]] || { echo 'sudo required'; exit 1; }
cd "$(dirname "$0")"
install -d -m 755 /opt/nixz /opt/nixz/releases
install -d -m 700 /etc/nixz /var/backups/nixz
exec 9>/run/nixz-deploy.lock
flock -n 9 || { echo 'Another deployment is active'; exit 1; }
mode=${1:---dry-run}
[[ $mode == --apply || $mode == --dry-run || $mode == --rollback ]] || exit 1
node=/etc/nixz/node.json
routes=${NIXZ_ROUTES_FILE:-$PWD/routes.json}
compose() {
  RELEASE_DIR="$1" docker compose --env-file "$1/images.env" -f "$1/compose.yaml" "${@:2}"
}
if [[ $mode == --rollback ]]; then
  previous=$(readlink -f /opt/nixz/previous)
  [[ $previous == /opt/nixz/releases/* && -d $previous ]] || { echo 'No previous release'; exit 1; }
  compose "$previous" up -d --force-recreate
  python3 probe.py --release "$previous"
  ln -sfn "$previous" /opt/nixz/current
  echo "Rolled back to $previous"
  exit
fi
python3 nixz.py validate --routes "$routes" --node "$node"
candidate=$(mktemp -d /opt/nixz/candidate.XXXXXX)
trap 'rm -rf "$candidate"' EXIT
python3 nixz.py render --routes "$routes" --node "$node" --out "$candidate/release"
release="$candidate/release"
cp compose.yaml "$release/compose.yaml"
cp .env.example "$release/images.env"
if [[ -f /opt/nixz/current/images.env ]]; then cp /opt/nixz/current/images.env "$release/images.env"; fi
if [[ -f /etc/nixz/images.env ]]; then cp /etc/nixz/images.env "$release/images.env"; fi
tls=$(python3 -c 'import json; print(json.load(open("/etc/nixz/node.json"))["tls"])')
if [[ $tls == True ]]; then
  hostname=$(python3 -c 'import json; print(json.load(open("/etc/nixz/node.json"))["hostname"])')
  openssl x509 -in "/etc/letsencrypt/live/$hostname/fullchain.pem" -checkend 604800 -noout
  openssl x509 -in "/etc/letsencrypt/live/$hostname/fullchain.pem" -checkhost "$hostname" -noout
  install -d -o 65532 -g 65532 -m 700 "$release/certs"
  install -o 65532 -g 65532 -m 400 "/etc/letsencrypt/live/$hostname/fullchain.pem" "$release/certs/fullchain.pem"
  install -o 65532 -g 65532 -m 400 "/etc/letsencrypt/live/$hostname/privkey.pem" "$release/certs/privkey.pem"
fi
# Parent traversal for the unprivileged dnsdist container; other local users cannot read its key.
chmod 755 "$candidate" "$release"
compose "$release" config --quiet
compose "$release" pull
# Each release locks actual pulled digests; rollback does not follow moving tags.
while IFS='=' read -r name image; do
  [[ $name == NGINX_IMAGE || $name == DNSDIST_IMAGE ]] || continue
  digest=$(docker image inspect "$image" --format '{{index .RepoDigests 0}}')
  [[ $digest == *@sha256:* ]] || exit 1
  printf '%s=%s\n' "$name" "$digest"
done < "$release/images.env" > "$release/images.lock"
mv "$release/images.lock" "$release/images.env"
compose "$release" run --rm --no-deps nginx -c /config/nginx.conf -t
compose "$release" run --rm --no-deps dnsdist --check-config -C /config/dnsdist.conf
if [[ $mode == --dry-run ]]; then
  echo 'Validation passed. No service or firewall changes.'
  exit
fi
[[ $(timedatectl show -p NTPSynchronized --value) == yes ]] || { echo 'NTP not synchronized'; exit 1; }
ufw status | grep -q 'Status: active' || { echo 'UFW must be active'; exit 1; }
old=$(readlink -f /opt/nixz/current || true)
if [[ ! -d $old ]]; then
  for port in 443 853 5300 8443 8853 9444; do
    if ss -lntu | grep -qE ":${port}[[:space:]]"; then echo "Port $port occupied"; exit 1; fi
  done
fi
new="/opt/nixz/releases/$(date -u +%Y%m%dT%H%M%SZ)-$$"
mv "$release" "$new"
recover() {
  echo 'Health check failed. Restoring previous release.'
  if [[ -d $old ]]; then compose "$old" up -d --force-recreate; else compose "$new" down; fi
}
if ! compose "$new" up -d --force-recreate; then recover; exit 1; fi
ok=false
for attempt in 1 2 3 4 5; do
  echo "Health attempt $attempt"
  if python3 probe.py --release "$new" --out "$new/local-evidence.json"; then ok=true; break; fi
  sleep 3
done
[[ $ok == true ]] || { recover; exit 1; }
[[ ! -d $old ]] || ln -sfn "$old" /opt/nixz/previous
ln -sfn "$new" /opt/nixz/current
echo "Activated $new. External and device tests are STILL REQUIRED."
# Keep the last five immutable releases, including the rollback target.
mapfile -t releases < <(find /opt/nixz/releases -mindepth 1 -maxdepth 1 -type d | sort -r)
for stale in "${releases[@]:5}"; do
  [[ $stale == "$old" || $stale == "$new" ]] || rm -rf -- "$stale"
done
