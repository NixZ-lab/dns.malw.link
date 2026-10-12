#!/usr/bin/env bash
set -Eeuo pipefail
cd /opt/nixz/repo/deployment/nixz
[[ $EUID == 0 ]] || exit 1
[[ ${1:---dry-run} == --apply || ${1:---dry-run} == --dry-run ]] || exit 1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# Only route DATA is read from GitHub. Newly committed code never runs automatically as root.
git -C /opt/nixz/repo fetch --no-tags origin master
sha=$(git -C /opt/nixz/repo rev-parse origin/master)
git -C /opt/nixz/repo show "$sha:deployment/nixz/routes.json" > "$tmp/routes.json"
[[ $(wc -c < "$tmp/routes.json") -lt 65536 ]] || exit 1
python3 nixz.py validate --routes "$tmp/routes.json" --node /etc/nixz/node.json
NIXZ_ROUTES_FILE="$tmp/routes.json" bash deploy.sh "${1:---dry-run}"
echo "Route source commit: $sha"
