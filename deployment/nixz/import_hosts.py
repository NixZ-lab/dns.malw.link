#!/usr/bin/env python3
"""Import domain candidates only; never retain source IPs or enable routes."""
import argparse
import ipaddress
import json
from pathlib import Path
from nixz import domain


def catalogue(text):
    groups, skipped = {}, set()
    label = 'Ungrouped'
    legacy = False
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if line.startswith('#'):
            label = line.lstrip('#').strip() or 'Ungrouped'
            legacy = label == 'Работающие IP без прокси'
            continue
        words = line.split('#', 1)[0].split()
        if len(words) < 2:
            raise ValueError(f'Malformed hosts line {number}')
        ipaddress.ip_address(words[0])
        for name in words[1:]:
            name = name.lower().rstrip('.')
            if legacy or name in ('localhost', 'ip6-localhost'):
                skipped.add(name)
                continue
            domain(name)
            groups.setdefault(label, set()).add(name)
    return {'schema': 1, 'status': 'UNVERIFIED_CANDIDATES_ONLY',
            'source_ips_discarded': True, 'enabled_groups': [],
            'groups': {label: sorted(names) for label, names in sorted(groups.items())},
            'excluded_legacy_names': sorted(skipped)}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('hosts', type=Path)
    p.add_argument('--out', required=True, type=Path)
    a = p.parse_args()
    result = catalogue(a.hosts.read_text())
    with a.out.open('x') as output:
        output.write(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print('Inactive candidate groups:', len(result['groups']), '; enabled: 0')


if __name__ == '__main__':
    main()
