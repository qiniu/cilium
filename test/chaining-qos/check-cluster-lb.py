#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate one Cluster-policy LB transfer. Keep both class byte deltas on failure."""

import ipaddress
import json
from pathlib import Path
import sys


def address(s):
    a = ipaddress.ip_address(s)
    return getattr(a, 'ipv4_mapped', None) or a


def counters(path):
    rows = json.loads(path.read_text())
    out = {}
    for key, minor in [('default', '3'), ('external', '4')]:
        q, = [r for r in rows if r['kind'] == 'fq_codel' and r['parent'].endswith(':' + minor)]
        out[key] = (q['handle'], q['bytes'])
    return out


def check(path, vip, backend, client, traffic, direction):
    report = json.loads((path / 'iperf.json').read_text())
    c, = report['start']['connected']
    s, = report['server_output_json']['start']['connected']
    original, seen = address(c['local_host']), address(s['remote_host'])
    print(f'{path.name}: {original} -> {c["remote_host"]}, backend sees {seen} -> {s["local_host"]}')
    if original != address(client) or address(s['local_host']) != address(backend):
        raise ValueError('unexpected client or backend')
    try:
        frontend = address(vip)
    except ValueError:  # iperf resolved the status hostname on the real client
        frontend = None
    dest = address(c['remote_host'])
    if dest == address(backend) or (frontend is not None and dest != frontend):
        raise ValueError('transfer did not use the published VIP')
    if traffic == 'external' and original != seen:
        print('external source was rewritten; do not infer client origin from the gateway IP')
    before, after = [counters(path / (which + '.json')) for which in ('before', 'after')]
    if any(before[k][0] != after[k][0] for k in before):
        raise ValueError('queues changed during transfer')
    delta = {k: after[k][1] - before[k][1] for k in before}
    received = report['end']['sum_received']
    cap = {('external', 'in'): 10, ('external', 'out'): 20,
           ('default', 'in'): 100, ('default', 'out'): 200}[traffic, direction]
    rx = received['bits_per_second'] / 1e6
    wire = 8 * delta[traffic] / received['seconds'] / 1e6
    print(f'  cap={cap} rx={rx:.2f} expected-queue={wire:.2f} Mbps bytes={delta}')
    other = 'external' if traffic == 'default' else 'default'
    if not (.90 * cap <= rx <= 1.05 * cap and .95 * cap <= wire <= 1.05 * cap
            and 0 <= delta[other] <= .05 * received['bytes']):
        raise ValueError('transfer not charged exclusively to the expected class at the configured rate')


if __name__ == '__main__':
    try:
        check(Path(sys.argv[1]), *sys.argv[2:])
    except (ValueError, KeyError) as err:
        sys.exit(f'FAIL: {err}')
