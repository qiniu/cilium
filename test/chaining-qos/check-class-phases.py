#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check three steady-state windows on the same four iperf connections."""

import ipaddress
import json
from pathlib import Path
import sys


def addr(value):
    parsed = ipaddress.ip_address(value)
    return getattr(parsed, 'ipv4_mapped', None) or parsed


def load(path):
    return json.loads(path.read_text())


def leaf(window, direction, minor, when):
    rows = load(window / f'{direction}-{when}.json')
    queue, = [q for q in rows if q['kind'] == 'fq_codel' and q['parent'].endswith(':' + minor)]
    stamp = float((window / f'{direction}-{when}.time').read_text())
    return stamp, queue


def check(root, backend, peer, vip, internal, role='limited'):
    caps = {'ew-in': 30, 'ew-out': 60, 'ns-in': 5, 'ns-out': 8} if role == 'neighbor' else {}
    for name, base, expected in [
        ('ew-in', 100, (internal, backend, internal, backend)),
        ('ew-out', 200, (backend, internal, backend, internal)),
        ('ns-in', 10, (peer, vip, peer, backend)),
        ('ns-out', 20, (backend, peer, None, peer)),
    ]:
        report = load(root / f'{name}.json')
        server = report['server_output_json']
        client_conn, = report['start']['connected']
        server_conn, = server['start']['connected']
        actual = tuple(map(addr, (client_conn['local_host'], client_conn['remote_host'],
                                  server_conn['remote_host'], server_conn['local_host'])))
        if any(want and addr(want) != got for want, got in zip(expected, actual)):
            raise ValueError(f'{name}: wrong path {actual}')
        if name == 'ns-out' and actual[2] == addr(backend):
            raise ValueError('no SNAT at external receiver')
        # iperf timestamps and host snapshots use the same kind node/host
        # wall clock. Older iperf versions give only whole start seconds.
        stamp = server['start']['timestamp']
        origin = stamp.get('timemillisecs', stamp['timesecs'] * 1000) / 1000
        traffic, direction = name.split('-')
        previous = None
        for phase, factor in [('baseline', 1), ('double', 2), ('restored', 1)]:
            cap = caps.get(name, base * factor)
            minor = '3' if traffic == 'ew' else '4'
            start, before = leaf(root / phase, direction, minor, 'before')
            end, after = leaf(root / phase, direction, minor, 'after')
            if before['handle'] != after['handle'] or before['parent'] != after['parent']:
                raise ValueError(f'{phase} {name}: queue replaced during measurement')
            if role == 'neighbor' and previous is not None:
                if (before['parent'], before['handle']) != (previous['parent'], previous['handle']) or before['bytes'] < previous['bytes']:
                    raise ValueError(f'{phase} {name}: updating A replaced B queue')
            previous = after
            # Exclude partial intervals and a second of clock granularity at
            # either boundary. Use receiver bytes, not offered traffic.
            samples = [i['sum'] for i in server['intervals']
                       if start + 1 <= origin + i['sum']['start']
                       and origin + i['sum']['end'] <= end - 1]
            seconds = sum(s['seconds'] for s in samples)
            if seconds < end - start - 5:
                raise ValueError(f'{phase} {name}: incomplete receiver window ({seconds:.2f}s)')
            rx = 8 * sum(s['bytes'] for s in samples) / seconds / 1e6
            wire = 8 * (after['bytes'] - before['bytes']) / (end - start) / 1e6
            print(f'{role:8} {phase:8} {name:6}: cap={cap:3} queue={wire:.2f} rx={rx:.2f} Mbps')
            if not (.90 * cap <= rx <= 1.05 * cap and .95 * cap <= wire <= 1.05 * cap):
                raise ValueError(f'{phase} {name}: classification or rate mismatch')


if __name__ == '__main__':
    check(Path(sys.argv[1]), *sys.argv[2:])
