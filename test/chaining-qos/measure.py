#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check a single iperf3 transfer against the *current* endpoint total cap."""

import argparse
import ipaddress
import json
from pathlib import Path


def fq_bytes(qdiscs):
    queues = [q for q in qdiscs if q['kind'] == 'fq' and q.get('root')]
    if len(queues) != 1:
        raise ValueError('expected one root fq')
    return queues[0]['bytes']


def evaluate(report, before, after, cap, path, pod_ip):
    if 'error' in report:
        raise ValueError(report['error'])
    server = report['server_output_json']
    client_conn = report['start']['connected'][0]
    server_conn = server['start']['connected'][0]
    def normalized(value):
        ip = ipaddress.ip_address(value)
        return getattr(ip, 'ipv4_mapped', None) or ip

    # Compare both views of the same connection, not the requested test label.
    pod = normalized(pod_ip)
    endpoint = server_conn if path == 'lb' else client_conn
    if normalized(endpoint['local_host']) != pod:
        raise ValueError('transfer did not use the expected Pod address')
    if path == 'snat' and normalized(server_conn['remote_host']) == pod:
        raise ValueError('SNAT not observed between Pod and receiver')
    if path == 'lb' and normalized(client_conn['remote_host']) == pod:
        raise ValueError('client connected directly to backend instead of VIP')
    rx = report['end']['sum_received']
    charged = fq_bytes(after) - fq_bytes(before)
    mbps = rx['bits_per_second'] / 1e6
    print(f'client={client_conn} server={server_conn} rx={mbps:.2f} Mbit/s fq_delta={charged} bytes')
    if not rx['bytes'] or charged < rx['bytes'] * 0.9:
        raise ValueError('expected endpoint queue did not carry the bulk transfer')
    if not 0.80 * cap <= mbps <= 1.05 * cap:
        raise ValueError(f'received throughput outside baseline window for {cap} Mbit/s')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', choices=['east-west', 'snat', 'lb'])
    parser.add_argument('pod_ip')
    parser.add_argument('cap', type=float)
    parser.add_argument('files', nargs=3, type=Path, metavar='JSON')
    args = parser.parse_args()
    evaluate(*(json.loads(f.read_text()) for f in args.files), args.cap, args.path, args.pod_ip)
