#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Second phase of class-kind.sh. The caller owns the temporary namespace.
set -euo pipefail
ns=$1; backend=$2; vip=$3; dir=$4; veth=$5; owner=$6
p=(kubectl --context "kind-$CLUSTER" -n "$ns"); worker=$CLUSTER-worker
# Prove a policy deny still takes effect with class selection active. Verify
# that connectivity returns after removal, not just that one probe failed.
policy='{"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","metadata":{"name":"deny-peer"},"spec":{"endpointSelector":{"matchLabels":{"run":"limited"}},"ingressDeny":[{"fromEndpoints":[{"matchLabels":{"run":"internal"}}]}]}}'
printf '%s' "$policy" | "${p[@]}" apply -f -
probe(){ "${p[@]}" exec internal -- iperf3 -c "$backend" -p 5202 --connect-timeout 1200 -t 1 -J; }
denied=false
for _ in {1..15}; do if ! probe >"$dir/deny.json" && jq -e '.error | test("timed out";"i")' "$dir/deny.json" >/dev/null; then denied=true;break;fi;done
$denied || { echo 'policy did not deny the internal connection' >&2;exit 1; }
"${p[@]}" delete cnp deny-peer
allowed=false;for _ in {1..15}; do if probe >"$dir/allow.json";then allowed=true;break;fi;done
$allowed || { echo 'internal connectivity did not recover' >&2;exit 1; }

# One established external connection spans all three configurations. Check
# receiver-side intervals well away from watch propagation and queue cutover.
docker exec "$EXTERNAL" iperf3 -c "$vip" -t 36 -i 1 -J --get-server-output >"$dir/live.json" & transfer=$!
sleep 9
"${p[@]}" annotate pod limited --overwrite qos.cilium.io/north-south-ingress-bandwidth=4M kubernetes.io/ingress-bandwidth=8M
sleep 12
# Real host namespace traffic remains exempt despite an 8M default.
docker run --rm --network "container:$worker" --entrypoint iperf3 "$IMAGE" -c "$backend" -p 5202 -b 40M -t 2 -J >"$dir/host.json"
jq -e '.end.sum_received.bits_per_second > 30000000' "$dir/host.json" >/dev/null
"${p[@]}" annotate pod limited qos.cilium.io/north-south-ingress-bandwidth- qos.cilium.io/north-south-egress-bandwidth-
wait "$transfer"
python3 - "$dir/live.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))['server_output_json']
for start,end,cap in [(2,7,10),(14,19,4),(30,35,8)]:
    rows=[row['sum'] for row in r['intervals'] if start-.1<=row['sum']['start']<end-.1]
    if len(rows)<4: raise ValueError('missing steady-state samples')
    rate=sum(s['bytes'] for s in rows)*8/sum(s['seconds'] for s in rows)/1e6
    if not .85*cap<=rate<=1.05*cap:raise ValueError(f'live transfer: {rate:.2f} / {cap}')
    print(f'live transfer: {rate:.2f} / {cap} Mbit/s')
PY
docker exec "$worker" tc -j qdisc show dev "$veth" | jq -e 'any(.[]; .root and .kind=="fq")' >/dev/null
docker exec "$worker" ip -j link | jq -e --arg owner "$owner" 'all(.[]; .ifalias!=$owner)' >/dev/null
# Both overrides are now gone. An internal upload and a VIP upload must
# share the old 8M ingress cap, not receive independent 8M allowances.
"${p[@]}" exec internal -- iperf3 -c "$backend" -p 5202 -t 10 --connect-timeout 4000 -J >"$dir/legacy-internal.json" & internal_pid=$!
docker exec "$EXTERNAL" iperf3 -c "$vip" -t 10 --connect-timeout 4000 -J >"$dir/legacy-external.json" & external_pid=$!
rc=0; wait "$internal_pid" || rc=1; wait "$external_pid" || rc=1; ((rc==0))
jq -es 'map(.end.sum_received.bits_per_second/1e6) | select(all(.[];.>0)) | add | select(.>=6.8 and .<=8.4)' "$dir"/legacy-{internal,external}.json
