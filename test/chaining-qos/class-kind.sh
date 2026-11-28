#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Class QoS on a disposable two-node IPv4 kind/Kube-OVN cluster. The agent's
# external prefix must contain only the external peer (not a NAT/join
# address). All other traffic shares the default. Use a source-preserving VIP.
set -euo pipefail
: "${CLUSTER:?}" "${IMAGE:?preloaded image with iperf3}" "${EXTERNAL:?external iperf3 server on the kind network}"
k=(kubectl --context "kind-$CLUSTER"); ns="qos-classes-$$"; p=("${k[@]}" -n "$ns")
vip=${VIP:-198.51.100.78}; duration=${DURATION:-15}; dir=$(mktemp -d);echo "artifacts=$dir"
worker=$CLUSTER-worker; control=$CLUSTER-control-plane
peer=$(docker inspect -f '{{(index .NetworkSettings.Networks "kind").IPAddress}}' "$EXTERNAL")
"${k[@]}" create ns "$ns"
added_route=false
cleanup(){ if $added_route; then docker exec "$EXTERNAL" ip route del "$vip/32" >/dev/null 2>&1 || :; fi; "${k[@]}" delete ns "$ns" --wait=false >/dev/null; }
trap cleanup EXIT
for pod in limited internal;do
 node=$control; opts=(); if [[ $pod == limited ]];then node=$worker;opts=(--annotations=kubernetes.io/ingress-bandwidth=100M --annotations=kubernetes.io/egress-bandwidth=200M)
 for spec in north-south-egress:20 north-south-ingress:10; do opts+=(--annotations="qos.cilium.io/${spec%:*}-bandwidth=${spec#*:}M");done;fi
 "${p[@]}" run "$pod" --image="$IMAGE" --image-pull-policy=Never --restart=Never --overrides="$(jq -nc --arg n "$node" '{spec:{nodeName:$n}}')" "${opts[@]}" --command -- iperf3 -s -J
done
"${p[@]}" wait --for=condition=Ready pod --all --timeout=120s
podip(){ "${p[@]}" get pod "$1" -o jsonpath='{.status.podIP}'; }; backend=$(podip limited); internal=$(podip internal)
"${p[@]}" exec limited -- iperf3 -s -D -p 5202 -J
"${p[@]}" expose pod limited --name=vip --type=LoadBalancer --port=5201 --external-ip="$vip"
"${p[@]}" patch svc vip --type merge -p '{"spec":{"externalTrafficPolicy":"Local"}}'
node_ip=$("${k[@]}" get node "$worker" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
docker exec "$EXTERNAL" ip route add "$vip/32" via "$node_ip"
added_route=true
idx=$("${p[@]}" exec limited -- cat /sys/class/net/eth0/iflink)
ep=$("${p[@]}" get cep limited -o jsonpath='{.status.id}')
veth=$(docker exec "$worker" ip -j link | jq -er --argjson idx "$idx" '.[] | select(.ifindex==$idx) | .ifname')
ifb=$(docker exec "$worker" ip -j link | jq -er --arg owner "cilium:chained-qos:$ep:$idx" '.[] | select(.ifalias==$owner) | .ifname')
snapshot(){ docker exec "$worker" tc -s -j qdisc show dev "$veth" >"$dir/in-$1.json"; docker exec "$worker" tc -s -j qdisc show dev "$ifb" >"$dir/out-$1.json"; }
snapshot before
# Start real connections, no socket priorities, test class IDs or tc overrides.
run(){ name=$1;shift; "$@" --connect-timeout 4000 -t "$duration" -J --get-server-output >"$dir/$name.json"; }
pids=(); run ew-out "${p[@]}" exec limited -- iperf3 -c "$internal" & pids+=("$!")
run ns-out "${p[@]}" exec limited -- iperf3 -c "$peer" & pids+=("$!")
run ew-in "${p[@]}" exec internal -- iperf3 -c "$backend" -p 5202 & pids+=("$!")
run ns-in docker exec "$EXTERNAL" iperf3 -c "$vip" & pids+=("$!")
rc=0;for pid in "${pids[@]}";do wait "$pid" || rc=1;done;((rc==0))
snapshot after
python3 - "$dir" "$backend" "$peer" "$vip" <<'PY'
import json,sys,ipaddress
from pathlib import Path
root,backend,peer,vip=sys.argv[1:]
def addr(x):
    a=ipaddress.ip_address(x);return str(getattr(a,'ipv4_mapped',None) or a)
for name,cap in [('ew-out',200),('ns-out',20),('ew-in',100),('ns-in',10)]:
    r=json.loads((Path(root)/(name+'.json')).read_text());client=r['start']['connected'][0];server=r['server_output_json']['start']['connected'][0]
    rate=r['end']['sum_received']['bits_per_second']/1e6
    print(f'{name}: {rate:.2f} / {cap} Mbit/s, {client} -> {server}')
    if not .90*cap <= rate <= 1.05*cap:raise ValueError(name+' rate')
    traffic,direction=name.split('-');minor='3' if traffic=='ew' else '4'
    def charged(when):
        rows=json.loads((Path(root)/f'{direction}-{when}.json').read_text())
        q,=[q for q in rows if q['kind']=='fq_codel' and q['parent'].endswith(':'+minor)]
        return q['bytes']
    delta=charged('after')-charged('before')
    if delta < .98*r['end']['sum_received']['bytes']:raise ValueError(f'{name}: wrong queue, delta={delta}')
    wire=8*delta/r['end']['sum_received']['seconds']/1e6
    if not .95*cap <= wire <= 1.05*cap:raise ValueError(f'{name}: class throughput {wire:.2f} / {cap}')
    print(f'  class queue: {delta} bytes, {wire:.2f} Mbit/s')
    if name=='ns-out' and (addr(client['local_host'])!=backend or addr(server['remote_host'])==backend):raise ValueError('no SNAT')
    if name=='ns-in' and (addr(client['remote_host'])!=vip or addr(server['local_host'])!=backend or addr(server['remote_host'])!=peer):raise ValueError('not source-preserving DNAT')
PY
bash "$(dirname "$0")/class-kind-lifecycle.sh" "$ns" "$backend" "$vip" "$dir" "$veth" "cilium:chained-qos:$ep:$idx"
