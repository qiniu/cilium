#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Class QoS on a disposable two-node IPv4 kind/Kube-OVN cluster. The agent's
# external prefix must contain only the external peer (not a NAT/join address).
set -euo pipefail
: "${CLUSTER:?}" "${IMAGE:?preloaded image with iperf3}" "${EXTERNAL:?external iperf3 server on the kind network}"
k=(kubectl --context "kind-$CLUSTER"); ns="qos-classes-$$"; p=("${k[@]}" -n "$ns")
vip=${VIP:-198.51.100.78}; duration=${DURATION:-15}; dir=$(mktemp -d); echo "artifacts=$dir"
[[ $duration =~ ^[0-9]+$ && $duration -ge 8 ]] || { echo 'DURATION must be at least 8 seconds per phase' >&2; exit 2; }
worker=$CLUSTER-worker; control=$CLUSTER-control-plane
peer=$(docker inspect -f '{{(index .NetworkSettings.Networks "kind").IPAddress}}' "$EXTERNAL")
"${k[@]}" create ns "$ns"
added_route=false
cleanup(){ if $added_route; then docker exec "$EXTERNAL" ip route del "$vip/32" >/dev/null 2>&1 || :; fi; "${k[@]}" delete ns "$ns" --wait=false >/dev/null; }
trap cleanup EXIT

# One annotation patch per transition, including both Kubernetes defaults.
rates(){
    local f=$1
    annotations=("kubernetes.io/ingress-bandwidth=$((100*f))M" "kubernetes.io/egress-bandwidth=$((200*f))M"
                 "qos.cilium.io/north-south-ingress-bandwidth=$((10*f))M" "qos.cilium.io/north-south-egress-bandwidth=$((20*f))M")
}
rates 1
for pod in limited internal; do
    node=$control; opts=()
    if [[ $pod == limited ]]; then node=$worker; opts=("${annotations[@]/#/--annotations=}"); fi
    "${p[@]}" run "$pod" --image="$IMAGE" --image-pull-policy=Never --restart=Never \
        --overrides="$(jq -nc --arg n "$node" '{spec:{nodeName:$n}}')" "${opts[@]}" --command -- iperf3 -s -J
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
owner="cilium:chained-qos:$ep:$idx"

# IFB and active veth band may change at each map swap. Wait for convergence
# and sample fresh counters. tc reports HTB ceil in bytes/s.
ready_tree(){
    docker exec "$worker" tc -j class show dev "$1" | jq -e --argjson def "$2" --argjson ext "$3" '
      [.[] | select(.class=="htb")] as $h | ($h|length)==2 and
      any($h[]; (.handle|endswith(":3")) and .ceil==($def*125000)) and
      any($h[]; (.handle|endswith(":4")) and .ceil==($ext*125000))' >/dev/null
}
await_rates(){
    local factor=$1 deadline=$((SECONDS+15))
    while ((SECONDS < deadline)); do
        if ifb=$(docker exec "$worker" ip -j link | jq -er --arg owner "$owner" '[.[]|select(.ifalias==$owner)|.ifname] | select(length==1) | .[0]') &&
           ready_tree "$ifb" "$((200*factor))" "$((20*factor))" && ready_tree "$veth" "$((100*factor))" "$((10*factor))"; then return; fi
        sleep .25
    done
    echo "timed out waiting for ${factor}x QoS on $ns/limited" >&2; return 1
}
snapshot(){
    local direction dev
    for direction in in out; do
        dev=$veth; if [[ $direction == out ]]; then dev=$ifb; fi
        date +%s.%N >"$dir/$1/$direction-$2.time"
        docker exec "$worker" tc -s -j qdisc show dev "$dev" >"$dir/$1/$direction-$2.json"
    done
}
await_rates 1
# Four persistent connections cover all windows. Budget for two bounded
# reconciliation waits, warmup after each swap, and collecting counters.
transfer_seconds=$((3*(duration+3)+40))
run(){ local name=$1; shift; "$@" --connect-timeout 4000 -t "$transfer_seconds" -i 1 -J --get-server-output >"$dir/$name.json"; }
pids=(); run ew-out "${p[@]}" exec limited -- iperf3 -c "$internal" & pids+=("$!")
run ns-out "${p[@]}" exec limited -- iperf3 -c "$peer" & pids+=("$!")
run ew-in "${p[@]}" exec internal -- iperf3 -c "$backend" -p 5202 & pids+=("$!")
run ns-in docker exec "$EXTERNAL" iperf3 -c "$vip" & pids+=("$!")
for phase in baseline double restored; do
    factor=1; if [[ $phase == double ]]; then factor=2; fi
    if [[ $phase != baseline ]]; then
        rates "$factor"
        "${p[@]}" annotate pod limited --overwrite "${annotations[@]}"
        await_rates "$factor"
    fi
    mkdir "$dir/$phase"
    sleep 3 # exclude slow start and transient queue cutover
    snapshot "$phase" before
    sleep "$duration"
    snapshot "$phase" after
done
rc=0; for pid in "${pids[@]}"; do wait "$pid" || rc=1; done; ((rc==0))
python3 "$(dirname "$0")/check-class-phases.py" "$dir" "$backend" "$peer" "$vip" "$internal"
bash "$(dirname "$0")/class-kind-lifecycle.sh" "$ns" "$backend" "$vip" "$dir" "$veth" "$owner"
