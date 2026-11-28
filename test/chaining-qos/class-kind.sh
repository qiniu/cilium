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
pods=(limited internal)
with_neighbor=${WITH_NEIGHBOR:-0}; [[ $with_neighbor == 0 || $with_neighbor == 1 ]]
if [[ $with_neighbor == 1 ]]; then pods+=(neighbor); fi
for pod in "${pods[@]}"; do
    node=$control; opts=()
    if [[ $pod == limited ]]; then node=$worker; opts=("${annotations[@]/#/--annotations=}"); fi
    if [[ $pod == neighbor ]]; then
        node=$worker
        opts=(--annotations=kubernetes.io/ingress-bandwidth=30M --annotations=kubernetes.io/egress-bandwidth=60M
              --annotations=qos.cilium.io/north-south-ingress-bandwidth=5M --annotations=qos.cilium.io/north-south-egress-bandwidth=8M)
    fi
    "${p[@]}" run "$pod" --image="$IMAGE" --image-pull-policy=Never --restart=Never \
        --overrides="$(jq -nc --arg n "$node" '{spec:{nodeName:$n}}')" "${opts[@]}" --command -- iperf3 -s -J
done
"${p[@]}" wait --for=condition=Ready pod --all --timeout=120s
podip(){ "${p[@]}" get pod "$1" -o jsonpath='{.status.podIP}'; }; backend=$(podip limited); internal=$(podip internal)
"${p[@]}" exec limited -- iperf3 -s -D -p 5202 -J
"${p[@]}" expose pod limited --name=vip --type=LoadBalancer --port=5201 --external-ip="$vip"
"${p[@]}" patch svc vip --type merge -p '{"spec":{"externalTrafficPolicy":"Local"}}'
if [[ $with_neighbor == 1 ]]; then
    "${p[@]}" expose pod neighbor --name=vip-b --type=LoadBalancer --port=5211 --target-port=5201 --external-ip="$vip"
    "${p[@]}" patch svc vip-b --type merge -p '{"spec":{"externalTrafficPolicy":"Local"}}'
    neighbor=$(podip neighbor)
    "${p[@]}" exec neighbor -- iperf3 -s -D -p 5202 -J
    "${p[@]}" exec internal -- iperf3 -s -D -p 5211 -J
    # iperf3 serves one active client/server at a time. One-off/idle timeout
    # on the reserved port leaves no permanent external server.
    docker exec "$EXTERNAL" iperf3 -s -1 -D --idle-timeout 60 -p 5211 -J
fi
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
    local alias=$1 link=$2 out=$3 ns_out=$4 in=$5 ns_in=$6 deadline=$((SECONDS+15)) queue
    while ((SECONDS < deadline)); do
        if queue=$(docker exec "$worker" ip -j link | jq -er --arg owner "$alias" '[.[]|select(.ifalias==$owner)|.ifname] | select(length==1) | .[0]') &&
           ready_tree "$queue" "$out" "$ns_out" && ready_tree "$link" "$in" "$ns_in"; then printf '%s\n' "$queue"; return; fi
        sleep .25
    done
    echo "timed out waiting for $alias QoS: default/external in $in/$ns_in, out $out/$ns_out" >&2; return 1
}
snapshot(){
    local direction dev
    for direction in in out; do
        dev=$3; if [[ $direction == out ]]; then dev=$4; fi
        date +%s.%N >"$dir/$1/$direction-$2.time"
        docker exec "$worker" tc -s -j qdisc show dev "$dev" >"$dir/$1/$direction-$2.json"
    done
}
ifb=$(await_rates "$owner" "$veth" 200 20 100 10)
if [[ $with_neighbor == 1 ]]; then
    idx_b=$("${p[@]}" exec neighbor -- cat /sys/class/net/eth0/iflink)
    ep_b=$("${p[@]}" get cep neighbor -o jsonpath='{.status.id}')
    veth_b=$(docker exec "$worker" ip -j link | jq -er --argjson idx "$idx_b" '.[] | select(.ifindex==$idx) | .ifname')
    ifb_b=$(await_rates "cilium:chained-qos:$ep_b:$idx_b" "$veth_b" 60 8 30 5)
    [[ $ifb_b != "$ifb" && $veth_b != "$veth" ]]
    mkdir "$dir/b"
fi
# Four persistent connections per limited Pod cover all windows. Budget for two bounded
# reconciliation waits, warmup after each swap, and collecting counters.
transfer_seconds=$((3*(duration+3)+40))
run(){ local name=$1; shift; "$@" --connect-timeout 4000 -t "$transfer_seconds" -i 1 -J --get-server-output >"$dir/$name.json"; }
pids=(); run ew-out "${p[@]}" exec limited -- iperf3 -c "$internal" & pids+=("$!")
run ns-out "${p[@]}" exec limited -- iperf3 -c "$peer" & pids+=("$!")
run ew-in "${p[@]}" exec internal -- iperf3 -c "$backend" -p 5202 & pids+=("$!")
run ns-in docker exec "$EXTERNAL" iperf3 -c "$vip" & pids+=("$!")
if [[ $with_neighbor == 1 ]]; then
    run b/ew-out "${p[@]}" exec neighbor -- iperf3 -c "$internal" -p 5211 & pids+=("$!")
    run b/ns-out "${p[@]}" exec neighbor -- iperf3 -c "$peer" -p 5211 & pids+=("$!")
    run b/ew-in "${p[@]}" exec internal -- iperf3 -c "$neighbor" -p 5202 & pids+=("$!")
    run b/ns-in docker exec "$EXTERNAL" iperf3 -c "$vip" -p 5211 & pids+=("$!")
fi
for phase in baseline double restored; do
    factor=1; if [[ $phase == double ]]; then factor=2; fi
    if [[ $phase != baseline ]]; then
        rates "$factor"
        "${p[@]}" annotate pod limited --overwrite "${annotations[@]}"
        ifb=$(await_rates "$owner" "$veth" "$((200*factor))" "$((20*factor))" "$((100*factor))" "$((10*factor))")
    fi
    mkdir "$dir/$phase"
    if [[ $with_neighbor == 1 ]]; then mkdir "$dir/b/$phase"; fi
    sleep 3 # exclude slow start and transient queue cutover
    snapshot "$phase" before "$veth" "$ifb"
    if [[ $with_neighbor == 1 ]]; then snapshot "b/$phase" before "$veth_b" "$ifb_b"; fi
    sleep "$duration"
    snapshot "$phase" after "$veth" "$ifb"
    if [[ $with_neighbor == 1 ]]; then snapshot "b/$phase" after "$veth_b" "$ifb_b"; fi
done
rc=0; for pid in "${pids[@]}"; do wait "$pid" || rc=1; done; ((rc==0))
python3 "$(dirname "$0")/check-class-phases.py" "$dir" "$backend" "$peer" "$vip" "$internal"
if [[ $with_neighbor == 1 ]]; then
    python3 "$(dirname "$0")/check-class-phases.py" "$dir/b" "$neighbor" "$peer" "$vip" "$internal" neighbor
fi
bash "$(dirname "$0")/class-kind-lifecycle.sh" "$ns" "$backend" "$vip" "$dir" "$veth" "$owner"
[[ $with_neighbor == 1 ]] || exit 0
# Removing A's policy must not tear down or restage B's queues.
snapshot b/restored post-remove "$veth_b" "$ifb_b"
for direction in in out; do
    jq -es 'def leaves: [.[]|select(.kind=="fq_codel")|[.parent,.handle]]|sort; (.[0]|leaves) == (.[1]|leaves)' \
        "$dir/b/restored/$direction-after.json" "$dir/b/restored/$direction-post-remove.json" >/dev/null
done
