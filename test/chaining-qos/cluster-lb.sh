#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Opt-in test: provisions a REAL LoadBalancer in a temporary namespace.
# See CLUSTER-LB.md for node/client/placement adapter contracts.
set -euo pipefail
: "${CONTEXT:?}" "${NODE_A:?}" "${NODE_B:?}" "${IMAGE:?iperf3 image}" "${EXTERNAL_IP:?expected client address}"
[[ $NODE_A != "$NODE_B" ]]
k=(kubectl --context "$CONTEXT"); ns="qos-cluster-lb-$$"; p=("${k[@]}" -n "$ns")
out=$(mktemp -d); echo "artifacts=$out context=$CONTEXT namespace=$ns"
node_exec(){ if [[ -n ${NODE_EXEC:-} ]]; then "$NODE_EXEC" "$@"; else docker exec "$@"; fi; }
external_exec(){ if [[ -n ${EXTERNAL_EXEC:-} ]]; then "$EXTERNAL_EXEC" "$@"; else docker exec "${EXTERNAL:?external test client}" "$@"; fi; }
ingress_node(){
    if [[ -n ${LB_INGRESS_NODE_CMD:-} ]]; then "$LB_INGRESS_NODE_CMD" "$CONTEXT" "$ns" frontend; else
        "${k[@]}" get servicel2statuses.metallb.io -A -o json | jq -er --arg ns "$ns" '
          [.items[].status|select(.serviceNamespace==$ns and .serviceName=="frontend")|.node]|unique|select(length==1)|.[0]'
    fi
}
"${k[@]}" create ns "$ns"
trap '"${k[@]}" delete ns "$ns" --wait=false >/dev/null' EXIT
for pod in a b internal; do
    node=$NODE_A; if [[ $pod == b ]]; then node=$NODE_B; fi
    opts=(); if [[ $pod != internal ]]; then
        opts=(--annotations=kubernetes.io/ingress-bandwidth=100M --annotations=kubernetes.io/egress-bandwidth=200M
              --annotations=qos.cilium.io/north-south-ingress-bandwidth=10M --annotations=qos.cilium.io/north-south-egress-bandwidth=20M)
    fi
    "${p[@]}" run "$pod" --image="$IMAGE" --image-pull-policy=IfNotPresent --restart=Never \
        --overrides="$(jq -nc --arg n "$node" '{spec:{nodeName:$n}}')" "${opts[@]}" --command -- iperf3 -s -J
done
"${p[@]}" wait --for=condition=Ready pod --all --timeout=180s
# No externalIPs, static host route, NodePort connection or Local fallback.
annotations=${LB_ANNOTATIONS:-'{}'}
jq -n --arg class "${LB_CLASS:-}" --argjson annotations "$annotations" '{apiVersion:"v1",kind:"Service",metadata:{name:"frontend",annotations:$annotations},spec:({type:"LoadBalancer",externalTrafficPolicy:"Cluster",selector:{run:"a"},ports:[{port:5201,protocol:"TCP",targetPort:5201}]}+(if $class=="" then {} else {loadBalancerClass:$class} end))}' | "${p[@]}" apply -f -
"${p[@]}" wait --for=jsonpath='{.status.loadBalancer.ingress[0]}' svc/frontend --timeout="${LB_TIMEOUT:-180s}"
"${p[@]}" get svc frontend -o json >"$out/service.json"
vip=$(jq -er 'select(.spec.type=="LoadBalancer" and .spec.externalTrafficPolicy=="Cluster" and (.spec.externalIPs|length)==0) | .status.loadBalancer.ingress[0] | .ip // .hostname' "$out/service.json")
pod_ip(){ "${p[@]}" get pod "$1" -o jsonpath='{.status.podIP}'; }
internal=$(pod_ip internal); status=0; local_seen=false; remote_seen=false
for pod in a b; do
    backend=$(pod_ip "$pod"); node=$("${p[@]}" get pod "$pod" -o jsonpath='{.spec.nodeName}')
    "${p[@]}" patch svc frontend --type=merge -p "$(jq -nc --arg pod "$pod" '{spec:{selector:{run:$pod}}}')"
    # Wait for exactly one ready backend; the tuple check also verifies LB convergence.
    deadline=$((SECONDS+60))
    until "${p[@]}" get endpointslice -l kubernetes.io/service-name=frontend -o json | jq -e --arg b "$backend" '[.items[].endpoints[]|select(.conditions.ready==true)|.addresses[]]==[$b]' >/dev/null; do
        ((SECONDS < deadline)) || { echo 'single ready backend not observed' >&2;exit 1; }; sleep 1
    done
    "${p[@]}" get endpointslice -l kubernetes.io/service-name=frontend -o json >"$out/$pod-endpoints.json"
    idx=$("${p[@]}" exec "$pod" -- cat /sys/class/net/eth0/iflink)
    ep=$("${p[@]}" get cep "$pod" -o jsonpath='{.status.id}')
    links=$(node_exec "$node" ip -j link)
    veth=$(jq -er --argjson idx "$idx" '.[]|select(.ifindex==$idx)|.ifname' <<<"$links")
    ifb=$(jq -er --arg owner "cilium:chained-qos:$ep:$idx" '[.[]|select(.ifalias==$owner)|.ifname]|select(length==1)|.[0]' <<<"$links")
    for origin in external default; do
        for dir in in out; do
            w="$out/$pod-$origin-$dir";mkdir "$w"
            reverse=();dev=$veth; if [[ $dir == out ]]; then reverse=(-R);dev=$ifb;fi
            client=(external_exec);source=$EXTERNAL_IP
            if [[ $origin == default ]]; then client=("${p[@]}" exec internal --);source=$internal;fi
            deadline=$((SECONDS+30)); until entry=$(ingress_node) && [[ -n $entry ]];do ((SECONDS < deadline)) || { echo 'cannot establish LB ingress placement' >&2;exit 1; };sleep 1;done
            printf 'vip=%s ingress=%s backend=%s node=%s\n' "$vip" "$entry" "$backend" "$node" | tee "$w/path.txt"
            node_exec "$node" tc -s -j qdisc show dev "$dev" >"$w/before.json"
            if ! "${client[@]}" iperf3 -c "$vip" -p 5201 "${reverse[@]}" --connect-timeout 4000 -t "${DURATION:-15}" -J --get-server-output >"$w/iperf.json"; then
                echo "$pod-$origin-$dir: iperf failed, see $w/iperf.json" >&2; status=1;continue
            fi
            node_exec "$node" tc -s -j qdisc show dev "$dev" >"$w/after.json"
            if [[ $(ingress_node) != "$entry" ]];then echo 'ingress placement changed' >&2;status=1;continue;fi
            if [[ $origin == external ]]; then if [[ $entry == "$node" ]];then local_seen=true;else remote_seen=true;fi;fi
            python3 "$(dirname "$0")/check-cluster-lb.py" "$w" "$vip" "$backend" "$source" "$origin" "$dir" 2>&1 | tee "$w/result.txt" || status=1
        done
    done
done
if ! $local_seen || ! $remote_seen;then echo 'did not cover both local and cross-node LB forwarding' >&2;status=1;fi
echo "Cluster-policy LB matrix: local=$local_seen cross-node=$remote_seen exit=$status artifacts=$out"
exit "$status"
