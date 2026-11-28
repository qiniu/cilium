#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Run on a disposable two-node, IPv4 kind cluster. Does not install a CNI.
set -euo pipefail
: "${CLUSTER:?kind cluster name}" "${IMAGE:?preloaded image with iperf3, cat and iproute2}"
export CONTEXT="kind-$CLUSTER" NS="qos-baseline-$$" POD=limited CAP=10
export EXTERNAL="$NS-external"
k=(kubectl --context "$CONTEXT")
p=("${k[@]}" -n "$NS")
local_node="$CLUSTER-worker"
other_node="$CLUSTER-control-plane"
network=${KIND_EXPERIMENTAL_DOCKER_NETWORK:-kind}
vip=${VIP:-198.51.100.74}
base=$(dirname "$0")
node_ip() { "${k[@]}" get node "$1" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}'; }
pod_ip() { "${p[@]}" get pod "$1" -o jsonpath='{.status.podIP}'; }
cleanup() {
    docker rm -f "$EXTERNAL" >/dev/null 2>&1 || true
    "${k[@]}" delete ns "$NS" --wait=false >/dev/null
}
"${k[@]}" create ns "$NS"
trap cleanup EXIT
docker run -d --name "$EXTERNAL" --network "$network" --cap-add NET_ADMIN \
    --entrypoint iperf3 "$IMAGE" -s -J >/dev/null
external_ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$network\").IPAddress}}" "$EXTERNAL")
for pod in limited near far; do
    node=$local_node; [[ $pod != far ]] || node=$other_node
    annotations=(); [[ $pod != limited ]] || annotations=(--annotations=kubernetes.io/ingress-bandwidth=10M --annotations=kubernetes.io/egress-bandwidth=10M)
    "${p[@]}" run "$pod" --image="$IMAGE" --image-pull-policy=Never --restart=Never \
        --overrides="$(jq -nc --arg node "$node" '{spec:{nodeName:$node}}')" \
        "${annotations[@]}" --command -- iperf3 -s -J
done
"${p[@]}" wait --for=condition=Ready pod --all --timeout=180s
"${p[@]}" expose pod limited --name=vip --port=5201 --external-ip="$vip"
# Send an external VIP through kube-proxy on each ingress node in turn. This
# exercises service DNAT, not an OVN-specific appliance or L7 proxy.
for dir in out in; do
    for peer in near far; do
        echo "east-west peer=$peer direction=$dir"
        TARGET=$(pod_ip "$peer") bash "$base/run.sh" east-west "$dir"
    done
    TARGET=$external_ip bash "$base/run.sh" snat "$dir"
done
cluster_ip=$("${p[@]}" get svc vip -o jsonpath='{.spec.clusterIP}')
for dir in in out; do
    echo "internal VIP control: client=far backend=$local_node direction=$dir"
    VIP_CLIENT_POD=far TARGET=$cluster_ip bash "$base/run.sh" lb "$dir"
done
for node in "$local_node" "$other_node"; do
    docker exec "$EXTERNAL" ip route replace "$vip/32" via "$(node_ip "$node")"
    for dir in in out; do
        echo "VIP ingress=$node backend=$local_node direction=$dir"
        TARGET=$vip bash "$base/run.sh" lb "$dir"
    done
done
