#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Run one case against provisioned kind endpoints; see README.md.
set -euo pipefail

case ${1:-}:${2:-} in
    east-west:out|snat:out) reverse=() ;;
    east-west:in|snat:in) reverse=(-R) ;;
    lb:in) reverse=() ;;
    lb:out) reverse=(-R) ;;
    *) echo "usage: $0 {east-west|snat|lb} {in|out}" >&2; exit 2 ;;
esac
: "${CONTEXT:?kind kubectl context}" "${NS:?namespace}" "${POD:?limited pod}" "${TARGET:?peer IP or VIP}" "${CAP:?direction cap in decimal Mbit/s}"
k=(kubectl --context "$CONTEXT")
p=("${k[@]}" -n "$NS")
config=$("${k[@]}" -n kube-system get cm cilium-config -o json)
jq -e '.data | .["cni-chaining-mode"] == "generic-veth" and .["enable-bandwidth-manager"] == "true"' <<<"$config" >/dev/null || { echo 'requires generic-veth and bandwidth manager' >&2; exit 1; }
node=$("${p[@]}" get pod "$POD" -o jsonpath='{.spec.nodeName}')
pod_ip=${POD_IP:-$("${p[@]}" get pod "$POD" -o jsonpath='{.status.podIP}')}
if [[ $2 == out ]]; then
    id=$("${p[@]}" get cep "$POD" -o jsonpath='{.status.id}')
    [[ $id =~ ^[1-9][0-9]*$ ]]
    dev=cilium_bwm$id
else
    idx=$("${p[@]}" exec "$POD" -- cat /sys/class/net/eth0/iflink)
    dev=$(docker exec "$node" ip -j link | jq -er --argjson idx "$idx" '.[] | select(.ifindex==$idx) | .ifname')
fi
client=("${p[@]}" exec "$POD" --)
if [[ $1 == lb ]]; then client=(docker exec "${EXTERNAL:?external client container}"); fi
out=$(mktemp -d "${TMPDIR:-/tmp}/chaining-qos.XXXXXXXX")
printf 'case=%s/%s pod=%s/%s node=%s queue=%s target=%s artifacts=%s\n' "$1" "$2" "$NS" "$POD" "$node" "$dev" "$TARGET" "$out" | tee "$out/case.txt"
docker exec "$node" tc -s -j qdisc show dev "$dev" > "$out/before.json"
"${client[@]}" iperf3 -c "$TARGET" -p "${PORT:-5201}" -t "${SECONDS_PER_RUN:-20}" "${reverse[@]}" -J --get-server-output > "$out/report.json"
docker exec "$node" tc -s -j qdisc show dev "$dev" > "$out/after.json"
python3 "$(dirname "$0")/measure.py" "$1" "$pod_ip" "$CAP" "$out"/{report,before,after}.json
