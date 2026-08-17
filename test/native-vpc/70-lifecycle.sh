#!/usr/bin/env bash
# Lifecycle plane: the state that ties an endpoint to its VPC must survive a
# restart, and must not be lost when the annotation temporarily disappears.
#
#   * the CiliumEndpoint carries the VNI so that the agents of other nodes can
#     scope the endpoint (dropping this annotation used to make every remote
#     endpoint lose its VPC);
#   * an annotation that disappears from a running pod must not downgrade the
#     endpoint into the shared plain scope - that is the direction that merges
#     two VPCs;
#   * after an agent restart the VNI, the identities and the VNI-scoped ipcache
#     must come back, and the policy behaviour must be unchanged;
#   * deleting one VPC's pod must not disturb the entries of the other VPCs.
set -uo pipefail
cd "$(dirname "$0")" && source ./lib.sh

log "the CiliumEndpoint carries the VNI annotation"
for vpc in "${VPCS[@]}"; do
  vni=$(pod_vni "$vpc" server)
  cep=$(kubectl -n "$vpc" get cep server -o jsonpath='{.metadata.annotations.native-vpc\.cilium\.io/vni}' 2>/dev/null)
  assert_eq "$vni" "$cep" "${vpc}: CiliumEndpoint annotation matches the pod's tunnel_key"
done

log "removing the annotation from a running pod must not drop its VPC scope"
before=$(cilium_exec cilium-dbg endpoint get "vni-ipv4:$(pod_vni vpc-b server):${SERVER_IP}" -o jsonpath='{[0].id}')
kubectl -n vpc-b annotate pod server ovn.kubernetes.io/tunnel_key- >/dev/null 2>&1
sleep 8
after=$(cilium_exec cilium-dbg endpoint get "vni-ipv4:$(kubectl -n vpc-b get cep server -o jsonpath='{.metadata.annotations.native-vpc\.cilium\.io/vni}' 2>/dev/null):${SERVER_IP}" -o jsonpath='{[0].id}' 2>/dev/null)
assert_eq "$before" "$after" "vpc-b: the endpoint keeps its VPC scope without the annotation"
still=$(try_connect vpc-b client "$SERVER_IP" "$PORT_ALLOWED")
assert_eq "open" "$still" "vpc-b: policy still behaves as before"
# put it back so the rest of the suite sees a consistent cluster
kubectl -n vpc-b annotate pod server "ovn.kubernetes.io/tunnel_key=7" --overwrite >/dev/null 2>&1

log "restarting the agent and re-checking every plane"
kubectl -n "$CILIUM_NS" rollout restart ds/cilium >/dev/null 2>&1
kubectl -n "$CILIUM_NS" rollout status ds/cilium --timeout=180s >/dev/null 2>&1
for _ in $(seq 30); do [[ "$(cilium_exec cilium-dbg status --brief)" == "OK" ]] && break; sleep 4; done
assert_eq "OK" "$(cilium_exec cilium-dbg status --brief)" "the agent is healthy again"

for vpc in "${VPCS[@]}"; do
  vni=$(pod_vni "$vpc" server)
  epid=$(cilium_exec cilium-dbg endpoint get "vni-ipv4:${vni}:${SERVER_IP}" -o jsonpath='{[0].id}')
  [[ -n "$epid" ]] && pass "${vpc}: endpoint restored with vni ${vni} (id ${epid})" \
                   || fail "${vpc}: endpoint lost its VNI across the restart"
done
ipc=$(cilium_exec cilium-dbg bpf ipcache list)
n=$(echo "$ipc" | grep -c "${SERVER_IP}/32@vni:")
assert_eq "3" "$n" "the VNI-scoped ipcache was repopulated"

log "policy behaviour is unchanged after the restart"
assert_eq "closed" "$(try_connect vpc-a client "$SERVER_IP" "$PORT_ALLOWED")" "vpc-a still denies"
assert_eq "open"   "$(try_connect vpc-b client "$SERVER_IP" "$PORT_ALLOWED")" "vpc-b still allows tcp/${PORT_ALLOWED}"
assert_eq "closed" "$(try_connect vpc-b client "$SERVER_IP" "$PORT_DENIED")"  "vpc-b still blocks tcp/${PORT_DENIED}"
assert_eq "open"   "$(try_connect vpc-c client "$SERVER_IP" "$PORT_ALLOWED")" "vpc-c still open"

log "deleting one VPC's pod leaves the other VPCs untouched"
kubectl -n vpc-a delete pod server --wait=true >/dev/null 2>&1
sleep 6
ipc=$(cilium_exec cilium-dbg bpf ipcache list)
gone=$(echo "$ipc" | grep -c "${SERVER_IP}/32@vni:$(pod_vni vpc-b server)" || true)
left=$(echo "$ipc" | grep -c "${SERVER_IP}/32@vni:" || true)
assert_eq "1" "${gone:-0}" "vpc-b's entry for the shared address survived"
assert_eq "2" "${left:-0}" "exactly the deleted VPC's entry disappeared"
assert_eq "open" "$(try_connect vpc-c client "$SERVER_IP" "$PORT_ALLOWED")" "vpc-c is unaffected by the deletion"

summary
