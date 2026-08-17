#!/usr/bin/env bash
# 55 - the scope of an endpoint is not a mutable field.
#
# An ipcache entry is keyed by (VNI, IP), so "the address did not change" says
# nothing about whether an entry is still the right one. Two rules follow, and
# this test checks both against a live cluster:
#
#   1. a running pod does not move between VPCs because its tunnel_key
#      annotation changed - the VNI is an identity and datapath dimension, and
#      nothing here re-derives the identity, the CiliumEndpoint other nodes
#      read, or the loaded BPF configuration. The annotation may drift; the
#      endpoint keeps the VPC it was admitted with, including across an agent
#      restart, and no entry is ever published under the VPC named by the
#      drifted annotation.
#
#   2. a real move (delete and recreate in another VPC, keeping the address)
#      leaves nothing behind: the entry of the old VPC is gone and only the new
#      one remains. Because all three subnets share one CIDR, the same address
#      is genuinely valid in both, which is exactly the case where a leftover
#      entry would resolve to the wrong pod.

set -uo pipefail
cd "$(dirname "$0")" && source ./lib.sh

PROBE_NS=vpc-c
PROBE=vni-scope-probe
PROBE_IP=10.99.0.31
DRIFT_VNI=4095   # a VNI no subnet in the fixture uses

cleanup_probe() { for ns in "${VPCS[@]}"; do kubectl -n "$ns" delete pod "$PROBE" --wait=true >/dev/null 2>&1; done; }
trap cleanup_probe EXIT

# entries_for <ip> - the VNIs under which the BPF ipcache holds that address
entries_for() {
  cilium_exec cilium-dbg bpf ipcache list | awk -v ip="$1/32" '$1 ~ "^"ip"@vni:" {sub(/.*@vni:/,"",$1); print $1}' | sort -n | tr '\n' ' ' | sed 's/ $//'
}

make_probe() {  # make_probe <namespace> <subnet>
  cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: $PROBE
  namespace: $1
  labels: {app: $PROBE}
  annotations:
    ovn.kubernetes.io/logical_switch: $2
    ovn.kubernetes.io/ip_address: $PROBE_IP
spec:
  nodeName: $(kubectl get nodes -o jsonpath='{.items[0].metadata.name}')
  containers:
  - name: c
    image: busybox:1.36
    command: ["sleep","3600"]
    imagePullPolicy: IfNotPresent
  terminationGracePeriodSeconds: 1
EOF
  kubectl -n "$1" wait --for=condition=Ready "pod/$PROBE" --timeout=120s >/dev/null 2>&1
  # kube-ovn writes tunnel_key as part of admitting the pod into the subnet; it
  # can land slightly after the pod is Ready.
  for _ in $(seq 30); do
    [[ -n "$(pod_vni "$1" "$PROBE")" ]] && break
    sleep 2
  done
  sleep 4
}

restart_agent() {
  kubectl -n "$CILIUM_NS" rollout restart ds/cilium >/dev/null 2>&1
  kubectl -n "$CILIUM_NS" rollout status ds/cilium --timeout=240s >/dev/null 2>&1
  sleep 12
}

log "a pod is admitted into the VPC of its subnet"
cleanup_probe
make_probe "$PROBE_NS" "subnet-${PROBE_NS}"
HOME_VNI=$(pod_vni "$PROBE_NS" "$PROBE")
info "pod ${PROBE_NS}/${PROBE} ip=${PROBE_IP} vni=${HOME_VNI}"
assert_eq "$HOME_VNI" "$(entries_for "$PROBE_IP")" \
  "the address exists in exactly one VPC"

log "the annotation drifts while the pod runs"
# This is what an administrator changing a subnet's tunnel key looks like from
# Cilium's side: the pod object changes, the datapath does not.
kubectl -n "$PROBE_NS" annotate pod "$PROBE" "ovn.kubernetes.io/tunnel_key=${DRIFT_VNI}" --overwrite >/dev/null
sleep 8
assert_eq "$DRIFT_VNI" "$(pod_vni "$PROBE_NS" "$PROBE")" "the pod now claims another VPC"
assert_eq "$HOME_VNI" "$(entries_for "$PROBE_IP")" \
  "the running pod stays in the VPC it was admitted with"

log "the drift survives an agent restart without being adopted"
# The restart is the interesting half: restore re-reads the annotation, which is
# how a pod that never had a VNI picks one up. Taking a *different* one here
# would move the address into a VPC while the identity still names another.
before=$(cilium_exec cilium-dbg bpf ipcache list | grep -c "@vni:")
restart_agent
assert_eq "$HOME_VNI" "$(entries_for "$PROBE_IP")" \
  "after restore the address is still only in its own VPC"
refusals=$(kubectl -n "$CILIUM_NS" logs "$(cilium_pod)" -c cilium-agent 2>/dev/null \
  | grep -c "Ignoring native-vpc VNI change on an existing endpoint")
if [[ "${refusals:-0}" -gt 0 ]]; then
  pass "the refusal is reported (${refusals} log lines)"
else
  fail "restore adopted the drifted VNI silently, or did not report refusing it"
fi
after=$(cilium_exec cilium-dbg bpf ipcache list | grep -c "@vni:")
assert_eq "$before" "$after" "the restart did not change the number of scoped entries"

log "no entry is published under the VPC named by the drifted annotation"
# The pod watcher keeps its own placeholder entries; those must not name a VPC
# the endpoint refused either, including during the startup window in which the
# endpoints are not restored yet.
drifted=$(cilium_exec cilium-dbg bpf ipcache list | grep -c "@vni:${DRIFT_VNI}")
assert_eq "0" "${drifted:-x}" "nothing exists in VPC ${DRIFT_VNI}"

log "the identity still describes the VPC the pod is in"
labels=$(cilium_exec cilium-dbg endpoint list -o json \
  | python3 -c "
import json,sys
for e in json.load(sys.stdin):
    st=e.get('status',{})
    for a in (st.get('networking',{}) or {}).get('addressing',[]) or []:
        if a.get('ipv4')=='${PROBE_IP}':
            print(' '.join(st['identity']['labels'])); raise SystemExit
")
assert_contains "$labels" "vni:io-cilium-native-vpc-vni=${HOME_VNI}" \
  "the identity label names the same VPC as the entry"

log "moving the pod to another VPC leaves nothing behind"
# The address is valid in every VPC of the fixture, so a leftover entry would
# not be inert: it would answer for an address another VPC legitimately owns.
cleanup_probe
sleep 5
assert_eq "" "$(entries_for "$PROBE_IP")" "deleting the pod removes its entry"

make_probe vpc-a subnet-vpc-a
NEW_VNI=$(pod_vni vpc-a "$PROBE")
PROBE_NS=vpc-a
info "recreated in vpc-a with the same address, vni=${NEW_VNI}"
assert_eq "$NEW_VNI" "$(entries_for "$PROBE_IP")" \
  "the address exists only in the new VPC (no entry left in VPC ${HOME_VNI})"

log "cleanup"
cleanup_probe
sleep 4
assert_eq "" "$(entries_for "$PROBE_IP")" "the fixture is left as it was found"

summary
