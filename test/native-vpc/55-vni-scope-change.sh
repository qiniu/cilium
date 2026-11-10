#!/usr/bin/env bash
# 55 - the scope of an endpoint follows its pod's tunnel_key.
#
# kube-ovn changes the tunnel_key of a running pod when the scope itself moves,
# most notably when the key moves from the subnet to the VPC. An ipcache entry
# is keyed by (VNI, IP), so "the address did not change" says nothing about
# whether an entry is still the right one. This test checks against a live
# cluster that:
#
#   1. a running pod moves to the scope its annotation names: the entry, the
#      identity label and the CiliumEndpoint annotation all move, and nothing
#      is left under the old VNI;
#   2. a missing or zero annotation never moves an endpoint (that would merge
#      it into the shared plain scope);
#   3. a key that changes while the agent is down is taken on restore;
#   4. a real move (delete and recreate in another VPC, keeping the address)
#      leaves nothing behind. Because all three subnets share one CIDR, the
#      same address is genuinely valid in both, which is exactly the case where
#      a leftover entry would resolve to the wrong pod.
#
# Annotations are written as kube-ovn-controller (kubeovn_annotate): kube-ovn's
# ValidatingAdmissionPolicy rejects anybody else.

set -uo pipefail
cd "$(dirname "$0")" && source ./lib.sh

PROBE_NS=vpc-c
PROBE=vni-scope-probe
PROBE_IP=10.99.0.31
MOVE_VNI=4095   # a VNI no VPC in the fixture uses

AGENTS_STOPPED=0
cleanup_probe() { for ns in "${VPCS[@]}"; do kubectl -n "$ns" delete pod "$PROBE" --wait=true >/dev/null 2>&1; done; }
on_exit() {
  # never leave the agents stopped, whatever interrupted the test
  [[ "$AGENTS_STOPPED" == 1 ]] && start_agents
  cleanup_probe
}
trap on_exit EXIT

# entries_for <ip> - the VNIs under which the BPF ipcache holds that address
entries_for() {
  cilium_exec cilium-dbg bpf ipcache list | awk -v ip="$1/32" '$1 ~ "^"ip"@vni:" {sub(/.*@vni:/,"",$1); print $1}' | sort -n | tr '\n' ' ' | sed 's/ $//'
}

# cep_vni <namespace> - the VNI the probe's CiliumEndpoint publishes
cep_vni() {
  kubectl -n "$1" get cep "$PROBE" -o jsonpath='{.metadata.annotations.native-vpc\.cilium\.io/vni}' 2>/dev/null
}

# wait_cep_vni <namespace> <want> - the CEP is published by its own controller
wait_cep_vni() {
  for _ in $(seq 30); do
    [[ "$(cep_vni "$1")" == "$2" ]] && return 0
    sleep 1
  done
}

# wait_entries <ip> <want> - entries move asynchronously (identity resolution)
wait_entries() {
  for _ in $(seq 30); do
    [[ "$(entries_for "$1")" == "$2" ]] && return 0
    sleep 1
  done
}

identity_labels_of() {
  cilium_exec cilium-dbg endpoint list -o json | python3 -c "
import json,sys
for e in json.load(sys.stdin):
    st=e.get('status',{})
    for a in (st.get('networking',{}) or {}).get('addressing',[]) or []:
        if a.get('ipv4')=='$1':
            print(' '.join(st['identity']['labels'])); raise SystemExit
"
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
  for _ in $(seq 30); do
    [[ -n "$(pod_vni "$1" "$PROBE")" ]] && break
    sleep 2
  done
  sleep 4
}

# The agents are stopped by a node selector no node has, which keeps the
# datapath and the pods untouched; removing it brings them back with restore.
stop_agents() {
  AGENTS_STOPPED=1
  kubectl -n "$CILIUM_NS" patch ds cilium --type=json \
    -p '[{"op":"add","path":"/spec/template/spec/nodeSelector/native-vpc-test~1agent-off","value":"true"}]' >/dev/null
  for _ in $(seq 60); do
    [[ -z "$(cilium_pod)" ]] && return 0
    sleep 2
  done
}
start_agents() {
  kubectl -n "$CILIUM_NS" patch ds cilium --type=json \
    -p '[{"op":"remove","path":"/spec/template/spec/nodeSelector/native-vpc-test~1agent-off"}]' >/dev/null
  AGENTS_STOPPED=0
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

log "kube-ovn moves the running pod to another scope"
kubeovn_annotate "$PROBE_NS" "$PROBE" "ovn.kubernetes.io/tunnel_key=${MOVE_VNI}" >/dev/null
wait_entries "$PROBE_IP" "$MOVE_VNI"
assert_eq "$MOVE_VNI" "$(entries_for "$PROBE_IP")" \
  "the address moved to the new scope and nothing is left under VNI ${HOME_VNI}"
assert_contains "$(identity_labels_of "$PROBE_IP")" "vni:io-cilium-native-vpc-vni=${MOVE_VNI}" \
  "the identity label names the new scope"
wait_cep_vni "$PROBE_NS" "$MOVE_VNI"
assert_eq "$MOVE_VNI" "$(cep_vni "$PROBE_NS")" \
  "the CiliumEndpoint other nodes read names the new scope"

log "a missing or zero annotation never moves the endpoint"
kubeovn_annotate "$PROBE_NS" "$PROBE" "ovn.kubernetes.io/tunnel_key=0" >/dev/null
sleep 6
assert_eq "$MOVE_VNI" "$(entries_for "$PROBE_IP")" "a zero key keeps the scope"
kubeovn_annotate "$PROBE_NS" "$PROBE" "ovn.kubernetes.io/tunnel_key-" >/dev/null
sleep 6
assert_eq "$MOVE_VNI" "$(entries_for "$PROBE_IP")" "a removed key keeps the scope"

log "a key that changes while the agent is down is taken on restore"
stop_agents
kubeovn_annotate "$PROBE_NS" "$PROBE" "ovn.kubernetes.io/tunnel_key=${HOME_VNI}" >/dev/null
start_agents
wait_entries "$PROBE_IP" "$HOME_VNI"
assert_eq "$HOME_VNI" "$(entries_for "$PROBE_IP")" \
  "after restore the address is only in the scope the annotation names"
assert_contains "$(identity_labels_of "$PROBE_IP")" "vni:io-cilium-native-vpc-vni=${HOME_VNI}" \
  "restore replaced the identity label"
moved=$(kubectl -n "$CILIUM_NS" logs "$(cilium_pod)" -c cilium-agent 2>/dev/null \
  | grep -c "Native-vpc VNI changed before the endpoint is exposed")
if [[ "${moved:-0}" -gt 0 ]]; then
  pass "restore reports the scope change (${moved} log lines)"
else
  fail "restore did not report taking the changed key"
fi
assert_eq "0" "$(cilium_exec cilium-dbg bpf ipcache list | grep -c "@vni:${MOVE_VNI}")" \
  "nothing is left in scope ${MOVE_VNI}"

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
