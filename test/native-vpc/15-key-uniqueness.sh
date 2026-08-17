#!/usr/bin/env bash
# 15 - (VNI, IP) is the key, on every plane that can be observed.
#
# The premise is that a pod's VNI and IP are fixed for the whole life of its CNI
# attachment. What has to hold then is narrow and checkable:
#
#   after CNI ADD  - the pod owns exactly one resource per plane, under its own
#                    (VNI, IP), and it collides with nothing that the pods with
#                    the same address in the other VPCs own;
#   after CNI DEL  - exactly that pod's resources are gone and every other VPC's
#                    resources on the same address are untouched.
#
# The fixture is built for this: three VPCs whose subnets share one CIDR, with a
# client and a server on the same two addresses in each. Any place that keys by
# address alone therefore holds one entry where there should be three - or three
# endpoints' worth of state where there should be one.
#
# Planes with no observable state (conntrack, service, encryption/egress) are
# covered by the startup rejections in 50-datapath.sh instead.

set -uo pipefail
cd "$(dirname "$0")" && source ./lib.sh

# vni_of <vpc> - the VNI of a VPC, read from a pod that lives in it
declare -A VNI
for vpc in "${VPCS[@]}"; do VNI[$vpc]=$(pod_vni "$vpc" server); done

# --- helpers, one per observable plane -------------------------------------

# cache: userspace ipcache, scoped keys only
cache_keys() { cilium_exec cilium-dbg ip list | awk -v ip="$1/32" '$1 ~ "^"ip"(@|$)" {print $1}' | sort; }

# forwarding: the VNI-scoped BPF ipcache
fwd_keys() { cilium_exec cilium-dbg bpf ipcache list | awk -v ip="$1/32" '$1 ~ "^"ip"(@|$)" {print $1}' | sort; }

# forwarding: the address-keyed endpoint map, which must not describe VPC pods
endpoint_map_rows() { cilium_exec cilium-dbg bpf endpoint list | grep -c "^$1:" ; }

# control: endpoints known to the agent for this address
control_ids() {
  cilium_exec cilium-dbg endpoint list -o json | python3 -c "
import json,sys
ids=[]
for e in json.load(sys.stdin):
    st=e.get('status',{})
    for a in (st.get('networking',{}) or {}).get('addressing',[]) or []:
        if a.get('ipv4')=='$1': ids.append(e['id'])
print(' '.join(str(i) for i in sorted(ids)))
"
}

# policy: identities in use for this address, one per VPC
identities_for() {
  cilium_exec cilium-dbg bpf ipcache list | awk -v ip="$1/32" '$1 ~ "^"ip"@vni:" {print $2}' | sed 's/identity=//' | sort -n | tr '\n' ' ' | sed 's/ $//'
}

log "topology: three VPCs, one CIDR, the same two addresses in each"
for vpc in "${VPCS[@]}"; do info "${vpc}: vni=${VNI[$vpc]} client=${CLIENT_IP} server=${SERVER_IP}"; done

# --- after CNI ADD ---------------------------------------------------------

log "cache plane: one key per VPC, and every key carries its scope"
for ip in "$CLIENT_IP" "$SERVER_IP"; do
  keys=$(cache_keys "$ip")
  n=$(echo "$keys" | grep -c .)
  assert_eq "3" "$n" "${ip}: three scoped ipcache keys"
  unscoped=$(echo "$keys" | grep -cv "@vni:")
  assert_eq "0" "${unscoped:-x}" "${ip}: no key without a scope"
  for vpc in "${VPCS[@]}"; do
    echo "$keys" | grep -q "@vni:${VNI[$vpc]}$" \
      && pass "${ip}: ${vpc} owns ${ip}@vni:${VNI[$vpc]}" \
      || fail "${ip}: no key for ${vpc} (vni ${VNI[$vpc]})"
  done
done

log "forwarding plane: the datapath sees the same three, and nothing bare"
for ip in "$CLIENT_IP" "$SERVER_IP"; do
  n=$(fwd_keys "$ip" | grep -c "@vni:")
  assert_eq "3" "$n" "${ip}: three scoped BPF ipcache entries"
  bare=$(fwd_keys "$ip" | grep -cv "@vni:")
  assert_eq "0" "${bare:-x}" "${ip}: nothing in the unscoped ipcache"
done

log "forwarding plane: the address-keyed endpoint map describes no VPC pod"
# cilium_lxc has no room for a scope in its key, so an entry for a shared
# address could only answer for whichever endpoint wrote last.
for ip in "$CLIENT_IP" "$SERVER_IP"; do
  assert_eq "0" "$(endpoint_map_rows "$ip")" "${ip}: no entry in the endpoint map"
done

log "control plane: three endpoints share the address, each addressable"
for ip in "$CLIENT_IP" "$SERVER_IP"; do
  ids=$(control_ids "$ip")
  n=$(echo "$ids" | wc -w)
  assert_eq "3" "$n" "${ip}: three endpoints (ids: ${ids})"
done

log "policy plane: three distinct identities on one address"
for ip in "$CLIENT_IP" "$SERVER_IP"; do
  ids=$(identities_for "$ip")
  uniq_n=$(echo "$ids" | tr ' ' '\n' | sort -u | grep -c .)
  assert_eq "3" "$uniq_n" "${ip}: identities are distinct per VPC (${ids})"
done

# --- after CNI DEL ---------------------------------------------------------

VICTIM=vpc-b
VICTIM_VNI=${VNI[$VICTIM]}
log "deleting ${VICTIM}/server removes its resources and only its own"

before_cache=$(cache_keys "$SERVER_IP" | grep -c .)
kubectl -n "$VICTIM" delete pod server --wait=true >/dev/null 2>&1
sleep 8

after=$(cache_keys "$SERVER_IP")
assert_eq "$((before_cache - 1))" "$(echo "$after" | grep -c .)" \
  "one ipcache key fewer"
echo "$after" | grep -q "@vni:${VICTIM_VNI}$" \
  && fail "the deleted pod's key ${SERVER_IP}@vni:${VICTIM_VNI} survived" \
  || pass "the deleted pod's key is gone"
for vpc in vpc-a vpc-c; do
  echo "$after" | grep -q "@vni:${VNI[$vpc]}$" \
    && pass "${vpc} still owns ${SERVER_IP}@vni:${VNI[$vpc]}" \
    || fail "${vpc} lost its key when ${VICTIM} was deleted"
done

fwd_after=$(fwd_keys "$SERVER_IP")
assert_eq "2" "$(echo "$fwd_after" | grep -c '@vni:')" "two scoped datapath entries remain"
echo "$fwd_after" | grep -q "@vni:${VICTIM_VNI}$" \
  && fail "the datapath entry of the deleted pod survived" \
  || pass "the datapath entry of the deleted pod is gone"

assert_eq "2" "$(control_ids "$SERVER_IP" | wc -w)" "two endpoints remain on the address"

log "the survivors still work"
# The point of the previous checks is this one: deleting a pod in one VPC must
# not disturb the pod that owns the same address in another VPC.
res=$(try_connect vpc-c client "$SERVER_IP" "$PORT_ALLOWED")
assert_eq "open" "$res" "vpc-c still reaches its own server on ${SERVER_IP}"

log "recreating it restores exactly one key, in its own VPC"
kubectl apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: server
  namespace: ${VICTIM}
  labels: {app: server, vni-test: "true"}
  annotations:
    ovn.kubernetes.io/ip_address: "${SERVER_IP}"
    ovn.kubernetes.io/logical_switch: subnet-${VICTIM}
spec:
  containers:
  - name: c
    image: docker.io/library/busybox:1.36
    imagePullPolicy: IfNotPresent
    command: ["sh","-c"]
    args:
    - |
      mkdir -p /www && echo "hello from ${VICTIM}" > /www/index.html
      httpd -p ${PORT_ALLOWED} -h /www
      httpd -p ${PORT_DENIED} -h /www
      sleep infinity
YAML
kubectl -n "$VICTIM" wait --for=condition=Ready pod/server --timeout=120s >/dev/null 2>&1
sleep 8

restored=$(cache_keys "$SERVER_IP")
assert_eq "3" "$(echo "$restored" | grep -c .)" "three keys again"
echo "$restored" | grep -q "@vni:${VICTIM_VNI}$" \
  && pass "${VICTIM} owns ${SERVER_IP}@vni:${VICTIM_VNI} again" \
  || fail "${VICTIM} did not get its key back"
assert_eq "0" "$(endpoint_map_rows "$SERVER_IP")" "still no entry in the endpoint map"

summary
