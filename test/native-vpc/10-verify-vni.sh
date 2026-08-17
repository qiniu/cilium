#!/usr/bin/env bash
# Verifies that Cilium keeps the three VPCs apart by (VNI, IP) on every plane,
# even though all six pods use only two distinct IP addresses.
set -uo pipefail
cd "$(dirname "$0")" && source ./lib.sh

log "control plane: every pod carries a distinct VNI from its subnet"
declare -A VNI
for vpc in "${VPCS[@]}"; do
  VNI[$vpc]=$(pod_vni "$vpc" server)
  [[ -n "${VNI[$vpc]}" ]] && pass "${vpc}: server has tunnel_key=${VNI[$vpc]}" || fail "${vpc}: server has no tunnel_key"
done
uniq_vnis=$(printf '%s\n' "${VNI[@]}" | sort -u | wc -l)
assert_eq "3" "$uniq_vnis" "the three VPCs use three different VNIs"

log "control plane: the same IP is used by all three VPCs"
ips=$(for vpc in "${VPCS[@]}"; do echo "$(pod_ip "$vpc" server)"; done | sort -u)
assert_eq "$SERVER_IP" "$ips" "all three servers share one address"

log "control plane: each endpoint gets its own identity and a VNI identity label"
eps=$(cilium_exec cilium-dbg endpoint list -o json)
for vpc in "${VPCS[@]}"; do
  vni=${VNI[$vpc]}
  id=$(echo "$eps" | python3 -c "
import json,sys
eps=json.load(sys.stdin)
for e in eps:
    st=e.get('status',{})
    lbls=(st.get('identity') or {}).get('labels') or []
    ns=[l for l in lbls if l=='k8s:io.kubernetes.pod.namespace=$vpc']
    srv=[l for l in lbls if l=='k8s:app=server']
    if ns and srv:
        print((st.get('identity') or {}).get('id'));break
")
  labels=$(echo "$eps" | python3 -c "
import json,sys
eps=json.load(sys.stdin)
for e in eps:
    st=e.get('status',{})
    lbls=(st.get('identity') or {}).get('labels') or []
    if 'k8s:io.kubernetes.pod.namespace=$vpc' in lbls and 'k8s:app=server' in lbls:
        print(','.join(lbls));break
")
  assert_contains "$labels" "vni:io-cilium-native-vpc-vni=${vni}" "${vpc}: identity carries the VNI label"
  echo "$id" > "/tmp/vni-id-${vpc}"
done
ids=$(cat /tmp/vni-id-vpc-a /tmp/vni-id-vpc-b /tmp/vni-id-vpc-c 2>/dev/null | sort -u | wc -l)
assert_eq "3" "$ids" "three different numeric identities for the same IP"

log "cache plane: the ipcache holds one entry per (VNI, IP)"
ipc=$(cilium_exec cilium-dbg bpf ipcache list)
for vpc in "${VPCS[@]}"; do
  vni=${VNI[$vpc]}
  assert_contains "$ipc" "${SERVER_IP}/32@vni:${vni}" "${vpc}: ${SERVER_IP} present under vni:${vni}"
done
n=$(echo "$ipc" | grep -c "${SERVER_IP}/32@vni:")
assert_eq "3" "$n" "the shared address resolves to three separate ipcache entries"

log "forwarding plane: each endpoint is loaded with its own VNI"
for vpc in "${VPCS[@]}"; do
  vni=${VNI[$vpc]}
  epid=$(cilium_exec cilium-dbg endpoint get "vni-ipv4:${vni}:${SERVER_IP}" -o jsonpath='{[0].id}')
  [[ -n "$epid" ]] && pass "${vpc}: endpoint resolvable by vni-ipv4:${vni}:${SERVER_IP} (id ${epid})" \
                   || fail "${vpc}: no endpoint for vni-ipv4:${vni}:${SERVER_IP}"
done

log "conntrack plane: the overlap precondition is reported"
overlap=$(cilium_exec cilium-dbg metrics list | awk '/native_vpc_overlapping_ips/{print int($NF)}')
[[ "${overlap:-0}" -ge 2 ]] \
  && pass "cilium_native_vpc_overlapping_ips=${overlap} (both shared addresses flagged)" \
  || fail "cilium_native_vpc_overlapping_ips=${overlap:-unset}, expected >= 2"

summary
