#!/usr/bin/env bash
# Datapath and tooling checks: the BPF map layouts this feature introduced, the
# per-endpoint load-time VNI, and the debug commands that must cope with
# (VNI, IP) keys.
#
# Regression guards for two defects that reached a running cluster:
#   * the full ipcache dump used to panic the agent on VNI keys, which made
#     "cilium-dbg ip list" (GET /ipcache) fatal;
#   * the fragment map key had no VPC scope, and later the C/Go layouts
#     disagreed, which made the agent exit on the alignment check.
set -uo pipefail
cd "$(dirname "$0")" && source ./lib.sh

log "the agent is healthy and running the native-vpc build"
st=$(cilium_exec cilium-dbg status --brief)
assert_eq "OK" "$st" "cilium-dbg status --brief"
kubectl -n "$CILIUM_NS" logs "$(cilium_pod)" -c cilium-agent --tail=2000 2>/dev/null \
  | grep -qiE "level=fatal|alignment check failed" \
  && fail "the agent log contains a fatal error" \
  || pass "no fatal error in the agent log"

log "forwarding plane: the VNI-scoped ipcache map exists with the expected layout"
vni_map=$(kubectl -n "$CILIUM_NS" exec "$(cilium_pod)" -c cilium-agent -- \
  sh -c 'ls /sys/fs/bpf/tc/globals/cilium_ipcache_vni 2>/dev/null' 2>/dev/null)
[[ -n "$vni_map" ]] && pass "cilium_ipcache_vni is pinned" || fail "cilium_ipcache_vni is missing"

if command -v bpftool >/dev/null 2>&1; then
  keysz=$(bpftool map show pinned /sys/fs/bpf/tc/globals/cilium_ipcache_vni 2>/dev/null | grep -oE 'key [0-9]+B' | grep -oE '[0-9]+')
  assert_eq "28" "${keysz:-?}" "cilium_ipcache_vni key size (VNI + family + IP)"

  # 16 bytes = the native-vpc fragment key (12 without the VPC scope). A wrong
  # size here is what previously made the agent fail the alignment check.
  fragsz=$(bpftool map show pinned /sys/fs/bpf/tc/globals/cilium_ipv4_frag_datagrams 2>/dev/null | grep -oE 'key [0-9]+B' | grep -oE '[0-9]+')
  assert_eq "16" "${fragsz:-?}" "cilium_ipv4_frag_datagrams key size (VNI scoped)"
else
  warn "bpftool not available on the host, skipping map layout checks"
fi

log "forwarding plane: each endpoint is loaded with its own VNI"
for vpc in "${VPCS[@]}"; do
  vni=$(pod_vni "$vpc" server)
  epid=$(cilium_exec cilium-dbg endpoint get "vni-ipv4:${vni}:${SERVER_IP}" -o jsonpath='{[0].id}')
  loaded=$(kubectl -n "$CILIUM_NS" exec "$(cilium_pod)" -c cilium-agent -- \
    sh -c "grep -o '\"VNIID\":[0-9]*' /var/run/cilium/state/${epid}/ep_config.json 2>/dev/null | head -1" 2>/dev/null)
  assert_eq "\"VNIID\":${vni}" "$loaded" "${vpc}: endpoint ${epid} carries the load-time VNI"
done

log "cache plane: the full ipcache dump handles VNI keys (used to crash the agent)"
# Keep the full listing: identities print on several lines, so truncating it
# would hide the very rows this check is about.
out=$(cilium_exec cilium-dbg ip list 2>&1)
if [[ -n "$out" ]] && ! echo "$out" | grep -qi "panic\|error"; then
  pass "cilium-dbg ip list works"
else
  fail "cilium-dbg ip list failed: $(echo "$out" | head -3)"
fi
st2=$(cilium_exec cilium-dbg status --brief)
assert_eq "OK" "$st2" "the agent survived the full dump"
# The listing must make the VPC scope visible: without it the three VPCs show
# up as identical rows for the same address.
n=$(echo "$out" | grep -c "@vni:")
[[ "${n:-0}" -ge 3 ]] && pass "the listing shows the VPC scope (${n} entries)" \
                      || fail "the listing does not show the VPC scope"
distinct=$(echo "$out" | grep "${SERVER_IP}/32@vni:" | awk '{print $1}' | sort -u | wc -l)
assert_eq "3" "$distinct" "the shared address appears as three distinguishable rows"

log "observability tooling: a shared address resolves to every VPC that uses it"
got=$(cilium_exec cilium-dbg bpf ipcache get "$SERVER_IP")
for vpc in "${VPCS[@]}"; do
  vni=$(pod_vni "$vpc" server)
  assert_contains "$got" "@vni:${vni}" "bpf ipcache get ${SERVER_IP} reports vni:${vni}"
done

summary
