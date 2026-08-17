#!/usr/bin/env bash
# Log and counter review.
#
# A feature that keeps overlapping addresses apart can easily "work" while the
# agent complains in the background - a missing annotation, an ipcache entry it
# refuses to write, a datapath drop with an unexpected reason. This script
# fails on any error, on any warning that is not explicitly expected, and on
# any datapath drop from the pod path other than the policy drops the test
# scenarios ask for.
set -uo pipefail
cd "$(dirname "$0")" && source ./lib.sh

AGENT=$(cilium_pod)
OPERATOR=$(kubectl -n "$CILIUM_NS" get pod -l io.cilium/app=operator -o name 2>/dev/null | head -1)

log "no error or fatal in the agent log"
errs=$(kubectl -n "$CILIUM_NS" logs "$AGENT" -c cilium-agent 2>/dev/null | grep -cE 'level=(error|fatal)')
assert_eq "0" "${errs:-x}" "agent error/fatal lines"
[[ "${errs:-0}" != "0" ]] && kubectl -n "$CILIUM_NS" logs "$AGENT" -c cilium-agent 2>/dev/null \
  | grep -E 'level=(error|fatal)' | tail -5 | sed 's/^/    /'

log "every policy currently in the cluster is valid"
# Judge the current state, not the log history: a policy that was rejected
# earlier in the session and then corrected would otherwise fail this check
# forever.
invalid=0
for ns in "${VPCS[@]}"; do
  for name in $(kubectl -n "$ns" get cnp -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
    msg=$(kubectl -n "$ns" get cnp "$name" -o jsonpath='{.status.conditions[?(@.type=="Valid")].message}' 2>/dev/null)
    info "${ns}/${name}: ${msg:-<no status>}"
    [[ "$msg" == "Policy validation succeeded" ]] || invalid=$((invalid+1))
  done
done
assert_eq "0" "$invalid" "no invalid CiliumNetworkPolicy"

if [[ -n "$OPERATOR" ]]; then
  log "operator errors, classified"
  oerrs=$(kubectl -n "$CILIUM_NS" logs "$OPERATOR" 2>/dev/null | grep -E 'level=(error|fatal)' || true)
  n_all=$(echo "$oerrs" | grep -c . || true)
  # "Detected invalid CNP" is only meaningful if a policy is *still* invalid,
  # which the check above covers.
  n_other=$(echo "$oerrs" | grep -v "Detected invalid CNP" | grep -c . || true)
  info "operator: ${n_all} error lines, ${n_other} unrelated to CNP validation"
  assert_eq "0" "${n_other:-x}" "no operator error outside CNP validation"
  [[ "${n_other:-0}" != "0" ]] && echo "$oerrs" | grep -v "Detected invalid CNP" | tail -3 | cut -c1-160 | sed 's/^/    /'
fi

log "every warning is one of the expected ones"
# Expected warnings:
#  1. the conntrack overlap notice this feature emits on purpose - the fixture
#     co-locates overlapping addresses, so it *must* appear;
#  2. leftover "<id>_next" state directories from endpoint regeneration, which
#     the restorer skips (upstream behaviour, not related to this feature);
#  3. the refusal to move an endpoint between VPCs on a drifted annotation,
#     which 55-vni-scope-change.sh provokes on purpose.
warns=$(kubectl -n "$CILIUM_NS" logs "$AGENT" -c cilium-agent 2>/dev/null | grep 'level=warn' || true)
total=$(echo "$warns" | grep -c . || true)
overlap=$(echo "$warns" | grep -c "local endpoints of different VPCs share an IP" || true)
stale=$(echo "$warns" | grep -c "Couldn't find state, ignoring endpoint" || true)
scope=$(echo "$warns" | grep -c "Ignoring native-vpc VNI change on an existing endpoint" || true)
other=$(echo "$warns" | grep -v "local endpoints of different VPCs share an IP" \
                      | grep -v "Couldn't find state, ignoring endpoint" \
                      | grep -v "Ignoring native-vpc VNI change on an existing endpoint" | grep -c . || true)
info "warnings: ${total} total = ${overlap} conntrack-overlap + ${stale} stale-state + ${scope} refused-scope-change + ${other} other"
assert_eq "0" "${other:-x}" "no unexpected warnings"
[[ "${other:-0}" != "0" ]] && echo "$warns" | grep -v "share an IP" | grep -v "Couldn't find state" | grep -v "Ignoring native-vpc VNI change" \
  | cut -c1-160 | tail -5 | sed 's/^/    /'

# The overlap warning is not noise: it is the conntrack-plane signal, and the
# fixture deliberately triggers it.
[[ "${overlap:-0}" -gt 0 ]] \
  && pass "the conntrack overlap warning was emitted (${overlap}x), as expected for this fixture" \
  || fail "the conntrack overlap warning is missing although the fixture overlaps addresses"

log "no native-vpc specific complaint"
for pat in "missing a valid VNI" "skipping ipcache registration" \
           "keeping the last known VNI" "does not match the pod annotation" \
           "alignment check failed" "unable to parse ipcache key"; do
  n=$(kubectl -n "$CILIUM_NS" logs "$AGENT" -c cilium-agent 2>/dev/null | grep -c "$pat" || true)
  assert_eq "0" "${n:-x}" "no '${pat}' message"
done

log "drops on the test addresses are policy drops only"
# Hubble carries a structured drop reason, so classify there rather than
# parsing the counter table (whose REASON column is multi-word, and whose
# "Interface" rows are REASON_PLAINTEXT forwards, not drops).
drops=$(cilium_exec hubble observe --last 400 -o json | SRC="$CLIENT_IP" DST="$SERVER_IP" python3 -c "
import json,os,sys
from collections import Counter
src=os.environ['SRC']; dst=os.environ['DST']
mine=Counter(); other=Counter()
for line in sys.stdin:
    try: f=json.loads(line).get('flow',{})
    except Exception: continue
    if f.get('verdict')!='DROPPED': continue
    ip=f.get('IP',{}) or {}
    reason=f.get('drop_reason_desc') or '?'
    if ip.get('source')==src and ip.get('destination')==dst:
        mine[reason]+=1
    else:
        other[reason]+=1
print('MINE ' + ','.join('%s=%d'%kv for kv in sorted(mine.items())))
print('OTHER ' + ','.join('%s=%d'%kv for kv in sorted(other.items())))
")
echo "$drops" | sed 's/^/    /'
mine=$(echo "$drops" | awk '/^MINE/{print $2}')
bad=$(echo "$mine" | tr ',' '\n' | grep -v '^POLICY_DENIED=' | grep -c . || true)
assert_eq "0" "${bad:-x}" "every drop between the test addresses is POLICY_DENIED"
echo "$mine" | grep -q "POLICY_DENIED=" \
  && pass "policy drops observed for the deny/port scenarios" \
  || fail "no policy drop observed although two VPCs deny traffic"

log "other drops in the cluster are explained"
# With enable-ipv6=false the pods still emit IPv6 link-local traffic (NDP,
# mDNS), which the datapath drops as an unsupported protocol. That is
# environmental, not a VPC scoping problem.
v6=$(kubectl -n "$CILIUM_NS" get cm cilium-config -o jsonpath='{.data.enable-ipv6}' 2>/dev/null)
info "enable-ipv6=${v6}"
otherd=$(echo "$drops" | awk '/^OTHER/{print $2}')
info "other drop reasons: ${otherd:-none}"
unexplained=$(echo "$otherd" | tr ',' '\n' \
  | grep -vE '^(UNSUPPORTED_L2_PROTOCOL|UNSUPPORTED_L3_PROTOCOL|STALE_OR_UNROUTABLE_IP|POLICY_DENIED)=' \
  | grep -c . || true)
assert_eq "0" "${unexplained:-x}" "no unexplained drop reason anywhere"

log "kube-ovn is not complaining about the overlapping subnets"
# "the vpc X not standby yet, requeue" is kube-ovn reconciling a subnet before
# its VPC router is ready; it retries and settles. Anything else would be worth
# looking at, e.g. a complaint about the overlapping CIDRs.
kovn=$(kubectl -n kube-system logs -l app=kube-ovn-controller --tail=500 2>/dev/null | grep -iE '\berror\b' || true)
# Transient reconcile races while a VPC/subnet is being created or deleted:
# the controller requeues and settles. They say nothing about the CIDR overlap.
transient=$(echo "$kovn" | grep -cE "not standby yet|not found, requeuing|v4 using ip range is empty" || true)
rest=$(echo "$kovn" | grep -vE "not standby yet|not found, requeuing|v4 using ip range is empty" | grep -c . || true)
info "kube-ovn-controller: ${transient} transient requeues, ${rest} other errors"
assert_eq "0" "${rest:-x}" "kube-ovn reports no error about the overlapping subnets"
for vpc in "${VPCS[@]}"; do
  ready=$(kubectl get subnet "subnet-${vpc}" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)
  assert_eq "True" "${ready:-?}" "subnet-${vpc} is Ready now"
done
[[ "${rest:-0}" != "0" ]] && echo "$kovn" | grep -v "not standby yet" | tail -3 | cut -c1-160 | sed 's/^/    /'
true

summary
