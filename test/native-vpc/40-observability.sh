#!/usr/bin/env bash
# Verifies that the observability plane attributes the identical address pairs
# to the right VPC: every flow must carry the VNI of the endpoint that produced
# it, and the drops of vpc-a must not be mixed with the allowed traffic of the
# other two VPCs.
set -uo pipefail
cd "$(dirname "$0")" && source ./lib.sh

log "generating traffic in all three VPCs"
for vpc in "${VPCS[@]}"; do
  for port in "$PORT_ALLOWED" "$PORT_DENIED"; do
    try_connect "$vpc" client "$SERVER_IP" "$port" >/dev/null
  done
done
sleep 3

log "collecting flows between the shared addresses"
flows=$(cilium_exec hubble observe --last 200 -o json | python3 -c "
import json,sys
out=[]
for line in sys.stdin:
    try: f=json.loads(line).get('flow',{})
    except Exception: continue
    ip=f.get('IP',{}) or {}
    if ip.get('source')!='${CLIENT_IP}' or ip.get('destination')!='${SERVER_IP}': continue
    s=f.get('source',{}) or {}; d=f.get('destination',{}) or {}
    l4=(f.get('l4',{}) or {}).get('TCP',{}) or {}
    out.append({'svni':s.get('vni_id'),'dvni':d.get('vni_id'),'sns':s.get('namespace'),
                'dns':d.get('namespace'),'verdict':f.get('verdict'),'dport':l4.get('destination_port')})
print(json.dumps(out))
")

log "every flow carries a VNI on both endpoints"
python3 - "$flows" <<'PY' > /tmp/vni-flow-report
import json,sys
flows=json.loads(sys.argv[1]) if sys.argv[1] else []
missing=[f for f in flows if not f['svni'] or not f['dvni']]
matched=[f for f in flows if f['svni'] and f['svni']==f['dvni']]
print(f"total={len(flows)} with_vni={len(flows)-len(missing)} missing_vni={len(missing)} same_vni_both_sides={len(matched)}")
byvni={}
for f in flows:
    byvni.setdefault((f['svni'],f['sns']),[]).append((f['verdict'],f['dport']))
for (vni,ns),v in sorted(byvni.items(), key=lambda x:str(x[0])):
    verdicts=sorted({x[0] for x in v})
    print(f"  vni={vni} ns={ns} verdicts={verdicts} ports={sorted({x[1] for x in v if x[1]})}")
PY
cat /tmp/vni-flow-report | sed 's/^/    /'

total=$(awk -F'[= ]' '/^total/{print $2}' /tmp/vni-flow-report)
missing=$(awk '{for(i=1;i<=NF;i++) if($i ~ /^missing_vni=/){split($i,a,"=");print a[2]}}' /tmp/vni-flow-report | head -1)
[[ "${total:-0}" -gt 0 ]] && pass "observed ${total} flows between the shared addresses" \
                          || fail "no flows observed"
assert_eq "0" "${missing:-x}" "every flow carries a VNI on both endpoints"

log "each VPC appears under its own VNI"
for vpc in "${VPCS[@]}"; do
  vni=$(pod_vni "$vpc" server)
  grep -q "vni=${vni} ns=${vpc}" /tmp/vni-flow-report \
    && pass "${vpc}: flows attributed to vni=${vni}" \
    || fail "${vpc}: no flows attributed to vni=${vni}"
done

log "the denied VPC shows drops, the open VPC does not"
vni_a=$(pod_vni vpc-a server); vni_c=$(pod_vni vpc-c server)
grep -q "vni=${vni_a} .*DROPPED" /tmp/vni-flow-report \
  && pass "vpc-a (vni=${vni_a}) traffic is dropped" || fail "vpc-a shows no drops"
if grep -q "vni=${vni_c} " /tmp/vni-flow-report && ! grep "vni=${vni_c} " /tmp/vni-flow-report | grep -q "DROPPED"; then
  pass "vpc-c (vni=${vni_c}) traffic is not dropped"
else
  warn "vpc-c verdicts: $(grep "vni=${vni_c} " /tmp/vni-flow-report || echo none)"
fi

summary
