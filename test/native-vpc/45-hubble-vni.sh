#!/usr/bin/env bash
# Hubble, in detail: can an operator actually see the forwarding-plane data of
# each VPC's pods, keyed by VNI + IP?
#
# All three VPCs move packets between the same two addresses, so a flow record
# is only useful if it carries the VPC scope. This script prints the per-VPC
# forwarding data and asserts that
#   * every flow carries VNI and identity on both endpoints,
#   * the verdict/port pattern matches that VPC's policy,
#   * the identities in the flows are the identities of *that* VPC's endpoints,
#   * flows can be filtered per VPC through the VNI identity label.
set -uo pipefail
cd "$(dirname "$0")" && source ./lib.sh

log "generating traffic in all three VPCs (both ports)"
for vpc in "${VPCS[@]}"; do
  for port in "$PORT_ALLOWED" "$PORT_DENIED"; do
    try_connect "$vpc" client "$SERVER_IP" "$port" >/dev/null
  done
done
sleep 4

raw=$(cilium_exec hubble observe --last 300 -o json)

for vpc in "${VPCS[@]}"; do
  vni=$(pod_vni "$vpc" server)
  cid=$(cilium_exec cilium-dbg endpoint get "vni-ipv4:${vni}:${CLIENT_IP}" -o jsonpath='{[0].status.identity.id}')
  sid=$(cilium_exec cilium-dbg endpoint get "vni-ipv4:${vni}:${SERVER_IP}" -o jsonpath='{[0].status.identity.id}')

  log "${vpc}: vni=${vni}  client identity=${cid}  server identity=${sid}"
  report=$(echo "$raw" | VNI="$vni" SRC="$CLIENT_IP" DST="$SERVER_IP" python3 -c "
import json,os,sys
vni=int(os.environ['VNI']); src=os.environ['SRC']; dst=os.environ['DST']
rows=[]
for line in sys.stdin:
    try: f=json.loads(line).get('flow',{})
    except Exception: continue
    ip=f.get('IP',{}) or {}
    s=f.get('source',{}) or {}; d=f.get('destination',{}) or {}
    if ip.get('source')!=src or ip.get('destination')!=dst: continue
    if int(s.get('vni_id') or 0)!=vni: continue
    l4=(f.get('l4',{}) or {}).get('TCP',{}) or {}
    rows.append({'sv':s.get('vni_id'),'dv':d.get('vni_id'),'si':s.get('identity'),'di':d.get('identity'),
                 'sp':s.get('pod_name'),'dp':d.get('pod_name'),'port':l4.get('destination_port'),
                 'verdict':f.get('verdict'),'reason':f.get('drop_reason_desc')})
agg={}
for r in rows:
    k=(r['port'],r['verdict'],r['reason'])
    agg[k]=agg.get(k,0)+1
print('FLOWS %d' % len(rows))
for (port,verdict,reason),n in sorted(agg.items(), key=lambda x:str(x[0])):
    print('  port=%-5s verdict=%-9s reason=%-22s count=%d' % (port,verdict,reason or '-',n))
if rows:
    r=rows[0]
    print('  sample: %s(vni=%s,id=%s) -> %s(vni=%s,id=%s)' % (r['sp'],r['sv'],r['si'],r['dp'],r['dv'],r['di']))
    print('IDS %s %s' % (r['si'], r['di']))
    print('MISSING %d' % sum(1 for r in rows if not r['sv'] or not r['dv'] or not r['si'] or not r['di']))
")
  echo "$report" | grep -v '^IDS\|^MISSING\|^FLOWS' | sed 's/^/    /'
  n=$(echo "$report" | awk '/^FLOWS/{print $2}')
  miss=$(echo "$report" | awk '/^MISSING/{print $2}')
  fids=$(echo "$report" | awk '/^IDS/{print $2" "$3}')

  [[ "${n:-0}" -gt 0 ]] && pass "${vpc}: ${n} forwarding-plane records visible under vni=${vni}" \
                        || fail "${vpc}: no flows visible for vni=${vni}"
  assert_eq "0" "${miss:-x}" "${vpc}: every record carries VNI and identity on both endpoints"
  assert_eq "${cid} ${sid}" "${fids:-none}" "${vpc}: the record identities are this VPC's endpoints"

  case "$vpc" in
    vpc-a) echo "$report" | grep -q "verdict=DROPPED" && pass "vpc-a: traffic is dropped as the policy says" || fail "vpc-a: expected drops" ;;
    vpc-b)
      echo "$report" | grep -qE "port=${PORT_ALLOWED} +verdict=FORWARDED" && pass "vpc-b: ${PORT_ALLOWED} forwarded" || fail "vpc-b: ${PORT_ALLOWED} not forwarded"
      echo "$report" | grep -qE "port=${PORT_DENIED} +verdict=DROPPED" && pass "vpc-b: ${PORT_DENIED} dropped" || fail "vpc-b: ${PORT_DENIED} not dropped"
      ;;
    vpc-c)
      echo "$report" | grep -q "verdict=DROPPED" && fail "vpc-c: unexpected drops" || pass "vpc-c: nothing is dropped"
      ;;
  esac
  echo
done

log "flows can be filtered per VPC through the VNI identity label"
for vpc in "${VPCS[@]}"; do
  vni=$(pod_vni "$vpc" server)
  out=$(cilium_exec hubble observe --last 300 --label "vni:io-cilium-native-vpc-vni=${vni}" -o json \
        | python3 -c "
import json,sys
vnis=set()
n=0
for line in sys.stdin:
    try: f=json.loads(line).get('flow',{})
    except Exception: continue
    n+=1
    for side in ('source','destination'):
        v=(f.get(side,{}) or {}).get('vni_id')
        if v: vnis.add(int(v))
print(n, sorted(vnis))
")
  cnt=$(echo "$out" | awk '{print $1}')
  vset=$(echo "$out" | cut -d' ' -f2-)
  info "${vpc}: --label vni:...=${vni} -> ${cnt} flows, VNIs seen ${vset}"
  [[ "${cnt:-0}" -gt 0 ]] && pass "${vpc}: the label filter returns flows" || fail "${vpc}: label filter returned nothing"
  [[ "$vset" == "[${vni}]" ]] && pass "${vpc}: the filter returns only vni=${vni}" \
                              || fail "${vpc}: the filter leaked other VNIs: ${vset}"
done

summary
