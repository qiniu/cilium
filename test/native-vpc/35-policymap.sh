#!/usr/bin/env bash
# Policy plane, as the datapath sees it.
#
# The policy map is keyed by *identity*, never by address. With three VPCs on
# the same addresses this is what makes a rule unambiguous: the peer allowed in
# vpc-b is the identity of the client that carries vni=7, so the identical
# address in vpc-a or vpc-c can never match it.
set -uo pipefail
cd "$(dirname "$0")" && source ./lib.sh

for vpc in "${VPCS[@]}"; do
  vni=$(pod_vni "$vpc" server)
  ep=$(cilium_exec cilium-dbg endpoint get "vni-ipv4:${vni}:${SERVER_IP}" -o jsonpath='{[0].id}')
  log "${vpc} (vni=${vni}) server endpoint ${ep}: ingress policy map"
  pol=$(cilium_exec cilium-dbg bpf policy get "$ep")
  echo "$pol" | grep -E "POLICY|Allow|Deny" | head -6 | sed 's/^/    /'

  case "$vpc" in
    vpc-a)
      # default deny: no rule may allow the client
      if echo "$pol" | grep -A 12 "Allow.*Ingress" | grep -q "k8s:app=client"; then
        fail "vpc-a: the policy map allows the client although the policy denies everything"
      else
        pass "vpc-a: no ingress rule allows the client"
      fi
      ;;
    vpc-b)
      entry=$(echo "$pol" | awk '/Allow +Ingress/{f=1} f&&/8080\/TCP/{print;exit}')
      [[ -n "$entry" ]] && pass "vpc-b: ingress allowed on 8080/TCP" || fail "vpc-b: no 8080/TCP allow entry"
      echo "$pol" | grep -q "9090/TCP" \
        && fail "vpc-b: 9090/TCP is present in the policy map" \
        || pass "vpc-b: 9090/TCP is not allowed"
      # the allowed peer must belong to the *same* VPC
      # note: the table is padded with trailing spaces, so match the label itself
      peer_vni=$(echo "$pol" | awk '/k8s:app=client/{f=1} f&&/vni:io-cilium-native-vpc-vni=/{print;exit}' \
                 | grep -oE 'vni:io-cilium-native-vpc-vni=[0-9]+' | grep -oE '[0-9]+')
      assert_eq "$vni" "${peer_vni:-none}" "vpc-b: the allowed peer identity carries the same VNI"
      pkts=$(echo "$pol" | awk '/8080\/TCP/{print $(NF-2)}' | head -1)
      [[ "${pkts:-0}" =~ ^[0-9]+$ && "${pkts:-0}" -gt 0 ]] \
        && pass "vpc-b: the allow entry has matched real traffic (${pkts} packets)" \
        || warn "vpc-b: no packet counter yet on the allow entry"
      ;;
    vpc-c)
      # no policy: the endpoint is not under ingress enforcement at all
      enf=$(cilium_exec cilium-dbg endpoint list -o json | python3 -c "
import json,sys
for e in json.load(sys.stdin):
    if str(e.get('id'))=='${ep}':
        print((e.get('status',{}).get('policy',{}).get('realized',{}) or {}).get('policy-enabled','?'));break
")
      [[ "$enf" == "none" || "$enf" == "egress" ]] \
        && pass "vpc-c: ingress is not enforced (policy-enabled=${enf})" \
        || fail "vpc-c: unexpected enforcement state '${enf}'"
      ;;
  esac
  echo
done

log "the three servers are three different identities"
ids=""
for vpc in "${VPCS[@]}"; do
  vni=$(pod_vni "$vpc" server)
  ep=$(cilium_exec cilium-dbg endpoint get "vni-ipv4:${vni}:${SERVER_IP}" -o jsonpath='{[0].id}')
  id=$(cilium_exec cilium-dbg endpoint get "$ep" -o jsonpath='{[0].status.identity.id}')
  info "${vpc}: endpoint ${ep} identity ${id}"
  ids="${ids}${id}\n"
done
assert_eq "3" "$(printf "$ids" | sort -u | grep -c .)" "three distinct identities behind one address"

summary
