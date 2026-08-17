#!/usr/bin/env bash
# The actual behaviour test. Every VPC runs the identical connection attempt
# from 10.99.0.11 to 10.99.0.12 on two ports; only the policy of that VPC may
# influence the result.
#
#   vpc-a (deny)  : both ports closed
#   vpc-b (port)  : PORT_ALLOWED open, PORT_DENIED closed
#   vpc-c (open)  : both ports open
#
# Because all three VPCs use the same two addresses, a wrong result here means
# the (VNI, IP) scoping leaked: one VPC's policy would have decided another
# VPC's traffic.
set -uo pipefail
cd "$(dirname "$0")" && source ./lib.sh

declare -A EXPECT=(
  ["vpc-a:${PORT_ALLOWED}"]=closed  ["vpc-a:${PORT_DENIED}"]=closed
  ["vpc-b:${PORT_ALLOWED}"]=open    ["vpc-b:${PORT_DENIED}"]=closed
  ["vpc-c:${PORT_ALLOWED}"]=open    ["vpc-c:${PORT_DENIED}"]=open
)
declare -A SCENARIO=( [vpc-a]="deny-all" [vpc-b]="allow tcp/${PORT_ALLOWED} only" [vpc-c]="no policy" )

log "connectivity matrix: client ${CLIENT_IP} -> server ${SERVER_IP} (identical in all VPCs)"
printf "    %-8s %-24s %-8s %-10s %-10s %s\n" VPC SCENARIO PORT EXPECTED ACTUAL RESULT
for vpc in "${VPCS[@]}"; do
  for port in "$PORT_ALLOWED" "$PORT_DENIED"; do
    want=${EXPECT["${vpc}:${port}"]}
    got=$(try_connect "$vpc" client "$SERVER_IP" "$port")
    if [[ "$want" == "$got" ]]; then
      PASS_COUNT=$((PASS_COUNT+1)); res="${GREEN}PASS${NC}"
    else
      FAIL_COUNT=$((FAIL_COUNT+1)); res="${RED}FAIL${NC}"
    fi
    printf "    %-8s %-24s %-8s %-10s %-10s %b\n" "$vpc" "${SCENARIO[$vpc]}" "$port" "$want" "$got" "$res"
  done
done

echo
log "cross-VPC proof: the deny policy of vpc-a must not affect the identical IP elsewhere"
a=$(try_connect vpc-a client "$SERVER_IP" "$PORT_ALLOWED")
c=$(try_connect vpc-c client "$SERVER_IP" "$PORT_ALLOWED")
if [[ "$a" == "closed" && "$c" == "open" ]]; then
  pass "same source IP, same destination IP, same port: denied in vpc-a, allowed in vpc-c"
else
  fail "cross-VPC scoping leaked (vpc-a=${a}, vpc-c=${c})"
fi

log "cross-VPC proof: the port policy of vpc-b must not leak into vpc-c"
b=$(try_connect vpc-b client "$SERVER_IP" "$PORT_DENIED")
c2=$(try_connect vpc-c client "$SERVER_IP" "$PORT_DENIED")
if [[ "$b" == "closed" && "$c2" == "open" ]]; then
  pass "tcp/${PORT_DENIED} blocked in vpc-b while open in vpc-c, for the same address pair"
else
  fail "port scoping leaked (vpc-b=${b}, vpc-c=${c2})"
fi

summary
