#!/usr/bin/env bash
# Shared helpers for the native-vpc (VNI) end-to-end tests.
# All tests run against a live cluster: kube-ovn provides three VPCs whose
# subnets deliberately use the *same* CIDR, so every VPC contains pods with
# identical IPs. Cilium must keep them apart by (VNI, IP).

set -uo pipefail

# Three VPCs, three subnets, all with the SAME CIDR: this overlap is the whole
# point of the feature under test.
export OVERLAP_CIDR="10.99.0.0/24"
export VPCS=(vpc-a vpc-b vpc-c)
# Fixed IPs so that every VPC has a client and a server on the *same* address.
export CLIENT_IP="10.99.0.11"
export SERVER_IP="10.99.0.12"
export PORT_ALLOWED=8080
export PORT_DENIED=9090

export CILIUM_NS=kube-system
export TEST_TIMEOUT=4

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; BLUE=$'\033[0;34m'; NC=$'\033[0m'

PASS_COUNT=0
FAIL_COUNT=0

log()  { echo "${BLUE}==>${NC} $*"; }
info() { echo "    $*"; }
warn() { echo "${YELLOW}[warn]${NC} $*"; }

pass() { PASS_COUNT=$((PASS_COUNT+1)); echo "${GREEN}[PASS]${NC} $*"; }
fail() { FAIL_COUNT=$((FAIL_COUNT+1)); echo "${RED}[FAIL]${NC} $*"; }

# assert_eq <expected> <actual> <description>
assert_eq() {
  if [[ "$1" == "$2" ]]; then pass "$3 (= $2)"; else fail "$3 (expected '$1', got '$2')"; fi
}

# assert_contains <haystack> <needle> <description>
assert_contains() {
  if [[ "$1" == *"$2"* ]]; then pass "$3"; else fail "$3 (missing '$2' in: $1)"; fi
}

summary() {
  echo
  echo "──────────────────────────────────────────────"
  if [[ $FAIL_COUNT -eq 0 ]]; then
    echo "${GREEN}ALL PASSED${NC}  (${PASS_COUNT} checks)"
  else
    echo "${RED}FAILURES: ${FAIL_COUNT}${NC}  (passed ${PASS_COUNT})"
  fi
  echo "──────────────────────────────────────────────"
  [[ $FAIL_COUNT -eq 0 ]]
}

cilium_pod() {
  kubectl -n "$CILIUM_NS" get pod -l k8s-app=cilium -o name 2>/dev/null | head -1
}

# cilium_exec <args...> - run cilium-dbg inside the agent
cilium_exec() {
  kubectl -n "$CILIUM_NS" exec "$(cilium_pod)" -c cilium-agent -- "$@" 2>/dev/null
}

# pod_vni <namespace> <pod> - the kube-ovn tunnel_key annotation
pod_vni() {
  kubectl -n "$1" get pod "$2" -o jsonpath='{.metadata.annotations.ovn\.kubernetes\.io/tunnel_key}' 2>/dev/null
}

pod_ip() {
  kubectl -n "$1" get pod "$2" -o jsonpath='{.status.podIP}' 2>/dev/null
}

# try_connect <namespace> <client pod> <target ip> <port> -> prints "open"/"closed"
try_connect() {
  local ns=$1 pod=$2 ip=$3 port=$4
  if kubectl -n "$ns" exec "$pod" -- wget -q -T "$TEST_TIMEOUT" -O- "http://${ip}:${port}/" >/dev/null 2>&1; then
    echo open
  else
    echo closed
  fi
}

wait_for_pod() {
  local ns=$1 pod=$2 tries=${3:-60}
  for _ in $(seq "$tries"); do
    [[ "$(kubectl -n "$ns" get pod "$pod" -o jsonpath='{.status.phase}' 2>/dev/null)" == "Running" ]] && return 0
    sleep 2
  done
  return 1
}
