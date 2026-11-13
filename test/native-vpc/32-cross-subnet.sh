#!/usr/bin/env bash
# Regression for qbox/las#4978: a security group shared by pods in two subnets
# of one VPC. kube-ovn writes the VPC's tunnel key, so both pods are in one
# (VNI, IP) scope and resolve each other with a single lookup.
set -euo pipefail
cd "$(dirname "$0")" && source ./lib.sh

NS=native-vpc-cross-subnet
cleanup() {
  kubectl delete namespace "$NS" --ignore-not-found --wait=true >/dev/null
  kubectl delete subnet native-vpc-cross-a native-vpc-cross-b --ignore-not-found --wait=true >/dev/null
  kubectl delete vpc native-vpc-cross --ignore-not-found --wait=true >/dev/null
}
kubectl create namespace "$NS"
trap cleanup EXIT
kubectl apply -f - <<YAML
apiVersion: kubeovn.io/v1
kind: Vpc
metadata:
  name: native-vpc-cross
spec:
  namespaces: [${NS}]
---
apiVersion: kubeovn.io/v1
kind: Subnet
metadata:
  name: native-vpc-cross-a
spec:
  vpc: native-vpc-cross
  cidrBlock: 10.98.0.0/24
  protocol: IPv4
  namespaces: [${NS}]
---
apiVersion: kubeovn.io/v1
kind: Subnet
metadata:
  name: native-vpc-cross-b
spec:
  vpc: native-vpc-cross
  cidrBlock: 10.98.8.0/24
  protocol: IPv4
YAML

for side in a b; do
  kubectl apply -f - <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: peer-${side}
  namespace: ${NS}
  labels:
    sg: shared
  annotations:
    ovn.kubernetes.io/logical_switch: native-vpc-cross-${side}
spec:
  containers:
  - name: c
    image: docker.io/library/busybox:1.36
    imagePullPolicy: IfNotPresent
    command: [sh, -c, 'mkdir -p /www; echo ok >/www/index.html; httpd -p 8080 -h /www; sleep infinity']
YAML
done
kubectl -n "$NS" wait --for=condition=Ready pod --all --timeout=180s
for pod in peer-a peer-b; do
  # CEP publication is asynchronous after CNI ADD.
  for attempt in $(seq 60); do
    if kubectl -n "$NS" get cep "$pod" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  kubectl -n "$NS" wait --for=jsonpath='{.status.state}'=ready "cep/$pod" --timeout=60s
done
A=$(pod_ip "$NS" peer-a)
B=$(pod_ip "$NS" peer-b)
VNI_A=$(pod_vni "$NS" peer-a)
VNI_B=$(pod_vni "$NS" peer-b)
info "peer-a=$A@vni:$VNI_A peer-b=$B@vni:$VNI_B"
assert_eq "$VNI_A" "$VNI_B" "pods in two subnets of one VPC share the VPC's VNI"
[[ -n "$VNI_A" ]] || { fail "pods carry no tunnel_key"; summary; exit 1; }

# First verify that kube-ovn routes between these subnets without SG policy.
kubectl -n "$NS" exec peer-a -- ping -c 1 -W 2 "$B"
kubectl -n "$NS" exec peer-b -- ping -c 1 -W 2 "$A"

kubectl apply -f - <<YAML
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: shared-sg
  namespace: ${NS}
spec:
  endpointSelector: {}
  ingress:
  - fromEndpoints:
    - matchLabels:
        sg: shared
  egress:
  - toEndpoints:
    - matchLabels:
        sg: shared
YAML
declare -A AGENT_PODS
for pod in peer-a peer-b; do
  node=$(kubectl -n "$NS" get pod "$pod" -o jsonpath='{.spec.nodeName}')
  agent=$(cilium_pod_on_node "$node")
  [[ -n "$agent" ]] || { echo "no Cilium agent on $node" >&2; exit 1; }
  AGENT_PODS[$pod]=$agent
  for attempt in $(seq 60); do
    policy=$(cilium_exec_pod "$agent" cilium-dbg policy get -o json)
    if jq -e '.policy | contains("shared")' <<<"$policy" >/dev/null; then
      revision=$(jq -r .revision <<<"$policy")
      cilium_exec_pod "$agent" cilium-dbg policy wait "$revision" --max-wait-time 60
      break
    fi
    sleep 1
  done
  jq -e '.policy | contains("shared")' <<<"$(cilium_exec_pod "$agent" cilium-dbg policy get -o json)" >/dev/null
done
for attempt in $(seq 5); do
  if [[ "$(try_connect "$NS" peer-a "$B" 8080)" == open ]] &&
     [[ "$(try_connect "$NS" peer-b "$A" 8080)" == open ]]; then
    break
  fi
  sleep 1
done
assert_eq open "$(try_connect "$NS" peer-a "$B" 8080)" "SG allows TCP A -> B across subnets"
assert_eq open "$(try_connect "$NS" peer-b "$A" 8080)" "SG allows TCP B -> A across subnets"
for pair in "peer-a $B" "peer-b $A"; do
  read -r pod ip <<<"$pair"
  if kubectl -n "$NS" exec "$pod" -- ping -c 1 -W 2 "$ip" >/dev/null 2>&1; then
    pass "SG allows ICMP $pod -> $ip"
  else
    fail "SG allows ICMP $pod -> $ip"
  fi
done

old_identity=$(kubectl -n "$NS" get cep peer-b -o jsonpath='{.status.identity.id}')
kubectl -n "$NS" label pod peer-b sg-
for attempt in $(seq 60); do
  identity=$(kubectl -n "$NS" get cep peer-b -o jsonpath='{.status.identity.id}')
  state=$(kubectl -n "$NS" get cep peer-b -o jsonpath='{.status.state}')
  [[ -n "$identity" && "$identity" != "$old_identity" && "$state" == ready ]] || { sleep 1; continue; }
  if [[ "$(try_connect "$NS" peer-a "$B" 8080)" == closed && "$(try_connect "$NS" peer-b "$A" 8080)" == closed ]]; then
    break
  fi
  sleep 1
done
[[ -n "$identity" && "$identity" != "$old_identity" && "$state" == ready ]]
assert_eq closed "$(try_connect "$NS" peer-a "$B" 8080)" "Removing SG membership denies A -> B"
assert_eq closed "$(try_connect "$NS" peer-b "$A" 8080)" "Removing SG membership denies B -> A"
summary
