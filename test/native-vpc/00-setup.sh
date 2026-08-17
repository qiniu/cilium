#!/usr/bin/env bash
# Creates three kube-ovn VPCs whose subnets share the SAME CIDR, one namespace
# per VPC, and a client+server pod per VPC pinned to identical IPs.
#
# After this script every VPC holds a pod at 10.99.0.11 and one at 10.99.0.12,
# i.e. three pods share each address and can only be told apart by their VNI.
set -uo pipefail
cd "$(dirname "$0")" && source ./lib.sh

log "creating VPCs, subnets (all ${OVERLAP_CIDR}) and namespaces"
for vpc in "${VPCS[@]}"; do
  kubectl apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Namespace
metadata:
  name: ${vpc}
  labels:
    vni-test: "true"
    vpc: ${vpc}
---
apiVersion: kubeovn.io/v1
kind: Vpc
metadata:
  name: ${vpc}
spec:
  namespaces:
  - ${vpc}
---
apiVersion: kubeovn.io/v1
kind: Subnet
metadata:
  name: subnet-${vpc}
spec:
  vpc: ${vpc}
  namespaces:
  - ${vpc}
  cidrBlock: ${OVERLAP_CIDR}
  protocol: IPv4
  # No NAT/gateway: the test is purely east-west inside each VPC.
  natOutgoing: false
YAML
done

log "waiting for the subnets to be ready"
for vpc in "${VPCS[@]}"; do
  for _ in $(seq 30); do
    [[ -n "$(kubectl get subnet subnet-${vpc} -o jsonpath='{.status.v4availableIPs}' 2>/dev/null)" ]] && break
    sleep 2
  done
done
kubectl get subnet -o custom-columns=NAME:.metadata.name,VPC:.spec.vpc,CIDR:.spec.cidrBlock --no-headers | grep -E "subnet-vpc" | sed 's/^/    /'

log "creating one client and one server pod per VPC, with identical IPs"
for vpc in "${VPCS[@]}"; do
  # The server serves two ports so that a port-scoped policy can be observed:
  # PORT_ALLOWED must stay reachable, PORT_DENIED must not.
  kubectl apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: server
  namespace: ${vpc}
  labels:
    app: server
    vni-test: "true"
  annotations:
    ovn.kubernetes.io/ip_address: "${SERVER_IP}"
    ovn.kubernetes.io/logical_switch: subnet-${vpc}
spec:
  containers:
  - name: c
    image: docker.io/library/busybox:1.36
    imagePullPolicy: IfNotPresent
    command: ["sh","-c"]
    args:
    - |
      mkdir -p /www && echo "hello from ${vpc}" > /www/index.html
      httpd -p ${PORT_ALLOWED} -h /www
      httpd -p ${PORT_DENIED} -h /www
      sleep infinity
---
apiVersion: v1
kind: Pod
metadata:
  name: client
  namespace: ${vpc}
  labels:
    app: client
    vni-test: "true"
  annotations:
    ovn.kubernetes.io/ip_address: "${CLIENT_IP}"
    ovn.kubernetes.io/logical_switch: subnet-${vpc}
spec:
  containers:
  - name: c
    image: docker.io/library/busybox:1.36
    imagePullPolicy: IfNotPresent
    command: ["sh","-c","sleep infinity"]
YAML
done

log "waiting for pods"
for vpc in "${VPCS[@]}"; do
  wait_for_pod "$vpc" server || warn "${vpc}/server not Running"
  wait_for_pod "$vpc" client || warn "${vpc}/client not Running"
done

echo
log "topology"
printf "    %-8s %-10s %-12s %-12s %s\n" VPC POD IP VNI NODE
for vpc in "${VPCS[@]}"; do
  for p in client server; do
    printf "    %-8s %-10s %-12s %-12s %s\n" "$vpc" "$p" "$(pod_ip $vpc $p)" "$(pod_vni $vpc $p)" \
      "$(kubectl -n $vpc get pod $p -o jsonpath='{.spec.nodeName}' 2>/dev/null)"
  done
done
