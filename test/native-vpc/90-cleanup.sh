#!/usr/bin/env bash
# Removes everything the suite created.
set -uo pipefail
cd "$(dirname "$0")" && source ./lib.sh

log "deleting policies and pods"
for vpc in "${VPCS[@]}"; do
  kubectl -n "$vpc" delete cnp --all --wait=false >/dev/null 2>&1
  kubectl -n "$vpc" delete pod --all --wait=false >/dev/null 2>&1
done
sleep 5

log "deleting subnets, VPCs and namespaces"
for vpc in "${VPCS[@]}"; do
  kubectl delete subnet "subnet-${vpc}" --wait=false >/dev/null 2>&1
  kubectl delete vpc "$vpc" --wait=false >/dev/null 2>&1
  kubectl delete ns "$vpc" --wait=false >/dev/null 2>&1
done

log "waiting for the namespaces to go away"
for _ in $(seq 30); do
  left=$(kubectl get ns -l vni-test=true --no-headers 2>/dev/null | wc -l)
  [[ "$left" == "0" ]] && break
  sleep 2
done
kubectl get ns -l vni-test=true --no-headers 2>/dev/null | sed 's/^/    still present: /'

log "overlap metric after cleanup"
cilium_exec cilium-dbg metrics list | grep native_vpc_overlapping_ips | sed 's/^/    /'
