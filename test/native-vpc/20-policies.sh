#!/usr/bin/env bash
# Applies one policy scenario per VPC. All three VPCs contain the same two IPs,
# so the only thing that can keep the scenarios apart is the (VNI, IP) scoped
# identity: a policy written for vpc-a must not affect the identical addresses
# in vpc-b or vpc-c.
#
#   vpc-a : deny   - the server accepts nothing (default deny, no allow rule)
#   vpc-b : port   - the server accepts only PORT_ALLOWED from the client
#   vpc-c : open   - no policy at all
set -uo pipefail
cd "$(dirname "$0")" && source ./lib.sh

log "vpc-a: default-deny on the server (no ingress allowed at all)"
kubectl apply -f - >/dev/null <<YAML
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: deny-all
  namespace: vpc-a
spec:
  endpointSelector:
    matchLabels:
      app: server
  ingress:
  # An empty fromEndpoints selects no peer: the endpoint is put under ingress
  # enforcement and nothing is allowed, i.e. default deny. (An empty "ingress"
  # list would not enable enforcement at all.)
  - fromEndpoints: []
YAML

log "vpc-b: allow only tcp/${PORT_ALLOWED} from the client"
kubectl apply -f - >/dev/null <<YAML
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-one-port
  namespace: vpc-b
spec:
  endpointSelector:
    matchLabels:
      app: server
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: client
    toPorts:
    - ports:
      - port: "${PORT_ALLOWED}"
        protocol: TCP
YAML

log "vpc-c: no policy (unrestricted)"
kubectl delete cnp --all -n vpc-c >/dev/null 2>&1 || true

sleep 5
log "the policies are accepted by the validator"
# A CNP that fails validation can still change behaviour (an unparsable rule
# ends up allowing nothing), so the suite asserts the status explicitly instead
# of inferring correctness from the connectivity result.
for ns in vpc-a vpc-b; do
  for name in $(kubectl -n "$ns" get cnp -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
    msg=$(kubectl -n "$ns" get cnp "$name" -o jsonpath='{.status.conditions[?(@.type=="Valid")].message}' 2>/dev/null)
    [[ "$msg" == "Policy validation succeeded" ]] \
      && echo "    ${ns}/${name}: ${msg}" \
      || { echo "    ${ns}/${name}: INVALID - ${msg}"; exit 1; }
  done
done

log "policies in place"
kubectl get cnp -A --no-headers 2>/dev/null | awk '{printf "    %-8s %s\n", $1, $2}'

log "policy enforcement as seen by Cilium"
cilium_exec cilium-dbg endpoint list | awk 'NR==1 || /server|client/' | head -10
