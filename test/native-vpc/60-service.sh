#!/usr/bin/env bash
# Service plane: Cilium must not translate a service address for an endpoint
# that has a VNI.
#
# A backend address is just an IP, and kube-ovn resolves it inside the sender's
# own VPC, so translating it could send a client of one tenant to a pod of
# another. Cilium therefore skips the service lookup for VPC endpoints and
# leaves load balancing to kube-ovn. This check proves both halves: services
# still work, and the flow record keeps the service address (which is also what
# lets Hubble annotate it).
#
# The probe runs in the default VPC, which is the only one with cluster DNS.
set -uo pipefail
cd "$(dirname "$0")" && source ./lib.sh

NS=default
PROBE=vni-svc-probe
DNS_IP=$(kubectl -n kube-system get svc -l k8s-app=kube-dns -o jsonpath='{.items[0].spec.clusterIP}' 2>/dev/null)
[[ -z "$DNS_IP" ]] && DNS_IP=$(kubectl -n kube-system get svc kube-dns -o jsonpath='{.spec.clusterIP}' 2>/dev/null)

log "cluster DNS service address: ${DNS_IP:-<none>}"
[[ -n "$DNS_IP" ]] && pass "found the DNS ClusterIP" || { fail "no DNS ClusterIP"; summary; exit 1; }

log "starting a probe pod in the default VPC"
kubectl -n "$NS" delete pod "$PROBE" --wait=true >/dev/null 2>&1
kubectl apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata: {name: ${PROBE}, namespace: ${NS}, labels: {app: ${PROBE}}}
spec:
  containers:
  - {name: c, image: docker.io/library/busybox:1.36, imagePullPolicy: IfNotPresent,
     command: ["sh","-c","sleep infinity"]}
YAML
wait_for_pod "$NS" "$PROBE" || { fail "probe pod did not start"; summary; exit 1; }
vni=$(pod_vni "$NS" "$PROBE")
[[ -n "$vni" ]] && pass "the probe is a VPC endpoint (vni=${vni})" || fail "probe has no VNI"

log "the service still resolves (kube-ovn performs the load balancing)"
if kubectl -n "$NS" exec "$PROBE" -- nslookup kubernetes.default.svc.cluster.local "$DNS_IP" 2>&1 | grep -q "Address"; then
  pass "ClusterIP ${DNS_IP} works from a VPC endpoint"
else
  fail "ClusterIP ${DNS_IP} is unreachable from a VPC endpoint"
fi

log "the datapath did not rewrite the destination"
kubectl -n "$NS" exec "$PROBE" -- nslookup kubernetes.default.svc.cluster.local "$DNS_IP" >/dev/null 2>&1
sleep 3
flows=$(cilium_exec hubble observe --last 100 -o json | python3 -c "
import json,sys
keep=[]
for line in sys.stdin:
    try: f=json.loads(line).get('flow',{})
    except Exception: continue
    ip=f.get('IP',{}) or {}
    if ip.get('destination')=='${DNS_IP}':
        s=f.get('source',{}) or {}
        svc=f.get('destination_service',{}) or {}
        keep.append((ip.get('source'),ip.get('destination'),s.get('vni_id'),svc.get('namespace'),svc.get('name')))
for k in keep[:3]: print('  %s -> %s src_vni=%s svc=%s/%s' % k)
print('count=%d' % len(keep))
")
echo "$flows" | sed 's/^/    /'
cnt=$(echo "$flows" | awk -F= '/^count=/{print $2}')
[[ "${cnt:-0}" -gt 0 ]] \
  && pass "flows keep the service address as destination (not a backend address)" \
  || fail "no flow towards ${DNS_IP}: the destination may have been rewritten"
echo "$flows" | grep -q "svc=kube-system/" \
  && pass "Hubble annotates the flow with the service name" \
  || warn "no service annotation on the flow"

log "the VPC endpoint's own address is not a service backend in the BPF maps"
lb=$(cilium_exec cilium-dbg bpf lb list | grep -c "${SERVER_IP}" || true)
assert_eq "0" "${lb:-0}" "the overlapping address is not programmed as a backend"

kubectl -n "$NS" delete pod "$PROBE" --wait=false >/dev/null 2>&1
summary
