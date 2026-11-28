# Cluster-policy LoadBalancer QoS acceptance (#79)

`cluster-lb.sh` is a strict, opt-in **real LB** test. It creates a separate namespace, two limited backends on different nodes, an internal client and one `type: LoadBalancer`, `externalTrafficPolicy: Cluster` Service. This can allocate a billable LB; run it only in an authorized test cluster. The trap requests namespace deletion (including the Service) on exit. Verify provider-side resource cleanup. No node routes, external client routes, NAT gateways, gateway QoS settings or existing Services are changed.

## Prerequisites

- Use the production-equivalent LB controller, forwarding mode, CNI and routing domain. Both backend nodes need generic-veth Cilium with the class scheduler. Configure the external test client's actual IP as an external peer; do **not** put a node, load balancer proxy, OVN join or masquerade address in that list. Preload or publish a container image with iperf3 supporting `-J --get-server-output` and `cat`.
- The external client and internal test Pod must both be able to reach the address announced in `status.loadBalancer.ingress`. Do not substitute `spec.externalIPs`, NodePort, port-forward, or add a /32 route on the client to force local delivery. The script selects a single ready backend on each node in turn via EndpointSlice and verifies the server's actual local address.
- Supply reliable evidence of which node receives external traffic. For MetalLB L2 the script reads `ServiceL2Status` and expects a single announcer, in `{NODE_A,NODE_B}`, stable across each run. For a different controller set `LB_INGRESS_NODE_CMD` to an executable which takes `context namespace service` and prints **one observed ingress node** for this client's traffic. Don't echo the backend node or guess from where the client runs. With ECMP or flow-dependent ingress, the adapter needs flow-specific evidence or a deterministic test setup; without it the same/cross-node matrix cannot be certified. This fixture is for L4 VIP-to-node backends, not direct-to-Pod or HTTP ingress.

```bash
# Docker kind example with an ALREADY running real L2 LoadBalancer controller,
# reachable address pool and external Docker test client on the same L2 network.
export CONTEXT=kind-qos79 NODE_A=qos79-worker NODE_B=qos79-control-plane
export IMAGE=qos74/iperf:local EXTERNAL=qos79-external EXTERNAL_IP=172.18.0.6
export LB_ANNOTATIONS='{"metallb.io/address-pool":"qos79"}'  # optional
bash test/chaining-qos/cluster-lb.sh
```

Optional `LB_CLASS` sets `spec.loadBalancerClass`. On non-Docker clusters provide `EXTERNAL_EXEC` (invokes its arguments on the external client) and `NODE_EXEC` (takes node name then command/arguments; runs read-only `ip` / `tc` in that node's host netns). `EXTERNAL_IP` is the original client address at the LB, not the rewritten source seen by the backend. `LB_TIMEOUT` bounds provisioning (default `180s`); `DURATION` is seconds per TCP test (default 15).

## Matrix and failure contract

For each backend placement, upload from the external client to the published VIP (Pod ingress, **10M**) then download with `iperf3 -R` (Pod egress, **20M**). Also upload/download from an internal Pod to that **same VIP** (default **100M/200M**). The script checks connection tuples, receiver throughput and the actual class byte deltas on the backend, against the same 90–105% payload and 95–105% queue windows as the single-Pod probe. Inspect `service.json`, `path.txt`, iperf output and before/after qdisc dumps under the printed artifacts directory. The script returns nonzero on any failed case or missing placement; a lack of LB infrastructure is not a pass. It runs separately from the generic CI isolation fixture so a simulated Local VIP cannot turn the Cluster-policy requirement green.

On kind v1.35.1 / Kube-OVN + MetalLB v0.15.2 L2 / kube-proxy iptables, the external endpoint was rewritten to the ingress node's OVN join IP on **both** placements. The four external transfers delivered ~95/190 Mbps, charging only the default class; the four internal controls passed. This is a known **failed acceptance** of north-south classification on that topology. A real production LB may behave differently: repeat there and use its observed tuples. The test deliberately does not treat the default cap as a successful external cap.
