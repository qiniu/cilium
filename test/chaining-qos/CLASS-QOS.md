# Single-domain generic-veth class QoS

`class-kind.sh` exercises the **agent-installed** queues, with no `SO_PRIORITY` and no manual `tc` rules. The two Kubernetes values are defaults; the two north-south values override rather than consume those defaults. Rates are decimal megabits/s from the Pod's perspective. The example uses these annotations on the limited Pod:

```yaml
metadata:
  annotations:
    kubernetes.io/ingress-bandwidth: 100M
    kubernetes.io/egress-bandwidth: 200M
    qos.cilium.io/north-south-ingress-bandwidth: 10M
    qos.cilium.io/north-south-egress-bandwidth: 20M
```

## Requirements

Use a disposable two-node, single-routing-domain IPv4 kind/Kube-OVN cluster with this agent **and its corresponding BPF sources**. Enable bandwidth manager, `generic-veth` chaining and legacy host routing; leave native-VPC off. Configure the following Cilium ConfigMap key (Helm: under `extraConfig`), then roll the agents. Supply the trusted external prefixes as a comma-separated string. The value here is a lab example, not a default:

```yaml
chained-qos-north-south-cidrs: "172.18.0.6/32"    # the actual outside test peer
```

Classification is explicitly by **visible peer**, not by presence of NAT, using host-owned TC flower filters. Rules must be disjoint across the routing domain. List only known external peers. All other peers, including internal and unknown, share the default queue; there is no internal prefix list or east-west annotation. Do not include masquerading gateway, shared proxy, node or OVN join addresses as a substitute for original external clients. With SNAT, the Pod's destination is still visible on egress. With source-preserving LB DNAT, the external source is visible on backend ingress. If both addresses are rewritten, no original client can be inferred: an unmatched peer consumes the direction default if configured. Without a default unmatched traffic is not rate-limited. With no override for a direction at all, its existing Kubernetes annotation still limits all traffic as one aggregate, exactly as before. Overlapping tenant domains, L7 proxies and source-rewritten LB class attribution are not covered by this classifier.

## Run

Preload an image containing `iperf3` and `cat` on both nodes. Start a Docker container with `iperf3 -s -J` on the kind network, with `NET_ADMIN` for a test route in that container only. Use its IP in the external prefix above. An external Service IP must be reachable through the backend node with `externalTrafficPolicy: Local`; the verified setup used kube-proxy in iptables mode.

```sh
export CLUSTER=qos78 IMAGE=qos74/iperf:local EXTERNAL=qos78-external
bash test/chaining-qos/class-kind.sh
```

The script creates a fresh namespace, a limited backend on the worker, a peer on the control-plane node, and a Service with a test external IP. The same four concurrent TCP connections stay open on the same Pod across three steady-state windows:

| Window | Default in / out (Mbps) | North-south in / out (Mbps) |
| --- | ---: | ---: |
| Initial | 100 / 200 | 10 / 20 |
| Hot update ×2 | 200 / 400 | 20 / 40 |
| Restore original | 100 / 200 | 10 / 20 |

Each transition updates all four annotations in a single request. Before measuring, the test rediscovers the endpoint IFB and waits for both direction trees to show the expected ceilings. For each of the 12 measurements it checks receiver interval throughput (90–105% of cap, allowing for headers) and byte deltas on that window's own queues (95–105%). It also verifies the connection tuples for SNAT and source-preserving DNAT. `DURATION` is the measurement time **per window** (default 15 seconds). Raw iperf JSON and per-window `tc` snapshots and timestamps remain in the printed artifacts directory. Additional lifecycle checks install and remove a deny policy, test a real node-originated connection, and measure receiver intervals on one external connection across a class-rate change and fallback to a legacy direction total. The test checks that the class IFB is gone, the veth has its aggregate FQ again, and simultaneous internal and external uploads share one legacy ingress cap after the overrides are removed. The namespace and external peer route are removed on exit. This is a bandwidth ceiling, not a minimum-rate guarantee on an undersized cluster.
