# Chained Pod bandwidth: path baseline (#74)

`run.sh` is a read-only probe for an **already provisioned** Docker kind cluster with Kube-OVN, generic-veth Cilium and bandwidth manager (#73). It tests the existing **aggregate** caps, not four-class scheduling. It does not install a CNI, create a NAT gateway or change any routes. Dependencies: bash, kubectl, docker, jq, python3 on the runner; iproute2 in the kind nodes.

## Fixtures

- Use a dedicated quiet, single-container, primary-interface (`eth0`) Pod with both `kubernetes.io/ingress-bandwidth: 10M` and `kubernetes.io/egress-bandwidth: 10M`. Start `iperf3 -s -J` there. Also run the same server on an unlimited Pod on each node and in a Docker container outside the cluster. Use iperf3 supporting `--get-server-output` on all peers. Confirm unrestricted peers can exceed 10 Mbit/s.
- Configure outbound SNAT for the Pod subnet towards the external container. Publish a TCP L4 LB VIP:port routing only to the limited Pod's iperf port. The external container must reach the VIP via the intended LB, **not** `kubectl port-forward`, a userspace TCP proxy or the Pod network. SNAT and LB can be provided by the lab; a kind NodePort alone doesn't establish this topology.
- Use the regular test kubeconfig/context. Node names must be the Docker container names. For dual-stack, set `POD_IP` to the address of the family being tested. Run one transfer at a time.

```bash
export CONTEXT=kind-kube-ovn NS=qos-test POD=limited CAP=10
# Replace these addresses with actual fixture addresses.
for dir in out in; do
  TARGET=$SAME_NODE_PEER_IP bash test/chaining-qos/run.sh east-west "$dir"
  TARGET=$OTHER_NODE_PEER_IP bash test/chaining-qos/run.sh east-west "$dir"
  TARGET=$EXTERNAL_IP bash test/chaining-qos/run.sh snat "$dir"
  EXTERNAL=$EXTERNAL_CONTAINER TARGET=$VIP PORT=$VIP_PORT bash test/chaining-qos/run.sh lb "$dir"
done
```

`in`/`out` are relative to the limited endpoint. SNAT `in` and LB `out` use `iperf3 -R` on the **same NAT path**, not a new connection to the translated address. Repeat LB cases with the backend local to and remote from the LB ingress node. Record actual ingress/backend placement, LB source-preservation setting and versions. Repeat from an internal peer to the VIP as a hairpin control (compare tuples manually; internal VIP access must not be classified external). If using unequal caps, set `CAP` per invocation.

## Automated IPv4 kind fixture

On an otherwise idle two-node Docker kind cluster with the above CNIs installed, run `CLUSTER=<kind-name> IMAGE=<preloaded-iperf-image> bash test/chaining-qos/kind-ipv4.sh`. The image needs iperf3, cat and iproute2 and must also exist in Docker. The script creates three Pods, one Service with a test external IP, and one external client on the kind network. It steers the VIP through each node by changing a route **only inside that client**. It compares with an internal Pod using the Service ClusterIP. Temporary client and namespace are removed on exit, including failure. This tests L4 Service DNAT, not a vendor LB provisioning controller. Do not use a cluster where the test external IP is in use.

### Measured matrix (#76)

Linux 7.0.0-44, kind nodes v1.35.1, Kube-OVN (distributed `ovn-default` subnet, veth pairs), kube-proxy IPVS, Cilium native routing / legacy host routing / generic-veth, bandwidth manager enabled. Agent and CNI built from this tree; BPF sources from the same revision. Each direction has a 10 Mbit/s limit. TCP receiver payload Mbit/s over 8 seconds, with a matching byte delta on the limited endpoint's ingress veth or egress IFB:

| Peer / path | Pod sends | Pod receives |
| --- | ---: | ---: |
| Pod, same node | 9.40 | 9.44 |
| Pod, other node | 9.42 | 9.44 |
| External peer, SNAT | 9.39 | 9.44 |
| Internal client via ClusterIP | 9.44 | 9.42 |
| External VIP, local backend | 9.44 | 9.42 |
| External VIP, remote backend | 9.44 | 9.42 |

Before #76 the external VIP to a local backend delivered **8202.76 Mbit/s** despite the veth FQ counting the transfer. Queue bytes alone are not proof of pacing. After the fix a host-network process sending directly to the Pod at 40 Mbit/s still delivered 40 Mbit/s (host exemption). In this lab the SNAT receiver saw the worker IP; the external VIP backend saw the ingress node's OVN join address instead of the client. The internal ClusterIP preserved the source Pod IP. This is path evidence, not a general classifier for join addresses or a test of four independent caps.

## Evidence and limits

Each run prints the artifact directory with both TCP endpoint views, receiver throughput and before/after `tc -s -j` counters on `cilium_bwm<endpoint-id>` (out) or the host peer of Pod `eth0` (in). The probe rejects missing root FQ, insufficient bulk bytes charged, wrong endpoint tuples for the chosen NAT path and throughput outside 80–105% of the specified cap. This window allows for wire headers and timing on an otherwise idle lab; it is not a QoS guarantee. For failure diagnosis inspect the raw JSON and hook attachments (`tc filter show dev <veth> ingress` and `egress` in the endpoint node). On multi-hop networks the two tuple views establish translation between endpoints, **not which hop performed it**.

Classification contract to validate before enabling four caps: SNAT egress retains the original peer at the source endpoint. For LB ingress, the backend sees the post-DNAT tuple. Compare the observed peer to the external client and to the internal VIP control. If they are indistinguishable after source rewriting, classification needs trusted LB/OVN connection metadata on the backend **and the return path**. Queue counters alone do not prove availability of that metadata. Keep unverified topologies explicitly unsupported.
