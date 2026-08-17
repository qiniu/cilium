# native-vpc (VNI) end-to-end test suite

Proves that Cilium keeps **overlapping IPs** apart by `(VNI, IP)` when kube-ovn
provides several VPCs with the same subnet.

## Fixture

Three kube-ovn VPCs, each with a subnet using the **same** CIDR `10.99.0.0/24`,
and each holding two pods pinned to the **same two addresses**:

| VPC   | VNI (tunnel_key) | client       | server       | policy scenario              |
|-------|------------------|--------------|--------------|------------------------------|
| vpc-a | e.g. 5           | 10.99.0.11   | 10.99.0.12   | default deny (nothing works) |
| vpc-b | e.g. 7           | 10.99.0.11   | 10.99.0.12   | only tcp/8080 allowed        |
| vpc-c | e.g. 9           | 10.99.0.11   | 10.99.0.12   | no policy (everything works) |

Every connection attempt in the suite uses the identical address pair
`10.99.0.11 -> 10.99.0.12`, so any wrong result means one VPC's policy decided
another VPC's traffic.

## Scripts

| Script                | What it does                                                                 |
|-----------------------|------------------------------------------------------------------------------|
| `00-setup.sh`         | creates the VPCs, the overlapping subnets, the namespaces and the six pods    |
| `10-verify-vni.sh`    | asserts the control/cache/forwarding/conntrack state is scoped per VNI        |
| `15-key-uniqueness.sh` | after CNI ADD each pod owns exactly one resource per plane under its own (VNI, IP); after CNI DEL only its own are gone |
| `20-policies.sh`      | applies the three policy scenarios                                            |
| `30-connectivity.sh`  | runs the connectivity matrix and the cross-VPC leak checks                    |
| `35-policymap.sh`     | the identity-keyed policy map of each server, as the datapath sees it          |
| `40-observability.sh` | asserts Hubble attributes every flow to the right VPC                         |
| `45-hubble-vni.sh`    | per-VPC forwarding-plane records (VNI+IP+identity+verdict) and VNI filtering   |
| `55-vni-scope-change.sh` | the VPC of a running pod is not changed by an annotation; a real move leaves nothing behind |
| `50-datapath.sh`      | BPF map layouts, per-endpoint load-time VNI, and the debug tooling             |
| `60-service.sh`       | services are resolved by kube-ovn, not rewritten by Cilium                     |
| `70-lifecycle.sh`     | CEP annotation, annotation loss, agent restart, pod deletion                   |
| `80-logs.sh`          | log and counter review: no errors, only expected warnings, explained drops     |
| `90-cleanup.sh`       | removes everything                                                            |
| `run-all.sh`          | runs the whole suite and prints one verdict                                   |

```bash
./run-all.sh        # full run
./90-cleanup.sh     # tear down
```

## What each check proves

**10-verify-vni.sh** (17 checks)
- each subnet hands out a different `ovn.kubernetes.io/tunnel_key`;
- the three servers really share one address;
- each endpoint's identity carries `vni:io-cilium-native-vpc-vni=<vni>` and the
  three identities are distinct — this is what makes policy VPC-aware;
- the ipcache holds three separate entries `10.99.0.12/32@vni:{5,7,9}`;
- each endpoint is resolvable by its `vni-ipv4:<vni>:<ip>` identifier;
- `cilium_native_vpc_overlapping_ips` reports the two shared addresses. This is
  the conntrack-plane precondition: the CT key has no VPC scope, so co-locating
  overlapping IPs on one node is only safe while this metric is watched.

**30-connectivity.sh** (8 checks)
- the six matrix cells behave exactly as the per-VPC policy says;
- the same `10.99.0.11 -> 10.99.0.12:8080` is *denied* in vpc-a and *allowed* in
  vpc-c;
- `tcp/9090` is blocked in vpc-b while open in vpc-c for the same address pair.

**40-observability.sh** (7 checks)
- every flow between the shared addresses carries a VNI on *both* endpoints;
- flows group by VNI to the correct namespace;
- vpc-a shows drops while vpc-c shows none, i.e. the verdicts are not mixed
  between VPCs that share addressing.

## Traceability: which check covers which fix

Every behaviour this PR changed has at least one live check. The planes refer
to the review in `Documentation/network/native-vpc.rst`.

| Plane | Behaviour introduced or fixed                          | Covered by                       |
|-------|--------------------------------------------------------|----------------------------------|
| 1 control    | pod annotation becomes the endpoint VNI          | `10-verify-vni.sh`               |
| 1 control    | the VNI becomes an identity label                | `10-verify-vni.sh`               |
| 1 control    | the CiliumEndpoint carries the VNI to other nodes| `70-lifecycle.sh`                |
| 1 control    | a lost annotation must not drop the VPC scope    | `70-lifecycle.sh`                |
| 2 cache      | one ipcache entry per (VNI, IP)                  | `10-verify-vni.sh`               |
| 2 cache      | the full dump copes with VNI keys (used to panic)| `50-datapath.sh`                 |
| 2 cache      | deleting one VPC leaves the others intact        | `70-lifecycle.sh`                |
| 2 cache      | a scope change is a delete plus an upsert, never | `55-vni-scope-change.sh`         |
|              | a second entry under the abandoned VPC           |                                  |
| 1 control    | a drifting annotation does not move a running    | `55-vni-scope-change.sh`         |
|              | pod between VPCs, not even across a restart      |                                  |
| 3 forwarding | VNI-scoped ipcache map and its key layout        | `50-datapath.sh`                 |
| `50-datapath.sh`                 |
| 3 forwarding | per-endpoint load-time VNI in bpf_lxc            | `55-vni-scope-change.sh` | the VPC of a running pod is not changed by an annotation; a real move leaves nothing behind |
| `50-datapath.sh`                 |
| 3 forwarding | endpoints addressable as `vni-ipv4:<vni>:<ip>`   | `10-verify-vni.sh`               |
| 4 policy     | identities, and therefore policy, are VPC-scoped | `30-connectivity.sh`             |
| 4 policy     | a policy of one VPC cannot affect another        | `30-connectivity.sh`             |
| 4 policy     | the policy map is keyed by identity, not address | `35-policymap.sh`                |
| 4 policy     | the allowed peer carries the same VNI            | `35-policymap.sh`                |
| 4 policy     | the port scope is visible in the policy map      | `35-policymap.sh`                |
| 5 conntrack  | the overlap precondition is observable           | `10-verify-vni.sh`               |
| 6 service    | no service translation for VPC endpoints         | `60-service.sh`                  |
| 6 service    | services still work (kube-ovn resolves them)     | `60-service.sh`                  |
| 7 fragments  | the fragment key is VPC scoped                   | `55-vni-scope-change.sh` | the VPC of a running pod is not changed by an annotation; a real move leaves nothing behind |
| `50-datapath.sh` (key size)      |
| 8 observ.    | flows carry the VNI on both endpoints            | `40-observability.sh`            |
| 8 observ.    | verdicts are not mixed between VPCs              | `40-observability.sh`            |
| 8 observ.    | the tooling shows the VPC scope                  | `55-vni-scope-change.sh` | the VPC of a running pod is not changed by an annotation; a real move leaves nothing behind |
| `50-datapath.sh`                 |
| 8 observ.    | per-VPC forwarding records carry VNI+IP+identity | `45-hubble-vni.sh`               |
| 8 observ.    | verdict/port pattern per VPC matches its policy  | `45-hubble-vni.sh`               |
| 8 observ.    | flows are filterable by the VNI identity label   | `45-hubble-vni.sh`               |
| 9 lifecycle  | a restart restores VNI, identities and ipcache   | `70-lifecycle.sh`                |
| 9 lifecycle  | policy behaviour is unchanged after a restart    | `70-lifecycle.sh`                |
| 10 assembly  | the agent starts in native-vpc mode              | `55-vni-scope-change.sh` | the VPC of a running pod is not changed by an annotation; a real move leaves nothing behind |
| `50-datapath.sh` (no fatal log)  |
| all          | the run produces no error log and no unexpected  | `80-logs.sh`                     |
|              | warning, drop reason or invalid policy           |                                  |

Checks that stay in the Go unit tests because they cannot be provoked on a live
cluster: the startup rejections (kube-proxy replacement, socket LB, egress
gateway, masquerade, encryption, SRv6, VTEP, CiliumEndpointSlice,
operator-managed identities, tunnel routing), the rejection of an API-supplied
VNI that disagrees with the annotation, and the C/Go alignment of both datapath
variants.

Known gap, by design: conntrack state has no VPC scope. The suite therefore
asserts the *precondition metric* rather than the absence of collisions; keep
overlapping IPs of different VPCs on disjoint nodes.

## Reading the evidence per layer

Each script prints the raw data it asserts on, so a reviewer can check the
layers by eye rather than trusting a boolean:

| Layer                      | Command used                                       | What to look for                                   |
|----------------------------|----------------------------------------------------|----------------------------------------------------|
| pod / kube-ovn             | `kubectl get pod -o jsonpath=...tunnel_key`        | a different key per subnet, identical pod IPs       |
| control (endpoint)         | `cilium-dbg endpoint list`                         | `vni:io-cilium-native-vpc-vni=<n>` and 3 identities |
| control (CiliumEndpoint)   | `kubectl get cep -o jsonpath=...native-vpc...vni`  | the same VNI, so other nodes can scope the endpoint |
| cache (ipcache)            | `cilium-dbg bpf ipcache list \| grep @vni:`         | one entry per (VNI, IP)                            |
| cache (API/listing)        | `cilium-dbg ip list`                               | rows rendered as `<prefix>@vni:<n>`                |
| forwarding (maps)          | `bpftool map show pinned .../cilium_ipcache_vni`   | lpm_trie, key 28B; fragment map key 16B            |
| forwarding (per endpoint)  | `/var/run/cilium/state/<id>/ep_config.json`        | `"VNIID":<n>`                                      |
| policy                     | `cilium-dbg bpf policy get <endpoint>`             | identity-keyed allow entries, port scope, counters |
| conntrack (limitation)     | `cilium-dbg metrics list \| grep native_vpc`        | the overlap precondition                            |
| observability              | `hubble observe -o json`                           | `vni_id` on both endpoints, verdicts per VPC        |
| observability (filter)     | `hubble observe --label vni:io-cilium-...=<n>`     | only that VPC's flows                              |

## What the logs are expected to contain

`80-logs.sh` fails on anything not in this list, so the expected noise is
documented rather than ignored:

| Message                                                    | Why it is expected                                                        |
|------------------------------------------------------------|---------------------------------------------------------------------------|
| `local endpoints of different VPCs share an IP` (warn)      | emitted on purpose: the fixture co-locates overlapping addresses, which is the conntrack-plane precondition. The script *requires* it to appear |
| `Couldn't find state, ignoring endpoint` for `<id>_next`    | upstream: leftover regeneration directories are skipped on restore        |
| `UNSUPPORTED_L2/L3_PROTOCOL` drops                          | the cluster runs with `enable-ipv6=false` while the pods still emit IPv6 link-local traffic |
| `STALE_OR_UNROUTABLE_IP` (a few packets)                    | stragglers from pods that were deleted during the run                     |
| kube-ovn `not standby yet` / `not found, requeuing` / `v4 using ip range is empty` / `datapath binding not found` | reconcile races while a VPC or subnet is created or deleted; the last one is the window before OVN binds the switch and the tunnel key exists. The suite asserts each subnet has settled on a key |

Everything else - any `level=error`, any other warning, any other drop reason,
any invalid CiliumNetworkPolicy - fails the run.

## Requirements

- kube-ovn with VPC support (tested with v1.15.10);
- Cilium in native-vpc mode: `nativeVPC.enabled=true`,
  `nativeVPC.vniAnnotation=ovn.kubernetes.io/tunnel_key`, `routingMode=native`,
  CNI chaining `generic-veth` behind kube-ovn;
- the `busybox:1.36` image present on the nodes (`imagePullPolicy: IfNotPresent`).

## Notes

- Pods are pinned to fixed addresses with `ovn.kubernetes.io/ip_address`, which
  is what makes the overlap deterministic instead of accidental.
- `vpc-a` uses `ingress: [{fromEndpoints: []}]` for default deny; an empty
  `ingress: []` list would *not* enable enforcement.
- Custom VPCs are isolated from the cluster network by design, so the pods have
  no DNS or API access; every check is pure east-west traffic inside one VPC.
