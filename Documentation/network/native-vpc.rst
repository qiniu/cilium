.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _native_vpc:

*************************
Native VPC Mode (kube-ovn)
*************************

Cilium can run in native-vpc mode on top of a kube-ovn underlay that provides
multiple VPCs and overlapping subnets. Cilium deliberately does **not** model
the kube-ovn VPC object: a VPC is an aggregate that can contain several
subnets, while each OVN logical switch/subnet has its own tunnel_key/VNI
(Virtual Network Identifier). The data-plane key is therefore (VNI, IP), not
(VPC, IP) and not bare IP. Every control/cache/forwarding/observability
consumer described below uses that VNI scope.

This document describes the tunnel_key contract between kube-ovn and Cilium,
and the recovery procedure when it is temporarily violated.

The tunnel_key annotation
=========================

kube-ovn writes the VNI of a pod's OVN subnet as the pod annotation
``ovn.kubernetes.io/tunnel_key`` (the annotation key is configurable on the
Cilium side via ``--native-vpc-vni-annotation``). Cilium reads this
annotation to place the pod in its logical-switch/VNI scope:

* endpoint creation reads it into the endpoint's ``VNIID``;
* the pod watcher reads it to register VNI-scoped ipcache entries;
* the datapath loads it into ``bpf_lxc`` as the per-endpoint
  ``CONFIG(native_vpc_vni)`` value (one compiled template serves all VNIs).

kube-ovn side guarantees
========================

kube-ovn guarantees that every non-hostNetwork pod on an OVN subnet carries a
**non-zero** ``ovn.kubernetes.io/tunnel_key`` annotation by the time its
network is configured (CNI ADD):

1. **Normal pod creation flow.** The kube-ovn controller refuses to allocate
   an IP (it requeues without persisting anything) while the subnet's tunnel
   key has not been synced from OVN SB (``status.tunnelKey == 0``), and writes
   the ``tunnel_key`` annotation in the same atomic patch as
   ``ovn.kubernetes.io/allocated=true``. The kube-ovn CNI server blocks until
   the pod is allocated, and Cilium (chained after kube-ovn, the primary CNI)
   only runs once kube-ovn's CNI ADD has succeeded, so Cilium always observes
   the annotation.

2. **kube-ovn-controller restart flow.** Pods created before the subnet
   tunnel key was synced (or before this behavior existed) may keep a missing
   annotation forever, because the allocation path never re-patches
   already-allocated pods. On startup the kube-ovn controller's init flow
   enqueues such pods into a dedicated repair queue
   (``enqueuePodTunnelKeyRepair``) and the repair worker patches the
   annotation from ``subnet.Status.TunnelKey``, retrying until the key is
   available.

A zero or missing annotation therefore only occurs for pods that are not in
an OVN logical-switch/VNI scope (hostNetwork pods, non-OVN/vlan subnets) or
for legacy pods before the backfill above has run.

Cilium side decision table
==========================

On endpoint creation and on every endpoint restore, Cilium re-reads the
``tunnel_key`` annotation and applies the following decision table (the
annotation is the single source of truth):

* annotation **absent** -> the pod uses the native (non-VPC) scheme
  (``VNIID = 0``), which is the normal case for hostNetwork pods and non-OVN
  subnets;
* annotation present and **valid** (``0 < VNI <= 16777215``) -> ``VNIID`` is
  set to the annotation value;
* annotation present and **0 / unparsable / out of range** -> an error is
  logged. A zero tunnel_key violates the kube-ovn guarantee (kube-ovn only
  ever writes a non-zero key), so the kube-ovn side must be investigated.

An endpoint that already has a VNI is never downgraded to the plain scheme by a
missing or broken annotation: that would merge it with the same IP in another
VPC and give it a foreign identity. The last known VNI is kept (fail closed;
at worst the endpoint stays isolated) and the condition is logged as an error.
Endpoint *creation* is stricter still: a non-hostNetwork pod without a usable
annotation is rejected, so the CNI ADD is retried instead of creating an
endpoint outside any VPC. The single authoritative "not in any VPC" signal is
``pod.spec.hostNetwork``, which is immutable, unlike an annotation.

When ``VNIID`` drops to 0 (annotation removed or broken), the endpoint also
loses its ``vni:io-cilium-native-vpc-vni=<vni>`` identity label: the
metadata resolver removes any
stale label and re-resolves the identity, so the endpoint fully returns to
the native scheme on all planes (identity, local ipcache registration and
``CONFIG(native_vpc_vni)`` datapath value). The resolver also removes the
legacy, semantically-wrong ``vpc:vpc=<vni>`` label during upgrade.

Recovery procedure
==================

If a running pod ever ends up missing its ``tunnel_key`` annotation (for
example a legacy pod created before the kube-ovn backfill existed), run the
fallback sequence:

1. **Restart kube-ovn-controller** - its init flow backfills the missing
   ``tunnel_key`` annotations on all pods of the affected subnets.
2. **Restart Cilium** - the agent re-reads the annotations on endpoint
   restore and re-flushes the resources tied to the ``tunnel_key`` + IP pair
   on all three planes:

   * **control plane**: the endpoint's ``VNIID`` is re-read from the
     annotation before the endpoint is exposed to the endpoint manager, and
     the ``vni:io-cilium-native-vpc-vni=<vni>`` identity label is
     re-injected by the metadata
     resolver, so identities are separated per logical switch/VNI again;
   * **cache plane**: the local ipcache registration (identity sync) and the
     pod watcher's VNI-scoped entries are re-created from the annotation;
   * **forwarding plane**: endpoint reload rewrites the per-endpoint
     ``CONFIG(native_vpc_vni)`` load-time value in ``bpf_lxc`` (without
     recompiling a per-VNI template), and the ipcache listener repopulates the VNI-scoped
     ipcache map (``cilium_ipcache_vni``), keyed by (VNI, IP) so that
     overlapping IPs from different logical switches/VPCs coexist.

Observability: the (VNI, IP) chain in Hubble
===========================================

Every Hubble flow of a native-vpc endpoint carries its VNI, and every lookup
Hubble performs to enrich a flow is scoped by (VNI, IP). The chain is:

1. **VNI context of the event.** For L3/L4 events (trace/drop/policy-verdict),
   the notification carries the id of the local endpoint whose BPF program
   emitted it. The parser resolves that endpoint by id and takes its
   ``VNIID``. This is exactly the scope the datapath used: ``bpf_lxc`` resolves
   the peer of an endpoint in ``cilium_ipcache_vni`` with that endpoint's own
   ``CONFIG(native_vpc_vni)``. For encapsulated packets that Cilium itself
   decodes, the overlay VNI of the tunnel header takes precedence.
   Socket-level events (``TraceSock``) derive the same scope from their cgroup
   id through the pod's endpoint, and debug events from their endpoint id.
   For L7 events the VNI is recorded on the proxy access-log record
   (``accesslog.EndpointInfo.VNIID``) from the resolved endpoint, or from the
   unambiguous ipcache entry.

2. **Endpoint resolution.** Local endpoints are looked up with the exact
   (VNI, IP) key. A miss falls back only to the key-exact *plain* scope, which
   holds non-VPC entities (host, nodes, non-OVN pods); it never degrades to a
   bare-IP guess that could select an endpoint of another VPC.

3. **Remote peer resolution.** With a VNI context, the identity and the pod
   metadata are read from the VNI-scoped ipcache entry (``<ip>@vni:<vni>``).
   Only if that misses does the plain ipcache answer, which is correct because
   it contains exactly the non-VPC entities. Without VNI context (for example
   events emitted by the host datapath), the VNI is recovered from the peer
   identity's ``vni:io-cilium-native-vpc-vni`` label, which is VNI-distinct by
   construction.

4. **Flow fields.** ``Endpoint.vni_id`` is set on both flow endpoints for
   L3/L4 and L7 flows, but only for peers that really resolved inside that VPC
   scope: a node/world peer of a VPC endpoint keeps ``vni_id = 0``.
   ``IPCacheNotification.vni`` carries the VNI of ipcache agent events.

5. **Filtering and metrics.** Flows can be filtered by VNI without any new API
   field, either through the VNI identity label
   (``--from-label 'vni:io-cilium-native-vpc-vni=36'``) or through the CEL
   filter (``_flow.source.vni_id == uint(36)``). Hubble metrics accept ``vni``
   as a source/destination context identifier and ``source_vni`` /
   ``destination_vni`` as ``labelsContext`` values, so that metrics of two VPCs
   that share an IP or a pod name do not collapse into one series.

6. **Flow log export (deployment-configured).** The flowlog exporter trims and
   aggregates flows with user-supplied proto field paths. In native-vpc mode a
   ``fieldMask`` must include ``source.vni_id`` and ``destination.vni_id``, and
   a ``fieldAggregate`` that aggregates on IPs or pod names must include them
   too - otherwise the exporter itself merges two VPCs that share an IP. This
   is the one place where the (VNI, IP) pair depends on configuration rather
   than on agent code.

Policy and security-group semantics
===================================

Native-vpc mode injects a
``vni:io-cilium-native-vpc-vni=<vni>`` identity label (source ``vni``, key
``io-cilium-native-vpc-vni``) into every OVN endpoint's identity. The
Cilium-owned key avoids collision with a user Kubernetes label named ``vni``.
This is an internal data-plane
scope, not a kube-ovn VPC identifier: two subnets in the same VPC normally
have different VNIs and therefore different Cilium identities even when every
other label and IP are equal.

Generic CNP selectors keep their normal label semantics. For example,
``fromEndpoints: {sg: web}`` selects every identity carrying ``sg=web``;
Cilium does not silently add a VPC constraint. This is acceptable for the
current deployment requirement because kube-ovn does not provide direct
inter-VPC reachability; traffic between VPCs goes through an explicit
interconnection/gateway path and is not a direct (VNI, IP) peer lookup.

If a platform later needs SG policy scoped to one subnet/logical switch, its
SG-to-CNP translator can explicitly select
``io-cilium-native-vpc-vni: "36"``. If one SG spans a
whole kube-ovn VPC with several subnets, the selector must include the set of
that VPC's subnet VNIs (for example a ``matchExpressions`` ``In`` list), not a
single value mislabeled as a VPC id. Future inter-VPC policy must explicitly
model the interconnection gateway and both endpoint-side VNI scopes.

CIDR/FQDN boundary
------------------

``fromCIDR`` / ``toCIDR`` and the FQDN identity-to-prefix table use plain IP
prefixes rather than (VNI, IP) keys. They cannot precisely distinguish the
same prefix/IP on two logical switches. This is not required by the current
feature (there is no direct inter-VPC communication); endpoint/SG membership
inside the cluster should use VNI-distinct endpoint identities. If direct
cross-VPC or VNI-aware CIDR/FQDN policy is added later, the CIDR/FQDN identity
and DNS-policy protocols must be extended to carry VNI; a /32 workaround must
not be used.

Identity resolution chain: consumer checklist
=============================================

The core invariant of native-vpc mode is:

  **Every consumer that maps an IP to an identity/metadata must query with the
  key (VNI, IP) - never with the bare IP alone** - because the same IP can
  exist in multiple VPCs.

Use the following table when reviewing any change that touches the identity
resolution chain; every new consumer (or new lookup path in an existing
consumer) must be added to it and marked VNI-aware. The four review questions
per consumer: (1) write key carries VNI? (2) read key carries VNI? (3) delete
uses the same key as write? (4) plain fallback can hit a foreign-VPC same-IP
entry?

Writers (key construction)
--------------------------

+--------------------------------------+-----------+-------------------------------------------+
| Consumer                             | VNI-aware | Notes                                     |
+======================================+===========+===========================================+
| endpoint create (parseVNIFromPod)    | yes       | reads tunnel_key into ``VNIID``           |
+--------------------------------------+-----------+-------------------------------------------+
| pod watcher register                 | yes       | ``ip@vni:N`` key                          |
+--------------------------------------+-----------+-------------------------------------------+
| pod watcher delete                   | yes       | key from the current annotation VNI       |
+--------------------------------------+-----------+-------------------------------------------+
| pod watcher old-IP delete            | yes*      | uses the NEW pod's VNI (VNI immutable     |
|                                      |           | per kube-ovn, so old==new in practice)    |
+--------------------------------------+-----------+-------------------------------------------+
| CiliumEndpoint watcher register      | yes       | ``ip@vni:N`` key                          |
+--------------------------------------+-----------+-------------------------------------------+
| CEP VNI annotation (write)           | yes       | ``native-vpc.cilium.io/vni`` written at   |
|                                      |           | CEP create and backfilled by an escaped   |
|                                      |           | JSON-Patch (RFC 6901) on existing CEPs    |
+--------------------------------------+-----------+-------------------------------------------+
| CEP informer transform               | yes       | keeps *only* that annotation; dropping    |
|                                      |           | it would leave every remote endpoint      |
|                                      |           | without a VNI (CES is rejected at start)  |
+--------------------------------------+-----------+-------------------------------------------+
| CiliumEndpoint watcher old-IP delete | yes       | uses the OLD CEP's VNI                    |
+--------------------------------------+-----------+-------------------------------------------+
| CiliumEndpoint watcher delete        | yes       | key from the deleted CEP's VNI            |
+--------------------------------------+-----------+-------------------------------------------+
| local identity sync (upsertLocal)    | yes       | ``ip@vni:N`` key; VNI=0 rejected in       |
|                                      |           | native-vpc (documented constraint)        |
+--------------------------------------+-----------+-------------------------------------------+
| kvstore identity sync (Upsert)       | yes       | ``IPIdentityPair.Vni`` + scoped key       |
+--------------------------------------+-----------+-------------------------------------------+
| kvstore watcher (OnUpdate/OnDelete)  | yes       | key rebuilt from ``pair.Vni``             |
+--------------------------------------+-----------+-------------------------------------------+
| ipcache BPF listener                 | yes       | routes to cilium_ipcache_vni by Vni       |
+--------------------------------------+-----------+-------------------------------------------+
| node/policy/apiserver UpsertMetadata | n/a       | node IPs, CIDRs, kube-apiserver (non-VPC  |
+--------------------------------------+-----------+-------------------------------------------+
| local identity restorer (dump)       | n/a*      | dumps only the plain map; VNI entries     |
|                                      |           | are rebuilt by the endpoint identity sync |
+--------------------------------------+-----------+-------------------------------------------+

Readers (lookup)
-----------------

+---------------------------------------+-----------+-------------------------------------------+
| Consumer                              | VNI-aware | Notes                                     |
+=======================================+===========+===========================================+
| datapath egress (bpf_lxc from_lxc)    | yes       | VNI map first, plain fallback             |
+---------------------------------------+-----------+-------------------------------------------+
| datapath ingress (bpf_lxc tail_*)     | yes       | VNI map first, plain fallback             |
+---------------------------------------+-----------+-------------------------------------------+
| datapath bpf_host                     | deploy    | plain lookups; must not be on the         |
|                                       |           | VNI-scoped pod data path (kube-ovn owns   |
|                                       |           | the host datapath)                        |
+---------------------------------------+-----------+-------------------------------------------+
| datapath bpf_overlay                  | deploy    | plain lookups; only if Cilium tunneling   |
|                                       |           | is enabled (native-vpc uses kube-ovn      |
|                                       |           | Geneve, whose VNI scopes a logical switch |
+---------------------------------------+-----------+-------------------------------------------+
| policy computation (CIDR shadow)      | yes       | shadow checks use ``KeyWithVNI``          |
+---------------------------------------+-----------+-------------------------------------------+
| fromEndpoints/toEndpoints selectors   | yes       | identities carry the internal VNI label;  |
|                                       |           | selectors keep normal label semantics     |
+---------------------------------------+-----------+-------------------------------------------+
| endpointmanager index (writer)        | yes       | ``vni-ipv4/6:<vni>:<ip>`` aux keys;       |
|                                       |           | native-vpc endpoints are *not* under the  |
|                                       |           | bare ``ipv4:/ipv6:`` keys                 |
+---------------------------------------+-----------+-------------------------------------------+
| endpointmanager LookupIP* (readers:   | yes*      | bare-IP lookups fall back to the per-IP   |
| DNS proxy source EP, Hubble local,    |           | VNI key index when exactly one VNI uses   |
| L7 accesslog, fqdn service, ipam API) |           | the IP on the node; overlapping IPs stay  |
|                                       |           | a deliberate miss (fail closed)           |
+---------------------------------------+-----------+-------------------------------------------+
| DNS proxy restored endpoints          | yes*      | per-IP *list* of restored endpoints; the  |
| (restart window)                      |           | bare-IP fallback resolves only when the   |
|                                       |           | list has exactly one entry, so restored   |
|                                       |           | DNS rules never leak across VNIs          |
+---------------------------------------+-----------+-------------------------------------------+
| Hubble VNI context (L3/L4)            | yes       | the emitting endpoint's VNI is read from  |
|                                       |           | the event's endpoint id, exactly like     |
|                                       |           | bpf_lxc uses CONFIG(native_vpc_vni)       |
+---------------------------------------+-----------+-------------------------------------------+
| Hubble local endpoint                 | yes       | exact (VNI, IP) lookup; falls back only   |
|                                       |           | to the key-exact plain scope for non-VPC  |
|                                       |           | peers, never to a bare-IP guess           |
+---------------------------------------+-----------+-------------------------------------------+
| Hubble remote endpoint                | yes       | key-exact (VNI, IP) ipcache identity +    |
|                                       |           | metadata when the flow has VNI context;   |
|                                       |           | otherwise VNI from the identity label     |
+---------------------------------------+-----------+-------------------------------------------+
| Hubble sock parser (socketLB)         | yes       | VNI from the exact cgroup -> pod ->       |
|                                       |           | endpoint context of the event             |
+---------------------------------------+-----------+-------------------------------------------+
| Hubble debug events                   | yes       | endpoint resolved by id, VNI reported     |
+---------------------------------------+-----------+-------------------------------------------+
| Hubble policy correlation             | yes       | keyed by endpoint id + remote identity,   |
|                                       |           | both VNI-exact (never by IP)              |
+---------------------------------------+-----------+-------------------------------------------+
| Hubble DNS names (SourceNames)        | yes       | per-endpoint DNS cache, keyed by the      |
|                                       |           | resolved endpoint id                      |
+---------------------------------------+-----------+-------------------------------------------+
| Hubble flowlog export                 | deploy    | ``fieldMask``/``fieldAggregate`` must     |
|                                       |           | include ``source.vni_id`` and             |
|                                       |           | ``destination.vni_id``                    |
+---------------------------------------+-----------+-------------------------------------------+
| Hubble service enrichment             | n/a       | service VIPs are cluster-scoped, not in   |
|                                       |           | the VPC address space                     |
+---------------------------------------+-----------+-------------------------------------------+
| Hubble metrics context                | yes       | ``vni`` context identifier and            |
|                                       |           | ``source_vni``/``destination_vni``        |
|                                       |           | labelsContext values                      |
+---------------------------------------+-----------+-------------------------------------------+
| Hubble flow filters                   | yes       | ``vni_id`` is filterable via the CEL      |
|                                       |           | filter and via the VNI identity label     |
+---------------------------------------+-----------+-------------------------------------------+
| L7 proxy accesslog (epinfo)           | yes       | records the endpoint's VNI on the log     |
|                                       |           | record (endpoint VNI, else the            |
|                                       |           | unambiguous ipcache entry's VNI)          |
+---------------------------------------+-----------+-------------------------------------------+
| Hubble L7 parser (DNS/HTTP flows)     | yes       | resolves pod metadata/workload with the   |
|                                       |           | recorded (VNI, IP) and sets ``vni_id``    |
|                                       |           | on both flow endpoints                    |
+---------------------------------------+-----------+-------------------------------------------+
| ipam API delete ("IP in use")         | yes       | VNI-agnostic in-use check (fails open on  |
|                                       |           | overlap on purpose: it is a guard, not    |
|                                       |           | an identity lookup)                       |
+---------------------------------------+-----------+-------------------------------------------+
| DNS proxy (fqdn)                      | yes       | same unambiguous bare-IP resolution       |
+---------------------------------------+-----------+-------------------------------------------+
| monitor events (IPCacheNotification)  | yes       | carries the VNI (agent JSON + hubble      |
|                                       |           | flowpb field 9)                           |
+---------------------------------------+-----------+-------------------------------------------+
| cilium-dbg bpf ipcache list           | yes       | dumps both the plain and VNI-scoped maps  |
+---------------------------------------+-----------+-------------------------------------------+
| ipcache API / list handler            | yes       | IPListEntry carries ``vniID``             |
+---------------------------------------+-----------+-------------------------------------------+
| envoy NPHDS (L7)                      | yes       | host lists are organized per identity     |
|                                       |           | (VNI-distinct); envoy matches by the      |
|                                       |           | packet's identity, not by bare IP         |
+---------------------------------------+-----------+-------------------------------------------+
| WireGuard agent                       | yes       | only consumes hostIP (peer routing) and   |
|                                       |           | bare-IP AllowedIPs (idempotent)           |
+---------------------------------------+-----------+-------------------------------------------+
| FQDN identity-to-IP table (service)   | no*       | bare prefixes; overlapping IPs appear     |
|                                       |           | under every VNI identity; fix requires    |
|                                       |           | the DNS-client protocol to carry VNI      |
+---------------------------------------+-----------+-------------------------------------------+
| ipcache metadata machinery            | n/a       | node/CIDR prefixes (non-VPC)              |
+---------------------------------------+-----------+-------------------------------------------+
| clustermesh kvstoremesh reflector     | deploy    | VNI-scoped keys are reflected to remote   |
|                                       |           | clusters; native-vpc must NOT be combined |
|                                       |           | with clustermesh (VPC != ClusterMesh)     |
+---------------------------------------+-----------+-------------------------------------------+
| ipsec datapath                        | deploy    | kube-ovn underlay does not use Cilium     |
|                                       |           | ipsec; not a supported combination        |
+---------------------------------------+-----------+-------------------------------------------+

``yes*`` / ``no*`` mark items that are correct or acceptable under the
kube-ovn guarantee (annotation/VNI immutable per pod), or that are mitigated
by a VNI-distinct identity elsewhere in the flow. ``deploy`` items must be
verified per deployment: bpf_host/bpf_overlay must not sit on the VNI-scoped
pod packet path (kube-ovn owns the host-side and tunnel-side datapath; Cilium's
per-endpoint bpf_lxc and the VNI-scoped ipcache are authoritative for pod
identity).

Non-VPC entities (node IPs, host, world, service/CIDR prefixes) stay in the
plain ipcache and are resolved by the plain fallback of the lookups above; they must
never be queried through the VNI-scoped maps.

Requirements
============

* kube-ovn with the tunnel_key backfill support (see the kube-ovn side
  guarantees above).
* **All Cilium agents must be upgraded before native-vpc is enabled.** The
  kvstore IP identity format is a stable API: native-vpc adds
  ``IPIdentityPair.Vni`` and scopes physical keys as ``<ip>@vni:<N>``. An
  older agent that does not understand ``Vni`` computes a bare-IP
  ``GetKeyName`` and rejects the scoped key during ``Unmarshal`` ("IP address
  does not match key"). Mixed-version native-vpc operation is unsupported.
  Clustermesh peers must not consume this VPC-scoped address space (VPC is not
  ClusterMesh; see the consumer checklist).
* The following features are **rejected at agent startup** in native-vpc mode,
  because their state is keyed by the bare IP and would silently mix two VPCs:
  kube-proxy replacement, socket LB (``--bpf-lb-sock``), the egress gateway,
  BPF masquerade, IPsec and WireGuard. Service load balancing is left to
  kube-proxy or kube-ovn, and kube-ovn performs SNAT.
* CiliumEndpoint CRD mode is required and **CiliumEndpointSlice must stay
  disabled** (``--enable-cilium-endpoint-slice=false``, the default). A CES
  packs endpoints as ``CoreCiliumEndpoint``, which carries no object metadata
  and therefore cannot transport the per-endpoint VNI annotation; the agent
  refuses to start with both enabled instead of silently registering remote
  endpoints without a VNI.
* Cilium must run as a **chained** CNI plugin behind kube-ovn (the primary
  CNI): ``--cni-chaining-mode=generic-veth`` with
  ``--cni-chaining-target`` pointing at the kube-ovn network, so that the
  kube-ovn CNI ADD (which blocks until the pod is allocated and annotated)
  completes before Cilium creates the endpoint.
* Cilium must use ``--routing-mode=native``. kube-ovn owns the host-side and
  Geneve tunnel datapath; Cilium tunneling/bpf_overlay performs plain-IP
  lookups and is rejected by native-vpc startup validation.
* Enable native-vpc mode and configure the annotation key:

  .. code-block:: shell-session

      $ helm upgrade cilium cilium/cilium --namespace kube-system \
          --set nativeVPC.enabled=true \
          --set nativeVPC.vniAnnotation="ovn.kubernetes.io/tunnel_key"

  or via agent flags ``--enable-native-vpc`` and
  ``--native-vpc-vni-annotation``. ``nativeVPC.enabled`` requires
  ``nativeVPC.vniAnnotation`` to be non-empty (the agent fails to start
  otherwise).

Plane-by-plane verification
===========================

The consumer checklist above is organised by data structure. This section is
the *process* view used to sign off the feature: the four planes are audited
one by one, every file that reads or writes an IP-keyed structure in that plane
is enumerated, and each item is answered with the same four questions.

The ten planes
--------------

The narrative in this document uses four planes (control, cache, forwarding,
observability) because those are the ones that had to be *changed* to carry the
VNI. A complete review needs six more, which are covered by their own sections
below:

+-----------------------------+------------------------------------------------+
| Plane                       | (VNI, IP) status                               |
+=============================+================================================+
| control                     | VNI-scoped                                     |
+-----------------------------+------------------------------------------------+
| cache                       | VNI-scoped                                     |
+-----------------------------+------------------------------------------------+
| forwarding                  | VNI-scoped (cilium_lxc is not authoritative)   |
+-----------------------------+------------------------------------------------+
| observability               | VNI-scoped                                     |
+-----------------------------+------------------------------------------------+
| policy                      | VNI-scoped through identities; CIDR/FQDN and   |
|                             | the L7 proxy are boundaries                    |
+-----------------------------+------------------------------------------------+
| conntrack / NAT             | **not** VNI-scoped: known limitation, detected |
|                             | and reported at runtime                        |
+-----------------------------+------------------------------------------------+
| service / load balancing    | not VNI-scoped: rejected at startup            |
+-----------------------------+------------------------------------------------+
| encryption / egress gateway | not VNI-scoped: rejected at startup            |
| / masquerade                |                                                |
+-----------------------------+------------------------------------------------+
| lifecycle (upgrade, repair) | procedural, see Recovery procedure             |
+-----------------------------+------------------------------------------------+
| assembly (hive graph)       | verified by TestAgentCell + compile-time       |
|                             | assertions on the optional interfaces          |
+-----------------------------+------------------------------------------------+

Ordered sign-off
----------------

The planes are reviewed in data-flow order. Each one is signed off on three
axes: **completeness** (every read/write site of the plane is covered),
**correctness** (keys match, unsafe fallbacks fail closed) and
**compatibility** (non-native-vpc deployments are unaffected, and upgrades /
restarts converge).

+----+----------------------+---------------------------------------------------+
| #  | Plane                | Sign-off                                          |
+====+======================+===================================================+
| 1  | control              | complete; correct (creation and restore both fail |
|    |                      | closed: a missing annotation rejects the endpoint |
|    |                      | resp. keeps the last VNI); compatible (VNIID is   |
|    |                      | serialized, so a restart converges even without   |
|    |                      | the pod store; inert when the mode is off)        |
+----+----------------------+---------------------------------------------------+
| 2  | cache                | complete; correct (write/delete symmetry and      |
|    |                      | per-IP index proven by test); compatible (a zero  |
|    |                      | VNI produces byte-identical keys and no index)    |
+----+----------------------+---------------------------------------------------+
| 3  | forwarding           | complete; correct (VNI map first, plain fallback  |
|    |                      | for non-VPC, endpoint-map fast path skipped);     |
|    |                      | compatible (the VNI map is pruned from the        |
|    |                      | program by the loader's reachability analysis     |
|    |                      | when native_vpc_vni == 0, so non-native-vpc nodes |
|    |                      | never even create it; map flags match the C side) |
+----+----------------------+---------------------------------------------------+
| 4  | policy               | complete for identity-based selection; correct    |
|    |                      | (the identity key includes the VNI label, proven  |
|    |                      | by test); boundaries: CIDR/FQDN prefixes and the  |
|    |                      | host-namespace L7 proxy                           |
+----+----------------------+---------------------------------------------------+
| 5  | conntrack / NAT      | **incomplete by design** (the CT key has no VNI); |
|    |                      | mitigated by scheduling; the precondition is      |
|    |                      | exported as cilium_native_vpc_overlapping_ips;    |
|    |                      | NAT is inert because its features are rejected    |
+----+----------------------+---------------------------------------------------+
| 6  | service / LB         | rejected at startup (test-covered both ways) and  |
|    |                      | the datapath skips service translation for VPC    |
|    |                      | endpoints, since ClusterIP is programmed even     |
|    |                      | with kube-proxy replacement disabled              |
+----+----------------------+---------------------------------------------------+
| 7  | encryption / egress  | rejected at startup (test-covered both ways)      |
|    | gateway / masquerade |                                                   |
+----+----------------------+---------------------------------------------------+
| 8  | observability        | complete; correct (every enrichment lookup is     |
|    |                      | (VNI, IP)- or id-keyed); compatible (the extra    |
|    |                      | endpoint lookup is skipped when the mode is off)  |
+----+----------------------+---------------------------------------------------+
| 9  | lifecycle            | restart converges (serialized VNI + annotation    |
|    |                      | re-read + CEP backfill); upgrade requires all     |
|    |                      | agents first; downgrade ignores the annotation    |
+----+----------------------+---------------------------------------------------+
| 10 | assembly (hive)      | TestAgentCell + compile-time assertions on the    |
|    |                      | optional interfaces                               |
+----+----------------------+---------------------------------------------------+

Method
------

For every item in a plane:

1. **Write key** - does the writer include the VNI in the key?
2. **Read key** - does the reader include the VNI in the key?
3. **Delete key** - is the delete key identical to the write key (no leak, no
   deletion of a foreign VPC's entry)?
4. **Fallback** - can a plain/bare-IP fallback path return an entry that
   belongs to a different VPC? If yes it must fail closed instead.

Plus, per plane, the boundary cases: VNI absent (0), VNI invalid or out of
range (> 16777215), VNI unavailable at the moment of the decision (pod store
down), agent restart, and mixed VPC/non-VPC entities.

Control plane
-------------

Scope: turning the ``tunnel_key`` annotation into an endpoint property, an
identity label, a CiliumEndpoint annotation, and endpoint-manager identifiers.

+-----------------------------------------------+--------------------------------------------------+
| File                                          | Result                                           |
+===============================================+==================================================+
| ``pkg/annotation/k8s.go``                     | annotation keys (pod ``tunnel_key`` is           |
|                                               | configurable, CEP ``native-vpc.cilium.io/vni``   |
|                                               | is fixed)                                        |
+-----------------------------------------------+--------------------------------------------------+
| ``pkg/endpoint/api/endpoint_api_manager.go``  | reads the annotation before conflict detection;  |
|                                               | rejects missing/0/unparsable/out-of-range;       |
|                                               | conflict detection keyed by (VNI, IP);           |
|                                               | ``requireVNI`` fails closed when the pod         |
|                                               | metadata is unavailable                          |
+-----------------------------------------------+--------------------------------------------------+
| ``pkg/endpoint/endpoint.go``                  | ``VNIID``, ``SyncVNIFromPodAnnotation`` decision |
|                                               | table, VNI identity label add/remove             |
+-----------------------------------------------+--------------------------------------------------+
| ``pkg/endpoint/identifiers.go``,              | ``vni-ipv4/6:<vni>:<ip>`` identifiers, mutually  |
| ``pkg/endpoint/id/id.go``                     | exclusive with the bare ``ipv4:/ipv6:`` ones     |
+-----------------------------------------------+--------------------------------------------------+
| ``pkg/endpoint/restore.go``,                  | VNI re-read from the annotation on restore       |
| ``daemon/cmd/endpoint_restore.go``            | before the endpoint is exposed                   |
+-----------------------------------------------+--------------------------------------------------+
| ``pkg/endpointmanager/manager.go``            | aux identifier index + per-IP VNI index for the  |
|                                               | explicit bare-IP fallback; compile-time          |
|                                               | assertion that the VNI lookups are implemented   |
+-----------------------------------------------+--------------------------------------------------+
| ``pkg/endpointmanager/endpointsynchronizer``  | writes the CEP VNI annotation at create and      |
|                                               | backfills it with an RFC 6901 escaped patch      |
+-----------------------------------------------+--------------------------------------------------+
| ``pkg/k8s/factory_functions.go``              | CEP informer transform keeps the VNI annotation  |
+-----------------------------------------------+--------------------------------------------------+
| ``pkg/k8s/watchers/{pod,cilium_endpoint}.go`` | VNI-scoped ipcache registration/deletion         |
+-----------------------------------------------+--------------------------------------------------+
| ``pkg/labels``, ``pkg/labelsfilter``,         | ``vni:io-cilium-native-vpc-vni`` is an identity  |
| ``pkg/identity``                              | label and cannot be filtered out                 |
+-----------------------------------------------+--------------------------------------------------+
| ``pkg/option/config.go``                      | startup validation: annotation key required,     |
|                                               | native routing required, CES rejected            |
+-----------------------------------------------+--------------------------------------------------+

Seams
~~~~~

*Upstream* (kube-ovn -> Cilium): the ``tunnel_key`` annotation is read by three
different planes - endpoint creation and restore (control), the pod watcher
(cache) and, through them, the datapath and observability planes. They now
share **one** decision table, ``pkg/nativevpc.VNIFromPod``, so a value cannot be
accepted by one reader and rejected by another. Before, the pod watcher used
its own parser without a range check, so an out-of-range ``tunnel_key`` would
register a VPC-scoped ipcache entry under a VNI that no endpoint had.

The API/CNI endpoint-creation request also carries a ``vni-id`` field. It is
untrusted: the value is only accepted if it matches the annotation, so it can
neither invent a VPC scope nor satisfy the mandatory-VNI gate when the
annotation could not be read.

*Downstream* (control -> cache/forwarding/observability): a VNI change is
propagated by replacing state, never by mutating it in place:

* the identity-sync controller captures the VNI at registration time, so the
  old controller's ``StopFunc`` deletes exactly the key its ``DoFunc`` wrote
  (``<ip>@vni:N``) instead of leaking it;
* the endpoint-manager references are replaced from a snapshot of the
  previously registered identifiers;
* the CiliumEndpoint annotation carries the VNI to the cache plane of the other
  nodes.

Defects found and fixed during this audit: the CEP informer transform dropped
the annotation (remote endpoints silently lost their VNI); the CEP backfill
patch used an unescaped JSON Pointer (the whole patch, including the status
update, failed); endpoint creation fell back to the plain-IP scheme when the
pod metadata was unavailable instead of failing closed; endpoint restore
*downgraded* a VPC endpoint to the plain scheme when the annotation was
transiently missing; the three annotation parsers disagreed on validity; the
API-supplied ``vni-id`` bypassed the "annotation is the single source of truth"
invariant.

Cache plane
-----------

Scope: the userspace ipcache, the endpoint-manager indexes and the kvstore
representation.

+----------------------------------------------+--------------------------------------------------+
| File                                         | Result                                           |
+==============================================+==================================================+
| ``pkg/ipcache/ipcache.go``                   | ``<ip>@vni:<vni>`` keys, per-IP VNI index,       |
|                                              | key-exact lookups, unambiguous fallback,         |
|                                              | shadowing checks keyed by (VNI, prefix)          |
+----------------------------------------------+--------------------------------------------------+
| ``pkg/ipcache/ipcache.go`` (dump)            | full dump strips the VNI suffix and carries the  |
|                                              | VNI in the identity; never panics on a key       |
+----------------------------------------------+--------------------------------------------------+
| ``pkg/ipcache/ipcache.go`` (raw-key readers) | ``LookupByIdentity`` (DNS rule restoration) and  |
|                                              | ``LookupByHostRLocked`` (WireGuard) return plain |
|                                              | addresses, never internal keys                   |
+----------------------------------------------+--------------------------------------------------+
| ``pkg/ipcache/metadata.go``                  | metadata layer is keyed by ``PrefixCluster`` and |
|                                              | only holds non-VPC prefixes (nodes, CIDRs,       |
|                                              | kube-apiserver); VNI keys never reach it         |
+----------------------------------------------+--------------------------------------------------+
| ``pkg/ipcache/kvstore.go``                   | ``IPIdentityPair.Vni`` + scoped physical key     |
+----------------------------------------------+--------------------------------------------------+
| ``pkg/ipcache/restore``                      | dumps only the plain map; VNI entries are        |
|                                              | rebuilt by the endpoint identity sync            |
+----------------------------------------------+--------------------------------------------------+
| ``pkg/fqdn/dnsproxy/proxy.go``               | restored endpoints are a per-IP list; resolves   |
|                                              | only when a single endpoint uses the IP          |
+----------------------------------------------+--------------------------------------------------+

Defects found and fixed during this audit: the full ipcache dump panicked on
VNI keys (``MustParseAddrCluster``), which crashed the agent on ``cilium-dbg ip
list`` / any listener registration; two readers returned raw ``<ip>@vni:<vni>``
strings to consumers that parse them as addresses (DNS rule restoration lost
every VPC IP, WireGuard could append a zero-value prefix).

Named ports remain a cluster-wide aggregate (as they are across namespaces
today); this is unchanged by native-vpc.

Forwarding plane
----------------

Scope: BPF maps and programs.

+--------------------------------------+--------------------------------------------------+
| File                                 | Result                                           |
+======================================+==================================================+
| ``bpf/lib/eps.h``,                   | ``cilium_ipcache_vni`` LPM keyed by (VNI, IP),   |
| ``pkg/maps/ipcache/ipcache.go``      | layout pinned by a Go/C size test                |
+--------------------------------------+--------------------------------------------------+
| ``bpf/bpf_lxc.c``                    | egress and ingress resolve the peer in the VNI   |
|                                      | map first; the endpoint-map fast path is skipped |
|                                      | when the endpoint has a VNI                      |
+--------------------------------------+--------------------------------------------------+
| ``bpf/include/bpf/config/lxc.h``,    | per-endpoint load-time ``native_vpc_vni``; one   |
| ``pkg/datapath/{config,loader}``     | template serves all VNIs, endpoint hash includes |
|                                      | the VNI                                          |
+--------------------------------------+--------------------------------------------------+
| ``pkg/datapath/ipcache/listener.go`` | routes upserts/deletes to the VNI map by         |
|                                      | ``Identity.Vni``; same key for both              |
+--------------------------------------+--------------------------------------------------+
| ``pkg/ipcache/cell/cell.go``         | the VNI map is recreated at startup in           |
|                                      | native-vpc mode and repopulated by the full dump |
+--------------------------------------+--------------------------------------------------+
| ``pkg/maps/lxcmap/lxcmap.go``        | ``cilium_lxc`` is keyed by the bare IP: it is    |
|                                      | not authoritative for native-vpc pods (bpf_lxc   |
|                                      | skips it) and deletion is compare-and-delete so  |
|                                      | one VPC cannot remove another VPC's entry        |
+--------------------------------------+--------------------------------------------------+

Seams
~~~~~

*Upstream* (cache -> forwarding): the listener picks the map from
``Identity.Vni`` for both upserts and deletions, so a deletion always targets
the map the entry was written to (test-covered, including two VPCs sharing an
IP). An entry never "moves" between the two maps, because the VNI is part of
the ipcache key: a scope change is a delete of one key plus an upsert of
another.

The shadow/revive relationship between an endpoint IP and an equally-sized CIDR
entry is resolved *within* one VNI scope (the lookup uses
``KeyWithVNI(prefix, keyVNI)``), which is what keeps that logic - designed for
one flat key space - correct when the entries live in two different BPF maps.

The Go and C key layouts are pinned by a test on the real invariant: the LPM
static prefix must equal the bit offset of the IP inside the key data.

*Downstream* (forwarding -> policy/observability): the VNI-scoped lookup yields
the peer identity that feeds the identity-keyed policy map, and the trace/drop
events carry the endpoint id from which the observability plane derives the
VNI. Neither consumer sees the (VNI, IP) key itself.

Defects found and fixed during this audit: endpoint teardown deleted the
``cilium_lxc`` entry of an overlapping IP owned by another VPC's endpoint; the
VNI key placed its padding *after* the IP field, which inflated the LPM static
prefix by 16 bits - host prefixes matched by accident (the extra bits land on
zeroed padding) but any shorter prefix would only have matched addresses whose
remaining bytes are zero.

Observability plane
-------------------

See `Observability: the (VNI, IP) chain in Hubble`_ for the narrative; the
files are ``pkg/hubble/parser/{threefour,seven,sock,debug,agent,common}``,
``pkg/hubble/parser/cell``, ``pkg/hubble/metrics/api/context.go``,
``pkg/monitor/api/types.go``, ``pkg/proxy/accesslog``, ``api/v1/flow`` and
``cilium-dbg/cmd/bpf_ipcache_{list,get}.go``.

Defects found and fixed during this audit: L7 flows had no VNI and lost all pod
metadata; L3/L4 flows never had a VNI context (the only source was a tunnel
header Cilium never sees under kube-ovn); socket-level flows had no VNI and
could be enriched with a foreign VPC's pod; debug events did not report the
VNI; ``cilium-dbg bpf ipcache get`` could not see VNI entries.

Policy plane
------------

Scope: identity allocation, selectors, the per-endpoint policy map and the L7
proxy.

* The policy map (``cilium_policy_v2``) is keyed by **identity**, not by IP, and
  identities are VNI-distinct in native-vpc mode (the VNI identity label is a
  mandatory identity label, see ``pkg/labelsfilter``). Two pods of different
  VPCs therefore never share a policy-map entry even with identical IPs and
  identical Kubernetes labels.
* ``fromEndpoints``/``toEndpoints`` selectors resolve through the identity
  layer and are consequently VNI-scoped as well.
* ``fromCIDR``/``toCIDR`` and FQDN identities are keyed by the bare prefix; see
  `CIDR/FQDN boundary`_. They are correct for destinations outside the VPC
  address space (the normal use) and cannot distinguish two VPCs that overlap
  on the same prefix.
* **Identity space (capacity boundary).** The identity is derived from the
  label set, so adding the VNI label multiplies the number of cluster-wide
  identities by the number of VNIs that share a label set: N workloads
  replicated across M VPCs consume N*M identities instead of N. The
  cluster-wide space is ``256..65535`` (with ClusterMesh it is smaller,
  ``2^(16-clusterIDShift)`` per cluster), so a deployment must size
  ``VNIs x distinct label sets`` against it. Local (CIDR/FQDN) identities are
  unaffected because they are node-local.
* **Identity management mode (rejected at startup).** The VNI identity label is
  computed by the *agent* from the pod annotation. The operator's
  CiliumIdentity controller derives identities from pod and namespace labels
  only; with ``--identity-management-mode=operator`` (or ``both``) it would
  create identities without the VNI label, consider the agent's VNI-scoped
  identities unused and garbage collect them - silently merging all VPCs into
  one identity. native-vpc therefore requires the default (agent-managed)
  mode and refuses to start otherwise.
* **L7 proxy (deployment boundary).** A redirected connection is proxied from
  the host network namespace to the original destination address. With
  overlapping VPC subnets the host cannot resolve which VPC that address
  belongs to, so L7 policy (HTTP rules, and the DNS proxy when the DNS server
  itself lives in a VPC subnet) must not be applied to VPC-internal
  destinations. L7 policy toward destinations outside the VPC address space is
  unaffected.

Assembly (hive) plane
---------------------

Scope: the object graph itself. Native-vpc adds dependencies between cells
(the identity synchronizer needs the local ipcache, the Hubble parsers need the
VNI-aware getters), and there are two failure modes that no package-level test
catches:

* a constructor parameter type that no cell provides makes the **entire agent**
  fail to start (``missing type: ...``). This happened with the local-ipcache
  interface of the identity synchronizer and is now covered by
  ``go test ./daemon/cmd/ -run TestAgentCell``;
* an *optional* interface that the production type stops implementing silently
  degrades the consumer to a bare-IP path. All of them now have compile-time
  assertions (``pkg/hubble/parser/cell``, ``pkg/endpointmanager``).

Seams
~~~~~

*Upstream* (control -> policy): the VNI reaches the policy plane only as an
identity label. The label is injected by the endpoint metadata resolver and is
hard-kept by ``pkg/labelsfilter`` in native-vpc mode, so it cannot be filtered
away by a user label whitelist or an explicit ignore rule. Because the identity
key is the sorted label list, two pods that differ only by VNI necessarily get
different numeric identities (test-covered in ``pkg/identity/key``).

*Cross-component*: identity **allocation** must stay agent-side. The operator's
CiliumIdentity controller derives identities from pod and namespace labels and
knows nothing about the annotation, so operator-managed CIDs are rejected at
startup (see above). The operator's identity *garbage collector* is safe: it
works on identity usage (CiliumEndpoint references and heartbeats), not on
recomputed label sets.

*Downstream* (policy -> forwarding/observability): the policy map is keyed by
identity, so the VNI never appears in the datapath policy lookup - the
VNI-scoped ipcache is what selects the right identity in the first place. Hubble
policy correlation is keyed by endpoint id plus remote identity, both of which
are VNI-exact.

Conntrack and NAT plane
-----------------------

Scope: ``cilium_ct4/6_global``, the NAT maps and the datapath state derived
from them.

**This is the one plane where the (VNI, IP) pair cannot be expressed today.**
The CT key is the bare 5-tuple (``struct ipv4_ct_tuple``: addresses, ports,
protocol, direction flags); upstream only extends it with a *cluster* scope
(``cilium_per_cluster_ct_*``, a statically sized map-of-maps for ClusterMesh),
which does not generalise to hundreds of logical switches.

Failure mode
~~~~~~~~~~~~

Two local endpoints of different VPCs that share an IP can share a CT entry if
they also talk to the same peer address, port and protocol with the same
ephemeral source port. The shared entry carries the connection state, the peer
identity and any proxy redirect, so:

* the second connection can be treated as established, and Cilium only
  evaluates policy on the first packet of a connection - i.e. it can bypass the
  policy of its own VPC;
* reply packets can be attributed to the peer identity of the other VPC.

**Likelihood.** This is not a rare corner case in the deployments native-vpc
targets. Mirrored VPCs typically have not only overlapping *pod* subnets but
also the same service addresses, so two pods that share an IP frequently talk
to the same destination IP and port; the only remaining degree of freedom is
the ephemeral source port (roughly 28 000 values), which collides with
noticeable probability after a few hundred connections. Treat co-scheduling of
overlapping IPs as unsafe rather than unlikely.

Scope: conntrack state is per node, so the collision requires the two endpoints
to be **on the same node**.

Mitigations available today
~~~~~~~~~~~~~~~~~~~~~~~~~~~

* **Scheduling.** Do not co-schedule pods with overlapping IPs from different
  VPCs on the same node (pod anti-affinity, or a kube-ovn/scheduler policy that
  keeps overlapping subnets on disjoint node sets). This removes the failure
  mode entirely.
* **Detection.** The agent detects the precondition - an IP used by more than
  one local endpoint in different VNIs - and both logs it (with both endpoint
  ids) and exports it as ``cilium_native_vpc_overlapping_ips``. Alert on
  ``> 0``: a zero value means there is no CT ambiguity on that node.
* The NAT maps are inert in the supported configuration: BPF masquerade,
  kube-proxy replacement and socket LB are rejected at startup, and kube-ovn
  performs SNAT itself.

Bounded fix plan (follow-up)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The proper fix is per-VNI conntrack state. The hook already exists:
``select_ct_map4()``/``select_ct_map6()`` in ``bpf_lxc.c`` choose the CT map at
runtime and already perform a map-in-map lookup for the ClusterMesh case, and a
missing map is already handled as a fail-closed drop
(``DROP_CT_NO_MAP_FOUND``). A follow-up therefore needs:

#. a ``HASH_OF_MAPS`` outer map keyed by VNI (the existing per-cluster maps are
   an ``ARRAY_OF_MAPS`` with statically declared inner maps, which does not
   scale to many logical switches);
#. agent-side inner-map lifecycle (create on the first endpoint of a VNI,
   remove when the last one goes away);
#. CT garbage collection over the inner maps, reusing the per-cluster GC
   machinery in ``pkg/maps/ctmap``;
#. sizing: inner maps divide the CT budget per VNI.

Adding a VNI field to ``struct ipv4_ct_tuple`` instead would touch the key
layout shared by CT, NAT, DSR and service handling, and is not recommended.

Service and load-balancing plane
--------------------------------

Scope: service frontends, backends and their BPF maps.

Backends are keyed by ``(IP, port, protocol)``, so two pods of different VPCs
sharing an IP collapse into a single backend entry. Worse, a backend address is
just an IP: whichever pod owns that IP **in the sender's own VPC** is what
kube-ovn delivers to. Translating a service address for a VPC endpoint can
therefore silently redirect a client of one tenant to a pod of another.

Native-vpc closes this on two levels:

* **Configuration**: kube-proxy replacement and socket LB are rejected at
  startup.
* **Datapath**: disabling kube-proxy replacement is *not* sufficient. Only
  NodePort and HostPort frontends are gated by it; ClusterIP frontends and
  their backends are still reflected into the load-balancing tables and
  programmed into the BPF maps, and ``bpf_lxc`` calls ``lb4_lookup_service()``
  unconditionally on pod egress. ``bpf_lxc`` therefore skips the service lookup
  entirely when the endpoint has a VNI (``CONFIG(native_vpc_vni) > 0``),
  exactly like it skips the endpoint-map fast path. Service load balancing is
  left to kube-ovn (or kube-proxy), which resolves backends inside the VPC's
  own routing domain.

Consumers of the load-balancing tables that remain active are VPC-agnostic by
nature and unaffected: Hubble's service enrichment resolves *frontends*
(cluster-scoped VIPs, never pod addresses), and the health checker as well as
NodePort/HostPort reflection are gated by kube-proxy replacement.
CiliumLocalRedirectPolicy is *not* gated by it, but it redirects to a backend
address and is therefore ineffective (and would be unsafe) for VPC endpoints
under the datapath rule above.

Why ``kubeProxyReplacement: false`` is not enough
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is worth spelling out, because the natural assumption is that disabling
kube-proxy replacement disables Cilium's service handling:

#. the load-balancing control plane (reflectors, maps, reconciler) is
   registered unconditionally in the agent, so the BPF service and backend maps
   are created and populated;
#. only NodePort, LoadBalancer and HostPort frontends are gated by kube-proxy
   replacement - **ClusterIP frontends are reflected unconditionally**, i.e.
   every ClusterIP service of the cluster ends up in the BPF maps;
#. ``bpf_lxc`` compiles per-packet load balancing whenever socket LB is not
   *fully* enabled (``#if !defined(ENABLE_SOCKET_LB_FULL) || ...``), and also
   whenever SCTP support is enabled - both of which hold for a kube-ovn
   chaining deployment with ``socketLB.enabled: false`` and
   ``sctp.enabled: true``.

Without the datapath rule above, a pod of VPC B connecting to a ClusterIP
therefore had its destination rewritten by Cilium to a backend pod address of,
say, VPC A - and kube-ovn then resolved that address inside VPC B, either
dropping the packet or delivering it to whatever pod owns the same IP there.

Operators can verify the state on a node with:

.. code-block:: shell-session

    # the maps exist and are populated even with kubeProxyReplacement=false
    $ cilium-dbg bpf lb list | head
    # after the fix, traffic from a VPC pod to a ClusterIP must leave the pod
    # untranslated (kube-ovn / kube-proxy resolves it):
    $ cilium-dbg monitor --type trace | grep <clusterIP>

Encryption, egress gateway and masquerade plane
-----------------------------------------------

All of these select traffic or peers by the bare IP:

* the egress gateway matches the source IP of a pod,
* BPF masquerade and the NAT maps work on the bare tuple,
* IPsec and WireGuard select the peer by node/endpoint IP.

They are rejected at startup together with the LB features above, so that an
unsupported combination fails immediately and deterministically instead of
mixing two VPCs at runtime:

.. code-block:: shell-session

    $ cilium-agent --enable-native-vpc ... --kube-proxy-replacement
    level=fatal msg="native-vpc mode is incompatible with kube-proxy replacement: ..."

Lifecycle plane
---------------

Scope: upgrade, restart and repair, i.e. the time dimension of the other
planes. Covered by `Recovery procedure`_ and `Requirements`_: agents must be
upgraded before native-vpc is enabled (the kvstore IP format is a stable API),
a missing annotation is repaired by restarting kube-ovn-controller and then
Cilium, and a VNI change is not hot-applied - the endpoint is re-read on
restore.

Review and verification gates
=============================

The four-plane narrative (control/cache/forwarding/observability) describes
recovery, but is not sufficient for completeness. Review every reader and
writer in the identity-resolution-chain table above and require the following
checks before merge:

* The agent object graph must still build. Constructors registered in a hive
  cell may only take types that some cell provides: an unexported (or simply
  unprovided) interface parameter makes the *whole agent* fail to start with
  ``missing type: ...``, and no unit test of the package involved catches it:

  .. code-block:: shell-session

      $ go test ./daemon/cmd/ -run TestAgentCell

* Go build/tests and formatting:

  .. code-block:: shell-session

      $ go build ./...
      $ go test ./pkg/ipcache/... ./pkg/hubble/... ./pkg/endpoint/... \
          ./pkg/endpointmanager/ ./pkg/k8s/watchers/ ./pkg/labelsfilter/ ...
      $ gofmt -l pkg/ daemon/ api/

* Real datapath compilation (``go build`` cannot validate BPF preprocessing or
  verifier-visible configuration):

  .. code-block:: shell-session

      $ make -B -C bpf bpf_lxc.o

* Load-time config generation must match the compiled BPF object exactly, and
  template/runtime tests must prove that VNI does not split the template cache
  but does change the endpoint reload hash:

  .. code-block:: shell-session

      $ cd pkg/datapath/config
      $ go run github.com/cilium/cilium/tools/dpgen \
          -path ../../../bpf/bpf_lxc.o -embed Node -kind object \
          -name BPFLXC -out /tmp/lxc_config.go
      $ diff -u lxc_config.go /tmp/lxc_config.go
      $ go test ../loader -run 'TestWrap|TestHashEndpoint|TestHashTemplate'

* Generated API files must be produced by the pinned toolchains and a second
  run must produce no diff:

  .. code-block:: shell-session

      $ make -C api/v1 proto
      $ make generate-api
      $ git diff --exit-code -- api/v1/flow/flow.pb.go \
          api/v1/models/ip_list_entry.go api/v1/server/embedded_spec.go

  When checking an uncommitted change, compare file checksums before/after the
  second generator run rather than requiring the working-tree diff to be
  empty.
