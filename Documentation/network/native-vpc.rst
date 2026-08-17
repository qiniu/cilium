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
  logged and the pod falls back to the native scheme. A zero tunnel_key
  violates the kube-ovn guarantee (kube-ovn only ever writes a non-zero key),
  so the kube-ovn side must be investigated.

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

Defects found and fixed during this audit: the CEP informer transform dropped
the annotation (remote endpoints silently lost their VNI); the CEP backfill
patch used an unescaped JSON Pointer (the whole patch, including the status
update, failed); endpoint creation fell back to the plain-IP scheme when the
pod metadata was unavailable instead of failing closed.

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

Defect found and fixed during this audit: endpoint teardown deleted the
``cilium_lxc`` entry of an overlapping IP owned by another VPC's endpoint.

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

Review and verification gates
=============================

The four-plane narrative (control/cache/forwarding/observability) describes
recovery, but is not sufficient for completeness. Review every reader and
writer in the identity-resolution-chain table above and require the following
checks before merge:

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
