// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package getters

import (
	"net/netip"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	cgroupManager "github.com/cilium/cilium/pkg/cgroups/manager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labels"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

// DNSGetter ...
type DNSGetter interface {
	// GetNamesOf fetches FQDNs of a given IP from the perspective of
	// the endpoint with ID sourceEpID. The returned names must not have
	// trailing dots.
	GetNamesOf(sourceEpID uint32, ip netip.Addr) (names []string)
}

// EndpointGetter ...
type EndpointGetter interface {
	// GetEndpointInfo looks up non-VPC endpoint by bare IP.
	GetEndpointInfo(ip netip.Addr) (endpoint EndpointInfo, ok bool)
	// GetEndpointInfo looks up endpoint by id
	GetEndpointInfoByID(id uint16) (endpoint EndpointInfo, ok bool)
}

// EndpointGetterVNI is the optional exact endpoint lookup extension for
// native-vpc flows. Implementations must not infer VNI from a bare IP.
// A zero VNI selects the plain (non-VPC) scope and is key-exact as well: it
// resolves only endpoints that are not in any VPC (host, nodes, non-OVN pods).
type EndpointGetterVNI interface {
	GetEndpointInfoForVNI(ip netip.Addr, vni uint32) (endpoint EndpointInfo, ok bool)
}

// EndpointGetterByPod is the optional pod-scoped endpoint lookup used by the
// socket-level parser: a TraceSock event identifies the local endpoint by
// cgroup id (hence by pod), which is an exact context and must be preferred
// over any bare-IP lookup in native-vpc mode.
type EndpointGetterByPod interface {
	GetEndpointInfoByPod(namespace, name string) (endpoint EndpointInfo, ok bool)
}

// IdentityGetter ...
type IdentityGetter interface {
	// GetIdentity fetches a full identity object given a numeric security id.
	GetIdentity(id uint32) (*identity.Identity, error)
}

// IPGetter fetches per-IP metadata
type IPGetter interface {
	// GetK8sMetadata returns Kubernetes metadata for the given IP address.
	GetK8sMetadata(ip netip.Addr) *ipcache.K8sMetadata
	// GetK8sMetadataForVNI returns the Kubernetes metadata of the native-vpc
	// VNI-scoped entry for the given IP (key "<ip>@vni:<vni>"), or nil if no
	// such entry exists. Overlapping IPs from different VPCs coexist as
	// VNI-scoped entries that the plain GetK8sMetadata lookup cannot see.
	GetK8sMetadataForVNI(ip netip.Addr, vni uint32) *ipcache.K8sMetadata
	// LookupSecIDByIP returns the corresponding security identity that
	// the specified IP maps to as well as if the corresponding entry exists.
	LookupSecIDByIP(ip netip.Addr) (ipcache.Identity, bool)
	// LookupSecIDByIPForVNI returns the identity of the native-vpc VNI-scoped
	// entry for the given IP. It is key-exact: it never resolves a plain or a
	// foreign-VPC entry, so a flow whose VNI context is known is never
	// attributed to another VPC.
	LookupSecIDByIPForVNI(ip netip.Addr, vni uint32) (ipcache.Identity, bool)
}

// ServiceGetter fetches service metadata.
type ServiceGetter interface {
	GetServiceByAddr(ip netip.Addr, port uint16) *flowpb.Service
}

// LinkGetter fetches local link information.
type LinkGetter interface {
	// GetIfNameCached returns the name of an interface (if it exists) by
	// looking it up in a regularly updated cache
	GetIfNameCached(ifIndex int) (string, bool)

	// Name returns the name of an interface, or returns a string
	// containing the ifindex if the link name cannot be determined.
	Name(ifIndex uint32) string
}

// PodMetadataGetter returns pod metadata based on identifiers received from
// datapath trace events.
type PodMetadataGetter interface {
	// GetPodMetadataForContainer returns the pod metadata for the given container
	// cgroup id.
	GetPodMetadataForContainer(cgroupId uint64) *cgroupManager.PodMetadata
}

// EndpointInfo defines readable fields of a Cilium endpoint.
type EndpointInfo interface {
	GetID() uint64
	GetIdentity() identity.NumericIdentity
	GetK8sPodName() string
	GetK8sNamespace() string
	GetLabels() labels.Labels
	GetPod() *slim_corev1.Pod
	GetVNIID() uint64
	GetPolicyCorrelationInfoForKey(key policyTypes.Key) (policyTypes.PolicyCorrelationInfo, bool)
}
