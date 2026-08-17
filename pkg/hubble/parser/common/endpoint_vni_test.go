// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
)

// TestEndpointResolverRemoteVNI verifies that a remote native-vpc endpoint is
// resolved through its VNI-scoped ipcache entry: the plain (bare-IP) lookup
// misses (overlapping VPC entries live under "<ip>@vni:<vni>"), so the parser
// derives the VNI from the (VNI-distinct) VNI identity label and does a
// direct VNI-scoped metadata lookup.
func TestEndpointResolverRemoteVNI(t *testing.T) {
	ip := netip.MustParseAddr("192.168.1.2")
	const datapathIdentity = uint32(21929)

	// The datapath identity carries the VNI identity label of logical switch 36.
	identityGetter := &testutils.FakeIdentityGetter{
		OnGetIdentity: func(secID uint32) (*identity.Identity, error) {
			require.Equal(t, datapathIdentity, secID)
			return identity.NewIdentity(identity.NumericIdentity(datapathIdentity), labels.Labels{
				labels.VNIKey: labels.NewLabel(labels.VNIKey, "36", labels.LabelSourceVNI),
			}), nil
		},
	}

	ipGetter := &testutils.FakeIPGetter{
		// The plain lookup misses: the entry lives under "192.168.1.2@vni:36".
		OnGetK8sMetadata: func(ip netip.Addr) *ipcache.K8sMetadata {
			return nil
		},
		OnGetK8sMetadataForVNI: func(ip netip.Addr, vni uint32) *ipcache.K8sMetadata {
			require.Equal(t, uint32(36), vni)
			return &ipcache.K8sMetadata{Namespace: "ns-a", PodName: "pod-a"}
		},
		OnLookupSecIDByIP: func(ip netip.Addr) (ipcache.Identity, bool) {
			return ipcache.Identity{}, false
		},
	}

	resolver := NewEndpointResolver(hivetest.Logger(t), &testutils.NoopEndpointGetter, identityGetter, ipGetter)
	ep := resolver.ResolveEndpoint(ip, datapathIdentity, DatapathContext{})

	require.Equal(t, "ns-a", ep.Namespace)
	require.Equal(t, "pod-a", ep.PodName)
	require.Equal(t, uint32(21929), ep.Identity)
	require.Equal(t, uint64(36), ep.VniId)
	require.Contains(t, ep.Labels, "vni:io-cilium-native-vpc-vni=36")
	require.NotNil(t, ep)
}

// TestEndpointResolverRemoteNoVNI verifies the plain (non-native-vpc) remote
// path is unchanged: metadata comes from the bare-IP lookup and the identity
// has no vpc label.
func TestEndpointResolverRemoteNoVNI(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.5")
	const datapathIdentity = uint32(21930)

	identityGetter := &testutils.FakeIdentityGetter{
		OnGetIdentity: func(secID uint32) (*identity.Identity, error) {
			return identity.NewIdentity(identity.NumericIdentity(datapathIdentity), labels.Labels{
				"k8s:app": labels.NewLabel("app", "web", labels.LabelSourceK8s),
			}), nil
		},
	}

	var vniLookupCalled bool
	ipGetter := &testutils.FakeIPGetter{
		OnGetK8sMetadata: func(ip netip.Addr) *ipcache.K8sMetadata {
			return &ipcache.K8sMetadata{Namespace: "ns-a", PodName: "pod-a"}
		},
		OnGetK8sMetadataForVNI: func(ip netip.Addr, vni uint32) *ipcache.K8sMetadata {
			vniLookupCalled = true
			return nil
		},
		OnLookupSecIDByIP: func(ip netip.Addr) (ipcache.Identity, bool) {
			return ipcache.Identity{ID: identity.NumericIdentity(datapathIdentity), Source: "kvstore"}, true
		},
	}

	resolver := NewEndpointResolver(hivetest.Logger(t), &testutils.NoopEndpointGetter, identityGetter, ipGetter)
	ep := resolver.ResolveEndpoint(ip, datapathIdentity, DatapathContext{})

	require.Equal(t, "ns-a", ep.Namespace)
	require.Equal(t, "pod-a", ep.PodName)
	require.False(t, vniLookupCalled, "VNI lookup must not be attempted when the plain metadata lookup succeeds")
}

// TestEndpointResolverVNIContextIsKeyExact verifies that when the datapath
// gives a VNI context (derived from the local endpoint that emitted the
// event), the remote peer is resolved key-exact under (VNI, IP): a foreign
// VPC or CIDR entry sitting under the bare IP must never win.
func TestEndpointResolverVNIContextIsKeyExact(t *testing.T) {
	ip := netip.MustParseAddr("192.168.1.2")
	const (
		vniIdentity   = uint32(21929) // the peer in VNI 36
		plainIdentity = uint32(21931) // a foreign/plain entry for the same IP
	)

	identityGetter := &testutils.FakeIdentityGetter{
		OnGetIdentity: func(secID uint32) (*identity.Identity, error) {
			return identity.NewIdentity(identity.NumericIdentity(secID), labels.Labels{
				labels.VNIKey: labels.NewLabel(labels.VNIKey, "36", labels.LabelSourceVNI),
			}), nil
		},
	}

	plainCalled := false
	ipGetter := &testutils.FakeIPGetter{
		OnLookupSecIDByIPForVNI: func(_ netip.Addr, vni uint32) (ipcache.Identity, bool) {
			require.Equal(t, uint32(36), vni)
			return ipcache.Identity{ID: identity.NumericIdentity(vniIdentity), Vni: 36}, true
		},
		OnLookupSecIDByIP: func(netip.Addr) (ipcache.Identity, bool) {
			plainCalled = true
			return ipcache.Identity{ID: identity.NumericIdentity(plainIdentity)}, true
		},
		OnGetK8sMetadataForVNI: func(_ netip.Addr, vni uint32) *ipcache.K8sMetadata {
			require.Equal(t, uint32(36), vni)
			return &ipcache.K8sMetadata{Namespace: "ns-a", PodName: "pod-a"}
		},
		OnGetK8sMetadata: func(netip.Addr) *ipcache.K8sMetadata {
			return &ipcache.K8sMetadata{Namespace: "foreign", PodName: "foreign"}
		},
	}

	resolver := NewEndpointResolver(hivetest.Logger(t), &testutils.NoopEndpointGetter, identityGetter, ipGetter)
	// datapathSecurityIdentity is unknown here, so the userspace (VNI-scoped)
	// identity is the one reported.
	ep := resolver.ResolveEndpoint(ip, uint32(identity.IdentityUnknown), DatapathContext{
		SrcIP:  ip,
		SrcVNI: 36,
		DstIP:  netip.MustParseAddr("192.168.1.3"),
		DstVNI: 36,
	})

	require.Equal(t, vniIdentity, ep.Identity)
	require.Equal(t, uint64(36), ep.VniId)
	require.Equal(t, "ns-a", ep.Namespace)
	require.Equal(t, "pod-a", ep.PodName)
	require.False(t, plainCalled, "the plain bare-IP identity lookup must not run once the VNI-scoped entry resolved")
}

// TestEndpointResolverVNIContextFallsBackToPlain verifies that a non-VPC peer
// (node, host, world) of a VPC endpoint is still resolved: the VNI-scoped
// lookup misses and the plain ipcache is the correct source for it.
func TestEndpointResolverVNIContextFallsBackToPlain(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.5")
	const plainIdentity = uint32(6) // remote-node like

	identityGetter := &testutils.FakeIdentityGetter{
		OnGetIdentity: func(secID uint32) (*identity.Identity, error) {
			return identity.NewIdentity(identity.NumericIdentity(secID), labels.Labels{
				"reserved:remote-node": labels.NewLabel("remote-node", "", labels.LabelSourceReserved),
			}), nil
		},
	}

	ipGetter := &testutils.FakeIPGetter{
		OnLookupSecIDByIPForVNI: func(netip.Addr, uint32) (ipcache.Identity, bool) {
			return ipcache.Identity{}, false
		},
		OnLookupSecIDByIP: func(netip.Addr) (ipcache.Identity, bool) {
			return ipcache.Identity{ID: identity.NumericIdentity(plainIdentity)}, true
		},
		OnGetK8sMetadataForVNI: func(netip.Addr, uint32) *ipcache.K8sMetadata {
			return nil
		},
		OnGetK8sMetadata: func(netip.Addr) *ipcache.K8sMetadata {
			return nil
		},
	}

	resolver := NewEndpointResolver(hivetest.Logger(t), &testutils.NoopEndpointGetter, identityGetter, ipGetter)
	ep := resolver.ResolveEndpoint(ip, uint32(identity.IdentityUnknown), DatapathContext{
		SrcIP:  netip.MustParseAddr("192.168.1.2"),
		SrcVNI: 36,
		DstIP:  ip,
		DstVNI: 36,
	})

	require.Equal(t, plainIdentity, ep.Identity)
	require.Zero(t, ep.VniId, "a non-VPC peer must not inherit the flow's VNI context")
}
