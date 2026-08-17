// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
)

// TestLookupIPVNIEndpoints verifies the endpointmanager side of the native-vpc
// identity resolution chain: endpoints with a VNI register only VNI-scoped aux
// identifiers (vni-ipv4:<vni>:<ip>), and the bare-IP fallback used by the DNS
// proxy / Hubble / L7 accesslog resolves them when exactly one VNI uses the IP
// on this node, while overlapping IPs (several VNIs) stay a deliberate miss.
func TestLookupIPVNIEndpoints(t *testing.T) {
	s := setupEndpointManagerSuite(t)
	logger := hivetest.Logger(t)
	mgr := New(logger, nil, &dummyEpSyncher{}, nil, nil, nil, defaultEndpointManagerConfig)

	newEP := func(id int64, ip string, vni uint64) *endpoint.Endpoint {
		model := newTestEndpointModel(int(id), endpoint.StateReady)
		ep, err := endpoint.NewEndpointFromChangeModel(t.Context(), logger, nil, &endpoint.MockEndpointBuildQueue{}, nil, nil, nil, nil, nil, identitymanager.NewIDManager(logger), nil, nil, s.repo, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), ctmap.NewFakeGCRunner(), nil, model, fakeTypes.WireguardConfig{}, fakeTypes.IPsecConfig{}, nil, nil)
		require.NoError(t, err)
		ep.Start(uint16(model.ID))
		t.Cleanup(ep.Stop)
		ep.IPv4 = netip.MustParseAddr(ip)
		ep.VNIID = vni
		return ep
	}

	ip := "192.168.1.2"
	addr := netip.MustParseAddr(ip)

	// Generic (key-exact) lookups never resolve a VPC endpoint from a bare IP.
	// The explicit fallback does, as long as the IP is used by a single VNI.
	epA := newEP(10, ip, 36)
	require.NoError(t, mgr.expose(epA))
	require.Nil(t, mgr.LookupIPv4(ip), "generic bare-IP lookup must remain key-exact")
	require.Same(t, epA, mgr.LookupIPUnambiguous(addr), "single-VNI IP must resolve for bare-IP consumers")
	require.Same(t, epA, mgr.LookupIPWithVNI(addr, 36))

	// Second endpoint, same IP, different VNI: the bare-IP lookup is now
	// ambiguous and must miss (never guess a VNI).
	epB := newEP(11, ip, 17)
	require.NoError(t, mgr.expose(epB))
	require.Nil(t, mgr.LookupIPv4(ip), "overlapping IP across VNIs must not resolve")
	require.Nil(t, mgr.LookupIPUnambiguous(addr), "overlapping IP must fail closed")
	require.NotNil(t, mgr.LookupIPAnyVNI(addr), "in-use checks must still see the IP")

	// The VNI-scoped identifier lookups stay exact.
	gotA, err := mgr.Lookup("vni-ipv4:36:" + ip)
	require.NoError(t, err)
	require.Equal(t, epA, gotA)
	gotB, err := mgr.Lookup("vni-ipv4:17:" + ip)
	require.NoError(t, err)
	require.Equal(t, epB, gotB)

	// Removing one endpoint makes the IP unambiguous again.
	mgr.WaitEndpointRemoved(epA)
	require.Same(t, epB, mgr.LookupIPUnambiguous(addr))
	require.Same(t, epB, mgr.LookupIPWithVNI(addr, 17))

	// Removing the last one cleans the index entirely.
	mgr.WaitEndpointRemoved(epB)
	require.Nil(t, mgr.LookupIPv4(ip))
	require.Nil(t, mgr.LookupIPUnambiguous(addr))
	require.Nil(t, mgr.LookupIPAnyVNI(addr))
	require.Nil(t, mgr.LookupIPWithVNI(addr, 17))
}

// TestLookupIPVNIAndPlainMixed pins the plain/VNI mixed case: generic plain
// readers see only the plain namespace, while VNI readers must provide VNI.
func TestLookupIPVNIAndPlainMixed(t *testing.T) {
	s := setupEndpointManagerSuite(t)
	logger := hivetest.Logger(t)
	mgr := New(logger, nil, &dummyEpSyncher{}, nil, nil, nil, defaultEndpointManagerConfig)

	newEP := func(id int64, ip string, vni uint64) *endpoint.Endpoint {
		model := newTestEndpointModel(int(id), endpoint.StateReady)
		ep, err := endpoint.NewEndpointFromChangeModel(t.Context(), logger, nil, &endpoint.MockEndpointBuildQueue{}, nil, nil, nil, nil, nil, identitymanager.NewIDManager(logger), nil, nil, s.repo, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), ctmap.NewFakeGCRunner(), nil, model, fakeTypes.WireguardConfig{}, fakeTypes.IPsecConfig{}, nil, nil)
		require.NoError(t, err)
		ep.Start(uint16(model.ID))
		t.Cleanup(ep.Stop)
		ep.IPv4 = netip.MustParseAddr(ip)
		ep.VNIID = vni
		return ep
	}

	ip := "192.168.1.3"
	addr := netip.MustParseAddr(ip)
	plain := newEP(20, ip, 0)
	vpc := newEP(21, ip, 36)
	require.NoError(t, mgr.expose(plain))
	require.NoError(t, mgr.expose(vpc))

	require.Equal(t, plain, mgr.LookupIPUnambiguous(addr), "the plain entry wins over the VNI fallback")
	require.Same(t, vpc, mgr.LookupIPWithVNI(addr, 36), "the VNI endpoint requires explicit VNI context")

	mgr.WaitEndpointRemoved(plain)
	require.Same(t, vpc, mgr.LookupIPUnambiguous(addr), "single remaining VNI endpoint resolves")
	require.Same(t, vpc, mgr.LookupIPWithVNI(addr, 36))
	mgr.WaitEndpointRemoved(vpc)
}

func TestUpdateReferencesVNIReplacement(t *testing.T) {
	s := setupEndpointManagerSuite(t)
	logger := hivetest.Logger(t)
	mgr := New(logger, nil, &dummyEpSyncher{}, nil, nil, nil, defaultEndpointManagerConfig)
	model := newTestEndpointModel(30, endpoint.StateReady)
	ep, err := endpoint.NewEndpointFromChangeModel(t.Context(), logger, nil, &endpoint.MockEndpointBuildQueue{}, nil, nil, nil, nil, nil, identitymanager.NewIDManager(logger), nil, nil, s.repo, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), ctmap.NewFakeGCRunner(), nil, model, fakeTypes.WireguardConfig{}, fakeTypes.IPsecConfig{}, nil, nil)
	require.NoError(t, err)
	ep.Start(uint16(model.ID))
	t.Cleanup(ep.Stop)
	ep.IPv4 = netip.MustParseAddr("192.0.2.30")
	ep.VNIID = 36
	require.NoError(t, mgr.expose(ep))
	ep.VNIID = 17
	require.NoError(t, mgr.UpdateReferences(ep))
	old, err := mgr.Lookup("vni-ipv4:36:192.0.2.30")
	require.NoError(t, err)
	require.Nil(t, old)
	newEP, err := mgr.Lookup("vni-ipv4:17:192.0.2.30")
	require.NoError(t, err)
	require.Same(t, ep, newEP)
	mgr.WaitEndpointRemoved(ep)
}
