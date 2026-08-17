// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

func TestKeyWithVNIRoundtrip(t *testing.T) {
	for _, tc := range []struct {
		ip   string
		vni  uint32
		want string
	}{
		{"192.168.1.2", 0, "192.168.1.2"},
		{"192.168.1.2", 36, "192.168.1.2@vni:36"},
		{"10.0.0.0/24", 17, "10.0.0.0/24@vni:17"},
		{"192.168.1.2@1", 10, "192.168.1.2@1@vni:10"}, // clusterID suffix + VNI suffix
	} {
		key := KeyWithVNI(tc.ip, tc.vni)
		require.Equal(t, tc.want, key)

		plain, vni := splitVNIKey(key)
		require.Equal(t, tc.ip, plain)
		require.Equal(t, tc.vni, vni)
	}

	// A key without the VNI suffix yields vni 0.
	plain, vni := splitVNIKey("192.168.1.2")
	require.Equal(t, "192.168.1.2", plain)
	require.Zero(t, vni)
}

// TestIPCacheVNICoexistence verifies that the same IP in two different VPCs
// (different VNI) maps to two distinct ipcache entries, and that each entry
// carries its own identity and VNI. This is the core fix for overlapping VPC
// subnets.
func TestIPCacheVNICoexistence(t *testing.T) {
	s := setupIPCacheTestSuite(t)

	endpointIP := "192.168.1.2"
	// Same IP in VPC A (vni 36) and VPC B (vni 17) with different identities.
	idA := identity.NumericIdentity(21929)
	idB := identity.NumericIdentity(21930)

	_, err := s.IPIdentityCache.Upsert(KeyWithVNI(endpointIP, 36), nil, 0, nil, Identity{
		ID:     idA,
		Source: source.CustomResource,
		Vni:    36,
	})
	require.NoError(t, err)
	_, err = s.IPIdentityCache.Upsert(KeyWithVNI(endpointIP, 17), nil, 0, nil, Identity{
		ID:     idB,
		Source: source.CustomResource,
		Vni:    17,
	})
	require.NoError(t, err)

	// Both entries coexist.
	require.Len(t, s.IPIdentityCache.ipToIdentityCache, 2)

	// Lookup each VPC-scoped entry.
	ia, ok := s.IPIdentityCache.LookupByIP(KeyWithVNI(endpointIP, 36))
	require.True(t, ok)
	require.Equal(t, idA, ia.ID)
	require.Equal(t, uint32(36), ia.Vni)

	ib, ok := s.IPIdentityCache.LookupByIP(KeyWithVNI(endpointIP, 17))
	require.True(t, ok)
	require.Equal(t, idB, ib.ID)
	require.Equal(t, uint32(17), ib.Vni)

	// The reverse identity->IP index contains both encoded keys.
	require.Contains(t, s.IPIdentityCache.identityToIPCache[idA], KeyWithVNI(endpointIP, 36))
	require.Contains(t, s.IPIdentityCache.identityToIPCache[idB], KeyWithVNI(endpointIP, 17))

	// Deleting one VPC's entry must not remove the other.
	s.IPIdentityCache.Delete(KeyWithVNI(endpointIP, 36), source.CustomResource)
	_, ok = s.IPIdentityCache.LookupByIP(KeyWithVNI(endpointIP, 36))
	require.False(t, ok)
	ib, ok = s.IPIdentityCache.LookupByIP(KeyWithVNI(endpointIP, 17))
	require.True(t, ok)
	require.Equal(t, idB, ib.ID)
	require.Len(t, s.IPIdentityCache.ipToIdentityCache, 1)
}

// TestIPCacheVNIMetadataListener verifies that the ipcache listener observes
// the VNI on upsert and delete for native-vpc entries.
func TestIPCacheVNIMetadataListener(t *testing.T) {
	s := setupIPCacheTestSuite(t)

	listener := &mockIPCacheListener{t: t}
	s.IPIdentityCache.AddListener(listener)

	endpointIP := "192.168.1.3"
	idA := identity.NumericIdentity(7979)
	_, err := s.IPIdentityCache.Upsert(KeyWithVNI(endpointIP, 36), nil, 0, nil, Identity{
		ID:     idA,
		Source: source.CustomResource,
		Vni:    36,
	})
	require.NoError(t, err)

	require.Len(t, listener.upserts, 1)
	require.Equal(t, uint32(36), listener.upserts[0].vni)
	require.Equal(t, idA, listener.upserts[0].id)

	s.IPIdentityCache.Delete(KeyWithVNI(endpointIP, 36), source.CustomResource)
	require.Len(t, listener.deletes, 1)
	require.Equal(t, uint32(36), listener.deletes[0].vni)
}

type ipCacheEvent struct {
	id  identity.NumericIdentity
	vni uint32
}

type mockIPCacheListener struct {
	t       *testing.T
	upserts []ipCacheEvent
	deletes []ipCacheEvent
}

func (m *mockIPCacheListener) OnIPIdentityCacheChange(modType CacheModification, cidrCluster cmtypes.PrefixCluster,
	oldHostIP, newHostIP net.IP, oldID *Identity, newID Identity, encryptKey uint8, k8sMeta *K8sMetadata, endpointFlags uint8) {
	m.t.Helper()
	ev := ipCacheEvent{id: newID.ID, vni: newID.Vni}
	switch modType {
	case Upsert:
		m.upserts = append(m.upserts, ev)
	case Delete:
		m.deletes = append(m.deletes, ev)
	}
}

// TestIPCacheVNIPureIPLookup verifies that generic bare-IP lookups remain
// key-exact, while the explicit best-effort helpers resolve a VNI-scoped entry
// when exactly one VPC uses the IP (L7 accesslog / DNS proxy), and report a
// miss when several VPCs overlap rather than guessing a VPC.
func TestIPCacheVNIPureIPLookup(t *testing.T) {
	s := setupIPCacheTestSuite(t)

	endpointIP := "192.168.1.2"
	idA := identity.NumericIdentity(21929)
	idB := identity.NumericIdentity(21930)

	// Single VNI entry: bare-IP lookups resolve it.
	_, err := s.IPIdentityCache.Upsert(KeyWithVNI(endpointIP, 36), nil, 0, &K8sMetadata{Namespace: "ns-a", PodName: "pod-a"}, Identity{
		ID:     idA,
		Source: source.CustomResource,
		Vni:    36,
	})
	require.NoError(t, err)

	_, ok := s.IPIdentityCache.LookupByIP(endpointIP)
	require.False(t, ok, "generic bare-IP lookup must remain key-exact")
	require.Nil(t, s.IPIdentityCache.GetK8sMetadata(netip.MustParseAddr(endpointIP)),
		"generic metadata lookup must remain key-exact")

	got, ok := s.IPIdentityCache.LookupSecIDByIPUnambiguous(netip.MustParseAddr(endpointIP))
	require.True(t, ok, "explicit best-effort lookup must resolve the single VNI-scoped entry")
	require.Equal(t, idA, got.ID)
	require.Equal(t, uint32(36), got.Vni)

	meta := s.IPIdentityCache.GetK8sMetadataUnambiguous(netip.MustParseAddr(endpointIP))
	require.NotNil(t, meta)
	require.Equal(t, "pod-a", meta.PodName)

	// Second VPC uses the same IP: the bare-IP lookup must now miss (ambiguous),
	// while the VNI-scoped lookups still work.
	_, err = s.IPIdentityCache.Upsert(KeyWithVNI(endpointIP, 17), nil, 0, &K8sMetadata{Namespace: "ns-b", PodName: "pod-b"}, Identity{
		ID:     idB,
		Source: source.CustomResource,
		Vni:    17,
	})
	require.NoError(t, err)

	_, ok = s.IPIdentityCache.LookupSecIDByIPUnambiguous(netip.MustParseAddr(endpointIP))
	require.False(t, ok, "overlapping IPs must stay ambiguous for the explicit best-effort lookup")

	// Removing one VPC restores unambiguous best-effort resolution, while the
	// generic lookup remains key-exact.
	s.IPIdentityCache.Delete(KeyWithVNI(endpointIP, 17), source.CustomResource)
	got, ok = s.IPIdentityCache.LookupSecIDByIPUnambiguous(netip.MustParseAddr(endpointIP))
	require.True(t, ok)
	require.Equal(t, idA, got.ID)
	_, ok = s.IPIdentityCache.LookupByIP(endpointIP)
	require.False(t, ok)
}

// TestIPCachePlainAndVNIEntryIsolation verifies the M1 regression case: a
// plain entry and a VNI-scoped entry may share the same IP, and deleting the
// plain entry must never read the VNI entry's metadata or remove its named
// ports.
func TestIPCachePlainAndVNIEntryIsolation(t *testing.T) {
	s := setupIPCacheTestSuite(t)
	endpointIP := "192.168.1.2"

	plainPorts := types.NamedPortMap{
		"plain": {Port: 80, Proto: u8proto.TCP},
	}
	vpcPorts := types.NamedPortMap{
		"vpc": {Port: 81, Proto: u8proto.TCP},
	}

	_, err := s.IPIdentityCache.Upsert(endpointIP, nil, 0,
		&K8sMetadata{Namespace: "native", PodName: "plain", NamedPorts: plainPorts},
		Identity{ID: identity.NumericIdentity(21928), Source: source.CustomResource})
	require.NoError(t, err)
	_, err = s.IPIdentityCache.Upsert(KeyWithVNI(endpointIP, 36), nil, 0,
		&K8sMetadata{Namespace: "vpc", PodName: "vpc", NamedPorts: vpcPorts},
		Identity{ID: identity.NumericIdentity(21929), Source: source.CustomResource, Vni: 36})
	require.NoError(t, err)

	npm := s.IPIdentityCache.GetNamedPorts()
	require.Equal(t, 2, npm.Len())

	s.IPIdentityCache.Delete(endpointIP, source.CustomResource)

	// VNI-scoped identity/metadata and named port remain intact.
	id, ok := s.IPIdentityCache.LookupByIP(KeyWithVNI(endpointIP, 36))
	require.True(t, ok)
	require.Equal(t, identity.NumericIdentity(21929), id.ID)
	meta := s.IPIdentityCache.GetK8sMetadataForVNI(netip.MustParseAddr(endpointIP), 36)
	require.NotNil(t, meta)
	require.Equal(t, "vpc", meta.PodName)
	_, err = npm.GetNamedPort("plain", u8proto.TCP)
	require.Error(t, err)
	port, err := npm.GetNamedPort("vpc", u8proto.TCP)
	require.NoError(t, err)
	require.Equal(t, uint16(81), port)
}

// TestLookupSecIDByIPForVNI verifies the key-exact (VNI, IP) identity lookup
// used by the Hubble parsers: it must never resolve a plain entry, a foreign
// VPC entry, or a shorter prefix for the same IP.
func TestLookupSecIDByIPForVNI(t *testing.T) {
	s := setupIPCacheTestSuite(t)
	ip := "192.168.1.2"
	addr := netip.MustParseAddr(ip)

	_, err := s.IPIdentityCache.Upsert(KeyWithVNI(ip, 36), nil, 0, nil, Identity{
		ID: identity.NumericIdentity(21929), Source: source.CustomResource, Vni: 36,
	})
	require.NoError(t, err)
	_, err = s.IPIdentityCache.Upsert(KeyWithVNI(ip, 17), nil, 0, nil, Identity{
		ID: identity.NumericIdentity(21930), Source: source.CustomResource, Vni: 17,
	})
	require.NoError(t, err)

	got, ok := s.IPIdentityCache.LookupSecIDByIPForVNI(addr, 36)
	require.True(t, ok)
	require.Equal(t, identity.NumericIdentity(21929), got.ID)
	require.Equal(t, uint32(36), got.Vni)

	got, ok = s.IPIdentityCache.LookupSecIDByIPForVNI(addr, 17)
	require.True(t, ok)
	require.Equal(t, identity.NumericIdentity(21930), got.ID)

	// A VPC that does not use the IP must miss, even though a plain /24 entry
	// covering it exists (LPM fallbacks are not allowed here).
	_, err = s.IPIdentityCache.Upsert("192.168.1.0/24", nil, 0, nil, Identity{
		ID: identity.NumericIdentity(21931), Source: source.Generated,
	})
	require.NoError(t, err)
	_, ok = s.IPIdentityCache.LookupSecIDByIPForVNI(addr, 99)
	require.False(t, ok)

	// A zero VNI is not a VPC scope.
	_, ok = s.IPIdentityCache.LookupSecIDByIPForVNI(addr, 0)
	require.False(t, ok)
}

// TestDumpToListenerVNI is a regression test for the full-dump path: the
// ipcache API handler and the BPF listener registration both dump every entry,
// and native-vpc keys ("<ip>@vni:<vni>") are not parsable as a prefix. The
// dump must not panic, must report the plain prefix, and must carry the VNI in
// the identity so listeners route the entry to the VNI-scoped map.
func TestDumpToListenerVNI(t *testing.T) {
	s := setupIPCacheTestSuite(t)

	_, err := s.IPIdentityCache.Upsert(KeyWithVNI("192.168.1.2", 36), nil, 0, nil, Identity{
		ID: identity.NumericIdentity(21929), Source: source.CustomResource, Vni: 36,
	})
	require.NoError(t, err)
	_, err = s.IPIdentityCache.Upsert(KeyWithVNI("192.168.1.2", 17), nil, 0, nil, Identity{
		ID: identity.NumericIdentity(21930), Source: source.CustomResource, Vni: 17,
	})
	require.NoError(t, err)
	_, err = s.IPIdentityCache.Upsert("10.0.0.1", nil, 0, nil, Identity{
		ID: identity.NumericIdentity(21931), Source: source.KubeAPIServer,
	})
	require.NoError(t, err)

	l := &dumpCollector{}
	require.NotPanics(t, func() { s.IPIdentityCache.DumpToListener(l) })

	require.Equal(t, map[string]uint32{
		"192.168.1.2/32@36": 36,
		"192.168.1.2/32@17": 17,
		"10.0.0.1/32@0":     0,
	}, l.seen)
}

type dumpCollector struct {
	seen map[string]uint32
}

func (d *dumpCollector) OnIPIdentityCacheChange(_ CacheModification, cidr cmtypes.PrefixCluster,
	_, _ net.IP, _ *Identity, newID Identity, _ uint8, _ *K8sMetadata, _ uint8,
) {
	if d.seen == nil {
		d.seen = map[string]uint32{}
	}
	d.seen[fmt.Sprintf("%s@%d", cidr.String(), newID.Vni)] = newID.Vni
}

// TestLookupByIdentityAndHostStripVNI verifies that the two ipcache readers
// which return raw key strings (DNS rule restoration and the WireGuard
// AllowedIPs list) never leak the internal "<ip>@vni:<vni>" key: their
// consumers parse the result as an address and would drop the entry.
func TestLookupByIdentityAndHostStripVNI(t *testing.T) {
	s := setupIPCacheTestSuite(t)
	id := identity.NumericIdentity(21929)
	hostIP := net.ParseIP("10.58.55.23")

	_, err := s.IPIdentityCache.Upsert(KeyWithVNI("192.168.1.2", 36), hostIP, 0, nil, Identity{
		ID: id, Source: source.CustomResource, Vni: 36,
	})
	require.NoError(t, err)

	require.Equal(t, []string{"192.168.1.2"}, s.IPIdentityCache.LookupByIdentity(id))

	s.IPIdentityCache.mutex.RLock()
	cidrs := s.IPIdentityCache.LookupByHostRLocked(hostIP, nil)
	s.IPIdentityCache.mutex.RUnlock()
	require.Len(t, cidrs, 1)
	require.Equal(t, "192.168.1.2/32", cidrs[0].String())
}
