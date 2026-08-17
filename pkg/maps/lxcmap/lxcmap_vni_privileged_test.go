// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lxcmap

import (
	"net/netip"
	"os"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

// vniFrontend is the minimum an endpoint has to answer to be written into the
// endpoint map.
type vniFrontend struct {
	id   uint64
	ipv4 netip.Addr
	vni  uint64
}

func (f vniFrontend) LXCMac() mac.MAC                       { return mac.MAC{0, 1, 2, 3, 4, 5} }
func (f vniFrontend) GetNodeMAC() mac.MAC                   { return mac.MAC{6, 7, 8, 9, 10, 11} }
func (f vniFrontend) GetIfIndex() int                       { return 7 }
func (f vniFrontend) GetParentIfIndex() int                 { return 0 }
func (f vniFrontend) GetID() uint64                         { return f.id }
func (f vniFrontend) IPv4Address() netip.Addr               { return f.ipv4 }
func (f vniFrontend) IPv6Address() netip.Addr               { return netip.Addr{} }
func (f vniFrontend) GetIdentity() identity.NumericIdentity { return identity.NumericIdentity(1000) }
func (f vniFrontend) IsAtHostNS() bool                      { return false }
func (f vniFrontend) SkipMasqueradeV4() bool                { return false }
func (f vniFrontend) SkipMasqueradeV6() bool                { return false }
func (f vniFrontend) GetVNIID() uint64                      { return f.vni }

// setupVNITest builds an endpoint map of its own. It deliberately does not use
// the production name: that map is pinned, so a test opening it would be
// editing the endpoint map of an agent running on the same machine.
func setupVNITest(tb testing.TB) *lxcMap {
	testutils.PrivilegedTest(tb)
	bpf.CheckOrMountFS(hivetest.Logger(tb), "")
	require.NoError(tb, rlimit.RemoveMemlock())

	m := &lxcMap{bpfMap: bpf.NewMap(
		"test_"+mapName+"_"+strconv.Itoa(os.Getpid())+"_"+strconv.Itoa(int(testCounter.Add(1))),
		ebpf.Hash, &EndpointKey{}, &EndpointInfo{}, MaxEntries, 0,
	)}
	require.NoError(tb, m.bpfMap.CreateUnpinned())
	tb.Cleanup(func() { _ = m.bpfMap.Close() })
	return m
}

var testCounter atomic.Int32

func countEntries(tb testing.TB, m *lxcMap) int {
	entries, err := m.DumpToMap()
	require.NoError(tb, err)
	return len(entries)
}

// TestPrivilegedWriteEndpointVPCScope covers the rule that decides whether an
// endpoint belongs in this map at all.
//
// The key is the address with no room for a scope, so two endpoints that share
// an address in different VPCs would be one entry: the second CNI ADD would
// take over the first one's entry, and the first one's CNI DEL would then find
// an entry it does not own. An endpoint that is in a VPC therefore creates no
// entry here, which is also what the datapath assumes - it consults this map
// only for endpoints whose compiled VNI is zero.
func TestPrivilegedWriteEndpointVPCScope(t *testing.T) {
	addr := netip.MustParseAddr("10.99.0.12")

	t.Run("an endpoint outside any VPC is represented", func(t *testing.T) {
		m := setupVNITest(t)
		require.NoError(t, m.WriteEndpoint(vniFrontend{id: 1, ipv4: addr}))
		require.Equal(t, 1, countEntries(t, m))

		require.Empty(t, m.DeleteElement(hivetest.Logger(t), vniFrontend{id: 1, ipv4: addr}))
		require.Zero(t, countEntries(t, m))
	})

	t.Run("endpoints sharing an address in different VPCs create nothing", func(t *testing.T) {
		prev := option.Config.EnableNativeVPC
		option.Config.EnableNativeVPC = true
		t.Cleanup(func() { option.Config.EnableNativeVPC = prev })
		m := setupVNITest(t)
		for _, vni := range []uint64{5, 7, 9} {
			require.NoError(t, m.WriteEndpoint(vniFrontend{id: vni, ipv4: addr, vni: vni}))
		}
		require.Zero(t, countEntries(t, m),
			"any entry would answer for whichever endpoint happened to write last")

		// And a CNI DEL of one of them cannot affect the others.
		require.Empty(t, m.DeleteElement(hivetest.Logger(t), vniFrontend{id: 7, ipv4: addr, vni: 7}))
		require.Zero(t, countEntries(t, m))
	})

	t.Run("an entry left by an older agent is reclaimed by its owner", func(t *testing.T) {
		m := setupVNITest(t)
		require.NoError(t, m.WriteEndpoint(vniFrontend{id: 42, ipv4: addr}))
		require.Equal(t, 1, countEntries(t, m))

		// The same endpoint, now known to be in a VPC.
		require.NoError(t, m.WriteEndpoint(vniFrontend{id: 42, ipv4: addr, vni: 5}))
		require.Zero(t, countEntries(t, m))
	})

	t.Run("an entry owned by another endpoint is left alone", func(t *testing.T) {
		m := setupVNITest(t)
		require.NoError(t, m.WriteEndpoint(vniFrontend{id: 42, ipv4: addr}))

		require.NoError(t, m.WriteEndpoint(vniFrontend{id: 43, ipv4: addr, vni: 5}))
		require.Equal(t, 1, countEntries(t, m),
			"endpoint 43 must not remove the entry endpoint 42 owns")
	})
}
