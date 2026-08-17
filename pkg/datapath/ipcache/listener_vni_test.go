// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tunnel"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheMap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/source"
)

// fakeMap records the keys/values written to a BPF map.
type fakeMap struct {
	updates []bpf.MapKey
	deletes []bpf.MapKey
}

func (f *fakeMap) Update(key bpf.MapKey, value bpf.MapValue) error {
	f.updates = append(f.updates, key)
	return nil
}
func (f *fakeMap) Delete(key bpf.MapKey) error {
	f.deletes = append(f.deletes, key)
	return nil
}

func newTestListener(t *testing.T) (*BPFListener, *fakeMap, *fakeMap) {
	v2 := &fakeMap{}
	vni := &fakeMap{}
	l := NewListener(v2, vni, nil, tunnel.Config{}, hivetest.Logger(t))
	return l, v2, vni
}

// TestBPFListenerVNIRouting verifies that ipcache entries with a non-zero VNI
// are written to the VNI-scoped map (keyed by VNI+IP) and entries without a
// VNI go to the plain ipcache map.
func TestBPFListenerVNIRouting(t *testing.T) {
	l, v2, vni := newTestListener(t)

	// Plain entry (VNI 0) -> v2 map with plain Key.
	prefix := cmtypes.MustParsePrefixCluster("192.168.1.2/32")
	l.OnIPIdentityCacheChange(ipcache.Upsert, prefix, nil, nil, nil, ipcache.Identity{
		ID:     21929,
		Source: source.CustomResource,
		Vni:    0,
	}, 0, nil, 0)
	require.Len(t, v2.updates, 1)
	require.Len(t, vni.updates, 0)
	_, ok := v2.updates[0].(*ipcacheMap.Key)
	require.True(t, ok, "plain entry must use ipcacheMap.Key")

	// Native-vpc entry (VNI 36) -> vni map with VniKey.
	l.OnIPIdentityCacheChange(ipcache.Upsert, prefix, nil, nil, nil, ipcache.Identity{
		ID:     21930,
		Source: source.CustomResource,
		Vni:    36,
	}, 0, nil, 0)
	require.Len(t, v2.updates, 1, "vni entry must not go to the v2 map")
	require.Len(t, vni.updates, 1)
	vk, ok := vni.updates[0].(*ipcacheMap.VniKey)
	require.True(t, ok, "vni entry must use ipcacheMap.VniKey")
	require.Equal(t, uint32(36), vk.Vni)

	// Delete of the VNI entry must hit the vni map with the same VNI key.
	l.OnIPIdentityCacheChange(ipcache.Delete, prefix, nil, nil, nil, ipcache.Identity{
		ID:     21930,
		Source: source.CustomResource,
		Vni:    36,
	}, 0, nil, 0)
	require.Len(t, vni.deletes, 1)
	vk, ok = vni.deletes[0].(*ipcacheMap.VniKey)
	require.True(t, ok)
	require.Equal(t, uint32(36), vk.Vni)
}

// TestBPFListenerDeleteUsesDeletedEntryVNI pins the cache->forwarding seam for
// deletions: the map is chosen by the VNI of the entry being removed, so
// deleting a VPC entry never touches the plain map (and vice versa), and two
// VPCs sharing an IP delete their own entry only.
func TestBPFListenerDeleteUsesDeletedEntryVNI(t *testing.T) {
	l, plain, vni := newTestListener(t)
	prefix := cmtypes.NewLocalPrefixCluster(netip.MustParsePrefix("10.16.32.10/32"))

	// Delete of a VPC entry -> VNI map only.
	l.OnIPIdentityCacheChange(ipcache.Delete, prefix, nil, nil, nil,
		ipcache.Identity{ID: 21929, Source: source.CustomResource, Vni: 36}, 0, nil, 0)
	require.Empty(t, plain.deletes)
	require.Len(t, vni.deletes, 1)
	require.Equal(t, "10.16.32.10/32@vni:36", vni.deletes[0].String())

	// Delete of the same IP in another VPC -> its own key.
	l.OnIPIdentityCacheChange(ipcache.Delete, prefix, nil, nil, nil,
		ipcache.Identity{ID: 21930, Source: source.CustomResource, Vni: 17}, 0, nil, 0)
	require.Len(t, vni.deletes, 2)
	require.Equal(t, "10.16.32.10/32@vni:17", vni.deletes[1].String())

	// Delete of a non-VPC entry -> plain map only.
	l.OnIPIdentityCacheChange(ipcache.Delete, prefix, nil, nil, nil,
		ipcache.Identity{ID: 6, Source: source.KubeAPIServer}, 0, nil, 0)
	require.Len(t, plain.deletes, 1)
	require.Len(t, vni.deletes, 2)
}
