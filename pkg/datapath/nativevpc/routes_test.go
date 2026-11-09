// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nativevpc

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/k8s/resource"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
)

func subnetObject(name, vpc, cidrs string, vni int64) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": name},
		"spec":     map[string]any{"vpc": vpc, "cidrBlock": cidrs},
		"status":   map[string]any{"tunnelKey": vni},
	}}
}

func routeKey(cidr string, vni uint32) ipcachemap.VniKey {
	ip, prefix, _ := net.ParseCIDR(cidr)
	return ipcachemap.NewVniKey(ip, prefix.Mask, vni)
}

func TestPeerRoutes(t *testing.T) {
	a := subnetObject("a", "vpc-a", "10.0.0.0/24,fd00::/64", 58)
	b := subnetObject("b", "vpc-a", "10.0.8.0/24,fd00:8::/64", 54)
	// Another VPC may reuse either subnet's addresses, but never its identity.
	foreign := subnetObject("foreign", "vpc-b", "10.0.8.0/24,fd00:8::/64", 99)
	pending := subnetObject("pending", "vpc-a", "10.0.9.0/24", 0)
	routes, err := peerRoutes([]*unstructured.Unstructured{a, b, foreign, pending})
	require.NoError(t, err)
	require.Equal(t, map[ipcachemap.VniKey]routeValue{
		routeKey("10.0.8.0/24", 58): {VNI: 54},
		routeKey("fd00:8::/64", 58): {VNI: 54},
		routeKey("10.0.0.0/24", 54): {VNI: 58},
		routeKey("fd00::/64", 54):   {VNI: 58},
	}, routes)

	for _, tc := range []struct {
		name string
		bad  *unstructured.Unstructured
	}{
		{"overlap", subnetObject("overlap", "vpc-a", "10.0.0.0/25", 60)},
		{"duplicate VNI", subnetObject("duplicate", "vpc-b", "10.1.0.0/24", 58)},
		{"out of range", subnetObject("large", "vpc-a", "10.1.0.0/24", 1<<24)},
		{"negative VNI", subnetObject("negative", "vpc-a", "10.1.0.0/24", -1)},
		{"invalid CIDR", subnetObject("invalid", "vpc-a", "not-a-cidr", 60)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			routes, err := peerRoutes([]*unstructured.Unstructured{a, b, tc.bad})
			require.Error(t, err)
			require.Empty(t, routes)
		})
	}
}

type fakeRouteMap struct {
	entries    map[ipcachemap.VniKey]routeValue
	failDelete bool
	failUpdate bool
}

func (m *fakeRouteMap) Update(key bpf.MapKey, value bpf.MapValue) error {
	if m.failUpdate {
		return errors.New("update failed")
	}
	m.entries[*key.(*ipcachemap.VniKey)] = *value.(*routeValue)
	return nil
}

func (m *fakeRouteMap) Delete(key bpf.MapKey) error {
	if m.failDelete {
		return errors.New("delete failed")
	}
	delete(m.entries, *key.(*ipcachemap.VniKey))
	return nil
}

func TestPeerRoutesKeepsHealthyVPCWhenAnotherVPCIsInvalid(t *testing.T) {
	healthyA := subnetObject("healthy-a", "vpc-a", "10.0.0.0/24", 58)
	healthyB := subnetObject("healthy-b", "vpc-a", "10.0.8.0/24", 54)
	invalid := subnetObject("invalid", "vpc-b", "broken", 99)

	routes, err := peerRoutes([]*unstructured.Unstructured{healthyA, healthyB, invalid})
	require.Error(t, err)
	require.Len(t, routes, 2)
	require.Equal(t, routeValue{VNI: 54}, routes[routeKey("10.0.8.0/24", 58)])
	require.Equal(t, routeValue{VNI: 58}, routes[routeKey("10.0.0.0/24", 54)])
}

func TestSyncRoutesMixedVPCs(t *testing.T) {
	a := subnetObject("a", "healthy", "10.0.0.0/24", 58)
	b := subnetObject("b", "healthy", "10.0.8.0/24", 54)
	bad := subnetObject("bad", "invalid", "broken", 99)
	m := &fakeRouteMap{entries: map[ipcachemap.VniKey]routeValue{}}
	installed := map[ipcachemap.VniKey]routeValue{}

	// Startup and subsequent additions must apply healthy routes despite errors elsewhere.
	require.Error(t, syncRoutes(m, installed, []*unstructured.Unstructured{a, b, bad}))
	require.Len(t, m.entries, 2)
	c := subnetObject("c", "healthy", "10.0.9.0/24", 60)
	require.Error(t, syncRoutes(m, installed, []*unstructured.Unstructured{a, b, c, bad}))
	require.Len(t, m.entries, 6)
	require.Equal(t, routeValue{VNI: 60}, m.entries[routeKey("10.0.9.0/24", 58)])
	require.NoError(t, unstructured.SetNestedField(bad.Object, "10.1.0.0/24", "spec", "cidrBlock"))
	require.NoError(t, syncRoutes(m, installed, []*unstructured.Unstructured{a, b, c, bad}))
	require.Len(t, m.entries, 6)
}

// Embed the unused store methods; List changes snapshots between calls to model informer updates.
type snapshotStore struct {
	resource.Store[*unstructured.Unstructured]
	snapshots [][]*unstructured.Unstructured
	calls     int
}

func (s *snapshotStore) List() []*unstructured.Unstructured {
	i := min(s.calls, len(s.snapshots)-1)
	s.calls++
	return s.snapshots[i]
}

func TestSyncTopologyUsesOneSnapshot(t *testing.T) {
	a := subnetObject("a", "vpc", "10.0.0.0/24", 58)
	b := subnetObject("b", "vpc", "10.0.8.0/24", 54)
	store := &snapshotStore{snapshots: [][]*unstructured.Unstructured{{a, b}, {a}}}
	m := &fakeRouteMap{entries: map[ipcachemap.VniKey]routeValue{}}
	installed := map[ipcachemap.VniKey]routeValue{}
	key := ""
	require.NoError(t, syncTopology(m, installed, &key, store))
	require.Equal(t, 1, store.calls)
	require.Len(t, m.entries, 2)
	require.Equal(t, subnetTopologyKey([]*unstructured.Unstructured{a, b}), key)
	require.NoError(t, syncTopology(m, installed, &key, store))
	require.Empty(t, m.entries)
}

func TestSyncTopologyRetriesEmptyTopology(t *testing.T) {
	a := subnetObject("a", "vpc", "10.0.0.0/24", 58)
	b := subnetObject("b", "vpc", "10.0.8.0/24", 54)
	store := &snapshotStore{snapshots: [][]*unstructured.Unstructured{{a, b}}}
	m := &fakeRouteMap{entries: map[ipcachemap.VniKey]routeValue{}}
	installed := map[ipcachemap.VniKey]routeValue{}
	key := ""
	require.NoError(t, syncTopology(m, installed, &key, store))
	require.Len(t, installed, 2)

	store.snapshots = [][]*unstructured.Unstructured{nil}
	m.failDelete = true
	require.Error(t, syncTopology(m, installed, &key, store))
	require.Empty(t, key)
	require.Len(t, m.entries, 2)
	m.failDelete = false
	require.NoError(t, syncTopology(m, installed, &key, store))
	require.Empty(t, m.entries)
	require.Empty(t, installed)
	// A subsequent empty snapshot must also converge without errors.
	require.NoError(t, syncTopology(m, installed, &key, store))
}

func TestSyncTopologyRestoresAfterFailure(t *testing.T) {
	for _, failure := range []string{"invalid topology", "delete", "update"} {
		t.Run(failure, func(t *testing.T) {
			a := subnetObject("a", "vpc", "10.0.0.0/24", 58)
			b := subnetObject("b", "vpc", "10.0.8.0/24", 54)
			original := []*unstructured.Unstructured{a, b}
			store := &snapshotStore{snapshots: [][]*unstructured.Unstructured{original}}
			m := &fakeRouteMap{entries: map[ipcachemap.VniKey]routeValue{}}
			installed := map[ipcachemap.VniKey]routeValue{}
			key := ""
			require.NoError(t, syncTopology(m, installed, &key, store))
			changed := b.DeepCopy()
			cidr := "10.0.9.0/24"
			if failure == "invalid topology" {
				cidr = "10.0.0.0/25"
			}
			require.NoError(t, unstructured.SetNestedField(changed.Object, cidr, "spec", "cidrBlock"))
			store.snapshots = [][]*unstructured.Unstructured{{a, changed}}
			m.failDelete = failure == "delete"
			m.failUpdate = failure == "update"
			require.Error(t, syncTopology(m, installed, &key, store))
			require.Empty(t, key)
			m.failDelete, m.failUpdate = false, false
			store.snapshots = [][]*unstructured.Unstructured{original}
			require.NoError(t, syncTopology(m, installed, &key, store))
			require.Len(t, m.entries, 2)
			require.Equal(t, routeValue{VNI: 54}, m.entries[routeKey("10.0.8.0/24", 58)])
		})
	}
}

func TestSyncRoutes(t *testing.T) {
	a := subnetObject("a", "vpc-a", "10.0.0.0/24", 58)
	b := subnetObject("b", "vpc-a", "10.0.8.0/24", 54)
	objects := []*unstructured.Unstructured{a, b}
	m := &fakeRouteMap{entries: map[ipcachemap.VniKey]routeValue{}}
	installed := map[ipcachemap.VniKey]routeValue{}

	m.failUpdate = true
	require.Error(t, syncRoutes(m, installed, objects))
	require.Empty(t, installed)
	m.failUpdate = false
	require.NoError(t, syncRoutes(m, installed, objects))
	require.Len(t, m.entries, 2)

	// Moving a subnet to another VPC revokes both directions before any additions.
	require.NoError(t, unstructured.SetNestedField(b.Object, "vpc-b", "spec", "vpc"))
	m.failDelete = true
	require.Error(t, syncRoutes(m, installed, objects))
	require.Len(t, installed, 2, "failed deletes must remain queued for retry")
	m.failDelete = false
	require.NoError(t, syncRoutes(m, installed, objects))
	require.Empty(t, m.entries)
	require.Empty(t, installed)

	// Restoration, ambiguous metadata, then deletion must not leave stale routes.
	require.NoError(t, unstructured.SetNestedField(b.Object, "vpc-a", "spec", "vpc"))
	require.NoError(t, syncRoutes(m, installed, objects))
	require.NoError(t, unstructured.SetNestedField(b.Object, "10.0.0.0/25", "spec", "cidrBlock"))
	require.Error(t, syncRoutes(m, installed, objects))
	require.Empty(t, m.entries)
	require.NoError(t, syncRoutes(m, installed, []*unstructured.Unstructured{a}))
	require.Empty(t, installed)
}
