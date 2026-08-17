// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"context"
	"net"
	"net/netip"
	"path"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/source"
)

// TestIPIdentitySynchronizerLocalFallbackVNI verifies that, when the kvstore
// is disabled (CRD-only identity mode), the synchronizer registers the
// endpoint mapping directly in the local ipcache keyed by IP+VNI, so that
// native-vpc endpoints are resolvable by the datapath even without a kvstore.
func TestIPIdentitySynchronizerLocalFallbackVNI(t *testing.T) {
	client := kvstore.SetupDummy(t, kvstore.DisabledBackendName)
	ipc := newLocalIPCacheSpy()
	sync := NewIPIdentitySynchronizer(nil, client, ipc)

	ip := netip.MustParseAddr("192.168.1.2")
	hostIP := netip.MustParseAddr("10.58.55.23")
	err := sync.Upsert(t.Context(), &UpsertParams{
		IP:           ip,
		HostIP:       hostIP,
		ID:           identity.NumericIdentity(21929),
		K8sNamespace: "vm-a",
		K8sPodName:   "pod-a",
		Vni:          36,
	})
	require.NoError(t, err)

	// The local ipcache must have received the VNI-encoded key with the VNI set.
	require.Len(t, ipc.upserts, 1)
	require.Equal(t, KeyWithVNI("192.168.1.2", 36), ipc.upserts[0].key)
	require.Equal(t, uint32(36), ipc.upserts[0].id.Vni)
	require.Equal(t, source.Local, ipc.upserts[0].id.Source)

	// Delete must remove the same VNI-encoded key.
	err = sync.Delete(t.Context(), "192.168.1.2", 36)
	require.NoError(t, err)
	require.Len(t, ipc.deletes, 1)
	require.Equal(t, KeyWithVNI("192.168.1.2", 36), ipc.deletes[0])
}

// TestIPIdentitySynchronizerKVStoreVNI verifies the kvstore-enabled path: the
// mapping is written under a VNI-scoped kvstore key and the pair carries the
// VNI, so the watcher can re-insert it into the ipcache keyed by IP+VNI (the
// previous behavior dropped the VNI and registered a plain-IP entry, which
// collided with overlapping VPC subnets).
func TestIPIdentitySynchronizerKVStoreVNI(t *testing.T) {
	client := &fakeKVStoreClient{enabled: true, store: map[string][]byte{}}
	sync := NewIPIdentitySynchronizer(hivetest.Logger(t), client, nil)

	ip := netip.MustParseAddr("192.168.1.2")
	hostIP := netip.MustParseAddr("10.58.55.23")
	err := sync.Upsert(t.Context(), &UpsertParams{
		IP:           ip,
		HostIP:       hostIP,
		ID:           identity.NumericIdentity(21929),
		K8sNamespace: "vm-a",
		K8sPodName:   "pod-a",
		Vni:          36,
	})
	require.NoError(t, err)

	// The kvstore key must be VNI-scoped so the same IP in a different VPC
	// does not overwrite it.
	ipKey := path.Join(IPIdentitiesPath, AddressSpace, KeyWithVNI("192.168.1.2", 36))
	val, ok := client.store[ipKey]
	require.True(t, ok, "mapping must be stored under the VNI-scoped key")

	pair := &identity.IPIdentityPair{}
	require.NoError(t, pair.Unmarshal(KeyWithVNI("192.168.1.2", 36), val))
	require.Equal(t, uint64(36), pair.Vni)

	// Deleting with the wrong VNI must not remove the entry (same IP, other VPC).
	require.NoError(t, sync.Delete(t.Context(), "192.168.1.2", 17))
	_, ok = client.store[ipKey]
	require.True(t, ok, "entry of VPC 36 must survive deletion of VPC 17")

	// Deleting with the right VNI removes it.
	require.NoError(t, sync.Delete(t.Context(), "192.168.1.2", 36))
	_, ok = client.store[ipKey]
	require.False(t, ok, "entry of VPC 36 must be removed by its own deletion")
}

// fakeKVStoreClient is a minimal in-memory kvstore.Client for tests. It embeds
// the (nil) BackendOperations interface to satisfy the type; only the methods
// exercised by IPIdentitySynchronizer are overridden.
type fakeKVStoreClient struct {
	kvstore.BackendOperations
	enabled bool
	store   map[string][]byte
}

func (f *fakeKVStoreClient) IsEnabled() bool { return f.enabled }

func (f *fakeKVStoreClient) UpdateIfDifferent(ctx context.Context, key string, value []byte, lease bool) (bool, error) {
	f.store[key] = value
	return true, nil
}

func (f *fakeKVStoreClient) Delete(ctx context.Context, key string) error {
	delete(f.store, key)
	return nil
}

// localIPCacheSpy records the Upsert/Delete calls for the local fallback path.
type localIPCacheSpy struct {
	upserts []struct {
		key string
		id  Identity
	}
	deletes []string
}

func newLocalIPCacheSpy() *localIPCacheSpy { return &localIPCacheSpy{} }

func (s *localIPCacheSpy) Upsert(ip string, hostIP net.IP, hostKey uint8, k8sMeta *K8sMetadata, newIdentity Identity) (bool, error) {
	s.upserts = append(s.upserts, struct {
		key string
		id  Identity
	}{ip, newIdentity})
	return false, nil
}

func (s *localIPCacheSpy) Delete(IP string, src source.Source) bool {
	s.deletes = append(s.deletes, IP)
	return true
}
