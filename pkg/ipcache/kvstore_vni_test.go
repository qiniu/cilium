// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"context"
	"net"
	"net/netip"
	"path"
	"strconv"
	"strings"
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
	sync := newIPIdentitySynchronizer(nil, client, ipc)

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
	err = sync.Delete(t.Context(), "192.168.1.2", 36, "ns", "pod", 1)
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
	sync := newIPIdentitySynchronizer(hivetest.Logger(t), client, nil)

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
	require.NoError(t, sync.Delete(t.Context(), "192.168.1.2", 17, "ns", "pod", 1))
	_, ok = client.store[ipKey]
	require.True(t, ok, "entry of VPC 36 must survive deletion of VPC 17")

	// Deleting with the right VNI removes it.
	require.NoError(t, sync.Delete(t.Context(), "192.168.1.2", 36, "ns", "pod", 1))
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
	// owner is the pod the spy pretends each entry describes, so that a
	// metadata-matched delete can be told apart from an unconditional one.
	owner map[string]string
}

func newLocalIPCacheSpy() *localIPCacheSpy { return &localIPCacheSpy{} }

func (s *localIPCacheSpy) Upsert(ip string, hostIP net.IP, hostKey uint8, k8sMeta *K8sMetadata, newIdentity Identity) (bool, error) {
	s.upserts = append(s.upserts, struct {
		key string
		id  Identity
	}{ip, newIdentity})
	return false, nil
}

// Delete satisfies IPCacher for the watcher tests, which exercise the remote
// path where the entry carries no pod metadata.
func (s *localIPCacheSpy) Delete(IP string, src source.Source) bool {
	s.deletes = append(s.deletes, IP)
	return true
}

func (s *localIPCacheSpy) DeleteOnMetadataMatch(IP string, src source.Source, namespace, name string) bool {
	if want, tracked := s.owner[IP]; tracked && want != namespace+"/"+name {
		return false
	}
	s.deletes = append(s.deletes, IP)
	return true
}

// TestIPIdentityWatcherVNIKeyOrdering pins the key-composition rule at the
// cache plane's kvstore seam: the ClusterID annotation is applied first and
// the VNI suffix last ("<ip>@<clusterID>@vni:<N>"), so that the cluster-aware
// parser sees a well-formed key after splitVNIKey has stripped the suffix.
// It also pins that the deletion key is byte-identical to the upsert key.
func TestIPIdentityWatcherVNIKeyOrdering(t *testing.T) {
	ip := netip.MustParseAddr("192.168.1.2")

	for _, tc := range []struct {
		name      string
		clusterID uint32
		vni       uint64
		want      string
	}{
		{name: "plain", want: "192.168.1.2"},
		{name: "vni only", vni: 36, want: "192.168.1.2@vni:36"},
		{name: "clusterID only", clusterID: 5, want: "192.168.1.2@5"},
		{name: "clusterID and vni", clusterID: 5, vni: 36, want: "192.168.1.2@5@vni:36"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spy := newLocalIPCacheSpy()
			w := &IPIdentityWatcher{ipcache: spy, clusterID: tc.clusterID, source: source.KVStore, log: hivetest.Logger(t)}

			pair := &identity.IPIdentityPair{IP: ip.AsSlice(), ID: 21929, Vni: tc.vni}
			w.OnUpdate(pair)
			require.Len(t, spy.upserts, 1)
			require.Equal(t, tc.want, spy.upserts[0].key)
			require.Equal(t, uint32(tc.vni), spy.upserts[0].id.Vni)

			w.OnDelete(pair)
			require.Equal(t, []string{tc.want}, spy.deletes,
				"the deletion key must be identical to the upsert key")

			// The key that the local agent writes into the kvstore must round
			// trip through the stable-API key name.
			require.Equal(t, tc.vni > 0, strings.HasSuffix(pair.GetKeyName(), "@vni:"+strconv.FormatUint(tc.vni, 10)))
		})
	}
}

// TestSynchronizerDeleteLeavesTheNewOwnerAlone covers an address being reused.
//
// An address outlives the pod it was given to: once released, kube-ovn can hand
// it to another pod, whose endpoint registers the very same (VNI, IP) key. The
// teardown of the previous endpoint runs on its own schedule, so it can arrive
// after that. Removing the entry then would take the running pod's entry away,
// and for an endpoint in a VPC there is no bare-address entry left to fall back
// on.
func TestSynchronizerDeleteLeavesTheNewOwnerAlone(t *testing.T) {
	spy := newLocalIPCacheSpy()
	spy.owner = map[string]string{"192.168.1.2@vni:36": "ns/successor"}
	sync := newIPIdentitySynchronizer(hivetest.Logger(t), kvstore.SetupDummy(t, kvstore.DisabledBackendName), spy)

	// The predecessor tears down after the address has been handed on.
	require.NoError(t, sync.Delete(t.Context(), "192.168.1.2", 36, "ns", "predecessor", 1))
	require.Empty(t, spy.deletes, "the entry of the pod holding the address must survive")

	// The owner removing its own entry still works.
	require.NoError(t, sync.Delete(t.Context(), "192.168.1.2", 36, "ns", "successor", 2))
	require.Equal(t, []string{"192.168.1.2@vni:36"}, spy.deletes)
}

// TestSynchronizerDeleteAfterSameNameRestart covers the case the pod metadata
// cannot describe: a pod that comes back under its own name, on its own
// address, in its own VPC.
//
// CNI DEL returns before the endpoint's controllers have finished stopping, so
// the new endpoint can register the address before the old one's teardown gets
// to run. Namespace, name, address and VNI are then all identical, and the only
// thing that differs is which endpoint registered the entry. Losing it would
// leave the running pod unresolvable by (VNI, IP), with no bare-address entry
// to fall back on.
func TestSynchronizerDeleteAfterSameNameRestart(t *testing.T) {
	spy := newLocalIPCacheSpy()
	sync := newIPIdentitySynchronizer(hivetest.Logger(t), kvstore.SetupDummy(t, kvstore.DisabledBackendName), spy)
	params := func(epID uint16) *UpsertParams {
		return &UpsertParams{
			IP:           netip.MustParseAddr("10.99.0.11"),
			ID:           1234,
			Vni:          5,
			K8sNamespace: "vpc-a",
			K8sPodName:   "server",
			EndpointID:   epID,
		}
	}

	require.NoError(t, sync.Upsert(t.Context(), params(100)))
	// The pod comes back with the same name and address; a new endpoint
	// registers it while the previous one is still being torn down.
	require.NoError(t, sync.Upsert(t.Context(), params(101)))

	require.NoError(t, sync.Delete(t.Context(), "10.99.0.11", 5, "vpc-a", "server", 100))
	require.Empty(t, spy.deletes, "the entry now belongs to the endpoint that came back")

	require.NoError(t, sync.Delete(t.Context(), "10.99.0.11", 5, "vpc-a", "server", 101))
	require.Equal(t, []string{"10.99.0.11@vni:5"}, spy.deletes, "its own teardown still removes it")
}
