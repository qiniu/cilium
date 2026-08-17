// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"net"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/annotation"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
)

// recordingIPCache records the keys the CiliumEndpoint watcher writes and
// removes, so a test can assert on the exact key strings rather than on the
// bare addresses they are derived from.
// testVNIAnnotation stands in for the kube-ovn annotation the deployment
// configures; the watcher reads whatever key option.Config names.
const testVNIAnnotation = "ovn.kubernetes.io/tunnel_key"

// fakeEndpointManager answers the pod watcher's question "is there a local
// endpoint for this pod, and which VPC is it actually in?".
type fakeEndpointManager struct{ eps []*endpoint.Endpoint }

func (f fakeEndpointManager) GetEndpointsByPodName(string) []*endpoint.Endpoint { return f.eps }
func (fakeEndpointManager) LookupCEPName(string) *endpoint.Endpoint             { return nil }
func (fakeEndpointManager) GetEndpoints() []*endpoint.Endpoint                  { return nil }
func (fakeEndpointManager) GetHostEndpoint() *endpoint.Endpoint                 { return nil }
func (fakeEndpointManager) UpdatePolicyMaps(context.Context) error              { return nil }

// fakePolicyManager swallows the policy recalculation triggers.
type fakePolicyManager struct{}

func (fakePolicyManager) TriggerPolicyUpdates(string) {}

type recordingIPCache struct {
	upserted []string
	deleted  []string
}

func (r *recordingIPCache) Upsert(ip string, _ net.IP, _ uint8, _ *ipcache.K8sMetadata, _ ipcache.Identity) (bool, error) {
	r.upserted = append(r.upserted, ip)
	return false, nil
}

func (r *recordingIPCache) LookupByIP(string) (ipcache.Identity, bool) {
	return ipcache.Identity{}, false
}

func (r *recordingIPCache) Delete(ip string, _ source.Source) bool {
	r.deleted = append(r.deleted, ip)
	return false
}

func (r *recordingIPCache) DeleteOnMetadataMatch(ip string, _ source.Source, _, _ string) bool {
	r.deleted = append(r.deleted, ip)
	return false
}

func (r *recordingIPCache) UpsertMetadata(cmtypes.PrefixCluster, source.Source, ipcacheTypes.ResourceID, ...ipcache.IPMetadata) {
}

func (r *recordingIPCache) RemoveLabelsExcluded(labels.Labels, map[cmtypes.PrefixCluster]struct{}, ipcacheTypes.ResourceID) {
}

func (r *recordingIPCache) RemoveMetadata(cmtypes.PrefixCluster, ipcacheTypes.ResourceID, ...ipcache.IPMetadata) {
}

func vniCEP(name, ip string, vni string, identity int64) *types.CiliumEndpoint {
	cep := &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
		Identity:   &v2.EndpointIdentity{ID: identity},
		Networking: &v2.EndpointNetworking{NodeIP: "10.0.0.1"},
	}
	cep.Networking.Addressing = append(cep.Networking.Addressing, &v2.AddressPair{IPV4: ip})
	if vni != "" {
		cep.Annotations = map[string]string{annotation.CiliumEndpointNativeVPCVNI: vni}
	}
	return cep
}

// TestEndpointUpdatedVNIChangeRemovesOldKey covers a CiliumEndpoint that keeps
// its address while moving to another VPC.
//
// The remote endpoint is registered under a (VNI, IP) scoped key, so "does this
// address still exist?" cannot be answered by comparing bare addresses: the
// address is unchanged, yet the entry that has to be removed is the one scoped
// by the *old* VNI. Leaving it behind lets the old VPC keep resolving that
// address to an endpoint that no longer belongs to it - and in native-vpc mode
// another VPC may legitimately own the very same address.
func TestEndpointUpdatedVNIChangeRemovesOldKey(t *testing.T) {
	prev := option.Config.EnableNativeVPC
	option.Config.EnableNativeVPC = true
	t.Cleanup(func() { option.Config.EnableNativeVPC = prev })

	for _, tc := range []struct {
		name         string
		oldVNI       string
		newVNI       string
		wantUpserted string
		wantDeleted  []string
	}{
		{
			name:         "VNI changes while the address stays",
			oldVNI:       "5",
			newVNI:       "7",
			wantUpserted: "10.99.0.11@vni:7",
			wantDeleted:  []string{"10.99.0.11@vni:5"},
		},
		{
			name:         "nothing changes",
			oldVNI:       "5",
			newVNI:       "5",
			wantUpserted: "10.99.0.11@vni:5",
			wantDeleted:  nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ipc := &recordingIPCache{}
			w := &K8sCiliumEndpointsWatcher{
				logger:      hivetest.Logger(t),
				ipcache:     ipc,
				wgConfig:    fakeTypes.WireguardConfig{},
				ipsecConfig: fakeTypes.IPsecConfig{},
			}

			old := vniCEP("client", "10.99.0.11", tc.oldVNI, 1234)
			new := vniCEP("client", "10.99.0.11", tc.newVNI, 1234)
			w.endpointUpdated(old, new)

			require.Equal(t, []string{tc.wantUpserted}, ipc.upserted)
			var deleted []string
			for _, d := range ipc.deleted {
				if d != "" { // the v6 slot of a v4-only endpoint
					deleted = append(deleted, d)
				}
			}
			require.Equal(t, tc.wantDeleted, deleted,
				"the entry of the VPC the endpoint left must be removed")
		})
	}
}

func vniPod(name, ip, hostIP, vni string) *slim_corev1.Pod {
	pod := &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
		Status: slim_corev1.PodStatus{
			HostIP: hostIP,
			PodIP:  ip,
			PodIPs: []slim_corev1.PodIP{{IP: ip}},
		},
	}
	if vni != "" {
		pod.Annotations = map[string]string{testVNIAnnotation: vni}
	}
	return pod
}

// TestUpdatePodHostDataVNIChange covers the pod watcher side of the same rule:
// the entry it maintains is keyed by (VNI, IP), so a pod that changes VPC has
// to lose the entry of the VPC it left, and that entry can only be addressed
// with the VNI it was written under - not with the pod's current one.
func TestUpdatePodHostDataVNIChange(t *testing.T) {
	prev := option.Config.EnableNativeVPC
	prevAnn := option.Config.NativeVPCVNIAnnotation
	option.Config.EnableNativeVPC = true
	option.Config.NativeVPCVNIAnnotation = testVNIAnnotation
	t.Cleanup(func() {
		option.Config.EnableNativeVPC = prev
		option.Config.NativeVPCVNIAnnotation = prevAnn
	})

	for _, tc := range []struct {
		name           string
		oldIP, newIP   string
		oldVNI, newVNI string
		wantUpserted   []string
		wantDeleted    []string
	}{
		{
			name:  "VPC change with the same address",
			oldIP: "10.99.0.11", newIP: "10.99.0.11",
			oldVNI: "5", newVNI: "7",
			wantUpserted: []string{"10.99.0.11@vni:7"},
			wantDeleted:  []string{"10.99.0.11@vni:5"},
		},
		{
			name:  "address change within one VPC",
			oldIP: "10.99.0.11", newIP: "10.99.0.12",
			oldVNI: "5", newVNI: "5",
			wantUpserted: []string{"10.99.0.12@vni:5"},
			wantDeleted:  []string{"10.99.0.11@vni:5"},
		},
		{
			name:  "address and VPC both change",
			oldIP: "10.99.0.11", newIP: "10.99.0.12",
			oldVNI: "5", newVNI: "7",
			wantUpserted: []string{"10.99.0.12@vni:7"},
			wantDeleted:  []string{"10.99.0.11@vni:5"},
		},
		{
			name:  "nothing changes",
			oldIP: "10.99.0.11", newIP: "10.99.0.11",
			oldVNI: "5", newVNI: "5",
			wantUpserted: nil,
			wantDeleted:  nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ipc := &recordingIPCache{}
			w := &K8sPodWatcher{
				logger:          hivetest.Logger(t),
				ipcache:         ipc,
				policyManager:   fakePolicyManager{},
				endpointManager: fakeEndpointManager{},
				wgConfig:        fakeTypes.WireguardConfig{},
				ipsecConfig:     fakeTypes.IPsecConfig{},
			}

			oldPod := vniPod("client", tc.oldIP, "192.168.0.1", tc.oldVNI)
			newPod := vniPod("client", tc.newIP, "192.168.0.1", tc.newVNI)
			err := w.updatePodHostData(oldPod, newPod,
				k8sTypes.IPSlice{tc.oldIP}, k8sTypes.IPSlice{tc.newIP})
			require.NoError(t, err)

			require.Equal(t, tc.wantUpserted, ipc.upserted)
			require.Equal(t, tc.wantDeleted, ipc.deleted,
				"the entry must be removed with the VNI it was written under")
		})
	}
}

// TestUpdatePodHostDataDriftFollowsEndpoint pins which of the two sources wins
// when they disagree.
//
// A ready endpoint does not adopt a new VNI from its pod annotation: the VNI is
// an identity and datapath dimension, and only a recreation converges it. The
// pod watcher therefore must not publish the annotation's scope either -
// doing so would announce the address in a VPC that no endpoint is in, which is
// exactly the cross-VPC lie the scoping exists to prevent. The entry stays
// where the datapath actually is until the pod is recreated.
func TestUpdatePodHostDataDriftFollowsEndpoint(t *testing.T) {
	prev := option.Config.EnableNativeVPC
	prevAnn := option.Config.NativeVPCVNIAnnotation
	option.Config.EnableNativeVPC = true
	option.Config.NativeVPCVNIAnnotation = testVNIAnnotation
	t.Cleanup(func() {
		option.Config.EnableNativeVPC = prev
		option.Config.NativeVPCVNIAnnotation = prevAnn
	})

	ep := &endpoint.Endpoint{VNIID: 9}
	ipc := &recordingIPCache{}
	w := &K8sPodWatcher{
		logger:          hivetest.Logger(t),
		ipcache:         ipc,
		policyManager:   fakePolicyManager{},
		endpointManager: fakeEndpointManager{eps: []*endpoint.Endpoint{ep}},
		wgConfig:        fakeTypes.WireguardConfig{},
		ipsecConfig:     fakeTypes.IPsecConfig{},
	}

	oldPod := vniPod("client", "10.99.0.11", "192.168.0.1", "9")
	newPod := vniPod("client", "10.99.0.11", "192.168.0.1", "99") // annotation drifted

	require.NoError(t, w.updatePodHostData(oldPod, newPod,
		k8sTypes.IPSlice{"10.99.0.11"}, k8sTypes.IPSlice{"10.99.0.11"}))

	require.Empty(t, ipc.upserted, "no entry may be published under a VPC the endpoint is not in")
	require.Empty(t, ipc.deleted, "the entry backing the running datapath must stay")
}

// TestUpdatePodHostDataLocalPodWithoutEndpoint covers the startup ordering: pod
// events are delivered before endpoint restore has finished, so the watcher has
// no endpoint to consult yet. It must not fall back to the annotation for a pod
// on this node - the annotation may be one the endpoint is about to refuse, and
// the placeholder would then name a VPC the endpoint never joins. The endpoint
// registers the real entry itself a moment later.
func TestUpdatePodHostDataLocalPodWithoutEndpoint(t *testing.T) {
	prev := option.Config.EnableNativeVPC
	prevAnn := option.Config.NativeVPCVNIAnnotation
	option.Config.EnableNativeVPC = true
	option.Config.NativeVPCVNIAnnotation = testVNIAnnotation
	t.Cleanup(func() {
		option.Config.EnableNativeVPC = prev
		option.Config.NativeVPCVNIAnnotation = prevAnn
	})

	ipc := &recordingIPCache{}
	w := &K8sPodWatcher{
		logger:          hivetest.Logger(t),
		ipcache:         ipc,
		policyManager:   fakePolicyManager{},
		endpointManager: fakeEndpointManager{}, // restore has not exposed it yet
		wgConfig:        fakeTypes.WireguardConfig{},
		ipsecConfig:     fakeTypes.IPsecConfig{},
	}

	pod := vniPod("client", "10.99.0.11", "192.168.0.1", "99")
	pod.Spec.NodeName = nodeTypes.GetName()

	require.NoError(t, w.updatePodHostData(nil, pod, nil, k8sTypes.IPSlice{"10.99.0.11"}))
	require.Empty(t, ipc.upserted, "the scope of a local pod is the endpoint's to publish")

	// A pod on another node has no local endpoint to wait for, so the
	// annotation remains the only available scope.
	remote := vniPod("peer", "10.99.0.12", "192.168.0.2", "99")
	remote.Spec.NodeName = "other-node"
	require.NoError(t, w.updatePodHostData(nil, remote, nil, k8sTypes.IPSlice{"10.99.0.12"}))
	require.Equal(t, []string{"10.99.0.12@vni:99"}, ipc.upserted)
}
