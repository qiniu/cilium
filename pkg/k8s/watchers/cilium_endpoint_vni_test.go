// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"net"
	"net/netip"
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
	// deletedAs records the pod name each metadata-matched delete was made
	// with. The entry was written with a pod name too, and a delete that uses
	// a different one silently matches nothing.
	deletedAs []string
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

func (r *recordingIPCache) DeleteOnMetadataMatch(ip string, _ source.Source, _, podName string) bool {
	r.deleted = append(r.deleted, ip)
	r.deletedAs = append(r.deletedAs, podName)
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

	// The pod's primary endpoint: it holds the address the watcher registers.
	ep := &endpoint.Endpoint{VNIID: 9, IPv4: netip.MustParseAddr("10.99.0.11")}
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

// TestUpdatePodHostDataMultusAttachment pins the multus/NAD case: the pod has
// one endpoint per interface, each in the VPC of its own OVN subnet, but
// pod.Status carries the primary network's addresses only. Picking just any of
// the pod's endpoints would publish the primary address under the attachment's
// VNI - an address announced in a VPC it is not in.
func TestUpdatePodHostDataMultusAttachment(t *testing.T) {
	prev := option.Config.EnableNativeVPC
	prevAnn := option.Config.NativeVPCVNIAnnotation
	option.Config.EnableNativeVPC = true
	option.Config.NativeVPCVNIAnnotation = testVNIAnnotation
	t.Cleanup(func() {
		option.Config.EnableNativeVPC = prev
		option.Config.NativeVPCVNIAnnotation = prevAnn
	})

	// net1 first on purpose: the attachment's endpoint may well be the one
	// the endpoint manager returns first.
	attachment := &endpoint.Endpoint{VNIID: 77, IPv4: netip.MustParseAddr("192.168.1.10")}
	primary := &endpoint.Endpoint{VNIID: 9, IPv4: netip.MustParseAddr("10.99.0.11")}

	ipc := &recordingIPCache{}
	w := &K8sPodWatcher{
		logger:          hivetest.Logger(t),
		ipcache:         ipc,
		policyManager:   fakePolicyManager{},
		endpointManager: fakeEndpointManager{eps: []*endpoint.Endpoint{attachment, primary}},
		wgConfig:        fakeTypes.WireguardConfig{},
		ipsecConfig:     fakeTypes.IPsecConfig{},
	}

	pod := vniPod("client", "10.99.0.11", "192.168.0.1", "9")
	require.NoError(t, w.updatePodHostData(nil, pod, nil, k8sTypes.IPSlice{"10.99.0.11"}))
	require.Equal(t, []string{"10.99.0.11@vni:9"}, ipc.upserted)
}

// TestUpdatePodHostDataEndpointWithOtherAddress covers the gap between the two
// cases above: the pod has an endpoint on this node, but none of its addresses
// is the one being registered (the attachment's endpoint exists while the
// primary one does not yet, or the pod's address has just changed). There is no
// endpoint that can speak for this address, so the watcher must defer to the
// endpoint that will register it rather than publish the annotation's scope.
func TestUpdatePodHostDataEndpointWithOtherAddress(t *testing.T) {
	prev := option.Config.EnableNativeVPC
	prevAnn := option.Config.NativeVPCVNIAnnotation
	option.Config.EnableNativeVPC = true
	option.Config.NativeVPCVNIAnnotation = testVNIAnnotation
	t.Cleanup(func() {
		option.Config.EnableNativeVPC = prev
		option.Config.NativeVPCVNIAnnotation = prevAnn
	})

	attachment := &endpoint.Endpoint{VNIID: 77, IPv4: netip.MustParseAddr("192.168.1.10")}
	ipc := &recordingIPCache{}
	w := &K8sPodWatcher{
		logger:          hivetest.Logger(t),
		ipcache:         ipc,
		policyManager:   fakePolicyManager{},
		endpointManager: fakeEndpointManager{eps: []*endpoint.Endpoint{attachment}},
		wgConfig:        fakeTypes.WireguardConfig{},
		ipsecConfig:     fakeTypes.IPsecConfig{},
	}

	pod := vniPod("client", "10.99.0.11", "192.168.0.1", "9")
	pod.Spec.NodeName = nodeTypes.GetName()
	require.NoError(t, w.updatePodHostData(nil, pod, nil, k8sTypes.IPSlice{"10.99.0.11"}))
	require.Empty(t, ipc.upserted, "no endpoint holds this address, so its scope is not this watcher's to publish")
}

// TestUpdatePodHostDataSharedIPv6 covers two interfaces of one pod that were
// given the same IPv6 address in different VPCs while their IPv4 addresses
// differ. Both endpoints are admitted (each is selected by its own IPv4), so
// the watcher must not let the attachment speak for the primary network just
// because one of its addresses appears in pod.Status: the primary IPv4 would
// then be published under the attachment's VNI.
func TestUpdatePodHostDataSharedIPv6(t *testing.T) {
	prev := option.Config.EnableNativeVPC
	prevAnn := option.Config.NativeVPCVNIAnnotation
	option.Config.EnableNativeVPC = true
	option.Config.NativeVPCVNIAnnotation = testVNIAnnotation
	t.Cleanup(func() {
		option.Config.EnableNativeVPC = prev
		option.Config.NativeVPCVNIAnnotation = prevAnn
	})

	// Listed first on purpose: it must not win.
	attachment := &endpoint.Endpoint{
		VNIID: 77,
		IPv4:  netip.MustParseAddr("192.168.1.10"),
		IPv6:  netip.MustParseAddr("fd00::5"),
	}
	primary := &endpoint.Endpoint{
		VNIID: 9,
		IPv4:  netip.MustParseAddr("10.99.0.11"),
		IPv6:  netip.MustParseAddr("fd00::5"),
	}

	ipc := &recordingIPCache{}
	w := &K8sPodWatcher{
		logger:          hivetest.Logger(t),
		ipcache:         ipc,
		policyManager:   fakePolicyManager{},
		endpointManager: fakeEndpointManager{eps: []*endpoint.Endpoint{attachment, primary}},
		wgConfig:        fakeTypes.WireguardConfig{},
		ipsecConfig:     fakeTypes.IPsecConfig{},
	}

	pod := vniPod("client", "10.99.0.11", "192.168.0.1", "9")
	require.NoError(t, w.updatePodHostData(nil, pod, nil,
		k8sTypes.IPSlice{"10.99.0.11", "fd00::5"}))
	require.Equal(t, []string{"10.99.0.11@vni:9", "fd00::5@vni:9"}, ipc.upserted,
		"the primary network's addresses must carry the primary endpoint's VNI")
}

// TestCiliumEndpointPodName pins that the pod name published to other agents
// is the pod's, not the CiliumEndpoint object's: an attachment's CEP is named
// "<pod>.7.<ifname>", and that name identifies no pod.
func TestCiliumEndpointPodName(t *testing.T) {
	attachment := &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      "client.7.net1",
			Namespace: "default",
			OwnerReferences: []slim_metav1.OwnerReference{
				{Kind: "Pod", Name: "client", UID: "uid-1"},
			},
		},
	}
	require.Equal(t, "client", attachment.PodName())

	// A CEP without owner references pre-dates the convention: keep its own
	// name, so that the ipcache write and the metadata-matched delete agree.
	legacy := &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{Name: "client", Namespace: "default"},
	}
	require.Equal(t, "client", legacy.PodName())

	// A pod named like the attachment's CEP replaces it under the same key;
	// the watcher must not skip that Upsert, or ipcache keeps PodName=client.
	replacement := &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:            "client.7.net1",
			Namespace:       "default",
			OwnerReferences: []slim_metav1.OwnerReference{{Kind: "Pod", Name: "client.7.net1", UID: "uid-2"}},
		},
	}
	require.False(t, attachment.DeepEqual(replacement))
}

// TestEndpointUpdatedAttachmentUsesPodName pins that the entry an attachment's
// CiliumEndpoint leaves behind can actually be removed. The ipcache entry is
// written with the pod name, so every delete - the one on CEP deletion and the
// one that drops the old address on an update - has to match on the same name.
// Matching on the object name ("client.7.net1") silently matches nothing and
// leaves a stale (VNI, IP) -> identity behind.
func TestEndpointUpdatedAttachmentUsesPodName(t *testing.T) {
	prev := option.Config.EnableNativeVPC
	option.Config.EnableNativeVPC = true
	t.Cleanup(func() { option.Config.EnableNativeVPC = prev })

	attachment := func(ip string) *types.CiliumEndpoint {
		cep := vniCEP("client.7.net1", ip, "5", 1234)
		cep.OwnerReferences = []slim_metav1.OwnerReference{{Kind: "Pod", Name: "client", UID: "uid-client"}}
		return cep
	}

	ipc := &recordingIPCache{}
	w := &K8sCiliumEndpointsWatcher{
		logger:        hivetest.Logger(t),
		ipcache:       ipc,
		policyManager: fakePolicyManager{},
		wgConfig:      fakeTypes.WireguardConfig{},
		ipsecConfig:   fakeTypes.IPsecConfig{},
	}

	// The address changes: the old one has to go.
	w.endpointUpdated(attachment("10.99.0.11"), attachment("10.99.0.12"))
	require.Equal(t, []string{"10.99.0.11@vni:5"}, ipc.deleted)
	require.Equal(t, []string{"client"}, ipc.deletedAs,
		"the delete must match the name the entry was written with")

	// Deleting the object removes the remaining entry under the same name.
	ipc.deleted, ipc.deletedAs = nil, nil
	w.endpointDeleted(attachment("10.99.0.12"))
	require.Equal(t, []string{"10.99.0.12@vni:5"}, ipc.deleted)
	require.Equal(t, []string{"client"}, ipc.deletedAs)
}
