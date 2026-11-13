// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/ipcache"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/option"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
)

// A running endpoint follows its pod's changed tunnel_key: the VNI, the
// (VNI, IP) references and the identity move together, and only for this pod
// incarnation and a usable key. The ipcache entry of the move is covered by
// the identity sync tests of pkg/endpoint.
func TestMigrateEndpointVNI(t *testing.T) {
	prev, prevAnn := option.Config.EnableNativeVPC, option.Config.NativeVPCVNIAnnotation
	prevV4, prevV6 := option.Config.EnableIPv4, option.Config.EnableIPv6
	option.Config.EnableNativeVPC, option.Config.NativeVPCVNIAnnotation = true, "ovn.kubernetes.io/tunnel_key"
	// No identity sync: its controllers read the global local node store and
	// outlive the endpoint (Stop does not wait for them).
	option.Config.EnableIPv4, option.Config.EnableIPv6 = false, false
	t.Cleanup(func() {
		option.Config.EnableNativeVPC, option.Config.NativeVPCVNIAnnotation = prev, prevAnn
		option.Config.EnableIPv4, option.Config.EnableIPv6 = prevV4, prevV6
	})

	logger := hivetest.Logger(t)
	s := setupEndpointManagerSuite(t)
	mgr := New(logger, nil, &dummyEpSyncher{}, nil, nil, nil, defaultEndpointManagerConfig)
	kvstoreSync := ipcache.NewIPIdentitySynchronizer(logger, kvstore.SetupDummy(t, kvstore.DisabledBackendName), testipcache.NewMockIPCache())

	model := newTestEndpointModel(42, endpoint.StateReady)
	ep, err := endpoint.NewEndpointFromChangeModel(t.Context(), logger, nil, &endpoint.MockEndpointBuildQueue{}, nil, nil, nil, nil, nil, identitymanager.NewIDManager(logger), nil, nil, s.repo, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), ctmap.NewFakeGCRunner(), kvstoreSync, model, fakeTypes.WireguardConfig{}, fakeTypes.IPsecConfig{}, nil, nil)
	require.NoError(t, err)
	ep.IPv4 = netip.MustParseAddr("10.98.0.2")
	ep.VNIID = 9
	ep.K8sNamespace, ep.K8sPodName, ep.K8sUID = "ns", "peer", "uid"
	ep.Start(uint16(model.ID))
	t.Cleanup(ep.Stop)
	require.NoError(t, mgr.expose(ep))

	pod := func(uid types.UID, key string) *slim_corev1.Pod {
		return &slim_corev1.Pod{ObjectMeta: slim_metav1.ObjectMeta{
			Name: "peer", Namespace: "ns", UID: uid,
			Annotations: map[string]string{
				"ovn.kubernetes.io/tunnel_key": key,
				"ovn.kubernetes.io/ip_address": "10.98.0.2",
			},
		}}
	}
	scoped := func(vni string) *endpoint.Endpoint {
		got, _ := mgr.Lookup("vni-ipv4:" + vni + ":10.98.0.2")
		return got
	}

	require.False(t, mgr.MigrateEndpointVNI(ep, pod("other-uid", "4")), "another incarnation of the pod")
	mirror := pod("other-uid", "4")
	mirror.Annotations[corev1.MirrorPodAnnotationKey] = "another-static-pod"
	require.False(t, mgr.MigrateEndpointVNI(ep, mirror), "a mirror pod of another static pod")
	require.False(t, mgr.MigrateEndpointVNI(ep, pod("uid", "0")), "an unusable key")
	require.False(t, mgr.MigrateEndpointVNI(ep, pod("uid", "9")), "the current scope")
	require.Equal(t, uint64(9), ep.GetVNIID())
	require.Same(t, ep, scoped("9"))

	// A static pod: kubelet gave the endpoint the static pod's UID, the API
	// object is its mirror pod.
	mirror = pod("mirror-uid", "4")
	mirror.Annotations[corev1.MirrorPodAnnotationKey] = "uid"
	require.True(t, mgr.MigrateEndpointVNI(ep, mirror))
	require.Equal(t, uint64(4), ep.GetVNIID())
	require.Same(t, ep, scoped("4"), "the endpoint is found in its new scope")
	require.Nil(t, scoped("9"), "and no longer in the old one")
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		id, err := ep.GetSecurityIdentity()
		if assert.NoError(c, err) && assert.NotNil(c, id) {
			assert.Contains(c, id.Labels.String(), "vni:io-cilium-native-vpc-vni=4")
		}
	}, 10*time.Second, 20*time.Millisecond, "the identity follows the new scope")
}
