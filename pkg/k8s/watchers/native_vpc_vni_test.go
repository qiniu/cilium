// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/annotation"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/option"
)

func TestPodVNI(t *testing.T) {
	oldEnable := option.Config.EnableNativeVPC
	oldAnnot := option.Config.NativeVPCVNIAnnotation
	t.Cleanup(func() {
		option.Config.EnableNativeVPC = oldEnable
		option.Config.NativeVPCVNIAnnotation = oldAnnot
	})
	option.Config.EnableNativeVPC = true
	option.Config.NativeVPCVNIAnnotation = "ovn.kubernetes.io/tunnel_key"

	// Valid annotation.
	pod := &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Annotations: map[string]string{"ovn.kubernetes.io/tunnel_key": "36"},
		},
	}
	require.Equal(t, uint32(36), podVNI(pod))

	// Missing annotation -> 0.
	pod = &slim_corev1.Pod{ObjectMeta: slim_metav1.ObjectMeta{Annotations: map[string]string{}}}
	require.Zero(t, podVNI(pod))

	// Invalid value -> 0.
	pod = &slim_corev1.Pod{ObjectMeta: slim_metav1.ObjectMeta{Annotations: map[string]string{"ovn.kubernetes.io/tunnel_key": "abc"}}}
	require.Zero(t, podVNI(pod))

	// nil pod -> 0.
	require.Zero(t, podVNI(nil))

	// native-vpc disabled -> 0 even with the annotation.
	option.Config.EnableNativeVPC = false
	pod = &slim_corev1.Pod{ObjectMeta: slim_metav1.ObjectMeta{Annotations: map[string]string{"ovn.kubernetes.io/tunnel_key": "36"}}}
	require.Zero(t, podVNI(pod))
}

func TestCiliumEndpointVNI(t *testing.T) {
	cep := &k8sTypes.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Annotations: map[string]string{annotation.NativeVPCVNIPrefix + "/vni": "17"},
		},
	}
	require.Equal(t, uint32(17), ciliumEndpointVNI(cep))

	// Missing annotation.
	cep = &k8sTypes.CiliumEndpoint{ObjectMeta: slim_metav1.ObjectMeta{Annotations: map[string]string{}}}
	require.Zero(t, ciliumEndpointVNI(cep))

	// Invalid value.
	cep = &k8sTypes.CiliumEndpoint{ObjectMeta: slim_metav1.ObjectMeta{Annotations: map[string]string{annotation.NativeVPCVNIPrefix + "/vni": "x"}}}
	require.Zero(t, ciliumEndpointVNI(cep))

	// nil.
	require.Zero(t, ciliumEndpointVNI(nil))
}

// TestPodVNIMatchesControlPlane pins the control/cache seam: the pod watcher
// must classify a pod exactly like endpoint creation does. Any value that
// endpoint creation rejects must yield VNI 0 here (no VPC-scoped ipcache
// entry), never a VPC scope that no endpoint has.
func TestPodVNIMatchesControlPlane(t *testing.T) {
	prevEnabled, prevKey := option.Config.EnableNativeVPC, option.Config.NativeVPCVNIAnnotation
	option.Config.EnableNativeVPC = true
	option.Config.NativeVPCVNIAnnotation = "ovn.kubernetes.io/tunnel_key"
	t.Cleanup(func() {
		option.Config.EnableNativeVPC = prevEnabled
		option.Config.NativeVPCVNIAnnotation = prevKey
	})

	pod := func(value string) *slim_corev1.Pod {
		return &slim_corev1.Pod{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name: "p", Namespace: "ns",
				Annotations: map[string]string{option.Config.NativeVPCVNIAnnotation: value},
			},
		}
	}

	require.Equal(t, uint32(36), podVNI(pod("36")))
	require.Equal(t, uint32(36), podVNI(pod(" 36 ")), "whitespace is tolerated like on the control plane")
	require.Equal(t, uint32(16777215), podVNI(pod("16777215")))

	// Values rejected by endpoint creation must not become a cache-plane scope.
	for _, bad := range []string{"0", "-1", "abc", "16777216", "4294967295", ""} {
		require.Zero(t, podVNI(pod(bad)), "value %q must not yield a VPC scope", bad)
	}
	require.Zero(t, podVNI(nil))

	option.Config.EnableNativeVPC = false
	require.Zero(t, podVNI(pod("36")), "inert when native-vpc is disabled")
}
