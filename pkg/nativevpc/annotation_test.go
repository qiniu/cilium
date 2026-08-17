// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nativevpc

import (
	"testing"

	"github.com/stretchr/testify/require"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/option"
)

// TestVNIFromPod pins the single decision table shared by endpoint creation,
// endpoint restore and the pod watcher. Before it existed, the three readers
// validated differently: the pod watcher accepted out-of-range values that
// endpoint creation rejected, so the cache plane could hold an entry under a
// VNI that no endpoint had.
func TestVNIFromPod(t *testing.T) {
	prevEnabled, prevKey := option.Config.EnableNativeVPC, option.Config.NativeVPCVNIAnnotation
	option.Config.EnableNativeVPC = true
	option.Config.NativeVPCVNIAnnotation = "ovn.kubernetes.io/tunnel_key"
	t.Cleanup(func() {
		option.Config.EnableNativeVPC = prevEnabled
		option.Config.NativeVPCVNIAnnotation = prevKey
	})

	pod := func(value string, hostNetwork bool) *slim_corev1.Pod {
		p := &slim_corev1.Pod{
			ObjectMeta: slim_metav1.ObjectMeta{Name: "p", Namespace: "ns"},
			Spec:       slim_corev1.PodSpec{HostNetwork: hostNetwork},
		}
		if value != "<none>" {
			p.Annotations = map[string]string{option.Config.NativeVPCVNIAnnotation: value}
		}
		return p
	}

	for _, tc := range []struct {
		name    string
		pod     *slim_corev1.Pod
		wantVNI uint64
		wantRes Result
	}{
		{name: "valid", pod: pod("36", false), wantVNI: 36, wantRes: Valid},
		{name: "valid with spaces", pod: pod(" 36 ", false), wantVNI: 36, wantRes: Valid},
		{name: "max", pod: pod("16777215", false), wantVNI: MaxVNI, wantRes: Valid},
		{name: "absent", pod: pod("<none>", false), wantRes: Absent},
		{name: "empty", pod: pod("", false), wantRes: Absent},
		{name: "blank", pod: pod("   ", false), wantRes: Absent},
		{name: "nil pod", pod: nil, wantRes: Absent},
		{name: "zero", pod: pod("0", false), wantRes: Invalid},
		{name: "negative", pod: pod("-1", false), wantRes: Invalid},
		{name: "not a number", pod: pod("abc", false), wantRes: Invalid},
		{name: "out of range", pod: pod("16777216", false), wantRes: Invalid},
		{name: "way out of range", pod: pod("4294967295", false), wantRes: Invalid},
		{name: "hostNetwork", pod: pod("36", true), wantRes: NotInVPC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vni, res, err := VNIFromPod(tc.pod)
			require.Equal(t, tc.wantRes, res)
			require.Equal(t, tc.wantVNI, vni)
			if tc.wantRes == Invalid {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}

	t.Run("disabled mode is inert", func(t *testing.T) {
		option.Config.EnableNativeVPC = false
		defer func() { option.Config.EnableNativeVPC = true }()
		vni, res, err := VNIFromPod(pod("36", false))
		require.NoError(t, err)
		require.Equal(t, NotInVPC, res)
		require.Zero(t, vni)
	})

	t.Run("empty annotation key is inert", func(t *testing.T) {
		option.Config.NativeVPCVNIAnnotation = ""
		defer func() { option.Config.NativeVPCVNIAnnotation = "ovn.kubernetes.io/tunnel_key" }()
		_, res, err := VNIFromPod(pod("36", false))
		require.NoError(t, err)
		require.Equal(t, NotInVPC, res)
	})
}
