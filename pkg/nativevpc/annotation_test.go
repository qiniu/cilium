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
		{name: "hostNetwork", pod: pod("36", true), wantRes: HostNetwork},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vni, res, err := VNIFromPod(tc.pod)
			require.Equal(t, tc.wantRes, res)
			require.Equal(t, tc.wantVNI, vni)
			if tc.wantRes == Invalid || tc.wantRes == Absent {
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
		require.Equal(t, Disabled, res, "callers must be able to tell 'mode off' from 'not in a VPC'")
		require.Zero(t, vni)
	})

	t.Run("empty annotation key is inert", func(t *testing.T) {
		option.Config.NativeVPCVNIAnnotation = ""
		defer func() { option.Config.NativeVPCVNIAnnotation = "ovn.kubernetes.io/tunnel_key" }()
		_, res, err := VNIFromPod(pod("36", false))
		require.NoError(t, err)
		require.Equal(t, Disabled, res)
	})
}

// TestVNIFromPodForIP pins the multus/NAD case: a pod with an attached
// network has one OVN subnet - and one VNI - per interface, so the endpoint of
// the attached interface must read the provider-scoped tunnel_key of *its*
// address. Reading the primary annotation instead would put the attached
// interface in the wrong VPC scope.
func TestVNIFromPodForIP(t *testing.T) {
	prevEnabled, prevKey := option.Config.EnableNativeVPC, option.Config.NativeVPCVNIAnnotation
	option.Config.EnableNativeVPC = true
	option.Config.NativeVPCVNIAnnotation = "ovn.kubernetes.io/tunnel_key"
	t.Cleanup(func() {
		option.Config.EnableNativeVPC = prevEnabled
		option.Config.NativeVPCVNIAnnotation = prevKey
	})

	multusPod := &slim_corev1.Pod{
		ObjectMeta: slim_metav1.ObjectMeta{
			Annotations: map[string]string{
				"ovn.kubernetes.io/ip_address":              "10.16.0.5,fd00::5",
				"ovn.kubernetes.io/tunnel_key":              "36",
				"net1.default.ovn.kubernetes.io/ip_address": "192.168.1.10",
				"net1.default.ovn.kubernetes.io/tunnel_key": "77",
				"net2.default.ovn.kubernetes.io/ip_address": "192.168.2.10",
				"net2.default.ovn.kubernetes.io/tunnel_key": "0",
			},
		},
	}

	for _, tc := range []struct {
		name    string
		ip      string
		wantVNI uint64
		wantRes Result
	}{
		{name: "primary interface", ip: "10.16.0.5", wantVNI: 36, wantRes: Valid},
		{name: "primary interface v6", ip: "fd00::5", wantVNI: 36, wantRes: Valid},
		{name: "attached interface", ip: "192.168.1.10", wantVNI: 77, wantRes: Valid},
		{name: "no ip falls back to the primary", ip: "", wantVNI: 36, wantRes: Valid},
		// An address kube-ovn never allocated (a vlan/macvlan attachment) is
		// in no VPC: it must not inherit the primary interface's VNI.
		{name: "address kube-ovn did not allocate", ip: "10.0.0.1", wantRes: Absent},
		// The provider-scoped value goes through the same decision table: a
		// broken attachment must not silently inherit the primary's VNI.
		{name: "attached interface with a broken key", ip: "192.168.2.10", wantRes: Invalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vni, res, err := VNIFromPodForIP(multusPod, tc.ip)
			require.Equal(t, tc.wantRes, res)
			require.Equal(t, tc.wantVNI, vni)
			if tc.wantRes == Invalid || tc.wantRes == Absent {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}

	t.Run("attachment without a tunnel_key is Absent, not the primary VNI", func(t *testing.T) {
		p := &slim_corev1.Pod{ObjectMeta: slim_metav1.ObjectMeta{Annotations: map[string]string{
			"ovn.kubernetes.io/ip_address":              "10.16.0.5",
			"ovn.kubernetes.io/tunnel_key":              "36",
			"net1.default.ovn.kubernetes.io/ip_address": "192.168.1.10",
		}}}
		vni, res, err := VNIFromPodForIP(p, "192.168.1.10")
		require.Equal(t, Absent, res)
		require.Zero(t, vni)
		// The error names the key that is missing: the attachment's, not the
		// primary one, which is present.
		require.EqualError(t, err, `missing tunnel_key annotation "net1.default.ovn.kubernetes.io/tunnel_key"`)
	})

	t.Run("an address two VPCs share is refused, not guessed", func(t *testing.T) {
		// Overlapping IPs in different VPCs are what native-vpc exists for, so
		// both of a pod's interfaces can hold the same address. Nothing left
		// here tells them apart (the interface name is not readable inside the
		// multus delegate chain), and the annotations are a map, so picking the
		// first match would hand out a VNI that differs from one call to the
		// next.
		p := &slim_corev1.Pod{ObjectMeta: slim_metav1.ObjectMeta{Annotations: map[string]string{
			"ovn.kubernetes.io/ip_address":              "10.16.0.5",
			"ovn.kubernetes.io/tunnel_key":              "36",
			"net1.default.ovn.kubernetes.io/ip_address": "10.16.0.5",
			"net1.default.ovn.kubernetes.io/tunnel_key": "77",
		}}}
		for range 20 {
			vni, res, err := VNIFromPodForIP(p, "10.16.0.5")
			require.Equal(t, Invalid, res)
			require.Zero(t, vni)
			require.ErrorContains(t, err, "claimed by 2 kube-ovn providers")
			// The message names the providers in a stable order, so the same
			// conflict does not read differently on every reconcile.
			require.ErrorContains(t, err, "net1.default.ovn, ovn")
		}
	})

	t.Run("hostNetwork wins over any address", func(t *testing.T) {
		p := multusPod.DeepCopy()
		p.Spec.HostNetwork = true
		_, res, err := VNIFromPodForIP(p, "192.168.1.10")
		require.NoError(t, err)
		require.Equal(t, HostNetwork, res)
	})
}

// TestVNIFromPodForIPWithoutKubeOVNAnnotations keeps the lookup robust for a
// pod kube-ovn never annotated with any address: the configured primary
// annotation stays the answer, exactly as before per-provider lookups existed.
func TestVNIFromPodForIPWithoutKubeOVNAnnotations(t *testing.T) {
	prevEnabled, prevKey := option.Config.EnableNativeVPC, option.Config.NativeVPCVNIAnnotation
	option.Config.EnableNativeVPC = true
	option.Config.NativeVPCVNIAnnotation = "ovn.kubernetes.io/tunnel_key"
	t.Cleanup(func() {
		option.Config.EnableNativeVPC = prevEnabled
		option.Config.NativeVPCVNIAnnotation = prevKey
	})

	p := &slim_corev1.Pod{ObjectMeta: slim_metav1.ObjectMeta{Annotations: map[string]string{
		"ovn.kubernetes.io/tunnel_key": "36",
	}}}
	vni, res, err := VNIFromPodForIP(p, "10.16.0.5")
	require.NoError(t, err)
	require.Equal(t, Valid, res)
	require.Equal(t, uint64(36), vni)
}

// TestVNIFromPodForIPCustomAnnotationKey pins that --native-vpc-vni-annotation
// still decides where the primary network's VNI is read from. Selecting the
// provider by address must not turn into deriving the annotation name from it:
// the primary provider is always "ovn", so a deployment that renamed the
// annotation would otherwise have every pod read a key kube-ovn never wrote and
// be rejected.
func TestVNIFromPodForIPCustomAnnotationKey(t *testing.T) {
	prevEnabled, prevKey := option.Config.EnableNativeVPC, option.Config.NativeVPCVNIAnnotation
	option.Config.EnableNativeVPC = true
	option.Config.NativeVPCVNIAnnotation = "custom.example.com/vni"
	t.Cleanup(func() {
		option.Config.EnableNativeVPC = prevEnabled
		option.Config.NativeVPCVNIAnnotation = prevKey
	})

	p := &slim_corev1.Pod{ObjectMeta: slim_metav1.ObjectMeta{Annotations: map[string]string{
		"ovn.kubernetes.io/ip_address":              "10.16.0.5",
		"custom.example.com/vni":                    "36",
		"net1.default.ovn.kubernetes.io/ip_address": "192.168.1.10",
		"net1.default.ovn.kubernetes.io/tunnel_key": "77",
	}}}

	t.Run("primary reads the configured key", func(t *testing.T) {
		vni, res, err := VNIFromPodForIP(p, "10.16.0.5")
		require.NoError(t, err)
		require.Equal(t, Valid, res)
		require.Equal(t, uint64(36), vni)
	})

	t.Run("attachment reads kube-ovn's per-provider key", func(t *testing.T) {
		// kube-ovn writes <provider>.kubernetes.io/tunnel_key for an
		// attachment whatever the primary annotation is called, so the
		// template is right here and the configured key is not.
		vni, res, err := VNIFromPodForIP(p, "192.168.1.10")
		require.NoError(t, err)
		require.Equal(t, Valid, res)
		require.Equal(t, uint64(77), vni)
	})
}

// TestVNIFromPodForIPAddressSpelling pins that the provider is selected by
// address, not by text. kube-ovn writes the annotation and the endpoint
// supplies the address, so one IPv6 address can legitimately reach this code
// in two spellings; comparing the strings would report "no provider claims
// this address" and reject a correctly configured pod.
func TestVNIFromPodForIPAddressSpelling(t *testing.T) {
	prevEnabled, prevKey := option.Config.EnableNativeVPC, option.Config.NativeVPCVNIAnnotation
	option.Config.EnableNativeVPC = true
	option.Config.NativeVPCVNIAnnotation = "ovn.kubernetes.io/tunnel_key"
	t.Cleanup(func() {
		option.Config.EnableNativeVPC = prevEnabled
		option.Config.NativeVPCVNIAnnotation = prevKey
	})

	p := &slim_corev1.Pod{ObjectMeta: slim_metav1.ObjectMeta{Annotations: map[string]string{
		// expanded spelling, as some writers produce
		"ovn.kubernetes.io/ip_address":              "fd00:0:0:0:0:0:0:5",
		"ovn.kubernetes.io/tunnel_key":              "36",
		"net1.default.ovn.kubernetes.io/ip_address": "192.168.1.10",
		"net1.default.ovn.kubernetes.io/tunnel_key": "77",
	}}}

	// netip.Addr.String() produces the canonical form; it must still match.
	vni, res, err := VNIFromPodForIP(p, "fd00::5")
	require.NoError(t, err)
	require.Equal(t, Valid, res, "an address must match its own expanded spelling")
	require.Equal(t, uint64(36), vni)

	// An address of another interface still selects that interface.
	vni, res, err = VNIFromPodForIP(p, "192.168.1.10")
	require.NoError(t, err)
	require.Equal(t, Valid, res)
	require.Equal(t, uint64(77), vni)

	// An address nobody allocated still fails closed.
	_, res, err = VNIFromPodForIP(p, "10.0.0.1")
	require.ErrorContains(t, err, "not allocated by any kube-ovn provider")
	require.Equal(t, Absent, res)
}
