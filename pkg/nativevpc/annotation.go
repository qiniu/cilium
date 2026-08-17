// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package nativevpc holds the single interpretation of the kube-ovn
// tunnel_key pod annotation for native-vpc mode.
//
// The annotation is the single source of truth for the VNI of a pod, and it is
// read on several planes: endpoint creation and restore (control plane), the
// pod watcher (cache plane) and, indirectly, the datapath and observability
// planes. Every reader must apply the *same* decision table, otherwise the
// planes diverge - e.g. an out-of-range value that endpoint creation rejects
// but the pod watcher accepts would register an ipcache entry under a VNI that
// no endpoint has.
package nativevpc

import (
	"fmt"
	"strconv"
	"strings"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/option"
)

// MaxVNI is the upper bound for a native-vpc VNI (Virtual Network Identifier).
// A Geneve/VXLAN VNI is a 24-bit value, and kube-ovn's tunnel_key uses the
// same space.
const MaxVNI = uint64(1<<24) - 1

// Result describes the outcome of reading the tunnel_key annotation of a pod.
//
// The cases are kept apart on purpose: a caller must never have to re-derive
// one of them (for example by looking at pod.Spec.HostNetwork itself), because
// that is how the readers drifted apart before this package existed.
type Result int

const (
	// Disabled means native-vpc is not in use, so every caller must behave
	// exactly as it did before the feature existed.
	Disabled Result = iota
	// HostNetwork means the pod is structurally not part of any VPC: it uses
	// the host network stack. Unlike a missing annotation this is immutable
	// and authoritative, so it is the one signal that may reset an existing
	// VPC scope to none.
	HostNetwork
	// Absent means the annotation is missing. kube-ovn guarantees a non-zero
	// tunnel_key on every non-hostNetwork pod before CNI ADD, so this only
	// happens for legacy pods, a stale pod object, or an error on the kube-ovn
	// side.
	Absent
	// Invalid means the annotation is present but is 0, unparsable or out of
	// range. It always violates the kube-ovn guarantee.
	Invalid
	// Valid means the annotation carries a usable VNI.
	Valid
)

// VNIFromPod applies the native-vpc decision table to a pod and returns the
// VNI (0 unless the result is Valid), the classification, and a descriptive
// error for the Invalid case.
//
// Callers decide what to do with each result, but the direction is fixed:
// never merge a VPC endpoint into the plain (bare-IP) scope on Absent or
// Invalid, because that is the direction that mixes two VPCs. Endpoint
// creation rejects the pod, the running-state paths keep the last known VNI,
// and the pod watcher skips registration.
func VNIFromPod(pod *slim_corev1.Pod) (uint64, Result, error) {
	if !option.Config.EnableNativeVPC || option.Config.NativeVPCVNIAnnotation == "" {
		return 0, Disabled, nil
	}
	if pod == nil {
		return 0, Absent, nil
	}
	if pod.Spec.HostNetwork {
		return 0, HostNetwork, nil
	}

	key := option.Config.NativeVPCVNIAnnotation
	raw, ok := pod.Annotations[key]
	if !ok || strings.TrimSpace(raw) == "" {
		return 0, Absent, nil
	}

	vni, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
	switch {
	case err != nil:
		return 0, Invalid, fmt.Errorf("annotation %q value %q is not a number: %w", key, raw, err)
	case vni == 0:
		return 0, Invalid, fmt.Errorf("annotation %q is 0: kube-ovn only ever writes a non-zero tunnel_key", key)
	case vni > MaxVNI:
		return 0, Invalid, fmt.Errorf("annotation %q value %d exceeds the maximum VNI (%d)", key, vni, MaxVNI)
	}
	return vni, Valid, nil
}
