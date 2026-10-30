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
	"net/netip"
	"slices"
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

// Annotation suffixes of the per-provider annotations kube-ovn writes for a
// multus attached network. The provider of an attachment is
// "<nad-name>.<nad-namespace>.ovn" and the one of the primary network is
// plain "ovn" (primaryProvider).
//
// Only the attachment keys are built from this template. The primary network's
// key stays --native-vpc-vni-annotation: that flag exists to let a deployment
// name the primary annotation itself, and deriving it from the provider here
// would silently ignore a configured value and reject every pod.
const (
	primaryProvider         = "ovn"
	providerIPAddressSuffix = ".kubernetes.io/ip_address"
	providerTunnelKeySuffix = ".kubernetes.io/tunnel_key"
)

// tunnelKeyProvidersForIP returns the kube-ovn providers that allocated ip for
// this pod, sorted for a deterministic result.
//
// A pod with multus attachments has one OVN subnet - and therefore one VNI -
// per interface, so the VNI of an endpoint must be read from the annotation of
// the provider that allocated *that* interface's address. The interface is
// identified by its IP rather than by its name on purpose: multus writes the
// name into the network-status annotation only after every delegate has
// returned (multus CmdAdd calls SetNetworkStatus after the delegate loop), so
// it is not readable while Cilium runs inside the delegate chain, whereas
// kube-ovn writes ip_address and tunnel_key together before its own CNI ADD
// returns.
//
// More than one provider can claim the same address, because overlapping IPs in
// different VPCs are exactly what native-vpc exists for. The caller must then
// fail closed instead of picking one: there is no second signal here that could
// tell the interfaces apart.
//
// claimed reports whether kube-ovn allocated any address at all for this pod.
// When it did and none of them is ip, the interface is not a kube-ovn one (a
// vlan/macvlan attachment, say): it is in no VPC, and the caller must fail
// closed rather than fall back to the primary network's annotation, which
// would place the interface in a VPC it is not in.
//
// Addresses are compared as addresses, not as text: the annotation is written
// by kube-ovn while ip comes from the endpoint, and two spellings of one IPv6
// address (“fd00:0:0:0:0:0:0:5“ and “fd00::5“) must not look like two
// different interfaces - that would reject a pod that is perfectly configured.
func tunnelKeyProvidersForIP(pod *slim_corev1.Pod, ip string) (providers []string, claimed bool) {
	want, err := netip.ParseAddr(ip)
	parsed := err == nil
	for annotation, value := range pod.Annotations {
		provider, ok := strings.CutSuffix(annotation, providerIPAddressSuffix)
		if !ok || provider == "" || strings.TrimSpace(value) == "" {
			continue
		}
		claimed = true
		if !parsed {
			continue
		}
		// Dual-stack addresses are comma-separated.
		for addr := range strings.SplitSeq(value, ",") {
			got, err := netip.ParseAddr(strings.TrimSpace(addr))
			if err == nil && got == want {
				providers = append(providers, provider)
				break
			}
		}
	}
	// The annotations are a map, so without this the provider picked for an
	// address two VPCs share would differ from one call to the next.
	slices.Sort(providers)
	return providers, claimed
}

// VNIFromPod applies the native-vpc decision table to the pod's primary
// network. Use VNIFromPodForIP for an endpoint whose address may belong to a
// multus attached network.
func VNIFromPod(pod *slim_corev1.Pod) (uint64, Result, error) {
	return VNIFromPodForIP(pod, "")
}

// VNIFromPodForIP applies the native-vpc decision table to a pod and returns
// the VNI (0 unless the result is Valid), the classification, and a
// descriptive error for the Absent and Invalid cases. The Absent error names
// the annotation that was read, which for an attachment is its provider's
// key, not --native-vpc-vni-annotation.
//
// ip selects the interface: when it matches the address kube-ovn allocated for
// a multus attachment, that attachment's provider-scoped tunnel_key is read,
// otherwise the primary network's configured annotation is. An address kube-ovn
// never allocated belongs to no VPC and yields Absent, and an address two of
// the pod's interfaces share yields Invalid, so the caller fails closed either
// way.
//
// Callers decide what to do with each result, but the direction is fixed:
// never merge a VPC endpoint into the plain (bare-IP) scope on Absent or
// Invalid, because that is the direction that mixes two VPCs. Endpoint
// creation rejects the pod, the running-state paths keep the last known VNI,
// and the pod watcher skips registration.
func VNIFromPodForIP(pod *slim_corev1.Pod, ip string) (uint64, Result, error) {
	if !option.Config.EnableNativeVPC || option.Config.NativeVPCVNIAnnotation == "" {
		return 0, Disabled, nil
	}
	if pod == nil {
		return 0, Absent, fmt.Errorf("missing pod metadata")
	}
	if pod.Spec.HostNetwork {
		return 0, HostNetwork, nil
	}

	key := option.Config.NativeVPCVNIAnnotation
	providers, claimed := tunnelKeyProvidersForIP(pod, ip)
	switch {
	case len(providers) == 1:
		// The primary network keeps the configured annotation: that is the one
		// --native-vpc-vni-annotation names, and overriding it with kube-ovn's
		// template would ignore a custom value and reject every pod.
		if providers[0] != primaryProvider {
			key = providers[0] + providerTunnelKeySuffix
		}
	case len(providers) > 1:
		// Two interfaces of this pod were allocated the same address in
		// different VPCs. Their VNIs differ, and nothing left here tells which
		// one this endpoint is, so no scope is better than a coin flip.
		return 0, Invalid, fmt.Errorf("address %s is claimed by %d kube-ovn providers (%s): the VPC of this interface cannot be decided",
			ip, len(providers), strings.Join(providers, ", "))
	case claimed && ip != "":
		// kube-ovn allocated addresses for this pod but not this one: the
		// interface is not on an OVN subnet and has no tunnel_key. Reporting
		// Absent makes endpoint creation reject it, instead of silently
		// adopting the primary interface's VPC.
		return 0, Absent, fmt.Errorf("missing a tunnel_key: address %s was not allocated by any kube-ovn provider of this pod", ip)
	}
	raw, ok := pod.Annotations[key]
	if !ok || strings.TrimSpace(raw) == "" {
		return 0, Absent, fmt.Errorf("missing tunnel_key annotation %q", key)
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
