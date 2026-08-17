// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package key

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/labels"
)

// TestVNIIdentityKeySeparation pins the policy-plane invariant of native-vpc:
// the numeric identity is derived from the identity label set, and the VNI
// identity label is part of it. Two pods that are identical in every other
// respect (same Kubernetes labels, and possibly the same IP in two VPCs)
// therefore never collapse into one identity, which is what keeps
// fromEndpoints/toEndpoints and the policy map VNI-scoped.
func TestVNIIdentityKeySeparation(t *testing.T) {
	withVNI := func(vni string) *GlobalIdentity {
		lbls := labels.Labels{
			"k8s:app": labels.NewLabel("app", "web", labels.LabelSourceK8s),
		}
		if vni != "" {
			lbls[labels.VNIKey] = labels.NewLabel(labels.VNIKey, vni, labels.LabelSourceVNI)
		}
		return &GlobalIdentity{LabelArray: lbls.LabelArray()}
	}

	vpcA, vpcB, plain := withVNI("36"), withVNI("17"), withVNI("")

	require.NotEqual(t, vpcA.GetKey(), vpcB.GetKey(),
		"endpoints of two VPCs must not share an identity key")
	require.NotEqual(t, vpcA.GetKey(), plain.GetKey(),
		"a VPC endpoint must not share the identity of a non-VPC endpoint")
	require.Equal(t, vpcA.GetKey(), withVNI("36").GetKey(),
		"the same VPC and labels must reuse one identity")

	// The label must be visible to selectors under its own source.
	require.Contains(t, vpcA.GetAsMap(), labels.LabelSourceVNI+":"+labels.VNIKey)
}
