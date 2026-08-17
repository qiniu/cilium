// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	types "github.com/cilium/cilium/pkg/policy/types"
)

// TestVNILabelSelectorMatch verifies that the control plane injects a VNI
// identity label (source "vni", key labels.VNIKey, value "<vni>"), and a
// CNP selector on labels.VNIKey selects exactly that logical
// switch/subnet scope. Different VNIs must not match, even if they belong to
// the same aggregate kube-ovn VPC.
func TestVNILabelSelectorMatch(t *testing.T) {
	vniLabel := labels.NewLabel(labels.VNIKey, "36", labels.LabelSourceVNI)
	require.Equal(t, "vni:io-cilium-native-vpc-vni=36", vniLabel.String())

	es := api.NewESFromMatchRequirements(map[string]string{labels.VNIKey: "36"}, nil)
	sel := types.NewLabelSelector(es)

	require.True(t, sel.Matches(labels.LabelArray{vniLabel}))
	require.False(t, sel.Matches(labels.LabelArray{labels.NewLabel(labels.VNIKey, "17", labels.LabelSourceVNI)}))
}
