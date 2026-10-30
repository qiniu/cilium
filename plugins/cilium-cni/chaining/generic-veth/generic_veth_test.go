// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package genericveth

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestValidateAttachmentCEPName pins that a name which cannot form a valid
// CiliumEndpoint is refused at CNI ADD. The CEP of an attachment is
// "<pod>.7.<ifname>", so both halves matter: a legal Linux interface name like
// "vpc_0" is not a DNS-1123 label, and a long pod name can push the result past
// the 253-character limit. Accepting either would let the ADD succeed while
// every later CEP write fails, leaving the attachment without an identity on
// every other node.
func TestValidateAttachmentCEPName(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ifName string
		ok     bool
	}{
		{name: "multus default name", ifName: "net1", ok: true},
		{name: "custom dns-safe name", ifName: "vpc0", ok: true},
		{name: "with hyphen", ifName: "vpc-0", ok: true},
		{name: "underscore is legal on linux but not in a k8s name", ifName: "vpc_0"},
		{name: "uppercase", ifName: "Net1"},
		{name: "empty", ifName: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAttachmentCEPName("pod", tc.ifName)
			if tc.ok {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				// The message has to name the interface, it is the only thing
				// the operator can act on.
				require.ErrorContains(t, err, tc.ifName)
			}
		})
	}

	t.Run("the concatenation must fit a Kubernetes object name", func(t *testing.T) {
		// A pod name is a DNS-1123 subdomain, so it may be long enough on its
		// own that appending an interface name overflows the limit.
		// The separator is ".7.", so the budget for the pod name is
		// 253 - 3 - len(ifname).
		longPod := strings.Repeat("a", 250)
		require.NoError(t, validateAttachmentCEPName(longPod[:246], "net1"),
			"246 + 3 + 4 = 253 is still a valid name")
		err := validateAttachmentCEPName(longPod[:247], "net1")
		require.Error(t, err, "247 + 3 + 4 = 254 exceeds the 253 limit")
		require.ErrorContains(t, err, "CiliumEndpoint would be named")
	})

	t.Run("a workload without a pod name has no CEP to name", func(t *testing.T) {
		require.NoError(t, validateAttachmentCEPName("", "net1"))
	})
}
