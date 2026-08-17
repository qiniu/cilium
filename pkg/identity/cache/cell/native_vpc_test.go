// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitycachecell

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/option"
)

// TestNativeVPCRequiresAgentManagedIdentities pins the policy-plane guard: the
// VNI identity label is computed by the agent from the pod annotation, while
// the operator's CiliumIdentity controller derives identities from pod and
// namespace labels only. With operator-managed CIDs the agent's VNI-scoped
// identities would be considered unused and garbage collected, merging every
// VPC into a single identity, so the combination must be rejected.
func TestNativeVPCRequiresAgentManagedIdentities(t *testing.T) {
	prev := option.Config.EnableNativeVPC
	t.Cleanup(func() { option.Config.EnableNativeVPC = prev })

	for _, tc := range []struct {
		mode      string
		nativeVPC bool
		reject    bool
	}{
		{mode: option.IdentityManagementModeAgent, nativeVPC: true},
		{mode: option.IdentityManagementModeOperator, nativeVPC: true, reject: true},
		{mode: option.IdentityManagementModeBoth, nativeVPC: true, reject: true},
		{mode: option.IdentityManagementModeOperator},
		{mode: option.IdentityManagementModeBoth},
	} {
		name := tc.mode
		if tc.nativeVPC {
			name += "/native-vpc"
		}
		t.Run(name, func(t *testing.T) {
			option.Config.EnableNativeVPC = tc.nativeVPC
			err := nativeVPCIdentityModeError(tc.mode)
			if !tc.reject {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, "identity-management-mode")
		})
	}
}
