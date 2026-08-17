// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestVPCEndpointPolicy covers what the proxy may be told about an endpoint
// that lives in a VPC.
//
// Envoy finds the policy of a connection by the endpoint's address. With
// overlapping VPC subnets that address is shared, so a policy pushed for one
// endpoint would be found for an endpoint in another VPC, and the last endpoint
// to regenerate would decide what the proxy enforces for all of them. Nothing
// is pushed for such an endpoint, and a policy that only the proxy could
// enforce is refused rather than applied to whoever shares the address.
func TestVPCEndpointPolicy(t *testing.T) {
	t.Run("no proxy policy is pushed", func(t *testing.T) {
		err, revert := vpcEndpointPolicy(5, 42, false)
		require.NoError(t, err)
		require.NotNil(t, revert, "the caller pushes this onto its revert stack")
		require.NoError(t, revert())
	})

	t.Run("a policy that needs the proxy is refused", func(t *testing.T) {
		err, _ := vpcEndpointPolicy(5, 42, true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "native-vpc")
		require.Contains(t, err.Error(), "VPC 5")
	})
}
