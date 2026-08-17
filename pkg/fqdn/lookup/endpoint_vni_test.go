// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lookup

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/option"
)

// vniEndpointManager answers the two questions the lookup asks: which endpoint
// owns this address unambiguously, and is the address in use at all.
type vniEndpointManager struct {
	endpointmanager.EndpointManager
	unambiguous *endpoint.Endpoint
	any         *endpoint.Endpoint
}

func (m vniEndpointManager) LookupIPUnambiguous(netip.Addr) *endpoint.Endpoint { return m.unambiguous }
func (m vniEndpointManager) LookupIPAnyVNI(netip.Addr) *endpoint.Endpoint      { return m.any }
func (m vniEndpointManager) LookupIP(netip.Addr) *endpoint.Endpoint            { return m.any }

// TestEndpointLookupError covers what the proxy is told when it cannot
// attribute an address.
//
// The proxy is reached from the host namespace with only the address of the
// connection, so an address several VPCs use cannot be attributed to one of
// them and the query is refused. That refusal is correct, but it looks exactly
// like an unknown address unless it says so - and the two call for opposite
// reactions from whoever is reading the log.
func TestEndpointLookupError(t *testing.T) {
	addr := netip.MustParseAddr("10.99.0.11")
	prev := option.Config.EnableNativeVPC
	t.Cleanup(func() { option.Config.EnableNativeVPC = prev })

	t.Run("an address no endpoint uses", func(t *testing.T) {
		option.Config.EnableNativeVPC = true
		err := endpointLookupError(vniEndpointManager{}, addr)
		require.ErrorContains(t, err, "cannot find endpoint")
		require.NotContains(t, err.Error(), "more than one VPC")
	})

	t.Run("an address several VPCs use", func(t *testing.T) {
		option.Config.EnableNativeVPC = true
		err := endpointLookupError(vniEndpointManager{any: &endpoint.Endpoint{}}, addr)
		require.ErrorContains(t, err, "more than one VPC")
		require.ErrorContains(t, err, addr.String())
	})

	t.Run("outside native-vpc the message is unchanged", func(t *testing.T) {
		option.Config.EnableNativeVPC = false
		err := endpointLookupError(vniEndpointManager{any: &endpoint.Endpoint{}}, addr)
		require.ErrorContains(t, err, "cannot find endpoint")
	})
}
