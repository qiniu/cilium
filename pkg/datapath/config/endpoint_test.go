// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"testing"

	"github.com/stretchr/testify/require"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

// TestEndpointCniChainingGenericVeth pins the gate of the ingress bandwidth
// policer in cil_to_container: it must be on exactly for generic-veth CNI
// chaining, where the chained CNI delivers to the pod itself and
// local_delivery() never runs, and off everywhere else, where local_delivery()
// already meters the packet. Getting this wrong either loses the limit or
// meters the same packet twice.
func TestEndpointCniChainingGenericVeth(t *testing.T) {
	old := option.Config.CNIChainingMode
	t.Cleanup(func() { option.Config.CNIChainingMode = old })

	ep := testutils.NewTestEndpoint(t)
	lnc := &datapath.LocalNodeConfiguration{EgressIfbIfIndex: 7}

	for mode, want := range map[string]bool{
		"generic-veth": true,
		"none":         false,
		"aws-cni":      false,
		"":             false,
	} {
		option.Config.CNIChainingMode = mode
		cfg := Endpoint(&ep, lnc).(*BPFLXC)
		require.Equal(t, want, cfg.CniChainingGenericVeth, "chaining mode %q", mode)
		// The datapath reads the pacing device from here: a zero ifindex
		// turns the egress pacing redirect off.
		require.Equal(t, uint32(7), cfg.BwmIfbIfIndex, "chaining mode %q", mode)
	}
}
