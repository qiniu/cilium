// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/cilium/cilium/api/v1/flow"
)

// TestVNIContext verifies the native-vpc metrics context: flows of two VPCs
// that share an IP/pod name must be distinguishable by the VNI label, and
// non-VPC endpoints must yield an empty value so that a "vni|pod" context
// falls through to the next identifier.
func TestVNIContext(t *testing.T) {
	opts, err := ParseContextOptions([]*ContextOptionConfig{
		{Name: "sourceContext", Values: []string{"vni"}},
		{Name: "destinationContext", Values: []string{"vni", "ip"}},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"source", "destination"}, opts.GetLabelNames())

	flow := &pb.Flow{
		IP:          &pb.IP{Source: "10.16.32.10", Destination: "10.16.32.20"},
		Source:      &pb.Endpoint{PodName: "client", Namespace: "vpc-a", VniId: 36},
		Destination: &pb.Endpoint{PodName: "server", Namespace: "vpc-a", VniId: 36},
	}
	values, err := opts.GetLabelValues(flow)
	require.NoError(t, err)
	assert.Equal(t, []string{"36", "36"}, values)

	// Same IPs, other VPC: the metric series must not be shared.
	flow.Source.VniId, flow.Destination.VniId = 17, 17
	values, err = opts.GetLabelValues(flow)
	require.NoError(t, err)
	assert.Equal(t, []string{"17", "17"}, values)

	// Non-VPC destination (node/world): empty VNI falls through to "ip".
	flow.Destination = &pb.Endpoint{}
	values, err = opts.GetLabelValues(flow)
	require.NoError(t, err)
	assert.Equal(t, []string{"17", "10.16.32.20"}, values)
}

// TestVNILabelsContext verifies the source_vni/destination_vni labelsContext.
func TestVNILabelsContext(t *testing.T) {
	opts, err := ParseContextOptions([]*ContextOptionConfig{
		{Name: "labelsContext", Values: []string{"source_vni", "destination_vni", "source_pod"}},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"source_pod", "source_vni", "destination_vni"}, opts.GetLabelNames())

	values, err := opts.GetLabelValues(&pb.Flow{
		Source:      &pb.Endpoint{PodName: "client", VniId: 36},
		Destination: &pb.Endpoint{PodName: "server"},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"client", "36", ""}, values)
}
