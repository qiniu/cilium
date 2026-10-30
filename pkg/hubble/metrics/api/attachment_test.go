// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	pb "github.com/cilium/cilium/api/v1/flow"
	slimmeta "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
)

func TestAttachmentDeletionPreservesCollidingPodMetrics(t *testing.T) {
	registry := prometheus.NewRegistry()
	opts, err := ParseContextOptions([]*ContextOptionConfig{{Name: "sourceContext", Values: []string{"pod"}}})
	require.NoError(t, err)
	handlers := initHandlers(t, opts, registry, hivetest.Logger(t))
	for _, name := range []string{"app", "app.7.net1"} {
		ExecuteAllProcessFlow(t.Context(), &pb.Flow{Source: &pb.Endpoint{Namespace: "default", PodName: name}}, *handlers)
	}
	verifyMetricSeriesExists(t, registry, 2)
	// The main CEP is deleted first, followed by its attachment CEP.
	ProcessCiliumEndpointDeletion(&types.CiliumEndpoint{ObjectMeta: slimmeta.ObjectMeta{Name: "app", Namespace: "default"}}, *handlers)
	ProcessCiliumEndpointDeletion(&types.CiliumEndpoint{ObjectMeta: slimmeta.ObjectMeta{Name: "app.7.net1", Namespace: "default", OwnerReferences: []slimmeta.OwnerReference{{Kind: "Pod", Name: "app"}}}}, *handlers)
	verifyMetricSeriesExists(t, registry, 1)
	families, err := registry.Gather()
	require.NoError(t, err)
	require.Equal(t, "default/app.7.net1", families[0].Metric[0].Label[0].GetValue())
}
