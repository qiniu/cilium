// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/controller"
	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/endpoint"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slimmeta "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy"
)

func TestLabelSyncWaitsForCEPPublication(t *testing.T) {
	logger := hivetest.Logger(t)
	_, client := k8sClient.NewFakeClientset(logger)
	repo := policy.NewPolicyRepository(logger, nil, nil, nil, nil, nil)
	ep, err := endpoint.NewEndpointFromChangeModel(t.Context(), logger, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, repo, nil, nil, nil, nil, nil,
		&models.EndpointChangeRequest{ID: 4242, K8sPodName: "client", K8sNamespace: "default"}, fakeTypes.WireguardConfig{}, fakeTypes.IPsecConfig{}, nil, nil)
	require.NoError(t, err)
	ep.SetPod(&corev1.Pod{ObjectMeta: slimmeta.ObjectMeta{Name: "client", Namespace: "default", Labels: map[string]string{"app": "old"}}})
	updateCiliumEndpointLabels(logger, client, ep, map[string]string{"app": "new"})
	// Wait until the initial attempt has run without a CEP UID.
	name := fmt.Sprintf("sync-pod-labels-with-cilium-endpoint (%v)", ep.GetID())
	require.Eventually(t, func() bool {
		for _, s := range controller.GetGlobalStatus() {
			if s.Name == name {
				return s.Status.FailureCount > 0 || s.Status.SuccessCount > 0
			}
		}
		return false
	}, time.Second, 10*time.Millisecond)
	_, err = client.CiliumV2().CiliumEndpoints("default").Create(t.Context(), &v2.CiliumEndpoint{ObjectMeta: metav1.ObjectMeta{Name: "client", Namespace: "default", UID: "cep-uid", Labels: map[string]string{"app": "old"}}}, metav1.CreateOptions{})
	require.NoError(t, err)
	ep.SetCiliumEndpointUID("cep-uid")
	require.Eventually(t, func() bool {
		cep, err := client.CiliumV2().CiliumEndpoints("default").Get(context.Background(), "client", metav1.GetOptions{})
		return err == nil && cep.Labels["app"] == "new"
	}, 10*time.Second, 20*time.Millisecond, "labels must converge without a second Pod event")
}

// TestLabelSyncRefusesAnotherPodsCEP pins the collision guard: an attachment's
// CEP name ("<pod>.7.<ifname>") is one another pod can carry, so the label
// patch must only apply to the object this endpoint published.
func TestLabelSyncRefusesAnotherPodsCEP(t *testing.T) {
	logger := hivetest.Logger(t)
	_, client := k8sClient.NewFakeClientset(logger)
	repo := policy.NewPolicyRepository(logger, nil, nil, nil, nil, nil)
	ep, err := endpoint.NewEndpointFromChangeModel(t.Context(), logger, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, repo, nil, nil, nil, nil, nil,
		&models.EndpointChangeRequest{ID: 4243, K8sPodName: "client", K8sNamespace: "default"}, fakeTypes.WireguardConfig{}, fakeTypes.IPsecConfig{}, nil, nil)
	require.NoError(t, err)
	ep.SetPod(&corev1.Pod{ObjectMeta: slimmeta.ObjectMeta{Name: "client", Namespace: "default"}})
	_, err = client.CiliumV2().CiliumEndpoints("default").Create(t.Context(), &v2.CiliumEndpoint{ObjectMeta: metav1.ObjectMeta{Name: "client", Namespace: "default", UID: "other-pods-cep", Labels: map[string]string{"app": "old"}}}, metav1.CreateOptions{})
	require.NoError(t, err)
	ep.SetCiliumEndpointUID("cep-uid")
	updateCiliumEndpointLabels(logger, client, ep, map[string]string{"app": "new"})
	name := fmt.Sprintf("sync-pod-labels-with-cilium-endpoint (%v)", ep.GetID())
	require.Eventually(t, func() bool {
		for _, s := range controller.GetGlobalStatus() {
			if s.Name == name {
				return s.Status.FailureCount > 0
			}
		}
		return false
	}, 5*time.Second, 10*time.Millisecond, "the UID test must reject the patch")
	cep, err := client.CiliumV2().CiliumEndpoints("default").Get(context.Background(), "client", metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, "old", cep.Labels["app"], "another pod's CEP must not be written")
}
