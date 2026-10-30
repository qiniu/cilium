// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"fmt"
	"net"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/endpoint"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/node"
)

func Test_updateCEPUID(t *testing.T) {
	logger := hivetest.Logger(t)
	podWithHostIP := func(hostIP string) *slim_corev1.Pod {
		return &slim_corev1.Pod{
			Status: slim_corev1.PodStatus{
				HostIP: hostIP,
			},
		}
	}
	podNamed := func(name, hostIP string) *slim_corev1.Pod {
		return &slim_corev1.Pod{
			ObjectMeta: slim_metav1.ObjectMeta{Name: name},
			Status:     slim_corev1.PodStatus{HostIP: hostIP},
		}
	}
	epWithUID := func(uid string, pod *slim_corev1.Pod) *endpoint.Endpoint {
		ep := &endpoint.Endpoint{}
		if pod != nil {
			// The CEP name, and therefore the ownership check, is derived from
			// the pod name the endpoint carries.
			ep.K8sPodName = pod.Name
		}
		ep.SetPod(pod)
		ep.SetCiliumEndpointUID(types.UID(uid))
		return ep
	}
	testIP := "1.2.3.4"
	someUID := func(s string) *types.UID {
		id := types.UID(s)
		return &id
	}
	for name, test := range map[string]struct {
		err           error
		cep           *v2.CiliumEndpoint
		ep            *endpoint.Endpoint
		nodeIP        string
		expectedEPUID *types.UID
	}{
		// In this test, our CEP has a UID that is different from the local Endpoint.
		// This means that the CEP is not owned by this EP.
		// Ownership should fail due to Endpoint not having a pod.
		// This condition is typically triggered when the pod is deleted.
		"no pod": {
			ep:     epWithUID("000", nil),
			err:    fmt.Errorf("no pod"),
			nodeIP: testIP,
			cep: &v2.CiliumEndpoint{
				ObjectMeta: v1.ObjectMeta{
					UID: "111", // Different UID from the local Endpoint.
				},
			},
		},
		"CiliumEndpoint not local": {
			// The CEP is explicitly not local (i.e the CEP's pod's hostIP doesn't match the nodeIP).
			ep:     epWithUID("1234", podWithHostIP(testIP)),
			nodeIP: "4.3.2.1",
			err:    fmt.Errorf("is not local"),
			cep: &v2.CiliumEndpoint{
				ObjectMeta: v1.ObjectMeta{UID: "1111"},
			},
		},
		"CiliumEndpoint not local, but already owned": {
			// The CEP is explicitly not local. But the CEP is already owned by the endpoint.
			// So ownership should proceed without error.
			ep:     epWithUID("000", podWithHostIP("4.3.2.1")), // matches CEP.
			nodeIP: testIP,
			cep: &v2.CiliumEndpoint{
				ObjectMeta: v1.ObjectMeta{UID: "000"},
			},
		},
		"ciliumendpoint already exists": {
			// CEP already exists, on the same node, we cannot take ownership of it
			// due to differing UID ref.
			//
			// This would be the case where two endpoint sync controllers are running for
			// a Pod with the same namespace/name on the same Agent, so we'd have to wait
			// until the other controller terminates and cleans up the CEP.
			err:           fmt.Errorf("did not match CEP UID"),
			expectedEPUID: someUID("b"),
			ep:            epWithUID("b", podWithHostIP(testIP)),
			nodeIP:        testIP,
			cep: &v2.CiliumEndpoint{
				ObjectMeta: v1.ObjectMeta{UID: types.UID("a")},
			},
		},
		"ciliumendpoint belongs to another pod": {
			// Pod "app" with an attachment "net1" publishes the CEP
			// "app.7.net1"; a pod literally named "app.7.net1" then finds an
			// object of its own name on its own node. Its CEP name equals its
			// pod name, so nothing but the owner separates the two - and
			// taking it over would leave both synchronizers writing one
			// object, each able to delete it.
			err:    fmt.Errorf("belongs to pod"),
			ep:     epWithUID("", podNamed("app.7.net1", testIP)),
			nodeIP: testIP,
			cep: &v2.CiliumEndpoint{
				ObjectMeta: v1.ObjectMeta{
					Name: "app.7.net1",
					UID:  types.UID("a"),
					OwnerReferences: []v1.OwnerReference{
						{Kind: "Pod", Name: "app", UID: types.UID("uid-app")},
					},
				},
			},
		},
		"ciliumendpoint of a pod recreated under the same name": {
			// A StatefulSet pod keeps its name across restarts and has to go
			// on adopting its own CEP, which still references the previous
			// incarnation's UID. This is what the adoption path exists for.
			ep:            epWithUID("", podNamed("app-0", testIP)),
			nodeIP:        testIP,
			expectedEPUID: someUID("a"),
			cep: &v2.CiliumEndpoint{
				ObjectMeta: v1.ObjectMeta{
					Name: "app-0",
					UID:  types.UID("a"),
					OwnerReferences: []v1.OwnerReference{
						{Kind: "Pod", Name: "app-0", UID: types.UID("uid-previous")},
					},
				},
			},
		},
		// This is the normal case of taking ownership.
		// Note that this also happens when the nodeIP changes during a reboot
		// but the endpoint snapshot is lost on reboot. The endpoint UID will
		// remain empty, but the CEP object will have a UID and a wrong nodeIP.
		// It is to counter this case that we check the pods hostIP against the
		// nodeIP instaed of the CEP's node IP.
		"take ownership of cep due to empty CiliumEndpointUID ref": {
			ep:            epWithUID("", podWithHostIP(testIP)),
			nodeIP:        testIP,
			expectedEPUID: someUID("a"),
			cep: &v2.CiliumEndpoint{
				ObjectMeta: v1.ObjectMeta{UID: types.UID("a")},
				Status: v2.EndpointStatus{
					Networking: &v2.EndpointNetworking{
						NodeIP: "4.5.6.7",
					},
				},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			var err error
			node.WithTestLocalNodeStore(func() {
				node.UpdateLocalNodeInTest(func(n *node.LocalNode) {
					n.SetNodeInternalIP(net.ParseIP(test.nodeIP))
				})
				err = updateCEPUID(logger, test.ep, test.cep)
			})
			if test.err == nil {
				assert.NoError(err)
			} else {
				assert.ErrorContains(err, test.err.Error())
			}
			if test.expectedEPUID != nil {
				assert.Equal(*test.expectedEPUID, test.ep.GetCiliumEndpointUID())
			}
		})

	}
}

// TestCEPOwnerConflict pins which CiliumEndpoint an endpoint may take over. The
// CEP name of an attachment ("<pod>.7.<ifname>") is a name another pod can
// carry, so the object's owner decides - and it must decide in both
// directions, or the pod-named side silently takes the attachment's object and
// two synchronizers end up writing one CEP.
func TestCEPOwnerConflict(t *testing.T) {
	cepWithOwner := func(ownerName string) *v2.CiliumEndpoint {
		cep := &v2.CiliumEndpoint{ObjectMeta: v1.ObjectMeta{Name: "app.7.net1", Namespace: "default"}}
		if ownerName != "" {
			cep.OwnerReferences = []v1.OwnerReference{{Kind: "Pod", Name: ownerName, UID: types.UID("uid-" + ownerName)}}
		}
		return cep
	}

	// The attachment of pod "app" owns it.
	assert.NoError(t, cepOwnerConflict(cepWithOwner("app"), "app"))
	// A pod that merely carries the name must not take it over...
	assert.Error(t, cepOwnerConflict(cepWithOwner("app"), "app.7.net1"))
	// ...and neither direction is exempt.
	assert.Error(t, cepOwnerConflict(cepWithOwner("app.7.net1"), "app"))

	// A pod recreated under the same name (a StatefulSet restart) has a new
	// UID but the same name, and has to keep adopting its own CEP: that is
	// what this adoption path exists for.
	recreated := cepWithOwner("app.7.net1")
	recreated.OwnerReferences[0].UID = "uid-previous-incarnation"
	assert.NoError(t, cepOwnerConflict(recreated, "app.7.net1"))

	// A CEP without a pod owner reference predates the convention: no evidence
	// of another owner, so it is adopted as before.
	assert.NoError(t, cepOwnerConflict(cepWithOwner(""), "app.7.net1"))
}
