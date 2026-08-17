// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/annotation"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/types"
)

// TestTransformToCiliumEndpointKeepsVNIAnnotation pins the native-vpc contract
// on the informer transform: the CiliumEndpoint VNI annotation is the only way
// a watcher on another node learns the (VNI, IP) scope of a remote endpoint.
// Dropping it (as the transform does for every other annotation) would make
// every remote native-vpc endpoint unresolvable.
func TestTransformToCiliumEndpointKeepsVNIAnnotation(t *testing.T) {
	cep := &v2.CiliumEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "bar",
			Annotations: map[string]string{
				annotation.CiliumEndpointNativeVPCVNI: "36",
				"unrelated":                           "dropped",
			},
			Labels: map[string]string{"app": "dropped"},
		},
	}

	got, err := TransformToCiliumEndpoint(cep)
	require.NoError(t, err)
	slim := got.(*types.CiliumEndpoint)
	require.Equal(t, map[string]string{annotation.CiliumEndpointNativeVPCVNI: "36"}, slim.Annotations)
	require.Nil(t, slim.Labels)

	got, err = TransformToCiliumEndpoint(cache.DeletedFinalStateUnknown{Key: "bar/foo", Obj: cep})
	require.NoError(t, err)
	slim = got.(cache.DeletedFinalStateUnknown).Obj.(*types.CiliumEndpoint)
	require.Equal(t, map[string]string{annotation.CiliumEndpointNativeVPCVNI: "36"}, slim.Annotations)

	// Non native-vpc CEPs keep the previous behavior (no annotations kept).
	cep.Annotations = map[string]string{"unrelated": "dropped"}
	got, err = TransformToCiliumEndpoint(cep)
	require.NoError(t, err)
	require.Nil(t, got.(*types.CiliumEndpoint).Annotations)
}
