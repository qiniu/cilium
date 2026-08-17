// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"encoding/json"
	"testing"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/k8s"
)

// TestJSONPointerEscape pins the RFC 6901 escaping of the CiliumEndpoint VNI
// annotation key. The key contains a '/', which unescaped would be parsed as a
// JSON Pointer path separator and would make the whole CEP patch (including
// the status replace) fail.
func TestJSONPointerEscape(t *testing.T) {
	require.Equal(t, "native-vpc.cilium.io~1vni", jsonPointerEscape(annotation.CiliumEndpointNativeVPCVNI))
	require.Equal(t, "a~0b~1c", jsonPointerEscape("a~b/c"))
	require.Equal(t, "plain", jsonPointerEscape("plain"))
}

// TestVNIAnnotationPatchApplies verifies that the patch the endpoint
// synchronizer builds actually applies, both when the CEP already has
// annotations and when the annotations object does not exist yet (an "add" on
// a missing parent member is an error in JSON Patch, so the whole map has to
// be created in that case).
func TestVNIAnnotationPatchApplies(t *testing.T) {
	apply := func(t *testing.T, doc string, patch []k8s.JSONPatch) map[string]any {
		t.Helper()
		raw, err := json.Marshal(patch)
		require.NoError(t, err)
		p, err := jsonpatch.DecodePatch(raw)
		require.NoError(t, err)
		out, err := p.Apply([]byte(doc))
		require.NoError(t, err)
		var got map[string]any
		require.NoError(t, json.Unmarshal(out, &got))
		return got
	}

	// Existing annotations: add a single escaped member, keeping the others.
	got := apply(t, `{"metadata":{"annotations":{"keep":"me"}}}`, []k8s.JSONPatch{{
		OP:    "add",
		Path:  "/metadata/annotations/" + jsonPointerEscape(annotation.CiliumEndpointNativeVPCVNI),
		Value: "36",
	}})
	annotations := got["metadata"].(map[string]any)["annotations"].(map[string]any)
	require.Equal(t, "36", annotations[annotation.CiliumEndpointNativeVPCVNI])
	require.Equal(t, "me", annotations["keep"])

	// No annotations object: create it wholesale.
	got = apply(t, `{"metadata":{}}`, []k8s.JSONPatch{{
		OP:    "add",
		Path:  "/metadata/annotations",
		Value: map[string]string{annotation.CiliumEndpointNativeVPCVNI: "36"},
	}})
	annotations = got["metadata"].(map[string]any)["annotations"].(map[string]any)
	require.Equal(t, "36", annotations[annotation.CiliumEndpointNativeVPCVNI])
}
