// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nativevpc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/time"
)

func TestSubnetTopologyKeyIgnoresStatusOnlyChanges(t *testing.T) {
	obj := subnetObject("a", "vpc-a", "10.0.0.0/24", 58)
	before := subnetTopologyKey([]*unstructured.Unstructured{obj})
	require.NoError(t, unstructured.SetNestedField(obj.Object, int64(7), "status", "v4usingIPs"))
	require.Equal(t, before, subnetTopologyKey([]*unstructured.Unstructured{obj}))
	require.NoError(t, unstructured.SetNestedField(obj.Object, int64(59), "status", "tunnelKey"))
	require.NotEqual(t, before, subnetTopologyKey([]*unstructured.Unstructured{obj}))
}

func TestSubnetResource(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	obj := subnetObject("a", "vpc-a", "10.0.0.0/24", 58)
	obj.SetGroupVersionKind(subnetGVR.GroupVersion().WithKind("Subnet"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("watch") == "true" {
			if r.URL.Query().Get("sendInitialEvents") == "true" {
				enc := json.NewEncoder(w)
				_ = enc.Encode(map[string]any{"type": "ADDED", "object": obj})
				bookmark := obj.DeepCopy()
				bookmark.SetResourceVersion("1")
				bookmark.SetAnnotations(map[string]string{"k8s.io/initial-events-end": "true"})
				_ = enc.Encode(map[string]any{"type": "BOOKMARK", "object": bookmark})
			}
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		list := &unstructured.UnstructuredList{Items: []unstructured.Unstructured{*obj}}
		list.SetAPIVersion("kubeovn.io/v1")
		list.SetKind("SubnetList")
		list.SetResourceVersion("1")
		_ = json.NewEncoder(w).Encode(list)
	}))
	defer server.Close()
	c, err := dynamic.NewForConfig(&rest.Config{Host: server.URL})
	require.NoError(t, err)
	var events <-chan resource.Event[*unstructured.Unstructured]
	h := hive.New(cell.Invoke(func(lc cell.Lifecycle) {
		events = newSubnetResource(lc, c, nil).Events(ctx)
	}))
	logger := hivetest.Logger(t)
	require.NoError(t, h.Start(logger, ctx))
	defer func() {
		stopCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		require.NoError(t, h.Stop(logger, stopCtx))
	}()
	next := func(kind resource.EventKind) {
		t.Helper()
		select {
		case ev := <-events:
			require.Equal(t, kind, ev.Kind)
			ev.Done(nil)
		case <-ctx.Done():
			t.Fatal("timed out waiting for subnet event")
		}
	}
	next(resource.Upsert)
	next(resource.Sync)
}
