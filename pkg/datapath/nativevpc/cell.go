// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nativevpc

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"native-vpc-peer-routes",
	"Resolve peer subnet VNIs within a kube-ovn VPC",
	cell.Invoke(register),
)

type params struct {
	cell.In
	Lifecycle cell.Lifecycle
	Jobs      job.Group
	Client    client.Clientset
	Metrics   workqueue.MetricsProvider
}

// routeValue must match the value of cilium_vni_routes in bpf/lib/eps.h.
type routeValue struct {
	VNI uint32
}

func (v *routeValue) String() string    { return fmt.Sprint(v.VNI) }
func (v *routeValue) New() bpf.MapValue { return &routeValue{} }

type routeMap interface {
	Update(bpf.MapKey, bpf.MapValue) error
	Delete(bpf.MapKey) error
}

func register(p params) error {
	if !option.Config.EnableNativeVPC || !p.Client.IsEnabled() {
		return nil
	}
	c, err := dynamic.NewForConfig(p.Client.RestConfig())
	if err != nil {
		return err
	}
	r := newSubnetResource(p.Lifecycle, c, p.Metrics)
	m := bpf.NewMap("cilium_vni_routes", ebpf.LPMTrie, &ipcachemap.VniKey{}, &routeValue{},
		65536, unix.BPF_F_NO_PREALLOC|unix.BPF_F_RDONLY_PROG)
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			if err := m.OpenOrCreate(); err != nil {
				return err
			}
			// Never reuse routes from a previous agent's VPC membership snapshot.
			return m.DeleteAll()
		},
		OnStop: func(cell.HookContext) error { return m.Close() },
	})
	p.Jobs.Add(job.OneShot("watch-subnets", func(ctx context.Context, health cell.Health) error {
		store, err := r.Store(ctx)
		if err != nil {
			return err
		}
		installed := map[ipcachemap.VniKey]routeValue{}
		topologyKey := ""
		synced := false
		events := r.Events(ctx)
		for {
			select {
			case <-ctx.Done():
				return nil
			case ev, ok := <-events:
				if !ok {
					return nil
				}
				if ev.Kind != resource.Sync && !synced {
					ev.Done(nil)
					continue
				}

				synced = true
				err = syncTopology(m, installed, &topologyKey, store)
				ev.Done(err)
				if err != nil {
					health.Degraded("Unable to resolve native-vpc peer subnets", err)
				} else {
					health.OK("Native-vpc peer routes synchronized")
				}
			}
		}
	}))
	return nil
}

var subnetGVR = schema.GroupVersionResource{Group: "kubeovn.io", Version: "v1", Resource: "subnets"}

func subnetTopologyKey(objects []*unstructured.Unstructured) string {
	parts := make([]string, 0, len(objects))
	for _, obj := range objects {
		vni, _, _ := unstructured.NestedInt64(obj.Object, "status", "tunnelKey")
		vpc, _, _ := unstructured.NestedString(obj.Object, "spec", "vpc")
		cidr, _, _ := unstructured.NestedString(obj.Object, "spec", "cidrBlock")
		parts = append(parts, fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%t", obj.GetName(), vpc, cidr, vni, obj.GetDeletionTimestamp() != nil))
	}
	sort.Strings(parts)
	return strings.Join(parts, "\x00")
}

func newSubnetResource(lc cell.Lifecycle, c dynamic.Interface, metrics workqueue.MetricsProvider) resource.Resource[*unstructured.Unstructured] {
	return resource.New[*unstructured.Unstructured](lc,
		utils.ListerWatcherFromTyped[*unstructured.UnstructuredList](c.Resource(subnetGVR)), metrics,
		resource.WithMetric("NativeVPCSubnet"),
		// Unlike typed Kubernetes objects, a nil Unstructured cannot report its GVK.
		resource.WithLazyTransform(func() runtime.Object {
			obj := &unstructured.Unstructured{}
			obj.SetGroupVersionKind(subnetGVR.GroupVersion().WithKind("Subnet"))
			return obj
		}, nil))
}

func syncTopology(m routeMap, installed map[ipcachemap.VniKey]routeValue, topologyKey *string, store resource.Store[*unstructured.Unstructured]) error {
	// Informer objects are immutable; one list keeps the key and applied routes consistent.
	subnets := store.List()
	key := subnetTopologyKey(subnets)
	if *topologyKey != "" && key == *topologyKey {
		return nil
	}
	if err := syncRoutes(m, installed, subnets); err != nil {
		// A failed sync may already have removed or replaced routes.
		*topologyKey = ""
		return err
	}
	*topologyKey = key
	return nil
}

func syncRoutes(m routeMap, installed map[ipcachemap.VniKey]routeValue, subnets []*unstructured.Unstructured) error {
	desired, parseErr := peerRoutes(subnets)
	// Invalid or ambiguous membership revokes old routes rather than retaining them.
	for key, value := range installed {
		if wanted, ok := desired[key]; ok && wanted == value {
			continue
		}
		if err := m.Delete(&key); err != nil {
			return errors.Join(parseErr, err)
		}
		delete(installed, key)
	}
	for key, value := range desired {
		if installed[key] == value {
			continue
		}
		if err := m.Update(&key, &value); err != nil {
			return errors.Join(parseErr, err)
		}
		installed[key] = value
	}
	return parseErr
}
