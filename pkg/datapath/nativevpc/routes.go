// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nativevpc

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
)

type subnet struct {
	vni      uint32
	prefixes []netip.Prefix
}

func peerRoutes(objects []*unstructured.Unstructured) (map[ipcachemap.VniKey]routeValue, error) {
	vpcs := map[string][]subnet{}
	invalidVPCs := map[string]error{}
	vniOwners := map[uint32]string{}

	for _, obj := range objects {
		vpc, _, _ := unstructured.NestedString(obj.Object, "spec", "vpc")
		vni, _, err := unstructured.NestedInt64(obj.Object, "status", "tunnelKey")
		if err != nil {
			if vpc != "" {
				invalidVPCs[vpc] = fmt.Errorf("subnet %s tunnel key: %w", obj.GetName(), err)
			}
			continue
		}
		if obj.GetDeletionTimestamp() != nil || vpc == "" || vni == 0 {
			continue
		}
		if vni < 0 || vni > 0xffffff {
			invalidVPCs[vpc] = fmt.Errorf("subnet %s has invalid VNI %d", obj.GetName(), vni)
			continue
		}
		if owner, ok := vniOwners[uint32(vni)]; ok {
			err := fmt.Errorf("VNI %d is used by VPCs %s and %s", vni, owner, vpc)
			invalidVPCs[owner] = err
			invalidVPCs[vpc] = err
			continue
		}
		vniOwners[uint32(vni)] = vpc

		cidrs, _, _ := unstructured.NestedString(obj.Object, "spec", "cidrBlock")
		s := subnet{vni: uint32(vni)}
		for cidr := range strings.SplitSeq(cidrs, ",") {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
			if err != nil || prefix.Addr().Is4In6() {
				invalidVPCs[vpc] = fmt.Errorf("subnet %s has invalid CIDR %q", obj.GetName(), cidr)
				s.prefixes = nil
				break
			}
			s.prefixes = append(s.prefixes, prefix.Masked())
		}
		vpcs[vpc] = append(vpcs[vpc], s)
	}

	for vpc, subnets := range vpcs {
		for i, local := range subnets {
			for j := i + 1; j < len(subnets); j++ {
				peer := subnets[j]
				if slices.ContainsFunc(local.prefixes, func(own netip.Prefix) bool {
					return slices.ContainsFunc(peer.prefixes, own.Overlaps)
				}) {
					invalidVPCs[vpc] = fmt.Errorf("overlapping subnets (VNIs %d and %d)", local.vni, peer.vni)
				}
			}
		}
	}
	var errs []error
	for vpc, err := range invalidVPCs {
		errs = append(errs, fmt.Errorf("VPC %s: %w", vpc, err))
		delete(vpcs, vpc)
	}

	routes := map[ipcachemap.VniKey]routeValue{}
	for _, subnets := range vpcs {
		for _, local := range subnets {
			for _, peer := range subnets {
				if local.vni == peer.vni {
					continue
				}
				for _, prefix := range peer.prefixes {
					key := ipcachemap.NewVniKey(net.IP(prefix.Addr().AsSlice()), net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()), local.vni)
					routes[key] = routeValue{VNI: peer.vni}
				}
			}
		}
	}
	return routes, errors.Join(errs...)
}
