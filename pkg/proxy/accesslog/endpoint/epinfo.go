// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"net/netip"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
)

// EndpointLookup is any type which maps from IP to the endpoint owning that IP.
//
// LookupCiliumID is part of the contract because the proxy usually already
// knows the endpoint id: resolving by id is exact, while a bare-IP lookup is
// ambiguous in native-vpc mode. Declaring it here rather than type-asserting
// it at the call site means a rename cannot silently degrade the access log to
// the bare-IP path.
type EndpointLookup interface {
	LookupIP(ip netip.Addr) (ep *endpoint.Endpoint)
	LookupCiliumID(id uint16) *endpoint.Endpoint
}

// endpointInfoRegistry provides a default implementation of the logger.EndpointInfoRegistry interface.
type endpointInfoRegistry struct {
	ipcache           *ipcache.IPCache
	endpointManager   EndpointLookup
	identityAllocator cache.IdentityAllocator
}

func NewEndpointInfoRegistry(ipc *ipcache.IPCache, endpointManager endpointmanager.EndpointsLookup, identityAllocator cache.IdentityAllocator) accesslog.EndpointInfoRegistry {
	// **NOTE** The global identity allocator is not yet initialized here;
	// that happens in the daemon init via InitIdentityAllocator().
	// Only the local identity allocator is initialized here.

	return &endpointInfoRegistry{
		ipcache:           ipc,
		endpointManager:   endpointManager,
		identityAllocator: identityAllocator,
	}
}

// FillEndpointInfo fills in as much information as possible from the provided information.
// It will populate empty fields on a best-effort basis.
// Resolving security labels may require accessing the kvstore; labelLookupTimeout sets
// the timeout.
func (r *endpointInfoRegistry) FillEndpointInfo(ctx context.Context, info *accesslog.EndpointInfo, addr netip.Addr) {
	if addr.IsValid() {
		if addr.Is4() {
			info.IPv4 = addr.String()
		} else {
			info.IPv6 = addr.String()
		}
	}

	// Resolve endpoint, if needed and possible.
	// This will fail if the IP does not correspond to an endpoint on this node.
	var ep *endpoint.Endpoint
	if info.ID == 0 {
		ep = endpointmanager.LookupIPUnambiguous(r.endpointManager, addr)
		if ep != nil {
			info.ID = ep.GetID()
		}
	} else {
		// The proxy already knows the local endpoint: resolve it by ID (never
		// by bare IP, which is ambiguous with overlapping VPC subnets) so that
		// the native-vpc VNI below is exact.
		ep = r.endpointManager.LookupCiliumID(uint16(info.ID))
	}

	// Native-vpc: record the (VNI, IP) scope of the endpoint so that the
	// observability plane (Hubble L7 flows) can resolve pod metadata with the
	// exact VNI-scoped key instead of a bare IP.
	if info.VNIID == 0 {
		if ep != nil {
			info.VNIID = ep.GetVNIID()
		} else if addr.IsValid() {
			if id, exists := r.ipcache.LookupSecIDByIPUnambiguous(addr); exists {
				info.VNIID = uint64(id.Vni)
			}
		}
	}

	// Only resolve the security identity if not passed in, as it may have changed since
	// reported by the proxy. This way we log the security identity and labels used for
	// policy enforcement, if any.
	if info.Identity == 0 {
		// Try and look up identity by endpoint
		if ep != nil {
			secid, err := ep.GetSecurityIdentity()
			// safe to ignore error; just means endpoint is going away.
			// this is best-effort anyways.
			if err == nil && secid != nil {
				info.Identity = uint64(secid.ID)
				info.Labels = secid.LabelArray
			}
		}

		// Fall back to ipcache. Native-vpc: use the unambiguous lookup so a
		// VNI-scoped entry is resolved when exactly one VPC uses the IP (L7
		// accesslog is best-effort; the generic key-exact lookup cannot see
		// "<ip>@vni:<vni>" entries and would degrade to WORLD).
		if info.Identity == 0 && addr.IsValid() {
			ID, exists := r.ipcache.LookupSecIDByIPUnambiguous(addr)
			if exists {
				info.Identity = uint64(ID.ID)
			}
		}

		// Default to WORLD if still unknown
		if info.Identity == 0 {
			info.Identity = uint64(identity.GetWorldIdentityFromIP(addr))
		}
	}

	// Look up security labels if not provided
	if info.Labels == nil {
		// The allocator should already have this in cache, but it may fall back to a
		// remote read if missing. So, provide the context.
		identity := r.identityAllocator.LookupIdentityByID(ctx, identity.NumericIdentity(info.Identity))
		if identity != nil {
			info.Labels = identity.LabelArray
		}
	}
}
