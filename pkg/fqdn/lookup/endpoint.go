// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lookup

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

type ProxyLookupHandler interface {
	// LookupSecIDByIP looks up the security ID for a given IP address from the
	// key-exact (bare-IP) ipcache entry.
	LookupSecIDByIP(ip netip.Addr) (secID ipcache.Identity, exists bool)

	// LookupSecIDByIPUnambiguous is the explicit best-effort exception used by
	// the DNS proxy: if the bare-IP entry is absent it resolves a native-vpc
	// VNI-scoped entry only when exactly one VPC uses the IP, and reports a
	// miss under overlap rather than guessing a VPC.
	LookupSecIDByIPUnambiguous(ip netip.Addr) (secID ipcache.Identity, exists bool)

	// LookupByIdentity is a provided callback that returns the IPs of a given security ID.
	LookupByIdentity(nid identity.NumericIdentity) []string

	// LookupRegisteredEndpoint looks up non-VPC endpoints by bare IP. Native-VPC
	// endpoints require VNI context and are intentionally unresolved here.
	LookupRegisteredEndpoint(endpointAddr netip.Addr) (endpoint *endpoint.Endpoint, isHost bool, err error)
}

type proxyLookupHandler struct {
	ipCache         *ipcache.IPCache
	localNodeStore  *node.LocalNodeStore
	endpointManager endpointmanager.EndpointManager
}

var _ ProxyLookupHandler = &proxyLookupHandler{}

func (p *proxyLookupHandler) LookupRegisteredEndpoint(endpointAddr netip.Addr) (endpoint *endpoint.Endpoint, isHost bool, err error) {
	if e := endpointmanager.LookupIPUnambiguous(p.endpointManager, endpointAddr); e != nil {
		return e, e.IsHost(), nil
	}

	localNode, err := p.localNodeStore.Get(context.Background())
	if err != nil {
		return nil, true, fmt.Errorf("local node has not been initialized yet: %w", err)
	}

	if localNode.IsNodeIP(endpointAddr) != "" {
		if e := p.endpointManager.GetHostEndpoint(); e != nil {
			return e, true, nil
		} else {
			return nil, true, errors.New("host endpoint has not been created yet")
		}
	}

	return nil, false, endpointLookupError(p.endpointManager, endpointAddr)
}

// endpointLookupError explains why an address could not be attributed to an
// endpoint.
//
// The proxy is reached from the host namespace and has only the address of the
// connection to work with. That is enough while an address belongs to one
// endpoint, and it stops being enough the moment several VPCs use it: the
// lookup then refuses to answer rather than picking one of them, and the query
// is dropped. Saying which of the two situations it is turns a stream of
// "cannot find endpoint" failures into something an operator can act on -
// either the address really is unknown, or DNS policy cannot be applied to this
// address at all.
func endpointLookupError(mgr endpointmanager.EndpointManager, addr netip.Addr) error {
	if option.Config.EnableNativeVPC && endpointmanager.LookupIPAnyVNI(mgr, addr) != nil {
		return fmt.Errorf("cannot attribute IP %s to an endpoint: it is used by endpoints in more than one VPC, "+
			"and the proxy sees only the address", addr)
	}
	return fmt.Errorf("cannot find endpoint with IP %s", addr)
}

func (p *proxyLookupHandler) LookupSecIDByIP(ip netip.Addr) (secID ipcache.Identity, exists bool) {
	return p.ipCache.LookupSecIDByIP(ip)
}

func (p *proxyLookupHandler) LookupSecIDByIPUnambiguous(ip netip.Addr) (secID ipcache.Identity, exists bool) {
	return p.ipCache.LookupSecIDByIPUnambiguous(ip)
}

func (p *proxyLookupHandler) LookupByIdentity(nid identity.NumericIdentity) []string {
	return p.ipCache.LookupByIdentity(nid)
}
