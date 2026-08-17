// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsproxy

import (
	"errors"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/endpoint"
)

type restoredLookupStub struct{}

func (restoredLookupStub) LookupRegisteredEndpoint(netip.Addr) (*endpoint.Endpoint, bool, error) {
	return nil, false, errors.New("endpoint manager unavailable during restore")
}
func (restoredLookupStub) LookupSecIDByIP(netip.Addr) (ipcache.Identity, bool) {
	return ipcache.Identity{}, false
}
func (restoredLookupStub) LookupSecIDByIPUnambiguous(netip.Addr) (ipcache.Identity, bool) {
	return ipcache.Identity{}, false
}
func (restoredLookupStub) LookupByIdentity(identity.NumericIdentity) []string { return nil }

// TestLookupEndpointByIPRestoredVNIOverlap exercises the actual DNS proxy
// fallback, rather than only testing the restoredEPs slice helper.
func TestLookupEndpointByIPRestoredVNIOverlap(t *testing.T) {
	ip := netip.MustParseAddr("192.168.1.2")
	p := &DNSProxy{
		proxyLookupHandler: restoredLookupStub{},
		restoredEPs:        restoredEPs{},
		restored:           perEPRestored{},
		logger:             slog.Default(),
	}
	epA := &endpoint.Endpoint{ID: 10, IPv4: ip, VNIID: 36}
	epB := &endpoint.Endpoint{ID: 11, IPv4: ip, VNIID: 17}

	p.RestoreRules(epA)
	got, _, err := p.LookupEndpointByIP(ip)
	require.NoError(t, err)
	require.Same(t, epA, got)

	p.RestoreRules(epB)
	got, _, err = p.LookupEndpointByIP(ip)
	require.Error(t, err, "same bare IP across VNIs must fail closed")
	require.Nil(t, got)

	// RestoreRules installs an empty ruleset in p.restored; removing epA must
	// retain epB's restored IP mapping.
	p.RemoveRestoredRules(epA.ID)
	got, _, err = p.LookupEndpointByIP(ip)
	require.NoError(t, err)
	require.Same(t, epB, got)

	p.RemoveRestoredRules(epB.ID)
	got, _, err = p.LookupEndpointByIP(ip)
	require.Error(t, err)
	require.Nil(t, got)
}
