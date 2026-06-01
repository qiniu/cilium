// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/option"
)

func TestIdentifiers_VNI(t *testing.T) {
	// Case 1: VNIID is 0 (Legacy/Default behavior)
	ep := &Endpoint{
		IPv4:  netip.MustParseAddr("1.1.1.1"),
		IPv6:  netip.MustParseAddr("fd00::1"),
		VNIID: 0,
	}

	ids := ep.Identifiers()
	require.Contains(t, ids, id.IPv4Prefix)
	require.Equal(t, "1.1.1.1", ids[id.IPv4Prefix])
	require.NotContains(t, ids, id.VNIIPv4Prefix)

	require.Contains(t, ids, id.IPv6Prefix)
	require.Equal(t, "fd00::1", ids[id.IPv6Prefix])
	require.NotContains(t, ids, id.VNIIPv6Prefix)

	// Case 2: VNIID > 0 with native-vpc mode enabled (Native-VPC behavior)
	origEnableNativeVPC := option.Config.EnableNativeVPC
	t.Cleanup(func() { option.Config.EnableNativeVPC = origEnableNativeVPC })
	option.Config.EnableNativeVPC = true

	epVNI := &Endpoint{
		IPv4:  netip.MustParseAddr("1.1.1.1"),
		IPv6:  netip.MustParseAddr("fd00::1"),
		VNIID: 100,
	}

	idsVNI := epVNI.Identifiers()
	// IPv4: Should HAVE VNI prefix, should NOT have legacy prefix
	require.Contains(t, idsVNI, id.VNIIPv4Prefix)
	require.Equal(t, "100:1.1.1.1", idsVNI[id.VNIIPv4Prefix])
	require.NotContains(t, idsVNI, id.IPv4Prefix)

	// IPv6: Should HAVE VNI prefix, should NOT have legacy prefix
	require.Contains(t, idsVNI, id.VNIIPv6Prefix)
	require.Equal(t, "100:fd00::1", idsVNI[id.VNIIPv6Prefix])
	require.NotContains(t, idsVNI, id.IPv6Prefix)

	// Case 3: VNIID > 0 but native-vpc mode DISABLED globally.
	// The VNI must be ignored and the endpoint must fall back to the legacy
	// IP-only identifiers, otherwise a stale/injected VNI would bypass the
	// standard IP-based lookups and conflict checks.
	option.Config.EnableNativeVPC = false

	idsNoVPC := epVNI.Identifiers()
	require.Contains(t, idsNoVPC, id.IPv4Prefix)
	require.Equal(t, "1.1.1.1", idsNoVPC[id.IPv4Prefix])
	require.NotContains(t, idsNoVPC, id.VNIIPv4Prefix)

	require.Contains(t, idsNoVPC, id.IPv6Prefix)
	require.Equal(t, "fd00::1", idsNoVPC[id.IPv6Prefix])
	require.NotContains(t, idsNoVPC, id.VNIIPv6Prefix)
}
