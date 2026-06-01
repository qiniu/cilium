// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/endpoint/id"
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

	// Case 2: VNIID > 0 (Native-VPC behavior)
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
}
