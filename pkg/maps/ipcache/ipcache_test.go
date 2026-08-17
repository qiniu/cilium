// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"net"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
)

func TestRemoteEndpointInfoFlagsStringReturnsCorrectValue(t *testing.T) {
	type stringTest struct {
		name string
		in   RemoteEndpointInfoFlags
		out  string
	}

	tests := []stringTest{
		{
			name: "no flags",
			in:   0,
			out:  "<none>",
		},
		{
			name: "FlagSkipTunnel",
			in:   FlagSkipTunnel,
			out:  "skiptunnel",
		},
		{
			name: "Multiple flags",
			in:   FlagSkipTunnel | FlagIPv6TunnelEndpoint,
			out:  "skiptunnel,ipv6tunnel",
		},
	}

	for _, test := range tests {
		if s := test.in.String(); s != test.out {
			t.Errorf(
				"Expected '%s' for string representation of %s, instead got '%s'",
				test.out, test.name, s,
			)
		}
	}
}

func TestVniKeyConstruction(t *testing.T) {
	// Cross-language layout contract: struct ipcache_vni_key in bpf/lib/eps.h
	// is __packed and MUST have the same size (28 bytes) so that the LPM
	// static prefix (64 bits) computed by getVniStaticPrefixBits() matches
	// IPCACHE_VNI_STATIC_PREFIX on the BPF side. If this fails, BPF lookups in
	// cilium_ipcache_vni never match Go-written entries and the agent-created
	// map is incompatible with the BPF ELF (ErrMapIncompatible).
	require.Equal(t, uint64(28), uint64(unsafe.Sizeof(VniKey{})),
		"VniKey size must stay in sync with struct ipcache_vni_key in bpf/lib/eps.h")
	require.Equal(t, uint32(64), getVniStaticPrefixBits(),
		"static prefix must match IPCACHE_VNI_STATIC_PREFIX (64 bits) in bpf/lib/eps.h")
	require.Equal(t, uint64(12), uint64(unsafe.Offsetof(VniKey{}.IP)),
		"IP offset must match the packed C union offset")

	// The real invariant behind the static prefix: it must cover exactly the
	// key bits that precede the IP. If padding is placed after the IP the two
	// numbers diverge, and every entry shorter than a host prefix silently
	// stops matching (only addresses whose remaining bytes are zero would).
	ipBitOffset := uint32(unsafe.Offsetof(VniKey{}.IP)-unsafe.Sizeof(VniKey{}.Prefixlen)) * 8
	require.Equal(t, ipBitOffset, getVniStaticPrefixBits(),
		"the static prefix must equal the bit offset of the IP field within the LPM key data")

	ip := net.ParseIP("192.168.1.2")
	mask := net.CIDRMask(32, 32)
	k := NewVniKey(ip, mask, 36)

	require.Equal(t, uint32(36), k.Vni)
	require.Equal(t, bpf.EndpointKeyIPv4, k.Family)
	// static prefix (vni 32 + pad1 8 + family 8 + pad2 16) + /32
	require.Equal(t, getVniStaticPrefixBits()+32, k.Prefixlen)
	require.Equal(t, "192.168.1.2/32@vni:36", k.String())

	// /24 CIDR entry in the VNI map: the prefix length must cover the static
	// part plus exactly 24 IP bits, so that the trie matches every address of
	// the subnet and not only those ending in zero.
	k24 := NewVniKey(net.ParseIP("192.168.1.0"), net.CIDRMask(24, 32), 17)
	require.Equal(t, getVniStaticPrefixBits()+24, k24.Prefixlen)
	require.Equal(t, "192.168.1.0/24@vni:17", k24.String())
	require.Equal(t, uint32(unsafe.Offsetof(VniKey{}.IP)-unsafe.Sizeof(VniKey{}.Prefixlen))*8+24, k24.Prefixlen,
		"a /24 must match on the first three IP bytes only")

	// IPv6.
	k6 := NewVniKey(net.ParseIP("fd00::1"), net.CIDRMask(128, 128), 10)
	require.Equal(t, bpf.EndpointKeyIPv6, k6.Family)
	require.Equal(t, getVniStaticPrefixBits()+128, k6.Prefixlen)
	require.Equal(t, "fd00::1/128@vni:10", k6.String())
}

func TestVniKeyDifferentVNIsAreDistinct(t *testing.T) {
	ip := net.ParseIP("192.168.1.3")
	mask := net.CIDRMask(32, 32)
	a := NewVniKey(ip, mask, 36)
	b := NewVniKey(ip, mask, 17)

	// Same IP, different VNI -> different keys (the core of the fix).
	require.NotEqual(t, a, b)
	// Prefixlen encodes the LPM prefix length (static bits + IP bits) and is
	// identical for both /32 entries; the VNI field is what distinguishes them.
	require.Equal(t, a.Prefixlen, b.Prefixlen)
	require.Equal(t, uint32(36), a.Vni)
	require.Equal(t, uint32(17), b.Vni)
}
