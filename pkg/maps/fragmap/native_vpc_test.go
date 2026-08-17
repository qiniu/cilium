package fragmap

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/option"
)

// TestFragmentKey4NativeVPCLayout pins the Go/C contract for both layouts of
// cilium_ipv4_frag_datagrams: without native-vpc the key is byte-identical to
// upstream, and with native-vpc it gains exactly the 4-byte VNI scope that
// prevents two VPCs sharing a source IP from colliding on the IP identifier.
func TestFragmentKey4NativeVPCLayout(t *testing.T) {
	require.Equal(t, uintptr(12), unsafe.Sizeof(FragmentKey4{}),
		"must match struct ipv4_frag_id without ENABLE_NATIVE_VPC")
	require.Equal(t, uintptr(16), unsafe.Sizeof(FragmentKey4NativeVPC{}),
		"must match struct ipv4_frag_id with ENABLE_NATIVE_VPC")

	prev := option.Config.EnableNativeVPC
	t.Cleanup(func() { option.Config.EnableNativeVPC = prev })

	option.Config.EnableNativeVPC = false
	require.IsType(t, &FragmentKey4{}, fragmentKey4())
	option.Config.EnableNativeVPC = true
	require.IsType(t, &FragmentKey4NativeVPC{}, fragmentKey4())
}
