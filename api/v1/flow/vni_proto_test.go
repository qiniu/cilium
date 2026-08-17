// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package flow_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

// TestIPCacheNotificationVNIContract locks the generated protobuf contract for
// monitor/Hubble native-vpc events: vni is field 9 and survives wire
// marshal/unmarshal, while the existing field numbers remain unchanged.
func TestIPCacheNotificationVNIContract(t *testing.T) {
	md := (&flowpb.IPCacheNotification{}).ProtoReflect().Descriptor()
	vni := md.Fields().ByNumber(9)
	require.NotNil(t, vni)
	require.Equal(t, protoreflect.Name("vni"), vni.Name())

	in := &flowpb.IPCacheNotification{
		Cidr:     "192.168.1.2/32",
		Identity: 100,
		Vni:      36,
	}
	data, err := proto.Marshal(in)
	require.NoError(t, err)
	out := &flowpb.IPCacheNotification{}
	require.NoError(t, proto.Unmarshal(data, out))
	require.Equal(t, uint32(36), out.GetVni())
	require.Equal(t, "192.168.1.2/32", out.GetCidr())

	require.Equal(t, protoreflect.Name("cidr"), md.Fields().ByNumber(1).Name())
	require.Equal(t, protoreflect.Name("pod_name"), md.Fields().ByNumber(8).Name())
}
