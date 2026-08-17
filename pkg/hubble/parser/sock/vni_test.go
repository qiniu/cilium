// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sock

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/byteorder"
	cgroupManager "github.com/cilium/cilium/pkg/cgroups/manager"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/monitor"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/types"
)

// podEndpointGetter resolves endpoints by pod (the exact context a socket
// event has, through its cgroup id) and by (VNI, IP).
type podEndpointGetter struct {
	byPod map[string]getters.EndpointInfo
	byVNI map[uint32]map[netip.Addr]getters.EndpointInfo
}

func (g *podEndpointGetter) GetEndpointInfo(netip.Addr) (getters.EndpointInfo, bool) {
	return nil, false
}

func (g *podEndpointGetter) GetEndpointInfoByID(uint16) (getters.EndpointInfo, bool) {
	return nil, false
}

func (g *podEndpointGetter) GetEndpointInfoByPod(namespace, name string) (getters.EndpointInfo, bool) {
	ep, ok := g.byPod[namespace+"/"+name]
	return ep, ok
}

func (g *podEndpointGetter) GetEndpointInfoForVNI(ip netip.Addr, vni uint32) (getters.EndpointInfo, bool) {
	ep, ok := g.byVNI[vni][ip]
	return ep, ok
}

// TestSockTraceVNIChain verifies that socket-level flows carry the native-vpc
// VNI derived from the exact cgroup -> pod -> endpoint context, and that the
// peer is then resolved with the (VNI, IP) key instead of the bare IP.
func TestSockTraceVNIChain(t *testing.T) {
	const (
		cgroupID = uint64(1234)
		localVNI = uint32(36)
	)
	srcAddr := netip.MustParseAddr("10.16.32.10")
	dstAddr := netip.MustParseAddr("10.16.32.20")

	localEP := &testutils.FakeEndpointInfo{
		ID: 42, PodName: "client", PodNamespace: "vpc-a", VNIID: uint64(localVNI),
	}
	endpointGetter := &podEndpointGetter{
		byPod: map[string]getters.EndpointInfo{"vpc-a/client": localEP},
		byVNI: map[uint32]map[netip.Addr]getters.EndpointInfo{
			localVNI: {srcAddr: localEP},
		},
	}
	cgroupGetter := &testutils.FakePodMetadataGetter{
		OnGetPodMetadataForContainer: func(id uint64) *cgroupManager.PodMetadata {
			require.Equal(t, cgroupID, id)
			return &cgroupManager.PodMetadata{
				Namespace: "vpc-a", Name: "client", IPs: []string{srcAddr.String()},
			}
		},
	}
	ipGetter := &testutils.FakeIPGetter{
		OnLookupSecIDByIPForVNI: func(ip netip.Addr, vni uint32) (ipcache.Identity, bool) {
			if ip == dstAddr && vni == localVNI {
				return ipcache.Identity{ID: identity.NumericIdentity(21929), Vni: localVNI}, true
			}
			return ipcache.Identity{}, false
		},
		OnGetK8sMetadataForVNI: func(ip netip.Addr, vni uint32) *ipcache.K8sMetadata {
			if ip == dstAddr && vni == localVNI {
				return &ipcache.K8sMetadata{Namespace: "vpc-a", PodName: "server"}
			}
			return nil
		},
		OnLookupSecIDByIP: func(netip.Addr) (ipcache.Identity, bool) {
			return ipcache.Identity{}, false
		},
		OnGetK8sMetadata: func(netip.Addr) *ipcache.K8sMetadata {
			// A foreign VPC pod with the same IP: must never be used.
			return &ipcache.K8sMetadata{Namespace: "vpc-b", PodName: "foreign"}
		},
	}

	// IPv4 addresses are stored in the first four bytes of the dst_ip field.
	var dstRaw types.IPv6
	copy(dstRaw[:], dstAddr.AsSlice())

	sock := monitor.TraceSockNotify{
		Type:       byte(monitorAPI.MessageTypeTraceSock),
		XlatePoint: monitor.XlatePointPreDirectionFwd,
		DstIP:      dstRaw,
		DstPort:    53,
		CgroupId:   cgroupID,
		L4Proto:    monitor.L4ProtocolUDP,
	}
	buf := &bytes.Buffer{}
	require.NoError(t, binary.Write(buf, byteorder.Native, &sock))

	parser, err := New(hivetest.Logger(t), endpointGetter, &testutils.NoopIdentityGetter,
		&testutils.NoopDNSGetter, ipGetter, &testutils.NoopServiceGetter, cgroupGetter)
	require.NoError(t, err)

	f := &flowpb.Flow{}
	require.NoError(t, parser.Decode(buf.Bytes(), f))

	require.Equal(t, uint64(42), uint64(f.GetSource().GetID()))
	require.Equal(t, "client", f.GetSource().GetPodName())
	require.Equal(t, uint64(localVNI), f.GetSource().GetVniId())
	require.Equal(t, "server", f.GetDestination().GetPodName())
	require.Equal(t, uint64(localVNI), f.GetDestination().GetVniId())
}
