// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package threefour

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/stretchr/testify/require"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/monitor"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/option"
)

// vniEndpointGetter resolves endpoints by the exact (VNI, IP) key and by ID,
// like the real payloadGetters do.
type vniEndpointGetter struct {
	byID  map[uint16]getters.EndpointInfo
	byVNI map[uint32]map[netip.Addr]getters.EndpointInfo
}

func (g *vniEndpointGetter) GetEndpointInfo(netip.Addr) (getters.EndpointInfo, bool) {
	// Native-vpc endpoints are never resolvable from a bare IP: the whole
	// point of the test is that the parser does not need this path.
	return nil, false
}

func (g *vniEndpointGetter) GetEndpointInfoByID(id uint16) (getters.EndpointInfo, bool) {
	ep, ok := g.byID[id]
	return ep, ok
}

func (g *vniEndpointGetter) GetEndpointInfoForVNI(ip netip.Addr, vni uint32) (getters.EndpointInfo, bool) {
	ep, ok := g.byVNI[vni][ip]
	return ep, ok
}

// TestTraceNotifyVNIChain pins the full L3/L4 observability chain of
// native-vpc mode:
//
//	datapath event (local endpoint id)
//	  -> local endpoint VNI (the same scope bpf_lxc used to resolve the peer)
//	  -> exact (VNI, IP) endpoint / ipcache lookups
//	  -> flow with vni_id on both endpoints
//
// Both pods use the same IP in two different VPCs, so any bare-IP lookup in
// the chain would attribute the flow to the wrong VPC.
func TestTraceNotifyVNIChain(t *testing.T) {
	oldNativeVPC := option.Config.EnableNativeVPC
	option.Config.EnableNativeVPC = true
	t.Cleanup(func() { option.Config.EnableNativeVPC = oldNativeVPC })

	const (
		localEPID   = uint16(1234)
		localVNI    = uint32(36)
		foreignVNI  = uint32(17)
		remoteSecID = uint32(21929)
	)
	srcAddr := netip.MustParseAddr("10.16.32.10")
	dstAddr := netip.MustParseAddr("10.16.32.20")

	localEP := &testutils.FakeEndpointInfo{
		ID:           uint64(localEPID),
		Identity:     identity.NumericIdentity(11111),
		IPv4:         srcAddr.AsSlice(),
		PodName:      "client",
		PodNamespace: "vpc-a",
		VNIID:        uint64(localVNI),
	}
	// Same IP as the peer, but in another VPC: must never be selected.
	foreignEP := &testutils.FakeEndpointInfo{
		ID:           uint64(4321),
		Identity:     identity.NumericIdentity(22222),
		IPv4:         dstAddr.AsSlice(),
		PodName:      "foreign",
		PodNamespace: "vpc-b",
		VNIID:        uint64(foreignVNI),
	}

	endpointGetter := &vniEndpointGetter{
		byID: map[uint16]getters.EndpointInfo{localEPID: localEP},
		byVNI: map[uint32]map[netip.Addr]getters.EndpointInfo{
			localVNI:   {srcAddr: localEP},
			foreignVNI: {dstAddr: foreignEP},
		},
	}

	// The destination is a remote pod of the same VPC: it is only present in
	// the VNI-scoped ipcache. The plain lookups return the foreign VPC entry
	// to prove they are not consulted.
	ipGetter := &testutils.FakeIPGetter{
		OnLookupSecIDByIPForVNI: func(ip netip.Addr, vni uint32) (ipcache.Identity, bool) {
			if ip == dstAddr && vni == localVNI {
				return ipcache.Identity{ID: identity.NumericIdentity(remoteSecID), Vni: localVNI}, true
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
			return ipcache.Identity{ID: identity.NumericIdentity(33333)}, true
		},
		OnGetK8sMetadata: func(netip.Addr) *ipcache.K8sMetadata {
			return &ipcache.K8sMetadata{Namespace: "vpc-b", PodName: "foreign"}
		},
	}

	identityGetter := &testutils.FakeIdentityGetter{
		OnGetIdentity: func(secID uint32) (*identity.Identity, error) {
			return identity.NewIdentity(identity.NumericIdentity(secID), labels.Labels{
				labels.VNIKey: labels.NewLabel(labels.VNIKey, "36", labels.LabelSourceVNI),
			}), nil
		},
	}

	// cil_from_container of the local endpoint: "source" is the emitting
	// (local) endpoint, and the datapath identity of the peer is unknown.
	tn := monitor.TraceNotify{
		Type:     byte(monitorAPI.MessageTypeTrace),
		Source:   localEPID,
		SrcLabel: identity.NumericIdentity(11111),
		Version:  monitor.TraceNotifyVersion2,
	}
	buf := &bytes.Buffer{}
	require.NoError(t, binary.Write(buf, byteorder.Native, &tn))
	packet := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(packet, gopacket.SerializeOptions{},
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
			DstMAC:       net.HardwareAddr{7, 8, 9, 0, 1, 2},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			IHL:      5,
			Length:   49,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    srcAddr.AsSlice(),
			DstIP:    dstAddr.AsSlice(),
		},
		&layers.UDP{SrcPort: 23939, DstPort: 53},
	))
	buf.Write(packet.Bytes())

	parser, err := New(hivetest.Logger(t), endpointGetter, identityGetter,
		&testutils.NoopDNSGetter, ipGetter, &testutils.NoopServiceGetter, &testutils.NoopLinkGetter)
	require.NoError(t, err)

	f := &flowpb.Flow{}
	require.NoError(t, parser.Decode(buf.Bytes(), f))

	// Source: local endpoint resolved by (VNI, IP), not by bare IP.
	require.Equal(t, uint32(localEPID), f.GetSource().GetID())
	require.Equal(t, "vpc-a", f.GetSource().GetNamespace())
	require.Equal(t, "client", f.GetSource().GetPodName())
	require.Equal(t, uint64(localVNI), f.GetSource().GetVniId())

	// Destination: remote peer of the same VPC, resolved through the
	// VNI-scoped ipcache; the foreign VPC entry under the same bare IP is
	// never used.
	require.Equal(t, remoteSecID, f.GetDestination().GetIdentity())
	require.Equal(t, "vpc-a", f.GetDestination().GetNamespace())
	require.Equal(t, "server", f.GetDestination().GetPodName())
	require.Equal(t, uint64(localVNI), f.GetDestination().GetVniId())
	require.NotEqual(t, "foreign", f.GetDestination().GetPodName())
}

// TestTraceNotifyNoVNIWhenDisabled verifies the extra endpoint-by-ID lookup is
// not performed outside native-vpc mode (hot path) and that flows keep their
// previous shape.
func TestTraceNotifyNoVNIWhenDisabled(t *testing.T) {
	oldNativeVPC := option.Config.EnableNativeVPC
	option.Config.EnableNativeVPC = false
	t.Cleanup(func() { option.Config.EnableNativeVPC = oldNativeVPC })

	endpointGetter := &testutils.FakeEndpointGetter{
		OnGetEndpointInfo: func(netip.Addr) (getters.EndpointInfo, bool) { return nil, false },
		OnGetEndpointInfoByID: func(uint16) (getters.EndpointInfo, bool) {
			t.Fatal("endpoint-by-ID lookup must not run when native-vpc is disabled")
			return nil, false
		},
	}

	tn := monitor.TraceNotify{
		Type:    byte(monitorAPI.MessageTypeTrace),
		Source:  1234,
		Version: monitor.TraceNotifyVersion2,
	}
	buf := &bytes.Buffer{}
	require.NoError(t, binary.Write(buf, byteorder.Native, &tn))
	packet := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(packet, gopacket.SerializeOptions{},
		&layers.IPv4{
			Version: 4, IHL: 5, Length: 49, TTL: 64,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    net.IPv4(10, 16, 32, 10),
			DstIP:    net.IPv4(10, 16, 32, 20),
		},
		&layers.UDP{SrcPort: 23939, DstPort: 53},
	))
	tn.Flags = monitor.TraceNotifyFlagIsL3Device
	buf.Reset()
	require.NoError(t, binary.Write(buf, byteorder.Native, &tn))
	buf.Write(packet.Bytes())

	parser, err := New(hivetest.Logger(t), endpointGetter, &testutils.NoopIdentityGetter,
		&testutils.NoopDNSGetter, &testutils.NoopIPGetter, &testutils.NoopServiceGetter, &testutils.NoopLinkGetter)
	require.NoError(t, err)

	f := &flowpb.Flow{}
	require.NoError(t, parser.Decode(buf.Bytes(), f))
	require.Zero(t, f.GetSource().GetVniId())
	require.Zero(t, f.GetDestination().GetVniId())
}
