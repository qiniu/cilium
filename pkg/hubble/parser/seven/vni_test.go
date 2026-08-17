// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package seven

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/u8proto"
)

// vniIPGetter resolves metadata only through the VNI-scoped key, mirroring
// native-vpc mode where pod entries live under "<ip>@vni:<vni>" and are
// invisible to the bare-IP lookup.
type vniIPGetter struct {
	vniMeta map[uint32]*ipcache.K8sMetadata
}

func (g *vniIPGetter) GetK8sMetadata(netip.Addr) *ipcache.K8sMetadata { return nil }

func (g *vniIPGetter) GetK8sMetadataForVNI(_ netip.Addr, vni uint32) *ipcache.K8sMetadata {
	return g.vniMeta[vni]
}

func (g *vniIPGetter) LookupSecIDByIP(netip.Addr) (ipcache.Identity, bool) {
	return ipcache.Identity{}, false
}

// TestL7FlowCarriesVNI verifies the observability plane of native-vpc: the L7
// record carries the (VNI, IP) scope resolved by the proxy, the parser uses it
// to look up pod metadata with the exact VNI-scoped key, and the resulting
// flow exposes the VNI on both endpoints.
func TestL7FlowCarriesVNI(t *testing.T) {
	src := accesslog.EndpointInfo{ID: 1234, IPv4: "10.16.32.10", Identity: 9876, VNIID: 36}
	dst := accesslog.EndpointInfo{ID: 4321, IPv4: "10.16.32.20", Identity: 6789, VNIID: 17, Port: 53}

	lr := &accesslog.LogRecord{
		Type:                accesslog.TypeRequest,
		Timestamp:           "2006-01-02T15:04:05.999999999Z",
		ObservationPoint:    accesslog.Egress,
		SourceEndpoint:      src,
		DestinationEndpoint: dst,
		IPVersion:           accesslog.VersionIPv4,
		Verdict:             accesslog.VerdictForwarded,
		TransportProtocol:   accesslog.TransportProtocol(u8proto.UDP),
		DNS:                 &accesslog.LogRecordDNS{Query: "example.com"},
	}

	ipGetter := &vniIPGetter{vniMeta: map[uint32]*ipcache.K8sMetadata{
		36: {Namespace: "vpc-a", PodName: "client"},
		17: {Namespace: "vpc-b", PodName: "server"},
	}}

	parser, err := New(hivetest.Logger(t), &testutils.NoopDNSGetter, ipGetter,
		&testutils.NoopServiceGetter, &testutils.NoopEndpointGetter)
	require.NoError(t, err)

	f := &flowpb.Flow{}
	require.NoError(t, parser.Decode(lr, f))

	require.Equal(t, uint64(36), f.GetSource().GetVniId())
	require.Equal(t, "vpc-a", f.GetSource().GetNamespace())
	require.Equal(t, "client", f.GetSource().GetPodName())
	require.Equal(t, uint64(17), f.GetDestination().GetVniId())
	require.Equal(t, "vpc-b", f.GetDestination().GetNamespace())
	require.Equal(t, "server", f.GetDestination().GetPodName())
}

// vniEndpointGetter implements the exact (VNI, IP) endpoint lookup.
type vniEndpointGetter struct {
	testutils.FakeEndpointGetter
	onVNI func(ip netip.Addr, vni uint32) (getters.EndpointInfo, bool)
}

func (g *vniEndpointGetter) GetEndpointInfoForVNI(ip netip.Addr, vni uint32) (getters.EndpointInfo, bool) {
	return g.onVNI(ip, vni)
}

// TestL7WorkloadLookupIsVNIScoped verifies that the workload lookup of an L7
// flow never falls back to a bare-IP endpoint lookup once a VNI is known: with
// overlapping IPs that would attribute the flow to a foreign VPC.
func TestL7WorkloadLookupIsVNIScoped(t *testing.T) {
	var gotVNI uint32
	epGetter := &vniEndpointGetter{
		FakeEndpointGetter: testutils.FakeEndpointGetter{
			OnGetEndpointInfo: func(netip.Addr) (getters.EndpointInfo, bool) {
				t.Fatal("bare-IP endpoint lookup must not be used when a VNI is known")
				return nil, false
			},
		},
		onVNI: func(_ netip.Addr, vni uint32) (getters.EndpointInfo, bool) {
			gotVNI = vni
			return nil, false
		},
	}

	parser, err := New(hivetest.Logger(t), &testutils.NoopDNSGetter, &testutils.NoopIPGetter,
		&testutils.NoopServiceGetter, epGetter)
	require.NoError(t, err)

	lr := &accesslog.LogRecord{
		Type:                accesslog.TypeRequest,
		Timestamp:           "2006-01-02T15:04:05.999999999Z",
		ObservationPoint:    accesslog.Egress,
		SourceEndpoint:      accesslog.EndpointInfo{ID: 1, IPv4: "10.16.32.10", VNIID: 36},
		DestinationEndpoint: accesslog.EndpointInfo{ID: 2, IPv4: "10.16.32.20", VNIID: 36},
		IPVersion:           accesslog.VersionIPv4,
		Verdict:             accesslog.VerdictForwarded,
		TransportProtocol:   accesslog.TransportProtocol(u8proto.UDP),
		DNS:                 &accesslog.LogRecordDNS{Query: "example.com"},
	}

	f := &flowpb.Flow{}
	require.NoError(t, parser.Decode(lr, f))
	require.Equal(t, uint32(36), gotVNI)
}
