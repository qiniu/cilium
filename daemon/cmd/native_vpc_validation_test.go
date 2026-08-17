// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"

	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/option"
)

// TestNativeVPCRejectsBareIPKeyedFeatures pins the startup guard for the
// planes whose state is keyed by the bare IP (service backends, socket LB,
// egress gateway, BPF masquerade, encryption). With overlapping VPC subnets
// they would silently mix two VPCs, so the agent must refuse to start - and
// must keep starting normally when native-vpc is off.
func TestNativeVPCRejectsBareIPKeyedFeatures(t *testing.T) {
	base := func(nativeVPC bool) daemonConfigParams {
		return daemonConfigParams{
			DaemonConfig: &option.DaemonConfig{
				EnableNativeVPC:        nativeVPC,
				NativeVPCVNIAnnotation: "ovn.kubernetes.io/tunnel_key",
				RoutingMode:            option.RoutingModeNative,
			},
			IPSecConfig:     fakeTypes.IPsecConfig{},
			WireguardConfig: fakeTypes.WireguardConfig{},
		}
	}

	for _, tc := range []struct {
		name    string
		mutate  func(p *daemonConfigParams)
		wantErr string
	}{
		{name: "clean", mutate: func(*daemonConfigParams) {}},
		{
			name:    "kube-proxy replacement",
			mutate:  func(p *daemonConfigParams) { p.KPRConfig = kpr.KPRConfig{KubeProxyReplacement: true} },
			wantErr: "kube-proxy replacement",
		},
		{
			name:    "socket LB",
			mutate:  func(p *daemonConfigParams) { p.KPRConfig = kpr.KPRConfig{EnableSocketLB: true} },
			wantErr: "socket LB",
		},
		{
			name:    "egress gateway",
			mutate:  func(p *daemonConfigParams) { p.DaemonConfig.EnableEgressGateway = true },
			wantErr: "egress gateway",
		},
		{
			name:    "bpf masquerade",
			mutate:  func(p *daemonConfigParams) { p.DaemonConfig.EnableBPFMasquerade = true },
			wantErr: "BPF masquerade",
		},
		{
			name:    "ipsec",
			mutate:  func(p *daemonConfigParams) { p.IPSecConfig = fakeTypes.IPsecConfig{EnableIPsec: true} },
			wantErr: "encryption",
		},
		{
			name:    "wireguard",
			mutate:  func(p *daemonConfigParams) { p.WireguardConfig = fakeTypes.WireguardConfig{EnableWireguard: true} },
			wantErr: "encryption",
		},
	} {
		t.Run(tc.name+"/native-vpc", func(t *testing.T) {
			p := base(true)
			tc.mutate(&p)
			err := nativeVPCDatapathCompatibility(p)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})

		t.Run(tc.name+"/native-vpc disabled", func(t *testing.T) {
			p := base(false)
			tc.mutate(&p)
			require.NoError(t, nativeVPCDatapathCompatibility(p),
				"the guard must not affect deployments without native-vpc")
		})
	}
}
