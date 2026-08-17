// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateNativeVPC(t *testing.T) {
	tests := []struct {
		name    string
		config  DaemonConfig
		wantErr string
	}{
		{
			name: "missing annotation",
			config: DaemonConfig{
				EnableNativeVPC: true,
				RoutingMode:     RoutingModeNative,
			},
			wantErr: "native-vpc-vni-annotation",
		},
		{
			name: "tunnel mode rejected",
			config: DaemonConfig{
				EnableNativeVPC:        true,
				NativeVPCVNIAnnotation: "ovn.kubernetes.io/tunnel_key",
				RoutingMode:            RoutingModeTunnel,
			},
			wantErr: "routing-mode=native",
		},
		{
			name: "native routing accepted",
			config: DaemonConfig{
				EnableNativeVPC:        true,
				NativeVPCVNIAnnotation: "ovn.kubernetes.io/tunnel_key",
				RoutingMode:            RoutingModeNative,
			},
		},
		{
			name: "native-vpc disabled ignores routing mode",
			config: DaemonConfig{
				EnableNativeVPC: false,
				RoutingMode:     RoutingModeTunnel,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validateNativeVPC()
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tt.wantErr)
			}
		})
	}
}
