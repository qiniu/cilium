// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	dpconfig "github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestWrap(t *testing.T) {
	var (
		realEPBuffer   bytes.Buffer
		templateBuffer bytes.Buffer
	)

	realEP := testutils.NewTestEndpoint(t)
	realEP.VNIID = 36
	template := wrap(&realEP)
	cfg := configWriterForTest(t)

	// Compile-time header/template hash must be independent of VNI: one
	// compiled bpf_lxc template serves all VPCs. The old implementation tried
	// to emit NATIVE_VPC_VNI through a type assertion on templateCfg, which
	// always failed because the wrapper only embedded CompileTimeConfiguration.
	err := cfg.WriteTemplateConfig(&realEPBuffer, &localNodeConfig, &realEP)
	require.NoError(t, err)
	err = cfg.WriteTemplateConfig(&templateBuffer, &localNodeConfig, template)
	require.NoError(t, err)
	require.Equal(t, realEPBuffer.String(), templateBuffer.String())
	require.False(t, strings.Contains(templateBuffer.String(), "NATIVE_VPC_VNI"),
		"VNI must be load-time .rodata.config data, not a template define")

	// Runtime configuration must carry the real endpoint VNI, while the
	// template object uses a non-zero dummy value that the loader replaces.
	realConfigs := endpointConfiguration(&realEP, &localNodeConfig)
	require.Len(t, realConfigs, 1)
	require.Equal(t, uint32(36), realConfigs[0].(*dpconfig.BPFLXC).NativeVpcVni)

	templateConfigs := endpointConfiguration(template, &localNodeConfig)
	require.Len(t, templateConfigs, 1)
	require.Equal(t, uint32(templateNativeVPCVNI), templateConfigs[0].(*dpconfig.BPFLXC).NativeVpcVni)
}
