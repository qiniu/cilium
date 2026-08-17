// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package alignchecker

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/option"
)

// TestCheckStructAlignmentsNativeVPC runs the real C/Go alignment check
// against both datapath variants.
//
// bpf_alignchecker.c is compiled on the node with that node's defines, so a
// struct whose layout depends on the mode (currently ipv4_frag_id, which gains
// a VNI in native-vpc) must be matched against the Go type of the *same* mode.
// Getting this wrong makes the agent exit with "C and Go structs alignment
// check failed", which no unit test on the Go structs alone would catch.
//
// The objects are produced by `make -C bpf bpf_alignchecker.o` (plain) and the
// same command with -DENABLE_NATIVE_VPC=1; the test skips when they are absent
// so it does not require clang in every environment.
func TestCheckStructAlignmentsNativeVPC(t *testing.T) {
	for _, tc := range []struct {
		name      string
		object    string
		nativeVPC bool
	}{
		{name: "plain", object: "../../../bpf/bpf_alignchecker.o"},
		{name: "native-vpc", object: "/tmp/bpf_alignchecker_nvpc.o", nativeVPC: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := os.Stat(tc.object); err != nil {
				t.Skipf("%s not built: %v", tc.object, err)
			}
			prev := option.Config.EnableNativeVPC
			option.Config.EnableNativeVPC = tc.nativeVPC
			t.Cleanup(func() { option.Config.EnableNativeVPC = prev })

			require.NoError(t, CheckStructAlignments(tc.object))
		})
	}
}
