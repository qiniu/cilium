// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
)

// TestCidrOf pins how the ipcache listing renders an entry. In native-vpc mode
// the same address exists once per VPC, so the scope has to be part of the
// rendered address: without it the listing shows several identical rows that
// an operator cannot tell apart. Entries without a scope must stay unchanged.
func TestCidrOf(t *testing.T) {
	cidr := "10.99.0.12/32"
	vni := func(v int64) *int64 { return &v }

	for _, tc := range []struct {
		name  string
		entry *models.IPListEntry
		want  string
	}{
		{
			name:  "no VPC scope",
			entry: &models.IPListEntry{Cidr: &cidr},
			want:  "10.99.0.12/32",
		},
		{
			name:  "zero VNI is not a scope",
			entry: &models.IPListEntry{Cidr: &cidr, VniID: vni(0)},
			want:  "10.99.0.12/32",
		},
		{
			name:  "scoped entry",
			entry: &models.IPListEntry{Cidr: &cidr, VniID: vni(7)},
			want:  "10.99.0.12/32@vni:7",
		},
		{
			name:  "missing address",
			entry: &models.IPListEntry{VniID: vni(7)},
			want:  "@vni:7",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, cidrOf(tc.entry))
		})
	}

	// The rendering must match the key format used by the BPF dump and by the
	// ipcache keys themselves, so that the three views can be correlated.
	require.Equal(t, "10.99.0.12/32@vni:5", cidrOf(&models.IPListEntry{Cidr: &cidr, VniID: vni(5)}))
}
