// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package bandwidth

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

// TestPrivilegedIngressFqLifecycle pins that the FQ shaping an endpoint's
// ingress is installed once, survives a second setup untouched (it may hold
// packets), and is removed without touching a qdisc that is not ours.
func TestPrivilegedIngressFqLifecycle(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	require.NoError(t, ns.Do(func() error {
		for _, name := range []string{"lim", "other"} {
			require.NoError(t, netlink.LinkAdd(&netlink.Veth{
				LinkAttrs: netlink.LinkAttrs{Name: name},
				PeerName:  name + "_p",
			}))
		}
		root := func(name string) netlink.Qdisc {
			link, err := safenetlink.LinkByName(name)
			require.NoError(t, err)
			q, err := rootQdisc(link)
			require.NoError(t, err)
			return q
		}

		require.NoError(t, setupIngressFq("lim"))
		fq := root("lim")
		require.True(t, isIngressFq(fq), "found %v", fq)
		require.NoError(t, setupIngressFq("lim"))
		require.Equal(t, fq.Attrs().Handle, root("lim").Attrs().Handle, "the qdisc was replaced")

		// Somebody else's fq, with the kernel's defaults.
		other, err := safenetlink.LinkByName("other")
		require.NoError(t, err)
		require.NoError(t, netlink.QdiscReplace(&netlink.Fq{
			QdiscAttrs: netlink.QdiscAttrs{LinkIndex: other.Attrs().Index, Parent: netlink.HANDLE_ROOT},
			Pacing:     1,
		}))
		require.False(t, isIngressFq(root("other")))

		require.NoError(t, removeIngressFqByName("other"))
		require.Equal(t, "fq", root("other").Type())
		require.NoError(t, removeIngressFqByName("lim"))
		require.False(t, isIngressFq(root("lim")))
		require.NoError(t, removeIngressFqByName("gone"))
		require.Error(t, setupIngressFq("gone"))

		// A configuration that does not shape ingress clears what the
		// previous one left behind, and nothing else.
		require.NoError(t, setupIngressFq("lim"))
		m := &manager{params: bandwidthManagerParams{
			Log:          hivetest.Logger(t),
			DaemonConfig: &option.DaemonConfig{},
		}}
		m.ReleaseUnusedPacing()
		require.False(t, isIngressFq(root("lim")))
		require.Equal(t, "fq", root("other").Type())
		return nil
	}))
}
