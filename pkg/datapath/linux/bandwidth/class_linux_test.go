// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bandwidth

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/bandwidth/classtree"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func TestPeerRules(t *testing.T) {
	for _, r := range []string{"10.0.0.0/8,10.4.0.0/16", "0.0.0.0/0", "", "10.0.0.1/8"} {
		_, err := parsePeerRules(r)
		require.Error(t, err)
	}
}
func TestPrivilegedChainedClassLifecycle(t *testing.T) {
	testutils.PrivilegedTest(t)
	ns := netns.NewNetNS(t)
	require.NoError(t, ns.Do(func() error {
		dev := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "pod", MTU: 1500}, PeerName: "peer"}
		require.NoError(t, netlink.LinkAdd(dev))
		table, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 8, ValueSize: 8, MaxEntries: 8})
		require.NoError(t, err)
		defer table.Close()
		peers, err := parsePeerRules("192.0.2.0/24")
		require.NoError(t, err)
		s := &classState{redirects: table, peers: peers, live: make(map[classKey]publishedClass)}
		m := &manager{classes: s}
		k := classKey{123, uint32(dev.Index)}
		const out = "qos.cilium.io/north-south-egress-bandwidth"
		const in = "qos.cilium.io/north-south-ingress-bandwidth"
		a := map[string]string{out: "10M", in: "15M", EgressBandwidth: "20M", IngressBandwidth: "30M"}
		require.NoError(t, m.UpdateClassBandwidth(123, "pod", a))
		var first, got classLinks
		require.NoError(t, table.Lookup(k, &first))
		require.NotZero(t, first.In)
		created, err := netlink.LinkByIndex(int(first.Out))
		require.NoError(t, err)
		require.Equal(t, classAlias(k), created.Attrs().Alias)
		require.NotEqual(t, first.In, first.Out)
		require.NoError(t, m.UpdateClassBandwidth(123, "pod", a))
		a[in] = "bad"
		require.Error(t, m.UpdateClassBandwidth(123, "pod", a))
		require.NoError(t, table.Lookup(k, &got))
		require.Equal(t, first, got)
		a[in] = "15M"
		// Simulate lost publication, then a deleted IFB with unchanged annotations.
		require.NoError(t, table.Delete(k))
		require.NoError(t, m.UpdateClassBandwidth(123, "pod", a))
		require.NoError(t, table.Lookup(k, &got))
		require.NotEqual(t, first.Out, got.Out)
		_, err = netlink.LinkByIndex(int(first.Out))
		require.Error(t, err)
		lost, err := netlink.LinkByIndex(int(got.Out))
		require.NoError(t, err)
		require.NoError(t, netlink.LinkDel(lost))
		require.NoError(t, m.UpdateClassBandwidth(123, "pod", a))
		require.NoError(t, table.Lookup(k, &first))
		require.NotEqual(t, got.Out, first.Out)
		// A queue can still exist while its classifier has disappeared.
		outDev, err := netlink.LinkByIndex(int(first.Out))
		require.NoError(t, err)
		filters, err := safenetlink.FilterList(outDev, classtree.ClassID(0))
		require.NoError(t, err)
		require.Len(t, filters, 1)
		require.NoError(t, netlink.FilterDel(filters[0]))
		require.NoError(t, m.UpdateClassBandwidth(123, "pod", a))
		require.NoError(t, table.Lookup(k, &got))
		require.NotEqual(t, first.Out, got.Out)
		first = got
		// Staged-but-unpublished tree and IFB left by interrupted cleanup.
		orphan, err := s.stageEgress(k, dev, &classtree.Limits{NorthSouth: 2000000})
		require.NoError(t, err)
		_, err = s.stageIngress(dev, &classtree.Limits{NorthSouth: 2000000}, first.In)
		require.NoError(t, err)
		s.cleanupPending = true
		require.NoError(t, m.UpdateClassBandwidth(123, "pod", a))
		_, err = netlink.LinkByIndex(int(orphan))
		require.Error(t, err)
		require.NoError(t, table.Lookup(k, &got))
		require.Equal(t, first, got)
		delete(a, in)
		require.NoError(t, m.UpdateClassBandwidth(123, "pod", a))
		require.NoError(t, table.Lookup(k, &got))
		require.Zero(t, got.In)
		_, err = netlink.LinkByIndex(int(first.Out))
		require.Error(t, err)
		require.NoError(t, m.DeleteClassBandwidth(123, "pod"))
		require.ErrorIs(t, table.Lookup(k, &got), ebpf.ErrKeyNotExist)
		// Interrupted after creating PRIO, before adding FQ or publishing.
		prio := &netlink.Prio{QdiscAttrs: netlink.QdiscAttrs{LinkIndex: dev.Index, Parent: netlink.HANDLE_ROOT, Handle: ingressRoot}, Bands: 3}
		require.NoError(t, netlink.QdiscReplace(prio))
		require.NoError(t, setupIngressFq("pod"))
		qs, err := safenetlink.QdiscList(dev)
		require.NoError(t, err)
		found := false
		for _, q := range qs {
			if q.Attrs().Parent == ingressRoot|1 && isIngressFq(q) {
				found = true
			}
		}
		require.True(t, found)
		require.NoError(t, m.sweepClasses())
		q, err := rootQdisc(dev)
		require.NoError(t, err)
		require.True(t, isIngressFq(q))
		// Aggregate setup runs before class setup: neither may take this root.
		foreign := netlink.NewFqCodel(netlink.QdiscAttrs{LinkIndex: dev.Index, Parent: netlink.HANDLE_ROOT, Handle: netlink.MakeHandle(0xd0, 0)})
		require.NoError(t, netlink.QdiscReplace(foreign))
		require.Error(t, setupIngressFq("pod"))
		a[in] = "10M"
		a[IngressBandwidth] = "20M"
		require.Error(t, m.UpdateClassBandwidth(123, "pod", a))
		q, err = rootQdisc(dev)
		require.NoError(t, err)
		require.Equal(t, foreign.Handle, q.Attrs().Handle)
		require.ErrorIs(t, table.Lookup(k, &got), ebpf.ErrKeyNotExist)
		return nil
	}))
}
