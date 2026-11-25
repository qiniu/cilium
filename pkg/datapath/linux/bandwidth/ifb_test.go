// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package bandwidth

import (
	"strings"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

// TestPrivilegedIfbLifecycle pins that the pacing device follows the
// configuration rather than the agent's lifetime: it appears when the egress
// limits have to be paced on it, it is picked up again on the next start
// instead of being duplicated, and it is removed as soon as the configuration
// no longer asks for it, without waiting for the agent to stop.
func TestPrivilegedIfbLifecycle(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	require.NoError(t, ns.Do(func() error {
		m := &manager{
			params: bandwidthManagerParams{
				Log:          hivetest.Logger(t),
				DaemonConfig: &option.DaemonConfig{CNIChainingMode: "generic-veth"},
			},
		}
		require.True(t, m.egressViaIfb())

		require.NoError(t, m.setupIfb())
		link, err := safenetlink.LinkByName(IfbDevice)
		require.NoError(t, err)
		require.Equal(t, link.Attrs().Index, m.EgressIfbIfIndex())
		require.NotZero(t, m.EgressIfbIfIndex())
		require.Equal(t, "ifb", link.Type())
		require.NotZero(t, link.Attrs().RawFlags&unix.IFF_UP,
			"the device has to be up, an ifb drops everything while down")

		qdiscs, err := safenetlink.QdiscList(link)
		require.NoError(t, err)
		var fq *netlink.Fq
		for _, q := range qdiscs {
			if f, ok := q.(*netlink.Fq); ok {
				fq = f
			}
		}
		require.NotNil(t, fq, "pacing needs an fq qdisc, found %v", qdiscs)
		require.Equal(t, uint32(FqDefaultHorizon.Microseconds()), fq.Horizon)

		// A restart has to pick the device up, not fail on it, stack a
		// second one, or replace the qdisc: the replacement would drop
		// whatever the pacing queue holds at that moment.
		require.NoError(t, m.setupIfb())
		require.Equal(t, link.Attrs().Index, m.EgressIfbIfIndex())
		qdiscs, err = safenetlink.QdiscList(link)
		require.NoError(t, err)
		require.Len(t, qdiscs, 1)
		require.Equal(t, fq.Handle, qdiscs[0].Attrs().Handle, "the qdisc was replaced")

		// A configuration that paces on the device keeps it.
		m.ReleaseEgressIfb()
		_, err = safenetlink.LinkByName(IfbDevice)
		require.NoError(t, err, "the device in use was removed")

		// The next run does not pace on it: it is removed, and releasing
		// twice finds nothing to do.
		next := &manager{params: bandwidthManagerParams{Log: hivetest.Logger(t)}}
		next.ReleaseEgressIfb()
		_, err = safenetlink.LinkByName(IfbDevice)
		require.ErrorAs(t, err, &netlink.LinkNotFoundError{})
		next.ReleaseEgressIfb()

		// A device that merely carries the name is not ours: it is neither
		// taken over nor removed.
		require.NoError(t, netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: IfbDevice}}))
		require.Error(t, m.setupIfb())
		next.ReleaseEgressIfb()
		link, err = safenetlink.LinkByName(IfbDevice)
		require.NoError(t, err, "a foreign device was removed")
		require.Equal(t, "dummy", link.Type())

		return nil
	}))
}

// recordingSysctl records the settings the bandwidth manager writes.
type recordingSysctl struct {
	writes []string
}

func (s *recordingSysctl) Disable(name []string) error        { return nil }
func (s *recordingSysctl) Enable(name []string) error         { return nil }
func (s *recordingSysctl) Read(name []string) (string, error) { return "", nil }
func (s *recordingSysctl) ReadInt(name []string) (int64, error) {
	return 0, nil
}

func (s *recordingSysctl) Write(name []string, val string) error {
	s.writes = append(s.writes, strings.Join(name, ".")+"="+val)
	return nil
}

func (s *recordingSysctl) WriteInt(name []string, val int64) error {
	s.writes = append(s.writes, strings.Join(name, "."))
	return nil
}

func (s *recordingSysctl) ApplySettings(settings []tables.Sysctl) error {
	for _, set := range settings {
		s.writes = append(s.writes, strings.Join(set.Name, ".")+"="+set.Val)
	}
	return nil
}

// TestPrivilegedSetupPacing pins what enabling the bandwidth manager touches.
// With a chained CNI it creates its own device and nothing else: the node's
// TCP settings (default_qdisc, congestion control, backlog sizes) exist to
// make pacing work in cil_to_netdev, which the endpoints' traffic never
// reaches there, so changing them would only disturb the node's own traffic.
// Without one it paces on the node's devices, tunes the node for it and
// creates no device.
func TestPrivilegedSetupPacing(t *testing.T) {
	testutils.PrivilegedTest(t)

	for mode, onIfb := range map[string]bool{"generic-veth": true, "none": false} {
		ns := netns.NewNetNS(t)
		require.NoError(t, ns.Do(func() error {
			sysctl := &recordingSysctl{}
			m := &manager{
				enabled: true,
				params: bandwidthManagerParams{
					Log:          hivetest.Logger(t),
					Sysctl:       sysctl,
					DaemonConfig: &option.DaemonConfig{CNIChainingMode: mode},
				},
			}

			require.NoError(t, m.setupPacing())
			if onIfb {
				require.NotZero(t, m.EgressIfbIfIndex())
				require.Empty(t, sysctl.writes, "the node's settings were changed")
			} else {
				require.Zero(t, m.EgressIfbIfIndex())
				require.NotEmpty(t, sysctl.writes)
				_, err := safenetlink.LinkByName(IfbDevice)
				require.ErrorAs(t, err, &netlink.LinkNotFoundError{})
			}
			return nil
		}))
	}
}
