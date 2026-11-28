// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package bandwidth

import (
	"os"
	"strings"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/maps/bwmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

// TestPrivilegedIfbLifecycle pins that every endpoint with an egress limit is
// paced on a device of its own, that the device follows the limit rather than
// the agent's lifetime, and that what is already in place is picked up
// untouched.
func TestPrivilegedIfbLifecycle(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	require.NoError(t, ns.Do(func() error {
		db := statedb.New()
		table, err := bwmap.NewEdtTable(db)
		require.NoError(t, err)
		m := &manager{
			enabled: true,
			params: bandwidthManagerParams{
				Log:          hivetest.Logger(t),
				DB:           db,
				EdtTable:     table,
				DaemonConfig: &option.DaemonConfig{CNIChainingMode: "generic-veth"},
			},
		}
		require.True(t, m.egressViaIfb())
		ifindex := func(epID uint16) uint32 {
			edt, _, found := table.Get(db.ReadTxn(), bwmap.EdtIDIndex.Query(bwmap.EdtIDKey{
				EndpointID: epID, Direction: DirectionEgress,
			}))
			require.True(t, found)
			return edt.IfIndex
		}
		fqHandle := func(name string) uint32 {
			link, err := safenetlink.LinkByName(name)
			require.NoError(t, err)
			root, err := rootQdisc(link)
			require.NoError(t, err)
			fq, ok := root.(*netlink.Fq)
			require.True(t, ok, "pacing needs an fq qdisc, found %v", root)
			require.Equal(t, uint32(FqDefaultHorizon.Microseconds()), fq.Horizon)
			// With the kernel's 100 packets per flow, a flow of small
			// packets that overruns its limit gets 100 packets per
			// horizon through.
			require.Equal(t, uint32(pacingFqLimit), fq.FlowPacketLimit)
			return fq.Handle
		}
		exists := func(name string) bool {
			_, err := safenetlink.LinkByName(name)
			return err == nil
		}

		// The entry names the endpoint's own device.
		m.UpdateBandwidthLimit(7, 1250000, 0)
		m.UpdateBandwidthLimit(8, 1250000, 0)
		link, err := safenetlink.LinkByName("cilium_bwm7")
		require.NoError(t, err)
		require.Equal(t, "ifb", link.Type())
		require.NotZero(t, link.Attrs().RawFlags&unix.IFF_UP,
			"the device has to be up, an ifb drops everything while down")
		require.Equal(t, uint32(link.Attrs().Index), ifindex(7))
		require.NotEqual(t, ifindex(7), ifindex(8), "endpoints share a device")

		// An update, like a restart, keeps the device and its qdisc: a
		// replacement would drop whatever the queue holds.
		handle := fqHandle("cilium_bwm7")
		m.UpdateBandwidthLimit(7, 2500000, 0)
		require.Equal(t, uint32(link.Attrs().Index), ifindex(7))
		require.Equal(t, handle, fqHandle("cilium_bwm7"), "the qdisc was replaced")

		// What no limit of this run uses is removed: the device of an
		// endpoint that is gone, and the one an earlier version shared.
		// Devices that are not ours stay.
		for _, name := range []string{"cilium_bwm9", "cilium_bwm", "ifb9"} {
			require.NoError(t, netlink.LinkAdd(&netlink.Ifb{LinkAttrs: netlink.LinkAttrs{Name: name}}))
		}
		require.NoError(t, netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "cilium_bwm10"}}))
		m.ReleaseUnusedPacing()
		require.True(t, exists("cilium_bwm7"), "a device in use was removed")
		require.True(t, exists("cilium_bwm8"), "a device in use was removed")
		require.False(t, exists("cilium_bwm9"))
		require.False(t, exists("cilium_bwm"))
		require.True(t, exists("ifb9"), "a foreign ifb was removed")
		require.True(t, exists("cilium_bwm10"), "a foreign device was removed")

		// A device that merely carries the name is not taken over, and
		// the limit is not written without a device to pace it on.
		m.UpdateBandwidthLimit(10, 1250000, 0)
		_, _, found := table.Get(db.ReadTxn(), bwmap.EdtIDIndex.Query(bwmap.EdtIDKey{
			EndpointID: 10, Direction: DirectionEgress,
		}))
		require.False(t, found)

		// The device goes with the limit: when only a priority is left,
		// and when the endpoint's entry is deleted.
		m.UpdateBandwidthLimit(7, 0, 5)
		require.False(t, exists("cilium_bwm7"))
		require.Zero(t, ifindex(7))
		m.DeleteBandwidthLimit(8)
		require.False(t, exists("cilium_bwm8"))

		// A run that does not pace on ifbs removes them all.
		m.UpdateBandwidthLimit(8, 1250000, 0)
		next := &manager{params: bandwidthManagerParams{Log: hivetest.Logger(t)}}
		next.ReleaseUnusedPacing()
		require.False(t, exists("cilium_bwm8"))
		require.True(t, exists("ifb9"))

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

// TestPrivilegedSetupPacing pins what enabling the bandwidth manager touches
// on the node. With a chained CNI that is nothing: the node's TCP settings
// (default_qdisc, congestion control, backlog sizes) exist to make pacing work
// in cil_to_netdev, which the endpoints' traffic never reaches there, so
// changing them would only disturb the node's own traffic. Without one it
// tunes the node for pacing on its devices.
func TestPrivilegedSetupPacing(t *testing.T) {
	testutils.PrivilegedTest(t)

	for mode, chained := range map[string]bool{"generic-veth": true, "none": false} {
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
			if chained {
				require.Empty(t, sysctl.writes, "the node's settings were changed")
			} else {
				require.NotEmpty(t, sysctl.writes)
			}
			return nil
		}))
	}
}

// unreadableSysctl is a node without the settings pacing on its devices
// needs, such as a node that is a container itself.
type unreadableSysctl struct{ recordingSysctl }

func (*unreadableSysctl) Read([]string) (string, error) { return "", os.ErrNotExist }

// TestProbeWithoutNodeSettings pins that the node's settings only decide
// whether the bandwidth manager runs where it is going to write them.
func TestProbeWithoutNodeSettings(t *testing.T) {
	for mode, want := range map[string]bool{"generic-veth": true, "none": false} {
		m := &manager{params: bandwidthManagerParams{
			Log:          hivetest.Logger(t),
			Sysctl:       &unreadableSysctl{},
			Config:       types.BandwidthConfig{EnableBandwidthManager: true},
			DaemonConfig: &option.DaemonConfig{CNIChainingMode: mode},
			IPsecConfig:  fakeTypes.IPsecConfig{},
		}}
		require.NoError(t, m.probe())
		require.Equal(t, want, m.enabled, "chaining mode %q", mode)
	}
}
