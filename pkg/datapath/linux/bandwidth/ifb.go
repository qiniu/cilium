// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package bandwidth

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/bwmap"
	"github.com/cilium/cilium/pkg/option"
)

// IfbPrefix starts the name of the device the egress of a chained endpoint is
// paced on; the endpoint ID follows. EDT pacing needs an FQ qdisc on the
// device the packet is queued on, and with a chained CNI the packet leaves
// Cilium's datapath at the endpoint's veth, which has no qdisc in that
// direction. cil_from_container therefore redirects to an ifb, whose FQ holds
// the packet until its departure time before the ifb hands it back to the
// path it came from.
//
// Each endpoint with an egress limit has an ifb of its own. An ifb handles a
// queue on one CPU at a time, the way of the packet back into the stack
// included, so endpoints sharing one share that capacity: on one device for
// the node, an endpoint flooding small packets within its own limit took the
// egress of every other limited endpoint down with it.
const IfbPrefix = "cilium_bwm"

// egressViaIfb reports whether the endpoints' egress limits have to be paced
// on an ifb rather than in cil_to_netdev.
//
// That is the case with a chained CNI (generic-veth, e.g. Kube-OVN): the
// packet is re-injected into the stack by the chained CNI, so the skb reaching
// cil_to_netdev carries no aggregate (skb->queue_mapping is gone) and is
// usually already SNATed or encapsulated: there is nothing left to pace per
// endpoint.
//
// Nothing the bandwidth manager does to the native devices or to the node's
// TCP settings has any effect on the endpoints then, so in this mode it leaves
// both alone.
func egressViaIfb(cfg *option.DaemonConfig) bool {
	return cfg.GenericVethChaining()
}

func (m *manager) egressViaIfb() bool {
	return egressViaIfb(m.params.DaemonConfig)
}

func ifbName(epID uint16) string {
	return IfbPrefix + strconv.Itoa(int(epID))
}

// setupIfb creates (or picks up) the pacing device of the endpoint and returns
// its ifindex. A device and a qdisc that are already in place are left alone,
// so that an update of the limit or a restart of the agent drops nothing.
func setupIfb(epID uint16) (int, error) {
	name := ifbName(epID)
	link, err := safenetlink.LinkByName(name)
	if err != nil {
		if !errors.As(err, &netlink.LinkNotFoundError{}) {
			return 0, err
		}
		if err := netlink.LinkAdd(&netlink.Ifb{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
			return 0, fmt.Errorf("creating: %w", err)
		}
		if link, err = safenetlink.LinkByName(name); err != nil {
			return 0, err
		}
	}
	// Only an ifb can be the one we created.
	if link.Type() != "ifb" {
		return 0, fmt.Errorf("device exists and is a %s, not an ifb", link.Type())
	}
	// An ifb drops every packet while the device is down.
	if err := netlink.LinkSetUp(link); err != nil {
		return 0, fmt.Errorf("setting up: %w", err)
	}
	if err := ensureFq(link, netlink.Fq{
		PacketLimit:     pacingFqLimit,
		FlowPacketLimit: pacingFqLimit,
		Horizon:         uint32(FqDefaultHorizon.Microseconds()),
	}); err != nil {
		return 0, fmt.Errorf("qdisc: %w", err)
	}
	return link.Attrs().Index, nil
}

func removeIfb(name string) error {
	link, err := safenetlink.LinkByName(name)
	if err != nil {
		if errors.As(err, &netlink.LinkNotFoundError{}) {
			return nil
		}
		return err
	}
	if link.Type() != "ifb" {
		return nil
	}
	return netlink.LinkDel(link)
}

// removeUnusedIfbs removes the pacing devices no egress limit of this run is
// paced on: those of endpoints that are gone or lost their limit while the
// agent was down, all of them when this configuration does not pace on ifbs,
// and the single device an earlier version shared between all endpoints.
func (m *manager) removeUnusedIfbs() error {
	links, err := safenetlink.LinkList()
	if err != nil {
		return fmt.Errorf("listing devices: %w", err)
	}
	var errs []error
	for _, link := range links {
		name := link.Attrs().Name
		if link.Type() != "ifb" || !strings.HasPrefix(name, IfbPrefix) || m.ifbInUse(name) {
			continue
		}
		if err := netlink.LinkDel(link); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		m.params.Log.Info("Removed an unused egress pacing device", logfields.Device, name)
	}
	return errors.Join(errs...)
}

func (m *manager) ifbInUse(name string) bool {
	if !m.enabled || !m.egressViaIfb() {
		return false
	}
	epID, err := strconv.ParseUint(strings.TrimPrefix(name, IfbPrefix), 10, 16)
	if err != nil {
		return false
	}
	edt, _, found := m.params.EdtTable.Get(m.params.DB.ReadTxn(), bwmap.EdtIDIndex.Query(bwmap.EdtIDKey{
		EndpointID: uint16(epID),
		Direction:  DirectionEgress,
	}))
	return found && edt.IfIndex != 0
}
