// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package bandwidth

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// IfbDevice is the device the egress of chained endpoints is paced on. EDT
// pacing needs an FQ qdisc on the device the packet is queued on, and with a
// chained CNI the packet leaves Cilium's datapath at the endpoint's veth,
// which has no egress qdisc for that direction. cil_from_container therefore
// redirects to this ifb, whose FQ applies the rate before the ifb hands the
// packet back to the path it came from.
const IfbDevice = "cilium_bwm"

// egressViaIfb reports whether the endpoints' egress limits have to be paced
// on the ifb device rather than in cil_to_netdev. With a chained CNI the
// packet is re-injected into the stack by the chained CNI, so the skb reaching
// cil_to_netdev carries no aggregate (skb->queue_mapping is gone) and is
// usually already SNATed or encapsulated: there is nothing left to pace per
// endpoint.
//
// Nothing the bandwidth manager does to the native devices or to the node's
// TCP settings has any effect on the endpoints then, so in this mode it leaves
// both alone and only manages its own device.
func egressViaIfb(cfg *option.DaemonConfig) bool {
	return cfg.GenericVethChaining()
}

func (m *manager) egressViaIfb() bool {
	return egressViaIfb(m.params.DaemonConfig)
}

// EgressIfbIfIndex returns the ifindex of the pacing device, or 0 when the
// egress limit is paced in cil_to_netdev as usual.
func (m *manager) EgressIfbIfIndex() int {
	return m.ifbIfIndex
}

// ReleaseEgressIfb removes the pacing device of a previous run when this
// configuration does not pace on it, so that the device does not outlive the
// configuration that asked for it.
//
// It must only be called once the restored endpoints have been regenerated:
// until then their programs are the ones the previous run loaded, and they
// still redirect the endpoints' egress to the device, which would be dropped
// if the device were gone.
func (m *manager) ReleaseEgressIfb() {
	if m.ifbIfIndex != 0 {
		return
	}
	if err := removeIfb(m.params.Log); err != nil {
		m.params.Log.Warn("Cannot remove the unused pacing device",
			logfields.Error, err,
			logfields.Device, IfbDevice)
	}
}

// isOurIfb guards against a device that merely has our name: only an ifb can
// be the one we created, anything else is left alone.
func isOurIfb(link netlink.Link) bool {
	return link.Type() == "ifb"
}

func removeIfb(log *slog.Logger) error {
	link, err := safenetlink.LinkByName(IfbDevice)
	if err != nil {
		if errors.As(err, &netlink.LinkNotFoundError{}) {
			return nil
		}
		return fmt.Errorf("retrieving device %s: %w", IfbDevice, err)
	}
	if !isOurIfb(link) {
		return nil
	}

	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("removing device %s: %w", IfbDevice, err)
	}

	log.Info("Removed the pacing device of the chained-CNI egress path",
		logfields.Device, IfbDevice)
	return nil
}

// setupIfb creates (or picks up) the pacing device and gives it the same FQ
// qdisc the native devices get.
func (m *manager) setupIfb() error {
	link, err := safenetlink.LinkByName(IfbDevice)
	if err != nil {
		if !errors.As(err, &netlink.LinkNotFoundError{}) {
			return fmt.Errorf("retrieving device %s: %w", IfbDevice, err)
		}
		ifb := &netlink.Ifb{LinkAttrs: netlink.LinkAttrs{Name: IfbDevice}}
		if err := netlink.LinkAdd(ifb); err != nil {
			return fmt.Errorf("creating device %s: %w", IfbDevice, err)
		}
		link, err = safenetlink.LinkByName(IfbDevice)
		if err != nil {
			return fmt.Errorf("retrieving device %s: %w", IfbDevice, err)
		}
	}

	if !isOurIfb(link) {
		return fmt.Errorf("device %s exists and is a %s, not an ifb", IfbDevice, link.Type())
	}

	// An ifb drops every packet while the device is down.
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("setting device %s up: %w", IfbDevice, err)
	}

	if err := setupPacingQdisc(m.params.Log, link, FqDefaultHorizon, FqDefaultBuckets); err != nil {
		return fmt.Errorf("setting up the pacing qdisc of %s: %w", IfbDevice, err)
	}

	m.ifbIfIndex = link.Attrs().Index
	m.params.Log.Info("Pacing the egress of chained endpoints",
		logfields.Device, IfbDevice,
		logfields.Interface, m.ifbIfIndex)
	return nil
}
