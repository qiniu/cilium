// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bandwidth

import (
	"errors"
	"fmt"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/bandwidth/classtree"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
)

// The root defaults to the legacy FQ. Two other bands allow a complete new
// tree to be staged before switching the selector in the endpoint map.
const ingressRoot uint32 = 0xc1700000

func isClassRoot(q netlink.Qdisc) bool {
	p, ok := q.(*netlink.Prio)
	return ok && p.Handle == ingressRoot && p.Bands == 3 && p.PriorityMap == [16]uint8{}
}

// An interrupted installation may leave the kernel's implicit leaf on the
// default band. Check it even when the class root itself already exists.
func ensureDefaultBand(dev netlink.Link) error {
	qs, err := safenetlink.QdiscList(dev)
	if err != nil {
		return err
	}
	for _, child := range qs {
		if child.Attrs().Parent != ingressRoot|1 {
			continue
		}
		if isIngressFq(child) {
			return nil
		}
		if child.Attrs().Handle != 0 {
			return fmt.Errorf("foreign default band on %s", dev.Attrs().Name)
		}
	}
	fq := ingressFq
	fq.QdiscAttrs = netlink.QdiscAttrs{LinkIndex: dev.Attrs().Index, Parent: ingressRoot | 1}
	fq.Pacing = 1
	return netlink.QdiscAdd(&fq)
}

func ingressMajor(band uint32) uint16 { return uint16(0xc180 + (band & 0xffff)) }
func (s *classState) stageIngress(dev netlink.Link, limits *classtree.Limits, old uint32) (band uint32, err error) {
	if limits == nil {
		return 0, nil
	}
	idx := dev.Attrs().Index
	q, err := rootQdisc(dev)
	if err != nil {
		return 0, err
	}
	if !isClassRoot(q) {
		if q != nil && q.Attrs().Handle != 0 && !isIngressFq(q) {
			return 0, fmt.Errorf("foreign root %s on %s", q.Type(), dev.Attrs().Name)
		}
		p := &netlink.Prio{QdiscAttrs: netlink.QdiscAttrs{LinkIndex: idx, Handle: ingressRoot, Parent: netlink.HANDLE_ROOT}, Bands: 3}
		if err = netlink.QdiscReplace(p); err != nil {
			return 0, err
		}
		defer func() {
			if err != nil {
				if isIngressFq(q) {
					err = errors.Join(err, ensureFq(dev, ingressFq))
				} else {
					err = errors.Join(err, netlink.QdiscDel(p))
				}
			}
		}()
	}
	if err = ensureDefaultBand(dev); err != nil {
		return 0, err
	}
	band = ingressRoot | 2
	if old == band {
		band = ingressRoot | 3
	}
	major := ingressMajor(band)
	// A process may have crashed after installing an inactive band. Remove
	// only that band's HTB; never delete the tree still referenced by BPF.
	qs, err := safenetlink.QdiscList(dev)
	if err != nil {
		return 0, err
	}
	for _, child := range qs {
		if child.Attrs().Parent == band && child.Type() == "htb" && child.Attrs().Handle == uint32(major)<<16 {
			if err = netlink.QdiscDel(child); err != nil {
				return 0, err
			}
		}
	}
	tree, err := classtree.InstallAt(dev, *limits, band, major)
	if err != nil {
		return 0, err
	}
	if err = s.addFilters(dev, uint32(major)<<16, true); err != nil {
		return 0, errors.Join(err, tree.Remove())
	}
	return band, nil
}
func retireIngress(k classKey, old, next uint32, keepFQ bool) error {
	if old == 0 {
		return nil
	}
	dev, err := netlink.LinkByIndex(int(k.Veth))
	if errors.As(err, &netlink.LinkNotFoundError{}) {
		return nil
	}
	if err != nil {
		return err
	}
	q, err := rootQdisc(dev)
	if err != nil || !isClassRoot(q) {
		return err
	}
	if next == 0 {
		if !keepFQ {
			return netlink.QdiscDel(q)
		}
		return ensureFq(dev, ingressFq)
	}
	qs, err := safenetlink.QdiscList(dev)
	if err != nil {
		return err
	}
	for _, child := range qs {
		if child.Type() == "htb" && child.Attrs().Handle == uint32(ingressMajor(old))<<16 && child.Attrs().Parent == old {
			return netlink.QdiscDel(child)
		}
	}
	return nil
}
