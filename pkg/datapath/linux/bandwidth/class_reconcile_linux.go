// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bandwidth

import (
	"errors"
	"net"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/bandwidth/classtree"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
)

// A crash can leave the reserved root even before the first map Put, or an
// inactive tree after Put. Without a selector use the legacy FQ: an endpoint
// may still have a direction total in the independently reconciled EDT map.
func recoverClassRoot(dev netlink.Link, active uint32) error {
	q, err := rootQdisc(dev)
	if err != nil || !isClassRoot(q) {
		return err
	}
	if active == 0 {
		return ensureFq(dev, ingressFq)
	}
	if err := ensureDefaultBand(dev); err != nil {
		return err
	}
	inactive := ingressRoot | 2
	if active == inactive {
		inactive = ingressRoot | 3
	}
	return retireIngress(classKey{Veth: uint32(dev.Attrs().Index)}, inactive, active, false)
}

// Never infer datapath state from an annotation cache alone. Only inspect the
// endpoint's links on the no-change path; full orphan collection runs after
// restore or an incomplete cleanup.
func (s *classState) targetsIntact(k classKey, dev netlink.Link, links classLinks, p classtree.Policy) (bool, error) {
	if (links.Out != 0) != (p.Egress != nil) || (links.In != 0) != (p.Ingress != nil) {
		return false, nil
	}
	if p.Egress != nil {
		out, err := netlink.LinkByIndex(int(links.Out))
		if errors.As(err, &netlink.LinkNotFoundError{}) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if out.Type() != "ifb" || out.Attrs().Alias != classAlias(k) || out.Attrs().Flags&net.FlagUp == 0 {
			return false, nil
		}
		if ok, err := s.hasTree(out, netlink.HANDLE_ROOT, classtree.ClassID(0), *p.Egress, false); err != nil || !ok {
			return ok, err
		}
	}
	if p.Ingress != nil {
		q, err := rootQdisc(dev)
		if err != nil || !isClassRoot(q) {
			return false, err
		}
		if err = ensureDefaultBand(dev); err != nil {
			return false, err
		}
		return s.hasTree(dev, links.In, uint32(ingressMajor(links.In))<<16, *p.Ingress, true)
	}
	return true, nil
}

func (s *classState) hasTree(dev netlink.Link, parent, root uint32, l classtree.Limits, ingress bool) (bool, error) {
	qs, err := safenetlink.QdiscList(dev)
	if err != nil {
		return false, err
	}
	htb := false
	leaves := map[uint32]bool{}
	for _, q := range qs {
		a := q.Attrs()
		if h, ok := q.(*netlink.Htb); ok && a.Parent == parent && a.Handle == root {
			htb = h.DirectQlen != nil && ((l.Default != 0 && h.Defcls == classtree.DefaultClass && *h.DirectQlen == 0) || (l.Default == 0 && h.Defcls == 0 && *h.DirectQlen > 0))
		}
		if q.Type() == "fq_codel" {
			leaves[a.Parent] = true
		}
	}
	if !htb {
		return false, nil
	}
	classes, err := safenetlink.ClassList(dev, root)
	if err != nil {
		return false, err
	}
	ceils := map[uint32]uint64{}
	for _, class := range classes {
		if h, ok := class.(*netlink.HtbClass); ok {
			ceils[h.Handle] = h.Ceil * 8
		}
	}
	for minor, rate := range map[uint16]uint64{classtree.DefaultClass: l.Default, classtree.NorthSouth: l.NorthSouth} {
		id := root | uint32(minor)
		if ceils[id] != rate || (rate != 0 && !leaves[id]) {
			return false, nil
		}
	}
	fs, err := safenetlink.FilterList(dev, root)
	if err != nil {
		return false, err
	}
	byPrio := map[uint16]*netlink.Flower{}
	for _, f := range fs {
		flower, ok := f.(*netlink.Flower)
		if !ok {
			return false, nil
		}
		byPrio[f.Attrs().Priority] = flower
	}
	for i, prefix := range s.peers {
		priority := uint16(i + 1)
		f := byPrio[priority]
		if f == nil || f.ClassId != root|classtree.NorthSouth {
			return false, nil
		}
		ip, mask := f.DestIP, f.DestIPMask
		if ingress {
			ip, mask = f.SrcIP, f.SrcIPMask
		}
		ones, bits := mask.Size()
		if !ip.Equal(net.IP(prefix.Addr().AsSlice())) || ones != prefix.Bits() || bits != prefix.Addr().BitLen() {
			return false, nil
		}
		delete(byPrio, priority)
	}
	return len(byPrio) == 0, nil
}
