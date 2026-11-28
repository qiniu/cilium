// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package classtree builds the opt-in scheduler for one direction of one
// chained endpoint. It does not identify traffic or attach itself to links.
package classtree

import (
	"errors"
	"fmt"
	"math"

	"github.com/vishvananda/netlink"
)

// Limits are in bits/s. Zero means no limit at that level.
type Limits struct{ Total, EastWest, NorthSouth uint64 }

const (
	major      = 0xc1
	parent     = 1
	Unknown    = 2
	EastWest   = 3
	NorthSouth = 4
)

// ClassID is written to skb->priority by a trusted classifier immediately
// before enqueue. Never pass a Pod-supplied priority through to HTB: the
// special major:0 priority goes to its unshaped direct queue.
func ClassID(minor uint16) uint32 { return netlink.MakeHandle(major, minor) }

type class struct {
	minor, parent uint16
	rate, ceil    uint64
}

func plan(l Limits) ([]class, error) {
	if l.EastWest == 0 && l.NorthSouth == 0 {
		return nil, errors.New("no class cap; use the existing aggregate shaper")
	}
	for _, v := range []uint64{l.Total, l.EastWest, l.NorthSouth} {
		// netlink's HTB rate table and burst calculations use whole bytes
		// and 32-bit timing fields. Reject unsupported values, never wrap.
		if v != 0 && (v < 8000 || v > math.MaxUint32*8 || v%8 != 0) {
			return nil, fmt.Errorf("unsupported HTB rate %d bits/s", v)
		}
	}
	var classes []class
	if l.Total != 0 {
		classes = append(classes, class{parent, 0, l.Total, l.Total})
	}
	for _, leaf := range []struct {
		minor uint16
		limit uint64
	}{{Unknown, 0}, {EastWest, l.EastWest}, {NorthSouth, l.NorthSouth}} {
		ceil := leaf.limit
		if l.Total == 0 {
			// No aggregate: independent classes, with the direct queue for
			// unknown/unlimited traffic. No synthetic node/link speed cap.
			if ceil != 0 {
				classes = append(classes, class{leaf.minor, 0, ceil, ceil})
			}
			continue
		}
		if ceil == 0 || ceil > l.Total {
			ceil = l.Total
		}
		// Rate distributes service under contention; ceil, not rate, is
		// the cap. A lone active leaf can borrow up to its full ceiling.
		share := min(ceil, (l.Total/8/3)*8)
		classes = append(classes, class{leaf.minor, parent, share, ceil})
	}
	return classes, nil
}

// Tree is exclusively managed by the caller for the lifetime of the link.
// Calls for a given tree must be serialized by the endpoint manager.
type Tree struct {
	root    *netlink.Htb
	mtu     uint32
	classes []class
}

func (t *Tree) kernelClass(c class) *netlink.HtbClass {
	attrs := netlink.ClassAttrs{LinkIndex: t.root.LinkIndex, Parent: ClassID(c.parent), Handle: ClassID(c.minor)}
	return netlink.NewHtbClass(attrs, netlink.HtbClassAttrs{Rate: c.rate, Ceil: c.ceil, Quantum: t.mtu})
}

// ErrRestage means a topology change needs a newly prepared device; the old
// tree still enforces the old policy. Rate-only updates retain all queues.
var ErrRestage = errors.New("class topology changed; stage a new tree")

func (t *Tree) Update(limits Limits) error {
	next, err := plan(limits)
	if err != nil {
		return err
	}
	if len(next) != len(t.classes) {
		return ErrRestage
	}
	for i, c := range next {
		if c.minor != t.classes[i].minor || c.parent != t.classes[i].parent {
			return ErrRestage
		}
	}
	for i, c := range next {
		if c == t.classes[i] {
			continue
		}
		if err := netlink.ClassChange(t.kernelClass(c)); err != nil {
			for j := i - 1; j >= 0; j-- {
				if next[j] != t.classes[j] {
					err = errors.Join(err, netlink.ClassChange(t.kernelClass(t.classes[j])))
				}
			}
			return fmt.Errorf("change HTB class %x: %w", c.minor, err)
		}
	}
	t.classes = next
	return nil
}

// Remove is called after traffic has been detached from this staging device.
func (t *Tree) Remove() error { return netlink.QdiscDel(t.root) }

// Install builds a fresh tree. Only use this on a staging device, before
// redirecting any packets to it. Do not remove or replace a working shaper
// to prepare this tree. QdiscAdd is exclusive; an operator-owned root or a
// second installation is never overwritten. On failure roll back only the
// root we just created (and thus its children).
func Install(link netlink.Link, limits Limits) (tree *Tree, err error) {
	classes, err := plan(limits)
	if err != nil {
		return nil, err
	}
	idx := link.Attrs().Index
	q := netlink.NewHtb(netlink.QdiscAttrs{LinkIndex: idx, Parent: netlink.HANDLE_ROOT, Handle: ClassID(0)})
	if limits.Total != 0 {
		q.Defcls = Unknown
		// With a total, every delivered packet must go through a child of
		// parent. Even an explicit major:0 cannot use HTB's direct FIFO.
		zero := uint32(0)
		q.DirectQlen = &zero
	}
	if err = netlink.QdiscAdd(q); err != nil {
		return nil, fmt.Errorf("add class scheduler: %w", err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, netlink.QdiscDel(q))
		}
	}()
	t := &Tree{root: q, mtu: uint32(link.Attrs().MTU), classes: classes}
	for _, c := range classes {
		cl := t.kernelClass(c)
		if err = netlink.ClassAdd(cl); err != nil {
			return nil, fmt.Errorf("add HTB class %x: %w", c.minor, err)
		}
		if c.minor != parent {
			// Separate queues: a backlogged low-rate class must not hold up
			// other classes. Limit the leaf backlog even when the device is
			// an IFB with a small or zero txqueuelen.
			fq := netlink.NewFqCodel(netlink.QdiscAttrs{LinkIndex: idx, Parent: cl.Handle, Handle: netlink.MakeHandle(major+c.minor, 0)})
			fq.Limit = 1024
			if err = netlink.QdiscAdd(fq); err != nil {
				return nil, fmt.Errorf("add queue to class %x: %w", c.minor, err)
			}
		}
	}
	return t, nil
}
