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

// Limits (bits/s) are independent. Default is shared by all traffic that
// does not match the north-south override, including unknown peers.
type Limits struct{ Default, NorthSouth uint64 }

const (
	major        = 0xc1
	DefaultClass = 3
	NorthSouth   = 4
)

// ClassID is written to skb->priority by a trusted classifier immediately
// before enqueue. Never pass a Pod-supplied priority through to HTB: the
// special major:0 priority goes to its unshaped direct queue.
func ClassID(minor uint16) uint32 { return netlink.MakeHandle(major, minor) }

type class struct {
	minor uint16
	rate  uint64
}

func plan(l Limits) ([]class, error) {
	if l.NorthSouth == 0 {
		return nil, errors.New("no north-south override; use the existing aggregate shaper")
	}
	for _, v := range []uint64{l.Default, l.NorthSouth} {
		// netlink's HTB rate table and burst calculations use whole bytes
		// and 32-bit timing fields. Reject unsupported values, never wrap.
		if v != 0 && (v < 8000 || v > math.MaxUint32*8 || v%8 != 0) {
			return nil, fmt.Errorf("unsupported HTB rate %d bits/s", v)
		}
	}
	var classes []class
	if l.Default != 0 {
		classes = append(classes, class{DefaultClass, l.Default})
	}
	return append(classes, class{NorthSouth, l.NorthSouth}), nil
}

// Tree is exclusively managed by the caller for the lifetime of the link.
// Calls for a given tree must be serialized by the endpoint manager.
type Tree struct {
	root    *netlink.Htb
	mtu     uint32
	classes []class
	// A failed netlink change may mean a class no longer exists. Even if
	// all earlier changes roll back, the cached plan cannot prove otherwise.
	needsRestage bool
}

func (t *Tree) kernelClass(c class) *netlink.HtbClass {
	attrs := netlink.ClassAttrs{LinkIndex: t.root.LinkIndex, Parent: t.root.Handle, Handle: ClassID(c.minor)}
	return netlink.NewHtbClass(attrs, netlink.HtbClassAttrs{Rate: c.rate, Ceil: c.rate, Quantum: t.mtu})
}

// ErrRestage means the requested topology differs, or the kernel tree no
// longer has a known configuration. Prepare a replacement on a staging link.
var ErrRestage = errors.New("class scheduler needs a newly staged tree")

func (t *Tree) Update(limits Limits) error {
	if t.needsRestage {
		return ErrRestage
	}
	next, err := plan(limits)
	if err != nil {
		return err
	}
	if len(next) != len(t.classes) {
		return ErrRestage
	}
	for i, c := range next {
		if c.minor != t.classes[i].minor {
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
			t.needsRestage = true
			return errors.Join(ErrRestage, fmt.Errorf("change HTB class %x: %w", c.minor, err))
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
	if limits.Default != 0 {
		q.Defcls = DefaultClass
		// Internal and unclassified share one default; no direct bypass.
		zero := uint32(0)
		q.DirectQlen = &zero
	} else {
		// Unmatched packets have no cap in this mode. Do not inherit
		// txqueuelen: on a zero-queue IFB this would drop every one.
		capacity := uint32(1024)
		q.DirectQlen = &capacity
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
		fq := netlink.NewFqCodel(netlink.QdiscAttrs{LinkIndex: idx, Parent: cl.Handle})
		fq.Limit = 1024
		if err = netlink.QdiscAdd(fq); err != nil {
			return nil, fmt.Errorf("add queue to class %x: %w", c.minor, err)
		}
	}
	return t, nil
}
