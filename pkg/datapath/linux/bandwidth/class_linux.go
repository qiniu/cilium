// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bandwidth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/bandwidth/classtree"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maps/bwmap"
)

const classMapName = "cilium_qos_ifb"
const classOwner = "cilium:chained-qos:"

type classKey struct{ EP, Veth uint32 }
type classLinks struct{ Out, In uint32 }
type publishedClass struct {
	classtree.Policy
	targets classLinks
}

type classState struct {
	lock.Mutex
	cleanupPending bool
	redirects      *ebpf.Map
	peers          []netip.Prefix
	live           map[classKey]publishedClass
}

func parsePeerRules(external string) ([]netip.Prefix, error) {
	var rules []netip.Prefix
	for s := range strings.SplitSeq(external, ",") {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil || p != p.Masked() || p.Bits() == 0 || p.Addr().Is4In6() {
			return nil, fmt.Errorf("invalid chained QoS peer prefix %q", s)
		}
		for _, r := range rules {
			if p.Overlaps(r) {
				return nil, fmt.Errorf("overlapping chained QoS prefixes %s and %s", p, r)
			}
		}
		rules = append(rules, p)
	}
	if len(rules) > 1024 {
		return nil, errors.New("at most 1024 chained QoS peer prefixes are supported")
	}
	return rules, nil
}

func (m *manager) initClasses() error {
	cfg := m.params.Config
	if cfg.ChainedQoSNorthSouthCIDRs == "" {
		return nil
	}
	if !m.enabled || !m.egressViaIfb() || m.params.DaemonConfig.EnableNativeVPC || !m.params.DaemonConfig.EnableHostLegacyRouting {
		return errors.New("chained class QoS requires bandwidth manager, single-domain generic-veth and legacy host routing")
	}
	peers, err := parsePeerRules(cfg.ChainedQoSNorthSouthCIDRs)
	if err != nil {
		return err
	}
	path := bpf.MapPath(m.params.Log, classMapName)
	redirects, err := ebpf.NewMapWithOptions(&ebpf.MapSpec{Name: classMapName, Type: ebpf.Hash, KeySize: 8, ValueSize: 8, MaxEntries: bwmap.MapSize, Pinning: ebpf.PinByName}, ebpf.MapOptions{PinPath: filepath.Dir(path)})
	if err != nil {
		return err
	}
	m.classes = &classState{redirects: redirects, peers: peers, live: map[classKey]publishedClass{}}
	return nil
}

func classAlias(k classKey) string { return fmt.Sprintf("%s%d:%d", classOwner, k.EP, k.Veth) }

// Stage on a new IFB. Never replace a live veth root or publish an ifindex
// until all classes and filters for both directions have been created.
func (s *classState) stageEgress(k classKey, dev netlink.Link, limits *classtree.Limits) (uint32, error) {
	if limits == nil {
		return 0, nil
	}
	link := &netlink.Ifb{LinkAttrs: netlink.LinkAttrs{Name: "cqos" + rand.Text()[:10], Alias: classAlias(k), MTU: dev.Attrs().MTU, TxQLen: 1000}}
	if err := netlink.LinkAdd(link); err != nil {
		return 0, fmt.Errorf("create class IFB: %w", err)
	}
	clean := true
	defer func() {
		if clean {
			_ = netlink.LinkDel(link)
		}
	}()
	// Set the ownership marker on the created device: IFB creation does not
	// reliably preserve IFLA_IFALIAS on all supported kernels.
	if err := netlink.LinkSetAlias(link, classAlias(k)); err != nil {
		return 0, err
	}
	if _, err := classtree.Install(link, *limits); err != nil {
		return 0, err
	}
	if err := s.addFilters(link, classtree.ClassID(0), false); err != nil {
		return 0, err
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return 0, err
	}
	clean = false
	return uint32(link.Index), nil
}

func (s *classState) addFilters(link netlink.Link, root uint32, ingress bool) error {
	for i, prefix := range s.peers {
		proto := uint16(unix.ETH_P_IPV6)
		if prefix.Addr().Is4() {
			proto = unix.ETH_P_IP
		}
		ip := net.IP(prefix.Addr().AsSlice())
		mask := net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen())
		f := &netlink.Flower{FilterAttrs: netlink.FilterAttrs{LinkIndex: link.Attrs().Index, Parent: root, Protocol: proto, Priority: uint16(i + 1)}, EthType: proto, ClassId: root | classtree.NorthSouth}
		if ingress {
			f.SrcIP = ip
			f.SrcIPMask = mask
		} else {
			f.DestIP = ip
			f.DestIPMask = mask
		}
		if err := netlink.FilterAdd(f); err != nil {
			return fmt.Errorf("install peer rule %s on %s: %w", prefix, link.Attrs().Name, err)
		}
	}
	return nil
}
func (s *classState) removeLink(k classKey, index uint32) error {
	if index == 0 {
		return nil
	}
	dev, err := netlink.LinkByIndex(int(index))
	if errors.As(err, &netlink.LinkNotFoundError{}) {
		return nil
	}
	if err != nil {
		return err
	}
	if dev.Type() == "ifb" && dev.Attrs().Alias == classAlias(k) {
		return netlink.LinkDel(dev)
	}
	return nil
}

// Sweep only after restored endpoints have regenerated: an old program may
// still use this pin while the feature is being disabled. Also collect staging
// links left by a crash between creation and publishing the map entry.
func (m *manager) sweepClasses() error {
	s := m.classes
	if s == nil {
		pin, err := ebpf.LoadPinnedMap(bpf.MapPath(m.params.Log, classMapName), nil)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		defer pin.Close()
		s = &classState{redirects: pin}
	}
	s.Lock()
	defer s.Unlock()
	if err := s.sweepLocked(m.classes != nil); err != nil {
		return err
	}
	if m.classes == nil {
		return s.redirects.Unpin()
	}
	return nil
}

func (s *classState) sweepLocked(enabled bool) error {
	activeBands := map[uint32]uint32{}
	var k classKey
	var v classLinks
	var stale []classKey
	used := map[uint32]bool{}
	it := s.redirects.Iterate()
	for it.Next(&k, &v) {
		if enabled {
			// An invalid update on restart retains the old valid tree.
			_, err := netlink.LinkByIndex(int(k.Veth))
			if err == nil {
				activeBands[k.Veth] = v.In
				used[v.Out] = true
				continue
			}
			if !errors.As(err, &netlink.LinkNotFoundError{}) {
				return err
			}
		}
		stale = append(stale, k)
	}
	if err := it.Err(); err != nil {
		return err
	}
	for _, key := range stale {
		if err := s.forget(key, true); err != nil {
			return err
		}
	}
	links, err := safenetlink.LinkList()
	if err != nil {
		return err
	}
	for _, link := range links {
		a := link.Attrs()
		if link.Type() == "veth" {
			if err := recoverClassRoot(link, activeBands[uint32(a.Index)]); err != nil {
				return err
			}
		}
		if link.Type() == "ifb" && strings.HasPrefix(a.Name, "cqos") && strings.HasPrefix(a.Alias, classOwner) && !used[uint32(a.Index)] {
			if err := netlink.LinkDel(link); err != nil {
				return err
			}
		}
	}
	s.cleanupPending = false
	return nil
}

func equalLimit(a, b *classtree.Limits) bool { return a == b || (a != nil && b != nil && *a == *b) }
func (m *manager) UpdateClassBandwidth(ep uint16, name string, annotations map[string]string) error {
	s := m.classes
	if s == nil {
		return nil
	}
	p, err := classtree.ParsePolicy(annotations)
	if err != nil {
		return err
	}
	if p.Ingress == nil && p.Egress == nil {
		return m.deleteClassBandwidth(ep, name, annotations[IngressBandwidth] != "")
	}
	dev, err := safenetlink.LinkByName(name)
	if err != nil {
		return err
	}
	if dev.Type() != "veth" {
		return fmt.Errorf("%s is not a veth", name)
	}
	k := classKey{uint32(ep), uint32(dev.Attrs().Index)}
	s.Lock()
	defer s.Unlock()
	if err := s.retryCleanup(); err != nil {
		return err
	}
	prev, ok := s.live[k]
	var old classLinks
	if err := s.redirects.Lookup(k, &old); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	if ok && prev.targets != old {
		s.cleanupPending = true
	} // detached resources are no longer reachable through the pin
	if ok && prev.targets == old && equalLimit(prev.Egress, p.Egress) && equalLimit(prev.Ingress, p.Ingress) {
		intact, err := s.targetsIntact(k, dev, old, p)
		if err != nil || intact {
			return err
		}
	}
	out, err := s.stageEgress(k, dev, p.Egress)
	if err != nil {
		return err
	}
	in, err := s.stageIngress(dev, p.Ingress, old.In)
	if err != nil {
		return errors.Join(err, s.removeLink(k, out))
	}
	if err := s.redirects.Put(k, classLinks{out, in}); err != nil {
		return errors.Join(err, s.removeLink(k, out), retireIngress(k, in, old.In, annotations[IngressBandwidth] != ""))
	}
	s.live[k] = publishedClass{p, classLinks{out, in}}
	err = errors.Join(s.removeLink(k, old.Out), retireIngress(k, old.In, in, annotations[IngressBandwidth] != ""))
	if err != nil {
		s.cleanupPending = true
		return err
	}
	return s.retryCleanup()
}
func (s *classState) retryCleanup() error {
	if s.cleanupPending {
		return s.sweepLocked(true)
	}
	return nil
}

func (s *classState) forget(k classKey, keepFQ bool) error {
	var old classLinks
	if err := s.redirects.Lookup(k, &old); errors.Is(err, ebpf.ErrKeyNotExist) {
		if _, ok := s.live[k]; ok {
			delete(s.live, k)
			s.cleanupPending = true
		}
		return nil
	} else if err != nil {
		return err
	}
	if err := s.redirects.Delete(k); err != nil {
		return err
	}
	delete(s.live, k)
	err := errors.Join(s.removeLink(k, old.Out), retireIngress(k, old.In, 0, keepFQ))
	if err != nil {
		s.cleanupPending = true
	}
	return err
}
func (m *manager) DeleteClassBandwidth(ep uint16, name string) error {
	return m.deleteClassBandwidth(ep, name, false)
}

func (m *manager) deleteClassBandwidth(ep uint16, name string, keepFQ bool) error {
	s := m.classes
	if s == nil {
		return nil
	}
	s.Lock()
	defer s.Unlock()
	if err := s.retryCleanup(); err != nil {
		return err
	}
	forget := func(key classKey) error {
		if err := s.forget(key, keepFQ); err != nil {
			return err
		}
		return s.retryCleanup()
	}
	dev, err := safenetlink.LinkByName(name)
	if errors.As(err, &netlink.LinkNotFoundError{}) {
		// The primary CNI may already have removed the host veth on DEL.
		for k := range s.live {
			if k.EP == uint32(ep) {
				return forget(k)
			}
		}
		return nil
	}
	if err != nil {
		return err
	}
	return forget(classKey{uint32(ep), uint32(dev.Attrs().Index)})
}
