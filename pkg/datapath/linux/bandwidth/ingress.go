// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bandwidth

import (
	"errors"
	"fmt"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// With a chained CNI (generic-veth) the ingress limit of an endpoint is shaped
// rather than policed. The endpoint's ingress program runs at the egress of
// the host-side veth, right in front of that device's qdisc: it computes a
// departure time, and an FQ on the veth holds the packet until then. The FQ
// only exists on the veth of an endpoint that has an ingress limit.
const (
	// IngressHorizon is how long a packet may wait for its turn before it is
	// dropped. It bounds the delay the limit adds to everything the endpoint
	// receives while it is saturated, and the memory a sender that does not
	// back off can make the node hold (horizon times rate).
	//
	// A sender on the same node is blocked by its socket buffer once about
	// 200KB are queued, which is 160ms at 10Mbit/s: with a shorter horizon,
	// or a lower rate, part of what it sends is dropped instead.
	IngressHorizon = 200 * time.Millisecond

	// pacingFqLimit is the packet limit of the FQs chained endpoints are
	// paced on, per flow and in total. The departure times already bound
	// what is queued, to horizon times rate, so it only has to stay out of
	// the way: a packet the FQ drops has been charged to the limit, and with
	// the default of 100 per flow a single flow of small packets that
	// overruns its limit is left with 100 packets per horizon.
	pacingFqLimit = 100000
)

// ingressViaFq reports whether ingress limits are shaped on the endpoints'
// veths instead of being policed in local_delivery().
func (m *manager) ingressViaFq() bool {
	return m.params.DaemonConfig.GenericVethChaining()
}

func rootQdisc(link netlink.Link) (netlink.Qdisc, error) {
	qdiscs, err := safenetlink.QdiscList(link)
	if err != nil {
		return nil, err
	}
	for _, q := range qdiscs {
		if q.Attrs().Parent == netlink.HANDLE_ROOT {
			return q, nil
		}
	}
	return nil, nil
}

func sameFq(q netlink.Qdisc, fq *netlink.Fq) bool {
	cur, ok := q.(*netlink.Fq)
	return ok && cur.PacketLimit == fq.PacketLimit && cur.FlowPacketLimit == fq.FlowPacketLimit &&
		cur.Horizon == fq.Horizon && (fq.Buckets == 0 || cur.Buckets == fq.Buckets)
}

// ensureFq makes fq the root qdisc of the device. One that is already there
// with the same parameters is left alone, so that an update of a limit or a
// restart of the agent does not drop what it holds.
func ensureFq(link netlink.Link, fq netlink.Fq) error {
	root, err := rootQdisc(link)
	if err != nil {
		return err
	}
	if sameFq(root, &fq) {
		return nil
	}
	fq.QdiscAttrs = netlink.QdiscAttrs{LinkIndex: link.Attrs().Index, Parent: netlink.HANDLE_ROOT}
	fq.Pacing = 1
	return netlink.QdiscReplace(&fq)
}

// ingressFq is the FQ on the veth of an endpoint with an ingress limit. Its
// parameters also tell it from an FQ somebody else put there.
var ingressFq = netlink.Fq{
	PacketLimit:       pacingFqLimit,
	FlowPacketLimit:   pacingFqLimit,
	Horizon:           uint32(IngressHorizon.Microseconds()),
	HorizonDropPolicy: netlink.HORIZON_DROP_POLICY_DROP,
}

func isIngressFq(q netlink.Qdisc) bool {
	return sameFq(q, &ingressFq)
}

func setupIngressFq(ifName string) error {
	link, err := safenetlink.LinkByName(ifName)
	if err != nil {
		return err
	}
	return ensureFq(link, ingressFq)
}

// removeIngressFq takes our FQ off the device again. A device that is gone, or
// that carries anything else, is left alone.
func removeIngressFq(link netlink.Link) error {
	root, err := rootQdisc(link)
	if err != nil || !isIngressFq(root) {
		return err
	}
	return netlink.QdiscDel(root)
}

func removeIngressFqByName(ifName string) error {
	link, err := safenetlink.LinkByName(ifName)
	if err != nil {
		if errors.As(err, &netlink.LinkNotFoundError{}) {
			return nil
		}
		return err
	}
	return removeIngressFq(link)
}

// removeAllIngressFq removes the FQs a previous run left on the endpoints'
// veths. Only called when this configuration does not shape ingress.
func removeAllIngressFq() error {
	links, err := safenetlink.LinkList()
	if err != nil {
		return fmt.Errorf("listing devices: %w", err)
	}
	var errs []error
	for _, link := range links {
		if link.Type() != "veth" {
			continue
		}
		if err := removeIngressFq(link); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", link.Attrs().Name, err))
		}
	}
	return errors.Join(errs...)
}

// ReleaseUnusedPacing removes what chained endpoints were paced on and no
// limit of this run uses: the ifbs of egress limits and the FQs of ingress
// limits.
//
// It must only be called once the restored endpoints have been regenerated:
// until then their limits may not have been read yet, and their programs are
// the ones the previous run loaded, which still redirect to the devices.
func (m *manager) ReleaseUnusedPacing() {
	if err := m.removeUnusedIfbs(); err != nil {
		m.params.Log.Warn("Cannot remove the unused egress pacing devices",
			logfields.Error, err)
	}
	if !m.enabled || !m.ingressViaFq() {
		if err := removeAllIngressFq(); err != nil {
			m.params.Log.Warn("Cannot remove the unused ingress pacing qdiscs",
				logfields.Error, err)
		}
	}
}
