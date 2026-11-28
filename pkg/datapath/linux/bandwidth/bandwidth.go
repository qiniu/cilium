// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

// NOTE: We can only build on linux because we import bwmap which in turn imports pkg/ebpf and pkg/bpf
//       which throw build errors when building on non-linux platforms.

package bandwidth

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/bwmap"
	"github.com/cilium/cilium/pkg/node"
)

const (
	// EgressBandwidth is the K8s Pod annotation.
	EgressBandwidth = "kubernetes.io/egress-bandwidth"
	// IngressBandwidth is the K8s Pod annotation.
	IngressBandwidth = "kubernetes.io/ingress-bandwidth"
	// Priority is the Cilium Pod priority annotation.
	Priority = "bandwidth.cilium.io/priority"

	// FqDefaultHorizon represents maximum allowed departure
	// time delta in future. Given applications can set SO_TXTIME
	// from user space this is a limit to prevent buggy applications
	// to fill the FQ qdisc.
	FqDefaultHorizon = bwmap.DefaultDropHorizon
	// FqDefaultBuckets is the default 32k (2^15) bucket limit for bwm.
	// Too low bucket limit can cause scalability issue.
	FqDefaultBuckets = 15

	// FQ priomap starting from index 0 is 1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1
	// Constants below map priority levels to bands high, medium and low.
	// TODO: These are picked arbitrarily for each QoS class amongst different possible
	// values. Revisit to see if picking these values would have any unintended side effects.
	// HACK: Increment prio values by 1 to allow for distinguishing between 0 prio and no prio set.

	// GuaranteedQoSDefaultPriority prio value to classify packets to high prio band
	GuaranteedQoSDefaultPriority = 6 + 1
	// BurstableQoSDefaultPriority prio value to classify packets to medium prio band
	BurstableQoSDefaultPriority = 8 + 1
	// BestEffortQoSDefaultPriority prio value to classify packets to medium prio band
	BestEffortQoSDefaultPriority = 5 + 1
)

// Must be in sync with DIRECTION_* in <bpf/lib/common.h>
const (
	DirectionEgress  uint8 = 0
	DirectionIngress uint8 = 1
)

type manager struct {
	enabled bool
	classes *classState

	// throttle is the BPF map the EDT table is reconciled to.
	throttle *bpf.Map

	params bandwidthManagerParams
}

func (m *manager) Enabled() bool {
	return m.enabled
}

func (m *manager) BBREnabled() bool {
	return m.params.Config.EnableBBR
}

func (m *manager) defines() (defines.Map, error) {
	cDefinesMap := make(defines.Map)

	if m.Enabled() {
		cDefinesMap["ENABLE_BANDWIDTH_MANAGER"] = "1"
	}

	if m.classes != nil {
		cDefinesMap["ENABLE_CHAINED_QOS_CLASSES"] = "1"
	}
	cDefinesMap["THROTTLE_MAP_SIZE"] = fmt.Sprintf("%d", bwmap.MapSize)

	return cDefinesMap, nil
}

func (m *manager) UpdateBandwidthLimit(epID uint16, bytesPerSecond uint64, prio uint32) {
	if !m.enabled {
		return
	}
	edt := bwmap.NewEdt(epID, DirectionEgress, bytesPerSecond, prio)
	if m.egressViaIfb() {
		if bytesPerSecond != 0 {
			// The device comes first: the datapath redirects to
			// whatever the entry names. On failure whatever limit
			// is in place stays as it is.
			// shortcut: no retry, the next update of the endpoint's
			// bandwidth or restart of the agent tries again.
			ifindex, err := setupIfb(epID)
			if err != nil {
				m.params.Log.Error("Cannot pace the egress of the endpoint, its egress bandwidth limit is not updated",
					logfields.Error, err,
					logfields.EndpointID, epID,
					logfields.Device, ifbName(epID))
				return
			}
			edt.IfIndex = uint32(ifindex)
		} else {
			// Before the new entry is committed: this takes the old
			// one out of the BPF map, and must not take the new one.
			m.removeIfb(epID)
		}
	}

	txn := m.params.DB.WriteTxn(m.params.EdtTable)

	// Set host endpoint to guaranteed QoS class
	// TODO: This attempts to lookup host endpoint for every BW manager update event.
	// Find a way to get host endpoint ID during BW manager initialization and move this section to init().
	// * init() seems to be too early to call node.GetEndpointID()
	// * Adding a dependency to node manager to call GetHostEndpoint() introduces a nested import.
	hostEpID := uint16(node.GetEndpointID())
	_, _, found := m.params.EdtTable.Get(txn, bwmap.EdtIDIndex.Query(bwmap.EdtIDKey{
		EndpointID: epID,
		Direction:  DirectionEgress,
	}))
	if !found {
		m.params.EdtTable.Insert(
			txn,
			bwmap.NewEdt(hostEpID, DirectionEgress, 0, GuaranteedQoSDefaultPriority),
		)
	}
	m.params.EdtTable.Insert(txn, edt)
	txn.Commit()
}

// removeIfb removes the pacing device of an endpoint that no longer has an
// egress limit.
func (m *manager) removeIfb(epID uint16) {
	// The datapath redirects to the device for as long as the entry in the
	// BPF map names it, and the table is only reconciled to the map a
	// moment from now: take the entry out first, or what the endpoint
	// sends in between is dropped with the device. The reconciler writes
	// the entry again if the table still has one.
	if m.throttle != nil {
		if _, err := m.throttle.SilentDelete(&bwmap.EdtId{Id: uint32(epID), Direction: DirectionEgress}); err != nil {
			m.params.Log.Warn("Cannot remove the egress limit of the endpoint from the datapath",
				logfields.Error, err,
				logfields.EndpointID, epID)
		}
	}
	if err := removeIfb(ifbName(epID)); err != nil {
		m.params.Log.Warn("Cannot remove the egress pacing device of the endpoint",
			logfields.Error, err,
			logfields.EndpointID, epID,
			logfields.Device, ifbName(epID))
	}
}

func (m *manager) DeleteBandwidthLimit(epID uint16) {
	if m.enabled {
		txn := m.params.DB.WriteTxn(m.params.EdtTable)
		obj, _, found := m.params.EdtTable.Get(txn, bwmap.EdtIDIndex.Query(bwmap.EdtIDKey{
			EndpointID: epID,
			Direction:  DirectionEgress,
		}))
		if found {
			m.params.EdtTable.Delete(txn, obj)
		}
		txn.Commit()

		if m.egressViaIfb() {
			m.removeIfb(epID)
		}
	}
}

func (m *manager) UpdateIngressBandwidthLimit(epID uint16, ifName string, bytesPerSecond uint64) {
	if !m.enabled {
		return
	}
	edt := bwmap.NewEdt(epID, DirectionIngress, bytesPerSecond, 0)
	// Policed, unless shaped below.
	edt.TimeHorizonDrop = 0
	if m.ingressViaFq() {
		// The qdisc comes first: a departure time nothing honours is no
		// limit at all.
		// On failure whatever limit is in place stays as it is: a limit
		// that worked is better than none.
		// shortcut: no retry, the next update of the endpoint's bandwidth
		// or restart of the agent tries again. Add one if failures turn
		// out to be transient in practice.
		if err := setupIngressFq(ifName); err != nil {
			m.params.Log.Error("Cannot shape the ingress of the endpoint, its ingress bandwidth limit is not updated",
				logfields.Error, err,
				logfields.EndpointID, epID,
				logfields.Interface, ifName)
			return
		}
		edt.TimeHorizonDrop = uint64(IngressHorizon)
	}
	txn := m.params.DB.WriteTxn(m.params.EdtTable)
	m.params.EdtTable.Insert(txn, edt)
	txn.Commit()
}

func (m *manager) DeleteIngressBandwidthLimit(epID uint16, ifName string) {
	if !m.enabled {
		return
	}
	txn := m.params.DB.WriteTxn(m.params.EdtTable)
	obj, _, found := m.params.EdtTable.Get(txn, bwmap.EdtIDIndex.Query(bwmap.EdtIDKey{
		EndpointID: epID,
		Direction:  DirectionIngress,
	}))
	if found {
		m.params.EdtTable.Delete(txn, obj)
	}
	txn.Commit()

	if m.ingressViaFq() {
		if err := removeIngressFqByName(ifName); err != nil {
			m.params.Log.Warn("Cannot remove the ingress pacing qdisc of the endpoint",
				logfields.Error, err,
				logfields.EndpointID, epID,
				logfields.Interface, ifName)
		}
	}
}

func GetBytesPerSec(bandwidth string) (uint64, error) {
	res, err := resource.ParseQuantity(bandwidth)
	if err != nil {
		return 0, err
	}
	return uint64(res.Value() / 8), err
}

// probe checks the various system requirements of the bandwidth manager and disables it if they are
// not met.
func (m *manager) probe() error {
	if !m.params.Config.EnableBandwidthManager {
		return nil
	}
	// The node's settings are only written to pace on its devices. With a
	// chained CNI they are left alone, and a node that is a container
	// itself (kind) does not have this one.
	if !m.egressViaIfb() {
		if _, err := m.params.Sysctl.Read([]string{"net", "core", "default_qdisc"}); err != nil {
			m.params.Log.Warn("BPF bandwidth manager could not read procfs. Disabling the feature.", logfields.Error, err)
			return nil
		}
	}
	if m.params.Config.EnableBBR {
		// We at least need 5.18 kernel for Pod-based BBR TCP congestion
		// control since earlier kernels just clear the skb->tstamp upon
		// netns traversal. See also:
		//
		// - https://lpc.events/event/11/contributions/953/
		// - https://lore.kernel.org/bpf/20220302195519.3479274-1-kafai@fb.com/
		if probes.HaveProgramHelper(m.params.Log, ebpf.SchedCLS, asm.FnSkbSetTstamp) != nil {
			return fmt.Errorf("cannot enable --%s, needs kernel 5.18 or newer", types.EnableBBRFlag)
		}
	}

	if !m.params.Config.EnableBBR && m.params.Config.EnableBBRHostnsOnly {
		return fmt.Errorf("cannot enable --%s without enabling --%s", types.EnableBBRHostnsOnlyFlag, types.EnableBBRFlag)
	}

	// Going via host stack will orphan skb->sk, so we do need BPF host
	// routing for it to work properly.
	if m.params.Config.EnableBBR && m.params.DaemonConfig.EnableHostLegacyRouting && !m.params.Config.EnableBBRHostnsOnly {
		return fmt.Errorf("BPF bandwidth manager's BBR setup requires BPF host routing.")
	}

	if m.params.Config.EnableBandwidthManager && m.params.IPsecConfig.Enabled() {
		m.params.Log.Warn("The bandwidth manager cannot be used with IPSec. Disabling the bandwidth manager.")
		return nil
	}

	m.enabled = true
	return nil
}

func (m *manager) init() error {
	m.params.Log.Info("Setting up BPF bandwidth manager")

	m.throttle = bwmap.ThrottleMap()
	if err := m.throttle.OpenOrCreate(); err != nil {
		return fmt.Errorf("failed to access ThrottleMap: %w", err)
	}
	return m.setupPacing()
}

// setupPacing prepares the node for pacing on its devices. With a chained CNI
// the endpoints are paced on devices of their own, set up with their limits.
func (m *manager) setupPacing() error {
	if m.egressViaIfb() {
		// The settings below tune pacing on the native devices, which the
		// endpoints' traffic never reaches here: leave the node's qdisc
		// default and congestion control as the operator set them.
		return nil
	}

	if err := setBaselineSysctls(m.params); err != nil {
		return fmt.Errorf("failed to set sysctl needed by BPF bandwidth manager: %w", err)
	}
	return nil
}

func setBaselineSysctls(p bandwidthManagerParams) error {
	// Ensure interger type sysctls are no smaller than our baseline settings
	baseIntSettings := []struct {
		name []string
		val  int64
	}{
		{[]string{"net", "core", "netdev_max_backlog"}, 1000},
		{[]string{"net", "core", "somaxconn"}, 4096},
		{[]string{"net", "ipv4", "tcp_max_syn_backlog"}, 4096},
	}

	for _, setting := range baseIntSettings {
		currentValue, err := p.Sysctl.ReadInt(setting.name)
		if err != nil {
			return fmt.Errorf("read sysctl %s failed: %w", strings.Join(setting.name, "."), err)
		}

		scopedLog := p.Log.With(
			logfields.SysParamName, strings.Join(setting.name, "."),
			logfields.SysParamValue, currentValue,
			logfields.SysParamBaselineValue, setting.val,
		)

		if currentValue >= setting.val {
			scopedLog.Info("Skip setting sysctl as it already meets baseline")
			continue
		}

		scopedLog.Info("Setting sysctl to baseline for BPF bandwidth manager")
		if err := p.Sysctl.WriteInt(setting.name, setting.val); err != nil {
			return fmt.Errorf("set sysctl %s=%d failed: %w", strings.Join(setting.name, "."), setting.val, err)
		}
	}

	// Ensure string type sysctls
	congctl := "cubic"
	if p.Config.EnableBBR {
		congctl = "bbr"
	}

	sysctls := []tables.Sysctl{
		{Name: []string{"net", "core", "default_qdisc"}, Val: "fq"},
		{Name: []string{"net", "ipv4", "tcp_congestion_control"}, Val: congctl},
	}

	// Few extra knobs which can be turned on along with pacing. EnableBBR
	// also provides the right kernel dependency implicitly as well.
	if p.Config.EnableBBR {
		sysctls = append(sysctls, tables.Sysctl{
			Name: []string{"net", "ipv4", "tcp_slow_start_after_idle"}, Val: "0",
		})
	}

	if err := p.Sysctl.ApplySettings(sysctls); err != nil {
		return fmt.Errorf("failed to apply sysctls: %w", err)
	}

	return nil
}
