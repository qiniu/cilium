// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import "github.com/spf13/pflag"

const (
	EnableBandwidthManagerFlag = "enable-bandwidth-manager"
	EnableBBRFlag              = "enable-bbr"
	EnableBBRHostnsOnlyFlag    = "enable-bbr-hostns-only"
)

type BandwidthConfig struct {
	// EnableBandwidthManager enables EDT-based pacing
	EnableBandwidthManager bool

	// Operator-defined, disjoint peer prefixes in a single routing domain.
	ChainedQoSNorthSouthCIDRs string

	// EnableBBR enables BBR TCP congestion control for the node including Pods
	EnableBBR bool

	// EnableBBRHostnsOnly enables BBR TCP congestion control for the node excluding Pods
	EnableBBRHostnsOnly bool
}

func (def BandwidthConfig) Flags(flags *pflag.FlagSet) {
	flags.String("chained-qos-north-south-cidrs", "", "Comma-separated trusted external peer prefixes for generic-veth class QoS (do not include NAT gateway addresses)")
	flags.Bool(EnableBandwidthManagerFlag, def.EnableBandwidthManager, "Enable BPF bandwidth manager")
	flags.Bool(EnableBBRFlag, def.EnableBBR, "Enable BBR for the bandwidth manager")
	flags.Bool(EnableBBRHostnsOnlyFlag, def.EnableBBRHostnsOnly, "Enable BBR only in the host network namespace.")
}

var DefaultBandwidthConfig = BandwidthConfig{
	EnableBandwidthManager: false,
	EnableBBR:              false,
	EnableBBRHostnsOnly:    false,
}

type BandwidthManager interface {
	BBREnabled() bool
	Enabled() bool

	UpdateBandwidthLimit(endpointID uint16, bytesPerSecond uint64, prio uint32)
	DeleteBandwidthLimit(endpointID uint16)
	UpdateClassBandwidth(endpointID uint16, ifName string, annotations map[string]string) error
	DeleteClassBandwidth(endpointID uint16, ifName string) error

	// ReleaseUnusedPacing removes the devices and qdiscs chained endpoints
	// were paced on and that no limit of this run uses. Only to be called
	// once the restored endpoints have been regenerated: until then their
	// limits may not be known yet, and their programs may be those of a
	// previous run.
	ReleaseUnusedPacing()
	// ifName is the endpoint's host-side interface: with a chained CNI the
	// ingress limit is shaped on it.
	UpdateIngressBandwidthLimit(endpointID uint16, ifName string, bytesPerSecond uint64)
	DeleteIngressBandwidthLimit(endpointID uint16, ifName string)
}
