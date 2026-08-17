// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

const (
	// MaxEntries is the maximum number of keys that can be present in the
	// RemoteEndpointMap.
	MaxEntries = 512000

	// OldName is the canonical name for the v1 IPCache map on the filesystem.
	OldName = "cilium_ipcache"

	// Name is the canonical name for the IPCache map on the filesystem.
	Name = "cilium_ipcache_v2"
)

// Key implements the bpf.MapKey interface.
//
// Must be in sync with struct ipcache_key in <bpf/lib/eps.h>
type Key struct {
	Prefixlen uint32 `align:"lpm_key"`
	ClusterID uint16 `align:"cluster_id"`
	Pad1      uint8  `align:"pad1"`
	Family    uint8  `align:"family"`
	// represents both IPv6 and IPv4 (in the lowest four bytes)
	IP types.IPv6 `align:"$union0"`
}

func getStaticPrefixBits() uint32 {
	staticMatchSize := unsafe.Sizeof(Key{})
	staticMatchSize -= unsafe.Sizeof(Key{}.Prefixlen)
	staticMatchSize -= unsafe.Sizeof(Key{}.IP)
	return uint32(staticMatchSize) * 8
}

func (k Key) String() string {
	var (
		addr netip.Addr
		ok   bool
	)

	switch k.Family {
	case bpf.EndpointKeyIPv4:
		addr, ok = netip.AddrFromSlice(k.IP[:net.IPv4len])
		if !ok {
			return "<unknown>"
		}
	case bpf.EndpointKeyIPv6:
		addr = netip.AddrFrom16(k.IP)
	default:
		return "<unknown>"
	}

	prefixLen := int(k.Prefixlen - getStaticPrefixBits())
	clusterID := uint32(k.ClusterID)

	return cmtypes.PrefixClusterFrom(netip.PrefixFrom(addr, prefixLen), cmtypes.WithClusterID(clusterID)).String()
}

func (k *Key) New() bpf.MapKey { return &Key{} }

func (k Key) Prefix() netip.Prefix {
	var addr netip.Addr
	prefixLen := int(k.Prefixlen - getStaticPrefixBits())
	switch k.Family {
	case bpf.EndpointKeyIPv4:
		addr = netip.AddrFrom4(*(*[4]byte)(k.IP[:4]))
	case bpf.EndpointKeyIPv6:
		addr = netip.AddrFrom16(k.IP)
	}
	return netip.PrefixFrom(addr, prefixLen)
}

// getPrefixLen determines the length that should be set inside the Key so that
// the lookup prefix is correct in the BPF map key. The specified 'prefixBits'
// indicates the number of bits in the IP that must match to match the entry in
// the BPF ipcache.
func getPrefixLen(prefixBits int) uint32 {
	return getStaticPrefixBits() + uint32(prefixBits)
}

// NewKey returns an Key based on the provided IP address, mask, and ClusterID.
// The address family is automatically detected
func NewKey(ip net.IP, mask net.IPMask, clusterID uint16) Key {
	result := Key{}

	ones, _ := mask.Size()
	if ip4 := ip.To4(); ip4 != nil {
		if mask == nil {
			ones = net.IPv4len * 8
		}
		result.Prefixlen = getPrefixLen(ones)
		result.Family = bpf.EndpointKeyIPv4
		copy(result.IP[:], ip4)
	} else {
		if mask == nil {
			ones = net.IPv6len * 8
		}
		result.Prefixlen = getPrefixLen(ones)
		result.Family = bpf.EndpointKeyIPv6
		copy(result.IP[:], ip)
	}

	result.ClusterID = clusterID

	return result
}

// VniKey implements the bpf.MapKey interface for the native-vpc VNI-scoped
// ipcache map (cilium_ipcache_vni).
//
// Must be in sync with struct ipcache_vni_key in <bpf/lib/eps.h>.
// The VNI is part of the LPM static prefix, so the trie matches on VNI+IP.
//
// Layout rule (identical to Key/struct ipcache_key): **every non-IP field must
// precede the IP field**, because the LPM static prefix is derived from
// sizeof(VniKey) - sizeof(Prefixlen) - sizeof(IP) and is then added to the IP
// prefix length. Pad2 therefore sits before IP: it rounds the non-IP part to 8
// bytes (the Go struct cannot be packed) and keeps both languages at a 64-bit
// static prefix. With the padding after the IP the static prefix would be
// inflated by 16 bits, which happens to work for host prefixes (the extra bits
// land on zeroed padding) but makes any shorter prefix match only addresses
// whose remaining bytes are zero.
//
// This is the "local ClusterID" split: upstream addresses overlapping IPs
// across clusters with a cluster_id field in the ipcache key; here the
// kube-ovn tunnel_key (VNI) plays that role for VPCs within one cluster,
// without touching the cluster_id semantics (see ipcache.ipcache.go).
type VniKey struct {
	Prefixlen uint32 `align:"lpm_key"`
	Vni       uint32 `align:"vni"`
	Pad1      uint8  `align:"pad1"`
	Family    uint8  `align:"family"`
	// Pad2 keeps the non-IP part at 8 bytes and unsafe.Sizeof(VniKey{}) equal
	// to sizeof(struct ipcache_vni_key) (28 bytes).
	Pad2 [2]byte `align:"pad2"`
	// represents both IPv6 and IPv4 (in the lowest four bytes)
	IP types.IPv6 `align:"$union0"`
}

// getVniStaticPrefixBits returns the number of LPM key bits that precede the
// IP field. It must equal the byte offset of IP within the key data (i.e.
// after Prefixlen) times 8; the test in this package pins that invariant.
func getVniStaticPrefixBits() uint32 {
	staticMatchSize := unsafe.Sizeof(VniKey{})
	staticMatchSize -= unsafe.Sizeof(VniKey{}.Prefixlen)
	staticMatchSize -= unsafe.Sizeof(VniKey{}.IP)
	return uint32(staticMatchSize) * 8
}

func getVniPrefixLen(prefixBits int) uint32 {
	return getVniStaticPrefixBits() + uint32(prefixBits)
}

// NewVniKey returns a VniKey based on the provided IP address, mask, and VNI.
// The address family is automatically detected.
func NewVniKey(ip net.IP, mask net.IPMask, vni uint32) VniKey {
	result := VniKey{}

	ones, _ := mask.Size()
	if ip4 := ip.To4(); ip4 != nil {
		if mask == nil {
			ones = net.IPv4len * 8
		}
		result.Prefixlen = getVniPrefixLen(ones)
		result.Family = bpf.EndpointKeyIPv4
		copy(result.IP[:], ip4)
	} else {
		if mask == nil {
			ones = net.IPv6len * 8
		}
		result.Prefixlen = getVniPrefixLen(ones)
		result.Family = bpf.EndpointKeyIPv6
		copy(result.IP[:], ip)
	}

	result.Vni = vni

	return result
}

func (k VniKey) String() string {
	var (
		addr netip.Addr
		ok   bool
	)

	switch k.Family {
	case bpf.EndpointKeyIPv4:
		addr, ok = netip.AddrFromSlice(k.IP[:net.IPv4len])
		if !ok {
			return "<unknown>"
		}
	case bpf.EndpointKeyIPv6:
		addr = netip.AddrFrom16(k.IP)
	default:
		return "<unknown>"
	}

	prefixLen := int(k.Prefixlen - getVniStaticPrefixBits())
	return fmt.Sprintf("%s@vni:%d", netip.PrefixFrom(addr, prefixLen).String(), k.Vni)
}

func (k *VniKey) New() bpf.MapKey { return &VniKey{} }

// RemoteEndpointInfoFlags represents various flags that can be attached to
// remote endpoints in the IPCache.
type RemoteEndpointInfoFlags uint8

// String returns a human-readable representation of the flags present in the
// RemoteEndpointInfoFlags.
// The output format is the string name of each flag contained in the flag set,
// separated by a comma. If no flags are set, then "<none>" is returned.
func (f RemoteEndpointInfoFlags) String() string {
	flags := ""
	if f&FlagSkipTunnel != 0 {
		flags += "skiptunnel,"
	}
	if f&FlagHasTunnelEndpoint != 0 {
		flags += "hastunnel,"
	}
	if f&FlagIPv6TunnelEndpoint != 0 {
		flags += "ipv6tunnel,"
	}
	if f&FlagRemoteCluster != 0 {
		flags += "remotecluster,"
	}

	if flags == "" {
		return "<none>"
	}
	return strings.TrimSuffix(flags, ",")
}

const (
	// FlagSkipTunnel can be applied to a remote endpoint to signal that
	// packets destined for said endpoint shall not be forwarded through
	// a VXLAN/Geneve tunnel, regardless of Cilium's configuration.
	FlagSkipTunnel RemoteEndpointInfoFlags = 1 << iota
	// FlagHasTunnelEndpoint is set when the tunnel endpoint is not null. It
	// aims to simplify the logic compared to checking the IPv6 address.
	FlagHasTunnelEndpoint
	// FlagIPv6TunnelEndpoint is set when the tunnel endpoint IP address
	// is an IPv6 address.
	FlagIPv6TunnelEndpoint
	// FlagRemoteCluster is set when the node is in a remote cluster.
	// It's always unset when clustermesh is disabled or for pods.
	FlagRemoteCluster
)

// RemoteEndpointInfo implements the bpf.MapValue interface. It contains the
// security identity of a remote endpoint.
type RemoteEndpointInfo struct {
	SecurityIdentity uint32 `align:"sec_identity"`
	// represents both IPv6 and IPv4 (in the lowest four bytes)
	TunnelEndpoint types.IPv6 `align:"tunnel_endpoint"`
	_              uint16
	Key            uint8                   `align:"key"`
	Flags          RemoteEndpointInfoFlags `align:"flag_skip_tunnel"`
}

func (v *RemoteEndpointInfo) String() string {
	return fmt.Sprintf("identity=%d encryptkey=%d tunnelendpoint=%s flags=%s",
		v.SecurityIdentity, v.Key, v.GetTunnelEndpoint(), v.Flags)
}

func (v *RemoteEndpointInfo) GetTunnelEndpoint() net.IP {
	if v.Flags&FlagIPv6TunnelEndpoint == 0 {
		return v.TunnelEndpoint[:4]
	}
	return v.TunnelEndpoint[:]
}

func (v *RemoteEndpointInfo) New() bpf.MapValue { return &RemoteEndpointInfo{} }

// RemoteEndpointInfoV1 implements the bpf.MapValue interface for the v1
// ipcache map value.
type RemoteEndpointInfoV1 struct {
	SecurityIdentity uint32     `align:"sec_identity"`
	TunnelEndpoint   types.IPv4 `align:"tunnel_endpoint"`
	_                uint16
	Key              uint8                   `align:"key"`
	Flags            RemoteEndpointInfoFlags `align:"flag_skip_tunnel"`
}

func (v *RemoteEndpointInfoV1) String() string {
	return fmt.Sprintf("identity=%d encryptkey=%d tunnelendpoint=%s flags=%s",
		v.SecurityIdentity, v.Key, v.TunnelEndpoint, v.Flags)
}

func (v *RemoteEndpointInfoV1) New() bpf.MapValue { return &RemoteEndpointInfoV1{} }

// NewValue returns a RemoteEndpointInfo based on the provided security
// identity, tunnel endpoint IP, IPsec key, and flags. The address family is
// automatically detected.
func NewValue(secID uint32, tunnelEndpoint net.IP, key uint8, flags RemoteEndpointInfoFlags) RemoteEndpointInfo {
	result := RemoteEndpointInfo{}

	result.SecurityIdentity = secID
	result.Key = key
	result.Flags = flags

	if tunnelEndpoint == nil {
		return result
	}

	result.Flags |= FlagHasTunnelEndpoint
	if ip4 := tunnelEndpoint.To4(); ip4 != nil {
		copy(result.TunnelEndpoint[:], ip4)
	} else {
		copy(result.TunnelEndpoint[:], tunnelEndpoint)
		result.Flags |= FlagIPv6TunnelEndpoint
	}

	return result
}

// Map represents an IPCache BPF map.
type Map struct {
	bpf.Map
}

func newIPCacheMap(name string) *bpf.Map {
	return bpf.NewMap(
		name,
		ebpf.LPMTrie,
		&Key{},
		&RemoteEndpointInfo{},
		MaxEntries,
		unix.BPF_F_NO_PREALLOC|unix.BPF_F_RDONLY_PROG)
}

func newIPCacheMapV1(name string) *bpf.Map {
	return bpf.NewMap(
		name,
		ebpf.LPMTrie,
		&Key{},
		&RemoteEndpointInfoV1{},
		MaxEntries,
		unix.BPF_F_NO_PREALLOC)
}

// NewMap instantiates a Map.
func NewMap(registry *metrics.Registry, name string) *Map {
	return &Map{
		Map: *newIPCacheMap(name).WithCache().WithPressureMetric(registry).
			WithEvents(option.Config.GetEventBufferConfig(name)),
	}
}

var (
	// IPCache is a mapping of all endpoint IPs in the cluster which this
	// Cilium agent is a part of to their corresponding security identities.
	// It is a singleton; there is only one such map per agent.
	ipcache *Map
	once    = &sync.Once{}

	oldIPcache     *Map
	onceOldIPcache = &sync.Once{}
)

// IPCacheMap gets the ipcache Map singleton. If it has not already been done,
// this also initializes the Map.
func IPCacheMap(registry *metrics.Registry) *Map {
	once.Do(func() {
		ipcache = NewMap(registry, Name)
	})
	return ipcache
}

// IPCacheMapV1 does the same as IPCacheMap but for the v1 ipcache map,
// from v1.18.
func IPCacheMapV1() *Map {
	onceOldIPcache.Do(func() {
		oldIPcache = &Map{
			Map: *newIPCacheMapV1(OldName),
		}
	})
	return oldIPcache
}

// VniName is the canonical name for the native-vpc VNI-scoped IPCache map.
// Entries are keyed by (VNI, IP) so that overlapping IPs from different VPCs
// can coexist. It is only used in native-vpc mode.
const VniName = "cilium_ipcache_vni"

var (
	vniIpcache     *Map
	onceVniIpcache = &sync.Once{}
)

func newIPCacheVniMap(name string) *bpf.Map {
	return bpf.NewMap(
		name,
		ebpf.LPMTrie,
		&VniKey{},
		&RemoteEndpointInfo{},
		MaxEntries,
		unix.BPF_F_NO_PREALLOC|unix.BPF_F_RDONLY_PROG)
}

// IPCacheVniMap gets the native-vpc VNI-scoped ipcache Map singleton.
func IPCacheVniMap(registry *metrics.Registry) *Map {
	onceVniIpcache.Do(func() {
		vniIpcache = &Map{
			Map: *newIPCacheVniMap(VniName).WithCache().WithPressureMetric(registry),
		}
	})
	return vniIpcache
}
