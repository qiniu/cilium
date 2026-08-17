// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/ipcache"
)

// ipcacheScope resolves which ipcache an operator command must act on.
//
// With native-vpc an address belongs to a VPC, and the two maps are separate
// key spaces: the unscoped map holds the addresses that have no VPC (the host,
// the world, CIDR and FQDN entries), the scoped one holds the endpoints. A
// command that silently defaulted to the unscoped map would report success for
// a deletion that removed nothing, and - worse for an update - would put a pod
// address into the space the datapath falls back to when a scoped lookup
// misses, which is exactly what must never contain one.
//
// So when the scoped map exists the scope has to be stated: --vni N for a VPC,
// --vni 0 for the addresses that are in none.
func ipcacheScope(cmd *cobra.Command, ip net.IP, mask net.IPMask, clusterID uint16) (*ipcache.Map, bpf.MapKey) {
	vni, err := cmd.Flags().GetUint32("vni")
	if err != nil {
		Usagef(cmd, "Invalid VNI. "+usage)
	}

	if vni > 0 {
		key := ipcache.NewVniKey(ip, mask, vni)
		return ipcache.IPCacheVniMap(nil), &key
	}

	if !cmd.Flags().Changed("vni") && vniIPCacheExists() {
		fmt.Fprintf(os.Stderr,
			"This node runs native-vpc, where an address belongs to a VPC and the two ipcaches are separate.\n"+
				"State the scope: --vni <n> for a VPC, or --vni 0 for the addresses that are in none.\n")
		os.Exit(1)
	}

	key := ipcache.NewKey(ip, mask, clusterID)
	return ipcache.IPCacheMap(nil), &key
}

// vniIPCacheExists reports whether this node runs with native-vpc, which is
// visible from the pinned map alone - cilium-dbg does not share the agent's
// configuration.
func vniIPCacheExists() bool {
	dump := map[string][]string{}
	err := ipcache.IPCacheVniMap(nil).Dump(dump)
	return !errors.Is(err, fs.ErrNotExist)
}
