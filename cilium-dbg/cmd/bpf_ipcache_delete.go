// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
)

func init() {
	BPFIPCacheCmd.AddCommand(bpfIPCacheDeleteCmd)

	bpfIPCacheDeleteCmd.PersistentFlags().Uint16("clusterid", 0, "Cluster ID")
	bpfIPCacheDeleteCmd.PersistentFlags().Uint32("vni", 0, "native-vpc VNI of the entry (0 = the unscoped ipcache)")
}

var bpfIPCacheDeleteCmd = &cobra.Command{
	Use:     "delete",
	Short:   "Delete an entry for a prefix",
	Example: "cilium bpf ipcache delete 10.244.3.110/32 --clusterid 1",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf ipcache delete")

		if len(args) < 1 || args[0] == "" {
			Usagef(cmd, "No prefix provided. "+usage)
		}

		arg := args[0]

		clusterID, err := cmd.Flags().GetUint16("clusterid")
		if err != nil {
			Usagef(cmd, "Invalid cluster ID. "+usage)
		}

		prefix, err := netip.ParsePrefix(arg)
		if err != nil {
			Usagef(cmd, "Invalid prefix address. "+usage)
		}

		ip := net.IP(prefix.Addr().AsSlice())
		mask := net.CIDRMask(prefix.Bits(), 32)
		m, key := ipcacheScope(cmd, ip, mask, clusterID)
		if err := m.Delete(key); err != nil {
			fmt.Fprintf(os.Stderr, "Error deleting entry %s: %v\n", key, err)
			os.Exit(1)
		}

		fmt.Printf("Deleted entry %s\n", key)
	},
}
