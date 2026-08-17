// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/ipcache"
)

const (
	ipAddrTitle   = "IP PREFIX/ADDRESS"
	identityTitle = "IDENTITY"
)

var (
	ipCacheListUsage = "List endpoint IPs (local and remote) and their corresponding security identities."
)

var bpfIPCacheListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List endpoint IPs (local and remote) and their corresponding security identities",
	Long:    ipCacheListUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf ipcache list")

		bpfIPCacheList := make(map[string][]string)
		if err := ipcache.IPCacheMap(nil).Dump(bpfIPCacheList); err != nil {
			fmt.Fprintf(os.Stderr, "error dumping contents of map: %s\n", err)
			os.Exit(1)
		}
		// Also dump the native-vpc VNI-scoped ipcache, if present. cilium-dbg is
		// a separate process, so the singleton starts closed: calling IsOpen()
		// here would always skip the map. Dump opens the pinned map itself;
		// absence is expected on non-native-vpc nodes and is ignored.
		if err := ipcache.IPCacheVniMap(nil).Dump(bpfIPCacheList); err != nil && !errors.Is(err, fs.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "error dumping contents of vni map: %s\n", err)
			os.Exit(1)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(bpfIPCacheList); err != nil {
				fmt.Fprintf(os.Stderr, "error getting output of map in %s: %s\n", command.OutputOptionString(), err)
				os.Exit(1)
			}
			return
		}

		if len(bpfIPCacheList) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n")
		} else {
			TablePrinter(ipAddrTitle, identityTitle, bpfIPCacheList)
		}
	},
}

func init() {
	BPFIPCacheCmd.AddCommand(bpfIPCacheListCmd)
	command.AddOutputOption(bpfIPCacheListCmd)
}
