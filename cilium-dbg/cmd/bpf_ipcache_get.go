// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"sort"
	"strings"

	iradix "github.com/hashicorp/go-immutable-radix/v2"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ipcache"
)

const usage = "IP address must be in dotted decimal (192.168.1.1) or IPv6 (feab::f02b) form"

var bpfIPCacheGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Retrieve identity for an ip",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf ipcache get")

		if len(args) < 1 || args[0] == "" {
			Usagef(cmd, "No ip provided. "+usage)
		}

		arg := args[0]

		ip := net.ParseIP(arg)
		if ip == nil {
			Usagef(cmd, "Invalid ip address. "+usage)
		}

		bpfIPCache := dumpIPCache()

		// Native-vpc: print every exact VNI-scoped entry for this IP first.
		// They are keyed by (VNI, IP), so several VPCs may legitimately answer
		// for the same address and an LPM over the merged key space would hide
		// all but one of them.
		vniMatches := lookupVNIEntries(ip)
		for _, m := range vniMatches {
			fmt.Printf("%s maps to identity %s\n", m.key, strings.Join(m.value, ","))
		}

		if len(bpfIPCache) == 0 {
			if len(vniMatches) > 0 {
				return
			}
			fmt.Fprintf(os.Stderr, "No entries found.\n")
			os.Exit(1)
		}

		value, exists := getLPMValue(ip, bpfIPCache)

		if !exists {
			if len(vniMatches) > 0 {
				return
			}
			fmt.Printf("%s does not map to any identity\n", arg)
			os.Exit(1)
		}

		v := value.([]string)
		if len(v) == 0 {
			fmt.Printf("Unable to retrieve identity for LPM entry %s\n", arg)
			os.Exit(1)
		}

		ids := strings.Join(v, ",")
		fmt.Printf("%s maps to identity %s\n", arg, ids)
	},
}

func init() {
	BPFIPCacheCmd.AddCommand(bpfIPCacheGetCmd)
}

func dumpIPCache() map[string][]string {
	bpfIPCache := make(map[string][]string)

	if err := ipcache.IPCacheMap(nil).Dump(bpfIPCache); err != nil {
		Fatalf("unable to dump IPCache: %s\n", err)
	}

	return bpfIPCache
}

type vniEntry struct {
	key   string
	value []string
}

// lookupVNIEntries returns the entries of the native-vpc VNI-scoped ipcache
// ("<prefix>@vni:<vni>") whose prefix contains ip. Entries of different VPCs
// for the same address are all returned: the (VNI, IP) key space is not
// totally ordered by prefix length, so there is no single "best" match without
// a VNI. The map is absent on non-native-vpc nodes, which is not an error.
func lookupVNIEntries(ip net.IP) []vniEntry {
	dump := make(map[string][]string)
	if err := ipcache.IPCacheVniMap(nil).Dump(dump); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			Fatalf("unable to dump native-vpc IPCache: %s\n", err)
		}
		return nil
	}

	var matches []vniEntry
	for key, value := range dump {
		prefixStr, _, found := strings.Cut(key, "@vni:")
		if !found {
			continue
		}
		_, subnet, err := net.ParseCIDR(prefixStr)
		if err != nil {
			log.Warn(
				"unable to parse native-vpc ipcache entry as a CIDR",
				logfields.Error, err,
				logfields.Entry, key,
			)
			continue
		}
		if subnet.Contains(ip) {
			matches = append(matches, vniEntry{key: key, value: value})
		}
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].key < matches[j].key })
	return matches
}

// getLPMValue calculates the longest prefix matching ip amongst the
// keys in entries. The keys in entries must be specified in CIDR notation.
// If LPM is found, the value associated with that entry is returned
// along with boolean true. Otherwise, false is returned.
func getLPMValue(ip net.IP, entries map[string][]string) (any, bool) {
	type lpmEntry struct {
		prefix   []byte
		identity []string
	}

	isV4 := isIPV4(ip)

	// Convert ip to 4-byte representation if IPv4.
	if isV4 {
		ip = ip.To4()
	}

	lpmEntries := make([]lpmEntry, 0, len(entries))
	for cidr, identity := range entries {
		currIP, subnet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Warn(
				"unable to parse ipcache entry as a CIDR",
				logfields.Error, err,
				logfields.Entry, cidr,
			)
			continue
		}

		// No need to include IPv6 addresses if the argument is
		// IPv4 and vice versa.
		if isIPV4(currIP) != isV4 {
			continue
		}

		// Convert ip to 4-byte representation if IPv4.
		if isV4 {
			currIP = currIP.To4()
		}

		ones, _ := subnet.Mask.Size()
		prefix := getPrefix(currIP, ones)

		lpmEntries = append(lpmEntries, lpmEntry{prefix, identity})
	}

	r := iradix.New[[]string]()
	for _, e := range lpmEntries {
		r, _, _ = r.Insert(e.prefix, e.identity)
	}

	// Look-up using all bits in the argument ip
	var mask int
	if isV4 {
		mask = 8 * net.IPv4len
	} else {
		mask = 8 * net.IPv6len
	}

	_, v, exists := r.Root().LongestPrefix(getPrefix(ip, mask))
	return v, exists
}

// getPrefix converts the most significant maskSize bits in ip
// into a byte slice - each bit is represented using one byte.
func getPrefix(ip net.IP, maskSize int) []byte {
	bytes := make([]byte, maskSize)
	var i, j uint8
	var n int

	for n < maskSize {
		for j = 0; j < 8 && n < maskSize; j++ {
			mask := uint8(128) >> uint8(j)

			if mask&ip[i] == 0 {
				bytes[i*8+j] = 0x0
			} else {
				bytes[i*8+j] = 0x1
			}
			n++
		}
		i++
	}

	return bytes
}

func isIPV4(ip net.IP) bool {
	return ip.To4() != nil
}
