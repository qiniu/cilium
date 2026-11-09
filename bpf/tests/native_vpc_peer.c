// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"

#define ENABLE_IPV4
#define ENABLE_IPV6
#include <bpf/config/node.h>
#include "lib/eps.h"

CHECK("tc", "native_vpc_peer")
int test_native_vpc_peer(__maybe_unused struct __sk_buff *ctx)
{
	struct remote_endpoint_info peer = { .sec_identity = 11195 };
	struct remote_endpoint_info foreign = { .sec_identity = 22222 };
	const struct remote_endpoint_info *info;
	__u32 peer_vni = 54;
	union v6addr addr = { .p1 = bpf_htonl(0xfd000008), .p4 = bpf_htonl(3) };
	struct ipcache_vni_key key = {
		.lpm_key = { IPCACHE_VNI_STATIC_PREFIX + 32, {} },
		.vni = 54,
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = bpf_htonl(0x0a000803),
	};

	test_init();
	TEST("ipv4_cross_subnet_and_isolation", {
		assert(map_update_elem(&cilium_ipcache_vni, &key, &peer, BPF_ANY) == 0);
		key.vni = 99;
		assert(map_update_elem(&cilium_ipcache_vni, &key, &foreign, BPF_ANY) == 0);

		info = ipcache_lookup4_vni(&cilium_ipcache_vni, key.ip4, 32, 58);
		assert(!info);
		key.vni = 58;
		key.lpm_key.prefixlen = IPCACHE_VNI_STATIC_PREFIX + 24;
		key.ip4 = bpf_htonl(0x0a000800);
		assert(map_update_elem(&cilium_vni_routes, &key, &peer_vni, BPF_ANY) == 0);

		info = ipcache_lookup4_vni(&cilium_ipcache_vni, bpf_htonl(0x0a000803), 32, 58);
		assert(info && info->sec_identity == peer.sec_identity);
		info = ipcache_lookup4_vni(&cilium_ipcache_vni, bpf_htonl(0x0a000803), 32, 99);
		assert(info && info->sec_identity == foreign.sec_identity);
		info = ipcache_lookup4_vni(&cilium_ipcache_vni, bpf_htonl(0x0a000803), 32, 100);
		assert(!info);
		assert(map_delete_elem(&cilium_vni_routes, &key) == 0);
		info = ipcache_lookup4_vni(&cilium_ipcache_vni, bpf_htonl(0x0a000803), 32, 58);
		assert(!info);
	});

	TEST("ipv6_cross_subnet_and_isolation", {
		key.family = ENDPOINT_KEY_IPV6;
		key.lpm_key.prefixlen = IPCACHE_VNI_STATIC_PREFIX + 128;
		key.vni = 54;
		key.ip6 = addr;
		assert(map_update_elem(&cilium_ipcache_vni, &key, &peer, BPF_ANY) == 0);
		key.vni = 99;
		assert(map_update_elem(&cilium_ipcache_vni, &key, &foreign, BPF_ANY) == 0);
		key.vni = 58;
		key.lpm_key.prefixlen = IPCACHE_VNI_STATIC_PREFIX + 64;
		key.ip6.p4 = 0;
		assert(map_update_elem(&cilium_vni_routes, &key, &peer_vni, BPF_ANY) == 0);

		info = ipcache_lookup6_vni(&cilium_ipcache_vni, &addr, 128, 58);
		assert(info && info->sec_identity == peer.sec_identity);
		info = ipcache_lookup6_vni(&cilium_ipcache_vni, &addr, 128, 99);
		assert(info && info->sec_identity == foreign.sec_identity);
		info = ipcache_lookup6_vni(&cilium_ipcache_vni, &addr, 128, 100);
		assert(!info);
		assert(map_delete_elem(&cilium_vni_routes, &key) == 0);
		info = ipcache_lookup6_vni(&cilium_ipcache_vni, &addr, 128, 58);
		assert(!info);
	});
	test_finish();
}

char __license[] __section("license") = "Dual BSD/GPL";
