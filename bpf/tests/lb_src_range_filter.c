// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable the code path under test: the standalone source range filter, i.e.
 * without the kube-proxy replacement (no ENABLE_NODEPORT).
 */
#define ENABLE_IPV4
#define ENABLE_IPV6
#define ENABLE_LB_SRC_RANGE_FILTER

#include "lib/bpf_host.h"
#include "lib/lb.h"

#define FRONTEND_IP		v4_svc_one
#define FRONTEND_PORT		tcp_svc_one
#define REV_NAT_INDEX		7
#define REV_NAT_INDEX_V6	8

static __always_inline void
add_source_range(__u16 rev_nat_index, __be32 addr, __u32 cidr_prefix_len)
{
	struct lb4_src_range_key key = {
		/* The LPM prefix covers the fixed part of the key (rev_nat_id and
		 * pad) plus the CIDR bits of the address, matching what the agent
		 * writes (see lpmPrefixLen4 in pkg/loadbalancer/maps).
		 */
		.lpm_key = { 8 * (sizeof(key.rev_nat_id) + sizeof(key.pad)) + cidr_prefix_len, {} },
		.rev_nat_id = rev_nat_index,
		.addr = addr,
	};
	__u8 value = 0;

	map_update_elem(&cilium_lb4_source_range, &key, &value, BPF_ANY);
}

static __always_inline void
add_source_range6(__u16 rev_nat_index, const __u8 *addr, __u32 cidr_prefix_len)
{
	struct lb6_src_range_key key = {
		.lpm_key = { 8 * (sizeof(key.rev_nat_id) + sizeof(key.pad)) + cidr_prefix_len, {} },
		.rev_nat_id = rev_nat_index,
	};
	__u8 value = 0;

	ipv6_addr_copy(&key.addr, (const union v6addr *)addr);
	map_update_elem(&cilium_lb6_source_range, &key, &value, BPF_ANY);
}

static __always_inline int
build_packet6(struct __ctx_buff *ctx, const __u8 *saddr)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  (__u8 *)saddr, (__u8 *)v6_svc_one,
					  tcp_src_one, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

static __always_inline int
build_packet(struct __ctx_buff *ctx, __be32 saddr)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)mac_one, (__u8 *)mac_two,
					  saddr, FRONTEND_IP,
					  tcp_src_one, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

static __always_inline int
check_status(const struct __ctx_buff *ctx, __u32 expected)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u32 *status_code;

	test_init();

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	if (*status_code != expected)
		test_fatal("expected status %d, got %d", expected, *status_code);

	test_finish();
}

/* A source inside the configured range is passed on untranslated. */
PKTGEN("tc", "lb_src_range_filter_allowed")
int lb_src_range_filter_allowed_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx, v4_ext_one);
}

SETUP("tc", "lb_src_range_filter_allowed")
int lb_src_range_filter_allowed_setup(struct __ctx_buff *ctx)
{
	lb_v4_add_service_with_flags(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP, 1,
				     REV_NAT_INDEX,
				     SVC_FLAG_ROUTABLE | SVC_FLAG_SOURCE_RANGE, 0);
	add_source_range(REV_NAT_INDEX, v4_ext_one, 32);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "lb_src_range_filter_allowed")
int lb_src_range_filter_allowed_check(const struct __ctx_buff *ctx)
{
	return check_status(ctx, CTX_ACT_OK);
}

/* A source outside the configured range is dropped. */
PKTGEN("tc", "lb_src_range_filter_denied")
int lb_src_range_filter_denied_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx, v4_ext_two);
}

SETUP("tc", "lb_src_range_filter_denied")
int lb_src_range_filter_denied_setup(struct __ctx_buff *ctx)
{
	lb_v4_add_service_with_flags(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP, 1,
				     REV_NAT_INDEX,
				     SVC_FLAG_ROUTABLE | SVC_FLAG_SOURCE_RANGE, 0);
	add_source_range(REV_NAT_INDEX, v4_ext_one, 32);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "lb_src_range_filter_denied")
int lb_src_range_filter_denied_check(const struct __ctx_buff *ctx)
{
	return check_status(ctx, CTX_ACT_DROP);
}

/* A frontend without source ranges is never filtered, whatever the source is. */
PKTGEN("tc", "lb_src_range_filter_no_ranges")
int lb_src_range_filter_no_ranges_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx, v4_ext_two);
}

SETUP("tc", "lb_src_range_filter_no_ranges")
int lb_src_range_filter_no_ranges_setup(struct __ctx_buff *ctx)
{
	lb_v4_add_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP, 1, REV_NAT_INDEX);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "lb_src_range_filter_no_ranges")
int lb_src_range_filter_no_ranges_check(const struct __ctx_buff *ctx)
{
	return check_status(ctx, CTX_ACT_OK);
}

/* With the deny policy the verdict is inverted: a source inside the configured
 * range is the one that gets dropped.
 */
PKTGEN("tc", "lb_src_range_filter_deny_policy")
int lb_src_range_filter_deny_policy_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx, v4_ext_one);
}

SETUP("tc", "lb_src_range_filter_deny_policy")
int lb_src_range_filter_deny_policy_setup(struct __ctx_buff *ctx)
{
	lb_v4_add_service_with_flags(FRONTEND_IP, FRONTEND_PORT, IPPROTO_TCP, 1,
				     REV_NAT_INDEX,
				     SVC_FLAG_ROUTABLE | SVC_FLAG_SOURCE_RANGE,
				     SVC_FLAG_SOURCE_RANGE_DENY);
	add_source_range(REV_NAT_INDEX, v4_ext_one, 32);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "lb_src_range_filter_deny_policy")
int lb_src_range_filter_deny_policy_check(const struct __ctx_buff *ctx)
{
	return check_status(ctx, CTX_ACT_DROP);
}

/* The IPv6 path is enforced the same way, here with a prefix rather than a
 * single address: a source inside fd04::/16 is outside the allowed 2001::/16.
 */
PKTGEN("tc", "lb_src_range_filter6_allowed")
int lb_src_range_filter6_allowed_pktgen(struct __ctx_buff *ctx)
{
	return build_packet6(ctx, (const __u8 *)v6_ext_node_one);
}

SETUP("tc", "lb_src_range_filter6_allowed")
int lb_src_range_filter6_allowed_setup(struct __ctx_buff *ctx)
{
	lb_v6_add_service_with_flags((const union v6addr *)v6_svc_one, FRONTEND_PORT,
				     IPPROTO_TCP, 1, REV_NAT_INDEX_V6,
				     SVC_FLAG_ROUTABLE | SVC_FLAG_SOURCE_RANGE, 0);
	add_source_range6(REV_NAT_INDEX_V6, (const __u8 *)v6_ext_node_one, 16);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "lb_src_range_filter6_allowed")
int lb_src_range_filter6_allowed_check(const struct __ctx_buff *ctx)
{
	return check_status(ctx, CTX_ACT_OK);
}

PKTGEN("tc", "lb_src_range_filter6_denied")
int lb_src_range_filter6_denied_pktgen(struct __ctx_buff *ctx)
{
	return build_packet6(ctx, (const __u8 *)v6_pod_two);
}

SETUP("tc", "lb_src_range_filter6_denied")
int lb_src_range_filter6_denied_setup(struct __ctx_buff *ctx)
{
	lb_v6_add_service_with_flags((const union v6addr *)v6_svc_one, FRONTEND_PORT,
				     IPPROTO_TCP, 1, REV_NAT_INDEX_V6,
				     SVC_FLAG_ROUTABLE | SVC_FLAG_SOURCE_RANGE, 0);
	add_source_range6(REV_NAT_INDEX_V6, (const __u8 *)v6_ext_node_one, 16);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "lb_src_range_filter6_denied")
int lb_src_range_filter6_denied_check(const struct __ctx_buff *ctx)
{
	return check_status(ctx, CTX_ACT_DROP);
}
