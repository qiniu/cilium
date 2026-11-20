// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test: the ingress policer in cil_to_container only
 * exists when the bandwidth manager is enabled and BPF host routing is off,
 * which is the generic-veth CNI chaining case.
 */
#define ENABLE_IPV4			1
#define ENABLE_BANDWIDTH_MANAGER	1

#define CLIENT_IP		v4_ext_one
#define CLIENT_PORT		__bpf_htons(111)

#define POD_IP			v4_pod_one
#define POD_PORT		__bpf_htons(222)
#define POD_EP_ID		233

static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *pod_mac = mac_two;

#include "lib/bpf_lxc.h"

ASSIGN_CONFIG(__u16, endpoint_id, POD_EP_ID)
ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = v4_pod_one })
ASSIGN_CONFIG(bool, cni_chaining_generic_veth, true)

#include "lib/policy.h"

/* Leave one of the pod's token buckets empty, so that the next packet of
 * ctx_wire_len() bytes cannot be paid for: bps is 1 byte/s and the last refill
 * is now, so no tokens have accumulated.
 */
static __always_inline void drain_tokens(__u8 direction)
{
	struct edt_id aggregate = {
		.id		= POD_EP_ID,
	};
	struct edt_info info = {
		.bps		= 1,
		.t_last		= ktime_get_ns(),
		.tokens		= 0,
	};

	aggregate.direction = direction;
	map_update_elem(&cilium_throttle, &aggregate, &info, BPF_ANY);
}

static __always_inline int build_packet(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)pod_mac,
					  CLIENT_IP, POD_IP,
					  CLIENT_PORT, POD_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

PKTGEN("tc", "01_to_container_over_ingress_limit")
int to_container_over_limit_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "01_to_container_over_ingress_limit")
int to_container_over_limit_setup(struct __ctx_buff *ctx)
{
	/* Allow the traffic, so that only the policer can drop it. */
	policy_add_ingress_allow_l3_l4_entry(0, 0, 0, 0); /* allow all */
	drain_tokens(DIRECTION_INGRESS);

	return pod_receive_packet(ctx);
}

CHECK("tc", "01_to_container_over_ingress_limit")
int to_container_over_limit_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_DROP);

	test_finish();
}

PKTGEN("tc", "02_to_container_hostns_not_metered")
int to_container_hostns_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "02_to_container_hostns_not_metered")
int to_container_hostns_setup(struct __ctx_buff *ctx)
{
	policy_add_ingress_allow_l3_l4_entry(0, 0, 0, 0); /* allow all */
	drain_tokens(DIRECTION_INGRESS);

	/* Traffic from the host namespace (health probes, hostNetwork pods) is
	 * not charged to the pod's ingress limit, matching local_delivery(),
	 * which skips from_host traffic.
	 */
	ctx->mark = MARK_MAGIC_HOST;

	return pod_receive_packet(ctx);
}

CHECK("tc", "02_to_container_hostns_not_metered")
int to_container_hostns_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code != CTX_ACT_DROP);

	test_finish();
}

PKTGEN("tc", "03_from_container_over_egress_limit")
int from_container_over_limit_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "03_from_container_over_egress_limit")
int from_container_over_limit_setup(struct __ctx_buff *ctx)
{
	/* The pod's own egress limit is policed in cil_from_container when a
	 * chained CNI owns the path to the wire, as the EDT aggregate does not
	 * survive it.
	 */
	policy_add_egress_allow_l3_l4_entry(0, 0, 0, 0); /* allow all */
	drain_tokens(DIRECTION_EGRESS_POLICE);

	return pod_send_packet(ctx);
}

CHECK("tc", "03_from_container_over_egress_limit")
int from_container_over_limit_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == CTX_ACT_DROP);

	test_finish();
}

PKTGEN("tc", "04_from_container_within_egress_limit")
int from_container_within_limit_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "04_from_container_within_egress_limit")
int from_container_within_limit_setup(struct __ctx_buff *ctx)
{
	struct edt_id aggregate = {
		.id		= POD_EP_ID,
		.direction	= DIRECTION_EGRESS_POLICE,
	};
	struct edt_info info = {
		.bps		= 1000000,
		.t_last		= ktime_get_ns(),
		.tokens		= 1000000,
	};

	policy_add_egress_allow_l3_l4_entry(0, 0, 0, 0); /* allow all */
	map_update_elem(&cilium_throttle, &aggregate, &info, BPF_ANY);

	return pod_send_packet(ctx);
}

CHECK("tc", "04_from_container_within_egress_limit")
int from_container_within_limit_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code != CTX_ACT_DROP);

	test_finish();
}
