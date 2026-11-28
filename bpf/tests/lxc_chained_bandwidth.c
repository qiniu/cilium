// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test: the ingress limit in cil_to_container only
 * exists when the bandwidth manager is enabled and BPF host routing is off,
 * which is the generic-veth CNI chaining case.
 */
#define ENABLE_IPV4			1
#define ENABLE_IPV6			1
#define ENABLE_BANDWIDTH_MANAGER	1
/* The departure time is handed over with bpf_skb_set_tstamp() on a 5.18 or
 * newer kernel, which is the path this exercises; below that the datapath
 * falls back to writing ctx->tstamp.
 */
#define HAVE_SKB_SET_TSTAMP		1

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
ASSIGN_CONFIG(union v6addr, endpoint_ipv6, { .addr = v6_pod_one_addr })
ASSIGN_CONFIG(bool, cni_chaining_generic_veth, true)

#include "lib/policy.h"

#define INGRESS_HORIZON 200000000ULL /* 200ms */

/* SETUP and CHECK are separate runs with any amount of time in between. */
static __u64 ingress_setup_ns;

static __always_inline void set_ingress_limit(__u64 bps)
{
	struct edt_id aggregate = {
		.id		= POD_EP_ID,
		.direction	= DIRECTION_INGRESS,
	};
	struct edt_info info = {
		.bps		= bps,
		.t_last		= ktime_get_ns(),
		/* What a policer loaded before an upgrade leaves behind:
		 * not a horizon.
		 */
		.tokens		= bps,
		.t_horizon_ingress = INGRESS_HORIZON,
	};

	ingress_setup_ns = info.t_last;

	map_update_elem(&cilium_throttle, &aggregate, &info, BPF_ANY);
}

/* At 1 byte/s the next packet would have to wait far longer than the horizon
 * allows.
 */
static __always_inline void drain_ingress_tokens(void)
{
	set_ingress_limit(1);
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

static __always_inline int build_packet6(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv6_tcp_packet(&builder,
					  (__u8 *)client_mac, (__u8 *)pod_mac,
					  (__u8 *)v6_ext_node_one, (__u8 *)v6_pod_one,
					  CLIENT_PORT, POD_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

static __always_inline int check_status(const struct __ctx_buff *ctx, __u32 expected)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == expected);

	test_finish();
}

PKTGEN("tc", "01_to_container_over_ingress_limit")
int to_container_over_limit_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "01_to_container_over_ingress_limit")
int to_container_over_limit_setup(struct __ctx_buff *ctx)
{
	/* Allow the traffic, so that only the limit can drop it. */
	policy_add_ingress_allow_l3_l4_entry(0, 0, 0, 0); /* allow all */
	drain_ingress_tokens();

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
	drain_ingress_tokens();

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

static __always_inline void set_egress_limit(__u64 bps, __u64 t_last)
{
	struct edt_id aggregate = {
		.id		= POD_EP_ID,
		.direction	= DIRECTION_EGRESS,
	};
	struct edt_info info = {
		.bps		= bps,
		.t_last		= t_last,
		.t_horizon_drop	= 2000000000ULL,
		/* The endpoint's pacing device, when it has a limit. */
		.ifindex	= bps ? 42 : 0,
	};

	map_update_elem(&cilium_throttle, &aggregate, &info, BPF_ANY);
}

PKTGEN("tc", "03_from_container_paced_on_ifb")
int from_container_paced_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "03_from_container_paced_on_ifb")
int from_container_paced_setup(struct __ctx_buff *ctx)
{
	/* The chained CNI owns the path from the veth to the wire, so the
	 * egress limit is paced by redirecting to the agent's ifb instead of
	 * by cil_to_netdev, which the aggregate never reaches.
	 */
	policy_add_egress_allow_l3_l4_entry(0, 0, 0, 0); /* allow all */
	set_egress_limit(1250000, ktime_get_ns());

	return pod_send_packet(ctx);
}

CHECK("tc", "03_from_container_paced_on_ifb")
int from_container_paced_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == TC_ACT_REDIRECT);

	test_finish();
}

PKTGEN("tc", "04_from_container_unlimited_is_not_redirected")
int from_container_unlimited_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "04_from_container_unlimited_is_not_redirected")
int from_container_unlimited_setup(struct __ctx_buff *ctx)
{
	/* An endpoint without a limit must keep its path: the detour costs a
	 * qdisc hop and reorders nothing it has to pay for.
	 */
	policy_add_egress_allow_l3_l4_entry(0, 0, 0, 0); /* allow all */
	set_egress_limit(0, 0);

	return pod_send_packet(ctx);
}

CHECK("tc", "04_from_container_unlimited_is_not_redirected")
int from_container_unlimited_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code != TC_ACT_REDIRECT);

	test_finish();
}

/* Any CLOCK_REALTIME value: decades ahead of the monotonic clock. */
#define RX_TIMESTAMP 1795595944182137036ULL

PKTGEN("tc", "05_from_container_receive_timestamp_is_not_a_departure_time")
int from_container_rx_tstamp_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "05_from_container_receive_timestamp_is_not_a_departure_time")
int from_container_rx_tstamp_setup(struct __ctx_buff *ctx)
{
	/* With timestamping enabled on the node (an NTP daemon, a packet
	 * capture), every packet of the pod that is not TCP arrives with its
	 * receive timestamp. Taken for a departure time it would move the
	 * aggregate's clock decades ahead, and the pod would lose its egress
	 * to the drop horizon for good after its first DNS query.
	 */
	policy_add_egress_allow_l3_l4_entry(0, 0, 0, 0); /* allow all */
	set_egress_limit(1250000, ktime_get_ns());
	ctx->tstamp = RX_TIMESTAMP;

	return pod_send_packet(ctx);
}

CHECK("tc", "05_from_container_receive_timestamp_is_not_a_departure_time")
int from_container_rx_tstamp_check(const struct __ctx_buff *ctx)
{
	struct edt_id aggregate = {
		.id		= POD_EP_ID,
		.direction	= DIRECTION_EGRESS,
	};
	void *data, *data_end;
	struct edt_info *info;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code == TC_ACT_REDIRECT);

	info = map_lookup_elem(&cilium_throttle, &aggregate);
	if (!info)
		test_fatal("no throttle entry");
	assert(info->t_last < RX_TIMESTAMP / 2);

	test_finish();
}

PKTGEN("tc", "06_to_container_within_horizon_is_queued")
int to_container_queued_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx);
}

SETUP("tc", "06_to_container_within_horizon_is_queued")
int to_container_queued_setup(struct __ctx_buff *ctx)
{
	/* At 20000 bytes/s a packet of this size waits a few milliseconds:
	 * over the limit, which a policer would drop, but within the horizon.
	 */
	policy_add_ingress_allow_l3_l4_entry(0, 0, 0, 0); /* allow all */
	set_ingress_limit(20000);

	return pod_receive_packet(ctx);
}

CHECK("tc", "06_to_container_within_horizon_is_queued")
int to_container_queued_check(const struct __ctx_buff *ctx)
{
	struct edt_id aggregate = {
		.id		= POD_EP_ID,
		.direction	= DIRECTION_INGRESS,
	};
	void *data, *data_end;
	struct edt_info *info;
	__u32 *status_code;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	assert(*status_code != CTX_ACT_DROP);

	/* The packet was given a departure time after the previous one. */
	info = map_lookup_elem(&cilium_throttle, &aggregate);
	if (!info)
		test_fatal("no throttle entry");
	assert(info->t_last > ingress_setup_ns);
	assert(info->t_last < ingress_setup_ns + INGRESS_HORIZON);

	test_finish();
}

PKTGEN("tc", "07_ipv6_to_container_over_ingress_limit")
int to_container_over_limit6_pktgen(struct __ctx_buff *ctx)
{
	return build_packet6(ctx);
}

SETUP("tc", "07_ipv6_to_container_over_ingress_limit")
int to_container_over_limit6_setup(struct __ctx_buff *ctx)
{
	policy_add_ingress_allow_l3_l4_entry(0, 0, 0, 0); /* allow all */
	drain_ingress_tokens();

	return pod_receive_packet(ctx);
}

CHECK("tc", "07_ipv6_to_container_over_ingress_limit")
int to_container_over_limit6_check(const struct __ctx_buff *ctx)
{
	return check_status(ctx, CTX_ACT_DROP);
}

PKTGEN("tc", "08_ipv6_from_container_paced_on_ifb")
int from_container_paced6_pktgen(struct __ctx_buff *ctx)
{
	return build_packet6(ctx);
}

SETUP("tc", "08_ipv6_from_container_paced_on_ifb")
int from_container_paced6_setup(struct __ctx_buff *ctx)
{
	policy_add_egress_allow_l3_l4_entry(0, 0, 0, 0); /* allow all */
	set_egress_limit(1250000, ktime_get_ns());

	return pod_send_packet(ctx);
}

CHECK("tc", "08_ipv6_from_container_paced_on_ifb")
int from_container_paced6_check(const struct __ctx_buff *ctx)
{
	return check_status(ctx, TC_ACT_REDIRECT);
}
