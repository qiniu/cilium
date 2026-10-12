/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* Standalone enforcement of spec.loadBalancerSourceRanges.
 *
 * Upstream Cilium enforces source ranges as one step of the eBPF kube-proxy
 * replacement: nodeport_svc_lb{4,6}() calls lb{4,6}_src_range_ok() right after
 * the service lookup and before the translation. Clusters which cannot enable
 * the kube-proxy replacement (for example when Cilium runs in CNI chaining mode
 * on top of another datapath) therefore lose the check even though the agent
 * still populates both the service maps (for LoadBalancer frontends taken from
 * status.loadBalancer.ingress) and cilium_lb{4,6}_source_range.
 *
 * This filter reuses exactly those maps to enforce the source ranges without
 * doing any load balancing: on ingress from a native device it looks the
 * frontend up and drops the packet when the source address is not allowed. The
 * translation stays with whatever does it today (kube-proxy, or a gateway the
 * packet is routed to afterwards).
 *
 * Scope and limitations, by design:
 *  - only traffic ingressing a device cil_from_netdev is attached to is filtered. Traffic that
 *    reaches a frontend through another path (socket LB, from-container, the local stack) is
 *    not seen here, which is how the upstream kube-proxy replacement ends up not restricting
 *    in-cluster access either: bpf_sock and bpf_lxc do not perform this check.
 *  - only frontends carrying SVC_FLAG_SOURCE_RANGE are affected; every other
 *    packet is passed on untouched. The allow/deny policy bit is honored since
 *    lb{4,6}_src_range_ok() applies it.
 *  - the match is on destination address and port, exactly like the kube-proxy replacement's
 *    service lookup. A reply to a connection that was source NAT'ed to a frontend address can
 *    therefore match the frontend when its ephemeral port collides with a frontend port.
 *  - packets whose L4 tuple cannot be extracted (unsupported protocol, non-first
 *    fragment) are passed on, as they cannot open a connection to a frontend.
 *
 * This is the first access to the ctx data on the from-netdev path (do_netdev() pulls right
 * after us), so revalidate_data_pull() is required: with revalidate_data() a header that did
 * not arrive in the linear data would make the lookup fail and silently skip the check. A
 * packet that cannot be pulled is left to do_netdev(), which drops it as DROP_INVALID.
 */

#pragma once

#include "lb.h"

#ifdef ENABLE_LB_SRC_RANGE_FILTER

#ifdef ENABLE_IPV4
static __always_inline int lb_src_range_filter4(struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple tuple = {};
	const struct lb4_service *svc;
	struct lb4_key key = {};
	void *data, *data_end;
	fraginfo_t fraginfo;
	struct iphdr *ip4;
	int ret, l4_off;

	if (!revalidate_data_pull(ctx, &data, &data_end, &ip4))
		return CTX_ACT_OK;

	fraginfo = ipfrag_encode_ipv4(ip4);
	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);

	ret = lb4_extract_tuple(ctx, ip4, fraginfo, l4_off, &tuple);
	if (IS_ERR(ret))
		return CTX_ACT_OK;

	lb4_fill_key(&key, &tuple);

	svc = lb4_lookup_service(&key, false);
	if (!svc)
		return CTX_ACT_OK;

	/* Returns true for every frontend without SVC_FLAG_SOURCE_RANGE, and
	 * inverts the verdict for frontends using the deny policy.
	 */
	if (lb4_src_range_ok(svc, ip4->saddr))
		return CTX_ACT_OK;

	return DROP_NOT_IN_SRC_RANGE;
}
#endif /* ENABLE_IPV4 */

#ifdef ENABLE_IPV6
static __always_inline int lb_src_range_filter6(struct __ctx_buff *ctx)
{
	struct ipv6_ct_tuple tuple __align_stack_8 = {};
	const struct lb6_service *svc;
	struct lb6_key key = {};
	void *data, *data_end;
	fraginfo_t fraginfo;
	struct ipv6hdr *ip6;
	int ret, l4_off;

	if (!revalidate_data_pull(ctx, &data, &data_end, &ip6))
		return CTX_ACT_OK;

	tuple.nexthdr = ip6->nexthdr;
	ret = ipv6_hdrlen_with_fraginfo(ctx, &tuple.nexthdr, &fraginfo);
	if (ret < 0)
		return CTX_ACT_OK;

	l4_off = ETH_HLEN + ret;

	ret = lb6_extract_tuple(ctx, ip6, fraginfo, l4_off, &tuple);
	if (IS_ERR(ret))
		return CTX_ACT_OK;

	lb6_fill_key(&key, &tuple);

	svc = lb6_lookup_service(&key, false);
	if (!svc)
		return CTX_ACT_OK;

	if (lb6_src_range_ok(svc, (const union v6addr *)&ip6->saddr))
		return CTX_ACT_OK;

	return DROP_NOT_IN_SRC_RANGE;
}
#endif /* ENABLE_IPV6 */

/* Returns CTX_ACT_OK when the packet may continue, or DROP_NOT_IN_SRC_RANGE. */
static __always_inline int lb_src_range_filter(struct __ctx_buff *ctx __maybe_unused,
					       __be16 proto __maybe_unused)
{
	switch (proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		return lb_src_range_filter4(ctx);
#endif
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		return lb_src_range_filter6(ctx);
#endif
	default:
		return CTX_ACT_OK;
	}
}

#else /* ENABLE_LB_SRC_RANGE_FILTER */

static __always_inline int lb_src_range_filter(struct __ctx_buff *ctx __maybe_unused,
					       __be16 proto __maybe_unused)
{
	return CTX_ACT_OK;
}

#endif /* ENABLE_LB_SRC_RANGE_FILTER */
