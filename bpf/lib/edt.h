/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/ctx/ctx.h>

#include <bpf/features_skb.h>

#include "common.h"
#include "time.h"

#define DIRECTION_EGRESS 0
#define DIRECTION_INGRESS 1

struct edt_id {
	__u32		id;
	__u8		direction;
	__u8		pad[3];
};

struct edt_info {
	__u64		bps;
	__u64		t_last;
	union {
		__u64	t_horizon_drop;
		__u64	tokens;
	};
	__u32		prio;
	/* The device the egress of a chained endpoint is paced on. */
	__u32		ifindex;
	/* The horizon of a shaped ingress limit. It has a field of its own
	 * because the policer keeps its tokens in the union above: a policer
	 * still loaded while the agent is being upgraded would overwrite it.
	 */
	__u64		t_horizon_ingress;
	__u64		pad[2];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct edt_id);
	__type(value, struct edt_info);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, THROTTLE_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_throttle __section_maps_btf;

/* From XDP layer, we neither go through an egress hook nor qdisc
 * from here, hence nothing to be set.
 */
#if defined(ENABLE_BANDWIDTH_MANAGER) && __ctx_is == __ctx_skb
static __always_inline void edt_set_aggregate(struct __ctx_buff *ctx,
					      __u32 aggregate)
{
	/* 16 bit as current used aggregate, and preserved in host ns. */
	ctx->queue_mapping = aggregate;
}

static __always_inline __u32 edt_get_aggregate(struct __ctx_buff *ctx)
{
	__u32 aggregate = ctx->queue_mapping;

	/* We need to reset queue mapping here such that new mapping will
	 * be performed based on skb hash. See netdev_pick_tx().
	 */
	ctx->queue_mapping = 0;

	return aggregate;
}

/* The length to charge to the limit. At the egress of a device this is what
 * the qdisc layer computed, the length on the wire. The egress of a chained
 * endpoint is seen on the ingress hook of its veth, where a GSO packet has to
 * be accounted for by hand: skb->len, which includes the Ethernet header while
 * the program runs, counts the headers of the first segment only.
 *
 * This starts from skb->len rather than from the qdisc layer's length, which
 * on that hook is skb->len without the Ethernet header up to Linux 6.18 and
 * accounts for the segments from 6.19 on.
 *
 * shortcut: the headers of a GSO segment are taken to be those of TCP with
 * timestamps over an IP header without options, which is off by a few bytes
 * per segment for anything else. Parse them if that ever matters.
 */
static __always_inline __u64
edt_wire_len(const struct __ctx_buff *ctx, __be16 proto, bool at_ingress_hook)
{
	__u32 len, hdr;

	if (!at_ingress_hook)
		return ctx_wire_len(ctx);

	len = ctx->len;
	/* Ethernet, IP and TCP headers, which skb->len counts once. */
	hdr = ETH_HLEN + 32 +
	      (proto == bpf_htons(ETH_P_IP) ? sizeof(struct iphdr) : sizeof(struct ipv6hdr));
	if (ctx->gso_size && len > hdr + ctx->gso_size)
		/* And once more for each further segment. */
		return len + (len - hdr - 1) / ctx->gso_size * hdr;
	return len;
}

/* Computes the earliest departure time for the given aggregate and hands it to
 * the FQ qdisc the packet is about to be queued on. The aggregate and its
 * direction are explicit because the chained-CNI paths know the endpoint they
 * run for, while cil_to_netdev has to read the aggregate back from the skb
 * (see edt_sched_departure()).
 */
static __always_inline int
edt_sched_departure_aggregate(struct __ctx_buff *ctx, __be16 proto, __u32 aggregate_id,
			      __u8 direction, bool chained, __u32 *ifindex)
{
	__u64 delay, now, t, t_next, horizon;
	struct edt_id aggregate = {};
	struct edt_info *info;

	if (!eth_is_supported_ethertype(proto))
		return CTX_ACT_OK;
	if (proto != bpf_htons(ETH_P_IP) &&
	    proto != bpf_htons(ETH_P_IPV6))
		return CTX_ACT_OK;

	aggregate.id = aggregate_id;
	if (!aggregate.id)
		return CTX_ACT_OK;

	aggregate.direction = direction;

	info = map_lookup_elem(&cilium_throttle, &aggregate);
	if (!info)
		return CTX_ACT_OK;
	if (!info->bps)
		goto out;

	if (ifindex)
		*ifindex = info->ifindex;

	now = ktime_get_ns();
	/* What skb->tstamp holds depends on where the program runs. In
	 * cil_to_netdev it is a departure time or zero: the IP forwarding
	 * path clears anything else. The egress of a chained endpoint runs on
	 * the ingress hook of its veth, where the packet has just been
	 * received: an skb that carries no departure time is given its
	 * receive timestamp, in CLOCK_REALTIME, as soon as something on the
	 * node asks for timestamps (an NTP daemon, a packet capture). Taking
	 * that for a departure time would move t_last decades ahead of the
	 * monotonic clock and have every later packet of the aggregate
	 * dropped at the horizon.
	 *
	 * The ingress of a chained endpoint is handed over by the chained
	 * CNI. OVS, the bridge and IP forwarding all clear a receive
	 * timestamp on the way, which the FQ on the veth depends on as much
	 * as any FQ behind them does, but the computation has no use for the
	 * value either way.
	 */
	t = chained ? 0 : ctx->tstamp;
	if (t < now)
		t = now;
	delay = edt_wire_len(ctx, proto, chained && direction == DIRECTION_EGRESS) *
		NSEC_PER_SEC / info->bps;
	t_next = READ_ONCE(info->t_last) + delay;
	if (t_next <= t) {
		WRITE_ONCE(info->t_last, t);
		return CTX_ACT_OK;
	}
	/* FQ implements a drop horizon, see also 39d010504e6b ("net_sched:
	 * sch_fq: add horizon attribute"). However, we explicitly need the
	 * drop horizon here to i) avoid having t_last messed up and ii) to
	 * potentially allow for per aggregate control.
	 */
	horizon = direction == DIRECTION_INGRESS ? info->t_horizon_ingress : info->t_horizon_drop;
	if (t_next - now >= horizon)
		return DROP_EDT_HORIZON;
	WRITE_ONCE(info->t_last, t_next);
	/* Hand the departure time over as a monotonic delivery time. Writing
	 * ctx->tstamp alone leaves skb->tstamp_type untouched, so on the
	 * chained-CNI path, which runs on the ingress hook of the veth where
	 * the skb may carry a receive timestamp, sch_fq would read the
	 * departure time back as a realtime one (see fq_skb_tstamp_to_mono()).
	 * The helper needs a 5.18 kernel, below that there is no tstamp type
	 * to get wrong and writing the field is all there is.
	 */
#ifdef HAVE_SKB_SET_TSTAMP
	if (skb_set_tstamp(ctx, t_next, BPF_SKB_TSTAMP_DELIVERY_MONO))
		return DROP_INVALID;
#else
	ctx->tstamp = t_next;
#endif
out:
	/* TODO: Hack to avoid defaulting prio 0 when user doesn't specify anything.
	 * Priority set by user will always be 1 greater than what scheduler expects.
	 */
	if (info->prio)
		ctx->priority = info->prio - 1;
	return CTX_ACT_OK;
}

static __always_inline int
edt_sched_departure(struct __ctx_buff *ctx, __be16 proto)
{
	return edt_sched_departure_aggregate(ctx, proto, edt_get_aggregate(ctx),
					     DIRECTION_EGRESS, false, NULL);
}
#else
static __always_inline void
edt_set_aggregate(struct __ctx_buff *ctx __maybe_unused,
		  __u32 aggregate __maybe_unused)
{
}
#endif /* ENABLE_BANDWIDTH_MANAGER */
