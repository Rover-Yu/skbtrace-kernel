/*
 *  skbtrace - sk_buff trace utilty
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * 2012 Li Yu <bingtian.ly@taobao.com>
 *
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/socket.h>
#include <linux/skbtrace_api.h>
#include <linux/skbtrace.h>
#include <net/flow_keys.h>
#include <trace/events/skbtrace_common.h>

static void skbtrace_skb_rps_info(struct skbtrace_tracepoint *t,
		struct sk_buff *skb, struct net_device *dev, int cpu)
SKBTRACE_SKB_EVENT_BEGIN
	struct skbtrace_skb_rps_info_blk blk, *b;
	struct flow_keys keys;

	b = skbtrace_block_get(t, NULL, &blk);
	INIT_SKBTRACE_BLOCK(&b->blk, skb,
			skbtrace_action_skb_rps_info,
			0,
			sizeof(blk));
	b->rx_hash = skb->rxhash;
	if (skb_rx_queue_recorded(skb))
		b->rx_queue = skb_get_rx_queue(skb);
	else
		b->rx_queue = 0;
	skb_flow_dissect(skb, &keys);
	b->keys.src = keys.src;
	b->keys.dst = keys.dst;
	b->keys.ports = keys.ports;
	b->keys.ip_proto = keys.ip_proto;
	b->cpu = cpu;
	b->ifindex = dev->ifindex;
	skbtrace_probe(t, NULL, &b->blk);
SKBTRACE_SKB_EVENT_END

#define DELAY_PER_SLOT_SIZE	sizeof(struct skbtrace_skb_delay)
#define DELAY_BLOCK_BASE_SIZE	\
	(sizeof(struct skbtrace_skb_delay_blk) - DELAY_PER_SLOT_SIZE)

struct skbtrace_skb_delay_param {
	bool ignore_kfree_only;
	bool ignore_zero;
	int nr_slots;
};

static struct skbtrace_skb_delay_param skb_delay_param = {
	.ignore_kfree_only = true,
	.ignore_zero	= true,
	.nr_slots	= 16,
};

static inline long delay_slots_max_nr(struct skbtrace_tracepoint *t)
{
	struct skbtrace_skb_delay_param *p;

	p = (struct skbtrace_skb_delay_param*)t->private;
	return p->nr_slots;
}

static inline int delay_slots_max_bytes(struct skbtrace_tracepoint *t)
{
	return  delay_slots_max_nr(t) * DELAY_PER_SLOT_SIZE;
}

static inline int delay_block_max_size(struct skbtrace_tracepoint *t)
{
	return DELAY_BLOCK_BASE_SIZE + delay_slots_max_bytes(t);
}

static inline int delay_block_size(int nr_slots)
{
	return DELAY_BLOCK_BASE_SIZE + nr_slots * DELAY_PER_SLOT_SIZE;
}

static inline int delay_slots_nr(struct skbtrace_skb_delay_blk *b)
{
	return (b->blk.len - DELAY_BLOCK_BASE_SIZE) / DELAY_PER_SLOT_SIZE;
}

static inline bool delay_slots_nr_inc(struct skbtrace_tracepoint *t,
					struct skbtrace_skb_delay_blk *b)
{
	if (b->blk.len >= delay_block_max_size(t))
		return true;
	b->blk.len += DELAY_PER_SLOT_SIZE;
	return false;
}

static inline u64 delay_slot_new(struct skbtrace_skb_delay_blk *b)
{
	struct timespec now, sub;

	ktime_get_ts(&now);
	sub = timespec_sub(now, b->start_ts);
	return sub.tv_sec * 1000000 + sub.tv_nsec/1000;
}

static void skb_delay_release_block(struct skbtrace_tracepoint *t,
					struct skbtrace_block **blk)
{
	kfree(*blk);
	*blk = NULL;
}

static void __skbtrace_skb_delay(struct skbtrace_tracepoint *t,
		struct sk_buff *skb, skb_delay_op action, void *loc)
{
	struct skbtrace_skb_delay_param *p;
	struct skbtrace_skb_delay_blk blk, *b;
	struct skbtrace_context *ctx;
	int last_slot = 0;
	bool overflow = false;

	p = (struct skbtrace_skb_delay_param*)t->private;
	ctx = skbtrace_skb_context_get(skb);
	if (!ctx)
		return;

	if (!ctx->skb.delay_block) {
		b = kzalloc(delay_block_max_size(t), GFP_ATOMIC);
		ctx->skb.delay_block = (struct skbtrace_block *)b;
	} else
		b = (struct skbtrace_skb_delay_blk *)ctx->skb.delay_block;

	if (!b) {
		b = &blk;
		b->blk.action = skbtrace_action_invalid;
	}

	if (skbtrace_action_invalid == b->blk.action) {
		INIT_SKBTRACE_BLOCK(&b->blk, skb,
			skbtrace_action_skb_delay,
			0,
			sizeof(blk));
		b->sk = (u64)ctx->skb.delay_sk;
		b->start_ts = ctx->skb.delay_ts;
		b->start_loc = (u64)ctx->skb.delay_loc;
	}

	if (!b->sk && skb->sk) {
		/* this means that we only take care of sender socket
		 * of loopback traffic
		 */
		b->sk = (u64)skb->sk;
		ctx->skb.delay_sk = (struct sock*)skb->sk;
	}

	switch (action) {
	case skbtrace_skb_delay_reset:
		b->blk.len = delay_block_size(0);
		b->start_loc = (u64)loc;
		ktime_get_ts(&b->start_ts);
		ctx->skb.delay_loc = (void*)loc;
		ctx->skb.delay_ts = b->start_ts;
		return;
	case skbtrace_skb_delay_append:
	case skbtrace_skb_delay_last:
		last_slot = delay_slots_nr(b);
		b->history[last_slot].loc = (u64)loc;
		b->history[last_slot].delay = delay_slot_new(b);
		overflow = delay_slots_nr_inc(t, b);
		if (overflow)
			b->blk.flags |= 1<<skbtrace_skb_delay_overflow;
		if (overflow || skbtrace_skb_delay_last == action)
			goto probe;
		return;
	default:
		b->blk.flags |= 1<<skbtrace_skb_delay_error;
	}

probe:

	if (p->ignore_kfree_only && 1 == delay_slots_nr(b)) {
		if (likely(b != &blk))
			skb_delay_release_block(t, &ctx->skb.delay_block);
		return;
	}

	if (p->ignore_zero &&
			!b->blk.flags &&
			!b->history[last_slot].delay) {
		if (likely(b != &blk))
			skb_delay_release_block(t, &ctx->skb.delay_block);
		return;
	}

	if (likely(b != &blk))
		skbtrace_dyn_probe(t, ctx, &ctx->skb.delay_block);
	else
		skbtrace_probe(t, ctx, &b->blk);
}

static void skbtrace_skb_delay(struct skbtrace_tracepoint *t,
		struct sk_buff *skb, skb_delay_op action)
SKBTRACE_SKB_EVENT_BEGIN
	return __skbtrace_skb_delay(t, skb, action,
				__builtin_return_address(0));
SKBTRACE_SKB_EVENT_END

static void skbtrace_skb_delay_param_skb(struct skbtrace_tracepoint *t,
							struct sk_buff *skb)
SKBTRACE_SKB_EVENT_BEGIN
	return __skbtrace_skb_delay(t, skb, skbtrace_skb_delay_append,
					__builtin_return_address(0));
SKBTRACE_SKB_EVENT_END

static void skbtrace_net_dev_xmit(struct skbtrace_tracepoint *t,
						struct sk_buff *skb,
						int rc,
						struct net_device *dev,
						unsigned int skb_len)
SKBTRACE_SKB_EVENT_BEGIN
	return __skbtrace_skb_delay(t, skb, skbtrace_skb_delay_append,
					__builtin_return_address(0));
SKBTRACE_SKB_EVENT_END

static void skbtrace_skb_copy_dg_iovec(struct skbtrace_tracepoint *t,
					struct sk_buff *skb,
					int len)
SKBTRACE_SKB_EVENT_BEGIN
	return __skbtrace_skb_delay(t, skb, skbtrace_skb_delay_append,
					__builtin_return_address(0));
SKBTRACE_SKB_EVENT_END

static struct skbtrace_tracepoint_probe skbtrace_skb_delay_probe_list[] = {
	{
		.name = "skb_delay",
		.probe = skbtrace_skb_delay,
	},
	{
		.name = "netif_receive_skb",
		.probe = skbtrace_skb_delay_param_skb,
	},
	{
		.name = "net_dev_queue",
		.probe = skbtrace_skb_delay_param_skb,
	},
	{
		.name = "netif_rx",
		.probe = skbtrace_skb_delay_param_skb,
	},
	{
		.name = "net_dev_xmit",
		.probe = skbtrace_net_dev_xmit,
	},
	{
		.name = "skb_copy_datagram_iovec",
		.probe = skbtrace_skb_copy_dg_iovec,
	},
	EMPTY_SKBTRACE_TP_PROBE_LIST
};

static struct skbtrace_tracepoint common[] = {
	{
		.trace_name = "skb_rps_info",
		.action = skbtrace_action_skb_rps_info,
		.block_size = sizeof(struct skbtrace_skb_rps_info_blk),
		.probe = skbtrace_skb_rps_info,
	},
	{
		.trace_name = "skb_delay",
		.action = skbtrace_action_skb_delay,
		.block_size = DELAY_BLOCK_BASE_SIZE,
		.probe_list = skbtrace_skb_delay_probe_list,
		.release_block = skb_delay_release_block,
		.private = (void*)&skb_delay_param,
	},
	EMPTY_SKBTRACE_TP
};

int skbtrace_events_common_init(void)
{
	return skbtrace_register_proto(AF_UNSPEC, common, NULL);
}

void skbtrace_events_common_cleanup(void)
{
	skbtrace_unregister_proto(AF_UNSPEC);
}

module_init(skbtrace_events_common_init);
module_exit(skbtrace_events_common_cleanup);
MODULE_ALIAS("skbtrace-af-" __stringify(AF_UNSPEC));
MODULE_LICENSE("GPL");
