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

static struct skbtrace_tracepoint common[] = {
	{
		.trace_name = "skb_rps_info",
		.action = skbtrace_action_skb_rps_info,
		.block_size = sizeof(struct skbtrace_skb_rps_info_blk),
		.probe = skbtrace_skb_rps_info,
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
