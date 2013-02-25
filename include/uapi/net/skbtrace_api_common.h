/*
 *  skbtrace - sk_buff trace utilty
 *
 *	User/Kernel Interface, Common events
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
#ifndef _NET_SKBTRACE_API_COMMON_H
#define _NET_SKBTRACE_API_COMMON_H

#include <linux/types.h>

/* skbtrace_block->action */
enum {
	skbtrace_action_common_min	= 1,
	skbtrace_action_skb_rps_info	= 1,
	skbtrace_action_sk_timer	= 2,
	skbtrace_action_skb_delay	= 3,
	skbtrace_action_common_max	= 99,
};

/* it is copied from <net/flow_keys.h>, except pad fields and packed */
struct skbtrace_flow_keys {
	__u32 src;
	__u32 dst;
	union {
		__u32 ports;
		__u16 port16[2];
	};
	__u32 ip_proto;
} __packed;

struct skbtrace_skb_rps_info_blk {
	struct skbtrace_block blk;
	__u16 rx_queue;
	__u16 pad;
	__u32 rx_hash;
	__u32 cpu;
	__u32 ifindex;
	struct skbtrace_flow_keys keys;
} __packed;

/* socket timers */
/* flags */
enum {
	skbtrace_sk_timer_setup	= 0,
	skbtrace_sk_timer_reset	= 1,
	skbtrace_sk_timer_stop	= 2,
	skbtrace_sk_timer_last	= 3,
};

struct skbtrace_sk_timer_blk {
	struct skbtrace_block blk;
	__s32	proto;
	__s32	timeout;
} __packed;

/* sk_buff delay history */
/* flags */
/* It does not have an inbound or outbound flag bit here, if so,
 * how we can handle it in loopback traffic? A solution is to
 * detect tx/rx direction by symbol lookup for location field
 * of delay history.
 */
enum {
	skbtrace_skb_delay_overflow	= 0,
	skbtrace_skb_delay_error	= 1,
};

struct skbtrace_skb_delay {
	__u64 loc;
	__u64 delay; /* in microseconds */
};

struct skbtrace_skb_delay_blk {
	struct skbtrace_block blk;
	__u64  sk;
	__u64  start_loc;
	struct timespec start_ts;
	struct skbtrace_skb_delay history[1];
} __packed;
#endif
