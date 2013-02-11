/*
 *  skbtrace - sk_buff trace utilty
 *
 *	User/Kernel Interface, TCP/IPv4 proctol suite events
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
#ifndef _NET_SKBTRACE_API_IPV4_H
#define _NET_SKBTRACE_API_IPV4_H

#include <linux/types.h>

#ifdef __KERNEL__
#include <linux/in.h>
#include <linux/in6.h>
#endif

/* skbtrace_block->action */
enum {
	skbtrace_action_tcp_min		= 101,
	skbtrace_action_tcp_congestion	= 101,
	skbtrace_action_tcp_connection	= 102,
	skbtrace_action_tcp_active_conn	= 104,
	skbtrace_action_tcp_rttm	= 105,
	skbtrace_action_tcp_max		= 199,
};

/* TCP congestion event (101) */

/* flags */
enum {
	skbtrace_tcp_cong_cwr		= 0,
	skbtrace_tcp_cong_loss		= 1,
	skbtrace_tcp_cong_fastrtx	= 2,
	skbtrace_tcp_cong_frto		= 3,
	skbtrace_tcp_cong_frto_loss	= 4,
	skbtrace_tcp_cong_leave		= 5,
};

struct skbtrace_tcp_cong_blk {
	struct skbtrace_block blk;
	__u32	rto;
	__u32	cwnd;
	__u32	sndnxt;
	__u32	snduna;
} __packed;

/* TCP basic connection event (102) */
struct skbtrace_tcp_conn_blk {
	struct skbtrace_block blk;
	union {
		struct {
			struct sockaddr local;
			struct sockaddr peer;
		};
		struct {
			struct sockaddr_in local;
			struct sockaddr_in peer;
		} inet;
		struct {
			struct sockaddr_in6 local;
			struct sockaddr_in6 peer;
		} inet6;
	} addr;
} __packed;

/* TCP RTTM event (105) */
struct skbtrace_tcp_rttm_blk {
	struct skbtrace_block blk;
	__u32 pad;
	__u32 snd_una;
	__u32 rtt_seq;
	__u32 rtt;
	__u32 rttvar;
	__u32 srtt;
	__u32 mdev;
	__u32 mdev_max;
} __packed;


#endif
