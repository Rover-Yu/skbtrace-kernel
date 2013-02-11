/*
 *  skbtrace - sk_buff trace utilty
 *
 *	Comon events
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

#if !defined(_TRACE_EVENTS_SKBTRACE_COMMON_H)
#define _TRACE_EVENTS_SKBTRACE_COMMON_H

#include <linux/tracepoint.h>

struct sk_buff;
struct net_device;
struct timer_list;

DECLARE_TRACE(skb_rps_info,
	TP_PROTO(struct sk_buff *skb, struct net_device *dev, int cpu),
	TP_ARGS(skb, dev, cpu));

DECLARE_TRACE(sk_timer,
	TP_PROTO(void *sk, struct timer_list *timer, int action),
	TP_ARGS(sk, timer, action));

#endif
