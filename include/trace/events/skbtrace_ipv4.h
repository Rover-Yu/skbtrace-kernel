 /*
 *  skbtrace - sk_buff trace utilty
 *
 *	The IPv4 related skbtrace events
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
 * Thanks for Web10G project here, some sources reference to it.
 *
 * 2012 Li Yu <bingtian.ly@taobao.com>
 *
 */

#if !defined(_TRACE_EVENTS_SKBTRACE_IPV4_H)
#define _TRACE_EVENTS_SKBTRACE_IPV4_H

#include <linux/tracepoint.h>

DECLARE_TRACE(tcp_congestion,
	TP_PROTO(void *sk, int reason),
	TP_ARGS(sk, reason));

#endif
