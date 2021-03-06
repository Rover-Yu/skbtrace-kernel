/*
 * consolidates trace point definitions
 *
 * Copyright (C) 2009 Neil Horman <nhorman@tuxdriver.com>
 */

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/string.h>
#include <linux/if_arp.h>
#include <linux/inetdevice.h>
#include <linux/inet.h>
#include <linux/interrupt.h>
#include <linux/export.h>
#include <linux/netpoll.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/rcupdate.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <linux/netlink.h>
#include <linux/net_dropmon.h>
#include <linux/slab.h>
#include <linux/skbtrace.h>

#include <asm/unaligned.h>
#include <asm/bitops.h>

#define CREATE_TRACE_POINTS
#include <trace/events/skb.h>
#include <trace/events/net.h>
#include <trace/events/napi.h>
#include <trace/events/sock.h>
#include <trace/events/udp.h>

EXPORT_TRACEPOINT_SYMBOL_GPL(kfree_skb);

EXPORT_TRACEPOINT_SYMBOL_GPL(napi_poll);

#if HAVE_SKBTRACE

#define NEW_SKBTRACE_TP(name) \
	DEFINE_TRACE(name); \
	EXPORT_TRACEPOINT_SYMBOL_GPL(name);

NEW_SKBTRACE_TP(skb_rps_info);
NEW_SKBTRACE_TP(sk_timer);
NEW_SKBTRACE_TP(skb_delay);

NEW_SKBTRACE_TP(tcp_congestion);
NEW_SKBTRACE_TP(tcp_connection);
NEW_SKBTRACE_TP(icsk_connection);
NEW_SKBTRACE_TP(tcp_sendlimit);
NEW_SKBTRACE_TP(tcp_active_conn);
NEW_SKBTRACE_TP(tcp_rttm);
NEW_SKBTRACE_TP(tcp_ca_state);
NEW_SKBTRACE_TP(tcp_reset);

unsigned long skbtrace_session;
EXPORT_SYMBOL(skbtrace_session);

#endif
