/*
 *  skbtrace - sk_buff trace utilty
 *
 *	User/Kernel Interface
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
#ifndef _LINUX_SKBTRACE_API_H
#define _LINUX_SKBTRACE_API_H

#include <linux/types.h>

#ifdef __KERNEL__
#include <linux/time.h>
#else
#include <time.h>
#define __packed	__attribute__ ((__packed__))
#endif

#define TRACE_SPEC_MAX_LEN	256

#define SKBTRACE_DEF_SUBBUF_SIZE	(1<<12)
#define SKBTRACE_DEF_SUBBUF_NR		(1<<11)

#define SKBTRACE_MIN_SUBBUF_SIZE	SKBTRACE_DEF_SUBBUF_SIZE
#define SKBTRACE_MIN_SUBBUF_NR		SKBTRACE_DEF_SUBBUF_NR

#define SKBTRACE_MAX_SUBBUF_SIZE	(1<<16)
#define SKBTRACE_MAX_SUBBUF_NR		(1<<20)

#define SC	0	/* for tracepoints in process context */
#define SI	1	/* for tracepoints in softirq context */
#define HW	2	/* for tracepoints in hardirq context */
#define NR_CHANNELS	3

/* struct skbtrace_block - be used in kernel/user interaction	*/
/* @len:	whole data structure size in bytes		*/
/* @action:	action of this skbtrace_block			*/
/* @flags:	the flags depend on above action field		*/
/* @ts:		the timestamp of this event.			*/
/* @ptr:	the major source kernel data structure		*/
/*		of this event, for gerneral, a sk_buff or sock	*/
/* PLEASE:							*/
/*	Keep 64 bits alignment 					*/
struct skbtrace_block {
	__u64 magic;
	__u16 len;
	__u16 action;
	__u32 flags;
	struct timespec ts;
	__u64 seq;
	void *ptr;
} __packed;

enum {
	skbtrace_action_invalid		= 0,
};

enum {
	skbtrace_flags_reserved_min = 28,
	skbtrace_flags_miss_secondary = 28,
	skbtrace_flags_reserved_max = 31,
};

#include <uapi/net/skbtrace_api_common.h>
#include <uapi/net/skbtrace_api_ipv4.h>

#endif
