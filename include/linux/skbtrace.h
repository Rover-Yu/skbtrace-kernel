/*
 *  skbtrace - sk_buff trace utilty
 *
 *	API for kernel
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

#ifndef _LINUX_SKBTRACE_H
#define _LINUX_SKBTRACE_H

#include <linux/jump_label.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/net.h>
#include <uapi/linux/skbtrace_api.h>
#include <asm/atomic.h>

#include <net/sock.h>
#if defined(CONFIG_SKBTRACE_IPV4) || defined(CONFIG_SKBTRACE_IPV4_MODULE)
#include <net/inet_timewait_sock.h>
#endif

#if defined(CONFIG_SKBTRACE) || defined(CONFIG_SKBTRACE_MODULE)
#define HAVE_SKBTRACE 1
#else
#define HAVE_SKBTRACE 0
#endif

#if HAVE_SKBTRACE

#define SKBTRACE_DYN_BLOCK_MAGIC	(~SKBTRACE_BLOCK_MAGIC)

#define SKBTRACE_BLOCK_MAXSIZE	(128)

/* The size parameters of secondary_buffer->slots */
#define SECONDARY_BUFFER_ORDER	0
#define SECONDARY_BUFFER_SIZE	(PAGE_SIZE<<SECONDARY_BUFFER_ORDER)
#define SECONDARY_BUFFER_UNIT	SKBTRACE_BLOCK_MAXSIZE
#define SECONDARY_BUFFER_COUNTS	(SECONDARY_BUFFER_SIZE/SECONDARY_BUFFER_UNIT)

struct secondary_buffer {
	atomic_t refcnt;
	struct hlist_node node;
	int action;	/* the action of primary event */
	spinlock_t lock;
	unsigned long session;
	int offset;	/* next writeable slot */
	int count;	/* count of current cached events in 'slots' */
	char *slots;	/* the cache of secondary events */
};

#define SECONDARY_TABLE_SHIFT	6
#define SECONDARY_TABLE_SIZE	(1<<SECONDARY_TABLE_SHIFT)
#define SECONDARY_TABLE_MASK	(SECONDARY_TABLE_SIZE - 1)

struct secondary_table {
	spinlock_t lock;
	struct hlist_head table[SECONDARY_TABLE_SIZE];
};

struct skbtrace_tracepoint_probe {
	const char *name;
	void *probe;
};

#define	EMPTY_SKBTRACE_TP_PROBE_LIST \
	{\
		.name = NULL,\
		.probe = NULL\
	}

struct skbtrace_tracepoint {
	const char *trace_name;
	int action;
	size_t block_size;
	void *private;

	union {
		struct {
			const char *probe_name;
			void *probe;
		};
		struct skbtrace_tracepoint_probe *probe_list;
	};

	int (*setup_options)(struct skbtrace_tracepoint *tp,
						char *options);
	void (*enable)(struct skbtrace_tracepoint *tp);
	void (*disable)(struct skbtrace_tracepoint *tp);
	char *(*desc)(struct skbtrace_tracepoint *tp);
	void (*release_block)(struct skbtrace_tracepoint *tp,
				struct skbtrace_block **blk);
	/* if has_mask_option is true */
	char **mask_names;
	int *mask_values;
	int nr_mask;
	unsigned long mask;

	/* if has_sk_mark_option is true */
	__u32 sk_mark;

	unsigned int has_mask_option : 1;
	unsigned int has_sk_mark_option : 1;

	/* Below is for internals, which is not a part of kernel API */
	unsigned int enabled : 1;
	struct skbtrace_tracepoint *primary;
	/* The secondary events of sk_buff based event are */
	/* cached here. The secondary events of socket based */
	/* event are cached in hash table skbtrace_context->sec_table */
	struct secondary_buffer sec_buffer;
	int nr_secondary;
};

#define MASK_OPTION_INIT(names, values) \
	.has_mask_option = 1,\
	.mask_names = names,\
	.mask_values = values,\
	.nr_mask = sizeof(values)/sizeof(int),\
	.mask = 0UL

#define EMPTY_SKBTRACE_TP	{.trace_name = NULL, }

extern atomic64_t skbtrace_event_seq;
extern int sysctl_skbtrace_filter_default;

#define INIT_SKBTRACE_BLOCK(blk, p, act, fl, blk_size) \
	do {\
		(blk)->magic = SKBTRACE_BLOCK_MAGIC;\
		(blk)->len = (blk_size);\
		(blk)->action = (act);\
		(blk)->flags = (fl);\
		(blk)->seq = atomic64_add_return(1, &skbtrace_event_seq);\
		(blk)->ts = current_kernel_time();\
		(blk)->ptr = (p);\
	} while (0)

struct inet_timewait_sock;
struct skbtrace_ops {
	int (*tw_getname)(struct inet_timewait_sock *tw,
			struct sockaddr *uaddr, int peer);
	int (*tw_filter_skb)(struct inet_timewait_sock *tw,
			struct sk_buff *skb);
	int (*getname)(struct sock *sk, struct sockaddr *uaddr,
		 int *uaddr_len, int peer);
	int (*filter_skb)(struct sock *sk, struct sk_buff *skb);
};

struct skbtrace_context {
	unsigned long session;
	struct skbtrace_ops *ops;
	union {
		unsigned int flags;
		unsigned int active_conn_hit : 1;
		unsigned int is_skb_context : 1;
	};
	union {
		struct {
			struct secondary_table *sec_table;
		};

		struct {
			struct skbtrace_block *delay_block;
			void *delay_loc;
			struct sock *delay_sk;
			struct timespec delay_ts;
		} skb;
	};
};

struct skbtrace_dyn_block_gate {
	u64 magic;
	struct skbtrace_block *blk;
	struct skbtrace_tracepoint *tp;
};

extern unsigned long skbtrace_session;

static inline void cond_local_bh_disable(void)
{
	if (in_irq() || irqs_disabled())
		return;
	local_bh_disable();
}

static inline void cond_local_bh_enable(void)
{
	if (in_irq() || irqs_disabled())
		return;
	local_bh_enable();
}

extern int skbtrace_register_proto(int af,
				struct skbtrace_tracepoint *tp_list,
				struct skbtrace_ops *ops);
extern void skbtrace_unregister_proto(int af);
extern struct skbtrace_ops* skbtrace_ops_get(int af);

extern bool __skbtrace_probe(struct skbtrace_tracepoint *tp,
				struct skbtrace_context *ctx,
				struct skbtrace_block *blk);
extern bool __skbtrace_dyn_probe(struct skbtrace_tracepoint *tp,
				struct skbtrace_context *ctx,
				struct skbtrace_block **blk);

extern struct static_key skbtrace_filters_enabled;
extern struct sk_filter *skbtrace_skb_filter;
extern struct sk_filter *skbtrace_sock_filter;

struct sk_buff** __skbtrace_get_sock_filter_skb(int cpu);
extern struct sk_buff* skbtrace_get_sock_filter_skb(struct sock *sk);
static inline void skbtrace_put_sock_filter_skb(struct sk_buff *skb)
{
	skb->data = skb->head;
	skb->len = 0;
	skb_reset_tail_pointer(skb);
	skb_reset_transport_header(skb);
	skb_reset_network_header(skb);
	cond_local_bh_enable();
}
extern struct sk_buff* skbtrace_get_twsk_filter_skb(
					struct inet_timewait_sock *tw);
#define skbtrace_put_twsk_filter_skb skbtrace_put_sock_filter_skb

static inline void skbtrace_probe(struct skbtrace_tracepoint *t,
				struct skbtrace_context *ctx,
				struct skbtrace_block *blk)
{
	if (skbtrace_action_invalid == blk->action)
		return;
	__skbtrace_probe(t, ctx, blk);
}

static inline void skbtrace_dyn_probe(struct skbtrace_tracepoint *t,
				struct skbtrace_context *ctx,
				struct skbtrace_block **blk)
{
	if (skbtrace_action_invalid == (*blk)->action)
		return;
	__skbtrace_dyn_probe(t, ctx, blk);
}

static inline int skbtrace_bypass_skb(struct sk_buff *skb)
{
	if (static_key_false(&skbtrace_filters_enabled)) {
		if (skb->skbtrace_filtered)
			return skb->hit_skbtrace;
		else if (skbtrace_skb_filter) {
			unsigned int pkt_len;

			pkt_len = SK_RUN_FILTER(skbtrace_skb_filter, skb);
			skb->hit_skbtrace = !pkt_len;
			skb->skbtrace_filtered = 1;
			return skb->hit_skbtrace;
		}
	}
	return 0;
}

static inline void secondary_buffer_get(struct secondary_buffer *buf)
{
	atomic_inc(&buf->refcnt);
}

static inline void secondary_buffer_put(struct secondary_buffer *buf)
{
	if (buf && atomic_dec_and_test(&buf->refcnt)) {
		int i;

		for (i = 0; i < buf->count; i++) {
			struct skbtrace_dyn_block_gate *gate;

			if (--buf->offset < 0)
				buf->offset = SECONDARY_BUFFER_COUNTS - 1;
			gate = (struct skbtrace_dyn_block_gate *) \
				&buf->slots[buf->offset * SECONDARY_BUFFER_UNIT];
			if (SKBTRACE_DYN_BLOCK_MAGIC == gate->magic)
				gate->tp->release_block(gate->tp, &gate->blk);
		}
		free_pages((unsigned long)buf->slots, SECONDARY_BUFFER_ORDER);
		buf->slots = NULL;
	}
}

static inline void secondary_buffer_reset(struct secondary_buffer *buf)
{
	buf->offset = 0;
	buf->count = 0;
}

static inline int secondary_buffer_init(struct secondary_buffer *buf,
					struct skbtrace_tracepoint *tp)
{
	buf->slots = (char *)__get_free_pages(GFP_ATOMIC,
						SECONDARY_BUFFER_ORDER);
	if (!buf->slots)
		return -ENOMEM;

	INIT_HLIST_NODE(&buf->node);
	spin_lock_init(&buf->lock);
	buf->action = tp->action;
	buf->session = skbtrace_session;
	atomic_set(&buf->refcnt, 0);
	secondary_buffer_reset(buf);
	secondary_buffer_get(buf);
	return 0;
}

static inline struct secondary_buffer* secondary_buffer_new(
					struct skbtrace_tracepoint *tp)
{
	struct secondary_buffer *buf;

	buf = kmalloc(sizeof(*buf), GFP_ATOMIC);
	if (buf && secondary_buffer_init(buf, tp)) {
		kfree(buf);
		buf = NULL;
	}
	return buf;
}

static inline void secondary_buffer_destroy(struct secondary_buffer *buf)
{
	if (buf) {
		secondary_buffer_put(buf);
		kfree(buf);
	}
}

static inline void secondary_table_init(struct secondary_table **table)
{
	unsigned int key;

	*table = kmalloc(sizeof(struct secondary_table), GFP_ATOMIC);
	if (!*table)
		return;

	spin_lock_init(&(*table)->lock);
	for (key = 0; key < SECONDARY_TABLE_SIZE; key++)
		INIT_HLIST_HEAD(&(*table)->table[key]);
}

static inline struct secondary_buffer* secondary_table_lookup(
				struct secondary_table **table,
				struct skbtrace_tracepoint *tp)
{
	unsigned int key;
	struct secondary_buffer *buffer;
	struct hlist_node *pos;

	if (!*table)
		secondary_table_init(table);
	if (!*table)
		return NULL;

	key = (47 * tp->action) & SECONDARY_TABLE_MASK;
	spin_lock_bh(&table->lock);
	hlist_for_each_entry(buffer, pos, &table->table[key], node) {
		if (buffer->session != skbtrace_session)
			continue;
		if (buffer->action == tp->action)
			goto unlock;
	}
	buffer = NULL;
unlock:
	spin_unlock_bh(&table->lock);

	return buffer;
}

static inline struct secondary_buffer* secondary_table_lookup_or_create(
				struct secondary_table **table,
				struct skbtrace_tracepoint *tp)
{
	unsigned int key;
	struct secondary_buffer *buffer;
	struct hlist_node *pos;

	if (!*table)
		secondary_table_init(table);
	if (!*table)
		return NULL;

	key = (47 * tp->action) & SECONDARY_TABLE_MASK;
	spin_lock_bh(&table->lock);
	hlist_for_each_entry(buffer, pos, &table->table[key], node) {
		if (buffer->session != skbtrace_session)
			continue;
		if (buffer->action == tp->action)
			goto unlock;
	}
	buffer = secondary_buffer_new(tp);
	if (buffer)
		hlist_add_head(&buffer->node, &table->table[key]);
unlock:
	spin_unlock_bh(&table->lock);

	return buffer;
}

static inline void secondary_table_clean(struct secondary_table **table)
{
	unsigned int key;

	if (!*table)
		return;

	spin_lock_bh(&(*table)->lock);
	for (key = 0; key < SECONDARY_TABLE_SIZE; key++) {
		while (!hlist_empty(&(*table)->table[key])) {
			struct secondary_buffer *buffer;

			buffer = container_of((*table)->table[key].first,
						struct secondary_buffer, node);
			hlist_del((*table)->table[key].first);
			secondary_buffer_destroy(buffer);
		}
	}
	spin_unlock_bh(&(*table)->lock);
	kfree(*table);
	*table = NULL;
}

extern struct skbtrace_context *skbtrace_context_get(struct sock *sk);
extern struct skbtrace_context *skbtrace_skb_context_get(struct sk_buff *skb);
extern struct skbtrace_context *skbtrace_context_new(
					bool is_skb_context,
					int gfp,
					struct skbtrace_ops *ops);

static inline void skbtrace_context_destroy(struct skbtrace_context **ctx)
{
	if (!*ctx)
		return;
	if (!(*ctx)->is_skb_context) {
		secondary_table_clean(&(*ctx)->sec_table);
	} else {
		kfree((*ctx)->skb.delay_block);
		(*ctx)->skb.delay_block = NULL;
	}
	kfree(*ctx);
	*ctx = NULL;
}

static inline void sock_skbtrace_reset(struct sock *sk)
{
	sk->sk_skbtrace = NULL;
}

static inline void* secondary_buffer_get_block(struct secondary_buffer *buf,
					struct skbtrace_tracepoint *primary)
{
	void *ret;

	if (!buf->slots && secondary_buffer_init(buf, primary))
		return NULL;

	spin_lock_bh(&buf->lock);
	ret = &buf->slots[buf->offset * SECONDARY_BUFFER_UNIT];
	if (buf->count < SECONDARY_BUFFER_COUNTS)
		buf->count++;
	if (++buf->offset >= SECONDARY_BUFFER_COUNTS)
		buf->offset = 0;
	spin_unlock_bh(&buf->lock);
	return ret;
}

static inline void* skbtrace_block_get(struct skbtrace_tracepoint *tp,
					struct skbtrace_context *ctx,
					void *fast)
{
	struct skbtrace_tracepoint *pri;

	if (!tp || !tp->primary)
		return fast;

	pri = tp->primary;
	if (ctx && !ctx->is_skb_context && ctx->sec_table) {
		/* use secondary buffer of current socket first */
		struct secondary_buffer *buf;

		buf = secondary_table_lookup_or_create(&ctx->sec_table, pri);
		if (!buf)
			return fast;
		return secondary_buffer_get_block(buf, pri) ? : fast;
	}
	return secondary_buffer_get_block(&pri->sec_buffer, pri) ? : fast;
}

#define SKBTRACE_SKB_EVENT_BEGIN \
{\
	if (skbtrace_bypass_skb(skb)) {\
		return;	\
	} else {

#define SKBTRACE_SKB_EVENT_END \
	} \
}

extern u32 skbtrace_sock_filter_id;
static inline int skbtrace_bypass_sock(struct skbtrace_tracepoint *t,
						struct sock *sk)
{
	if (static_key_false(&skbtrace_filters_enabled)) {
		if (likely(sk->sk_skbtrace_filtered &&
				(skbtrace_sock_filter_id == sk->sk_skbtrace_fid))) {
			return sk->sk_hit_skbtrace;
		}
		if (skbtrace_sock_filter) {
			unsigned int pkt_len;
			struct sk_buff *skb;

			skb = skbtrace_get_sock_filter_skb(sk);
			if (skb) {
				pkt_len = SK_RUN_FILTER(skbtrace_sock_filter, skb);
				sk->sk_hit_skbtrace = !pkt_len;
				sk->sk_skbtrace_filtered = 1;
				skbtrace_put_sock_filter_skb(skb);
				sk->sk_skbtrace_fid = skbtrace_sock_filter_id;
				return sk->sk_hit_skbtrace;
			}
			return sysctl_skbtrace_filter_default;
		}
	}
	if (t->sk_mark)
		return t->sk_mark != sk->sk_mark;
	return 0;
}

#if defined(CONFIG_SKBTRACE_IPV4) || defined(CONFIG_SKBTRACE_IPV4_MODULE)
static inline int skbtrace_bypass_twsk(struct inet_timewait_sock *tw)
{
	if (static_key_false(&skbtrace_filters_enabled)) {
		if (likely(tw->tw_skbtrace_filtered &&
				(skbtrace_sock_filter_id == tw->tw_skbtrace_fid))) {
			return tw->tw_hit_skbtrace;
		}
		if (skbtrace_sock_filter) {
			unsigned int pkt_len;
			struct sk_buff *skb;

			skb = skbtrace_get_twsk_filter_skb(tw);
			if (skb) {
				pkt_len = SK_RUN_FILTER(skbtrace_sock_filter, skb);
				tw->tw_hit_skbtrace = !pkt_len;
				tw->tw_skbtrace_filtered = 1;
				skbtrace_put_twsk_filter_skb(skb);
				tw->tw_skbtrace_fid = skbtrace_sock_filter_id;
				return tw->tw_hit_skbtrace;
			}
			return sysctl_skbtrace_filter_default;
		}
	}
	return 0;
}
#endif

#define SKBTRACE_SOCK_EVENT_BEGIN \
{\
	if (skbtrace_bypass_sock(t, sk)) {\
		return;	\
	} else {

#define SKBTRACE_SOCK_EVENT_END \
	} \
}

extern int inet_filter_skb(struct sock *sk, struct sk_buff *skb);
extern int inet_tw_getname(struct inet_timewait_sock *tw,
				struct sockaddr *uaddr, int peer);
extern int inet_tw_filter_skb(struct inet_timewait_sock *tw,
				struct sk_buff *skb);
extern int tcp_tw_filter_skb(struct inet_timewait_sock *tw,
				struct sk_buff *skb);
extern int tcp_filter_skb(struct sock *sk, struct sk_buff *skb);

#else /* HAVE_SKBTRACE */

static inline void sock_skbtrace_reset(struct sock *sk)
{
}

static inline void skbtrace_context_destroy(struct skbtrace_context **ctx)
{
}

#endif /* HAVE_SKBTRACE */

#endif /* _LINUX_SKBTRACE_H */
