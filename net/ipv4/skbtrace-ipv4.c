/*
 *  skbtrace - sk_buff trace for TCP/IPv4 protocol suite support
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
#include <linux/relay.h>
#include <linux/debugfs.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/jhash.h>
#include <linux/inet.h>

#include <linux/skbtrace.h>
#include <linux/tcp.h>
#include <net/inet_common.h>
#include <net/inet_connection_sock.h>
#include <net/tcp.h>

static struct skbtrace_context *skbtrace_context_twsk_get(
				struct inet_timewait_sock *tw)
{
	struct skbtrace_ops *ops;
	struct skbtrace_context *ctx;

	ops = skbtrace_ops_get(tw->tw_family);
	if (!ops)
		return NULL;
	local_bh_disable();

	if (tw->tw_skbtrace &&
			(skbtrace_session != tw->tw_skbtrace->session)) {
		skbtrace_context_destroy(&tw->tw_skbtrace);
	}

	if (!tw->tw_skbtrace) {
		ctx = kzalloc(sizeof(struct skbtrace_context), GFP_ATOMIC);
		if (likely(ctx)) {
			skbtrace_context_setup(ctx, ops);
			tw->tw_skbtrace = ctx;
		}
	}
	local_bh_enable();
	return tw->tw_skbtrace;
}
EXPORT_SYMBOL(skbtrace_context_twsk_get);

static int __inet_filter_skb(struct sock *sk, struct sk_buff *skb)
{
	struct inet_sock *inet = inet_sk(sk);
	struct iphdr *iph;

	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	*((__be16 *)iph) = htons((4 << 12) | (5 << 8));
	iph->frag_off = 0;
	iph->ttl      = 0;
	iph->protocol = sk->sk_protocol;
	iph->saddr = inet->inet_saddr;
	iph->daddr = inet->inet_daddr;
	iph->id = 0;
	iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));

	return sizeof(struct iphdr);
}

int inet_filter_skb(struct sock *sk, struct sk_buff *skb)
{
	int size, prot_size;

	if (!skb || !sk->sk_prot->filter_skb)
		return -ENODEV;
	size = __inet_filter_skb(sk, skb);
	if (size < 0)
		return -EINVAL;

	skb->len += size;
	skb->tail += size;
	skb->data += size;

	prot_size = sk->sk_prot->filter_skb(sk, skb);
	if (prot_size < 0)
		return -ENODEV;
	skb->len += prot_size;
	skb->tail += prot_size;

	skb->data -= size;
	return 0;
}
EXPORT_SYMBOL_GPL(inet_filter_skb);

int inet_tw_getname(struct inet_timewait_sock *tw,
					struct sockaddr *addr, int peer)
{
	struct sockaddr_in *in = (struct sockaddr_in*)addr;

	in->sin_family = AF_INET;
	if (!peer) {
		in->sin_port = tw->tw_sport;
		in->sin_addr.s_addr = tw->tw_rcv_saddr;
	} else {
		in->sin_port = tw->tw_dport;
		in->sin_addr.s_addr = tw->tw_daddr;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(inet_tw_getname);

static int __inet_tw_filter_skb(struct inet_timewait_sock *tw,
						struct sk_buff *skb)
{
	struct iphdr *iph;

	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	*((__be16 *)iph) = htons((4 << 12) | (5 << 8));
	iph->frag_off = 0;
	iph->ttl      = 0;
	iph->protocol = IPPROTO_TCP;
	iph->saddr = tw->tw_rcv_saddr;
	iph->daddr = tw->tw_daddr;
	iph->id = 0;
	iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));

	return sizeof(struct iphdr);
}

int inet_tw_filter_skb(struct inet_timewait_sock *tw, struct sk_buff *skb)
{
	int size, prot_size;

	if (!skb)
		return -EINVAL;

	size = __inet_tw_filter_skb(tw, skb);
	if (size < 0)
		return -EINVAL;
	skb->len += size;
	skb->tail += size;
	skb->data += size;

	prot_size = tcp_tw_filter_skb(tw, skb);
	if (size < 0)
		return -EINVAL;
	skb->len += prot_size;
	skb->tail += prot_size;

	skb->data -= size;
	return 0;
}
EXPORT_SYMBOL_GPL(inet_tw_filter_skb);

struct sk_buff* skbtrace_get_twsk_filter_skb(struct inet_timewait_sock *tw)
{
	unsigned int cpu;
	struct sk_buff **p_skb;
	int ret;
	struct skbtrace_ops *ops;

	local_bh_disable();

	ops = skbtrace_ops_get(tw->tw_family);
	if (!ops || !ops->filter_skb) {
		local_bh_enable();
		return NULL;
	}

	cpu = smp_processor_id();
	p_skb = __skbtrace_get_sock_filter_skb(cpu);
	if (unlikely(!*p_skb)) {
		*p_skb = alloc_skb(1500, GFP_ATOMIC);
		if (!*p_skb) {
			local_bh_enable();
			return NULL;
		}
	}

	ret = ops->tw_filter_skb(tw, *p_skb);
	if (ret < 0) {
		skbtrace_put_twsk_filter_skb(*p_skb);
		return NULL;
	}

	return *p_skb;
}
EXPORT_SYMBOL_GPL(skbtrace_get_twsk_filter_skb);

static char* tcp_cong_mask_names[] = {
	"cwr",
	"loss",
	"fastrtx",
	"frto",
	"frto-loss",
	"leave",
};

static int tcp_cong_mask_values[] = {
	skbtrace_tcp_cong_cwr,
	skbtrace_tcp_cong_loss,
	skbtrace_tcp_cong_fastrtx,
	skbtrace_tcp_cong_frto,
	skbtrace_tcp_cong_frto_loss,
	skbtrace_tcp_cong_leave,
};

static void skbtrace_tcp_congestion(struct skbtrace_tracepoint *t,
					struct sock *sk, int reason)
SKBTRACE_SOCK_EVENT_BEGIN
	struct skbtrace_tcp_cong_blk blk, *b;
	struct tcp_sock *tp;
	struct skbtrace_context *ctx;

	if (t->mask & (1<<reason))
		return;

	tp = tcp_sk(sk);
	ctx = skbtrace_context_get(sk);
	b = skbtrace_block_get(t, ctx, &blk);
	INIT_SKBTRACE_BLOCK(&b->blk, tp,
			skbtrace_action_tcp_congestion,
			1 << reason,
			sizeof(*b));
	b->cwnd = tp->snd_cwnd * tp->mss_cache;
	b->rto = inet_csk(sk)->icsk_rto;
	b->snduna = tp->snd_una;
	b->sndnxt = tp->snd_nxt;
	skbtrace_probe(t, ctx, &b->blk);
SKBTRACE_SOCK_EVENT_END

static void skbtrace_tcp_connection(struct skbtrace_tracepoint *t,
							void *ptr, u32 state)
{
	struct sock *sk = ptr;
	struct inet_timewait_sock *tw = inet_twsk(ptr);
	struct skbtrace_context *ctx;

	switch (state) {
	case TCP_TIME_WAIT + TCP_MAX_STATES:
	case TCP_FIN_WAIT2 + TCP_MAX_STATES:
		{
			struct skbtrace_tcp_conn_blk blk, *b;
			struct skbtrace_context *ctx;

			if (skbtrace_bypass_twsk(tw))
				return;

			ctx = skbtrace_context_twsk_get(tw);
			b = skbtrace_block_get(t, ctx, &blk);
			state -= TCP_MAX_STATES;
			INIT_SKBTRACE_BLOCK(&b->blk, tw,
				skbtrace_action_tcp_connection,
				1 << state,
				sizeof(blk));
			b->addr.inet.local.sin_family = AF_INET;
			b->addr.inet.local.sin_port = tw->tw_sport;
			b->addr.inet.local.sin_addr.s_addr = tw->tw_rcv_saddr;
			b->addr.inet.peer.sin_family = AF_INET;
			b->addr.inet.peer.sin_port = tw->tw_dport;
			b->addr.inet.peer.sin_addr.s_addr = tw->tw_daddr;
			skbtrace_probe(t, ctx, &b->blk);
			break;
		}
	case TCP_ESTABLISHED:
	case TCP_FIN_WAIT1:
	case TCP_CLOSE:
	case TCP_CLOSE_WAIT:
	case TCP_LAST_ACK:
	case TCP_SYN_SENT:
	case TCP_SYN_RECV:
	case TCP_CLOSING:
		{
			struct skbtrace_tcp_conn_blk blk, *b;
			struct skbtrace_ops *ops;

			if (skbtrace_bypass_sock(t, sk))
				return;

			if (TCP_CLOSE == sk->sk_state &&
				SHUTDOWN_MASK == sk->sk_shutdown)
				/* for active TCP connections, we will call
				 * tcp_set_state(sk, TCP_CLOSE) two times,
				 * this hack help skip second one */
				return;

			ops = skbtrace_ops_get(sk->sk_family);
			if (!ops)
				return;

			ctx = skbtrace_context_get(sk);
			b = skbtrace_block_get(t, ctx, &blk);
			INIT_SKBTRACE_BLOCK(&b->blk, ptr,
				skbtrace_action_tcp_connection,
				1 << state,
				sizeof(blk));
			ops->getname(sk, &b->addr.local, NULL, 0);
			if (TCP_LISTEN != state)
				ops->getname(sk, &b->addr.peer, NULL, 1);
			skbtrace_probe(t, ctx, &b->blk);
			break;
		}
	}
}

static void skbtrace_icsk_connection(struct skbtrace_tracepoint *t,
						struct sock *sk, u32 state)
SKBTRACE_SOCK_EVENT_BEGIN
	struct skbtrace_tcp_conn_blk blk, *b;
	struct skbtrace_ops *ops;
	struct skbtrace_context *ctx;

	if (TCP_LISTEN != state)
		return;
	ops = skbtrace_ops_get(sk->sk_family);
	if (!ops)
		return;

	ctx = skbtrace_context_get(sk);
	b = skbtrace_block_get(t, ctx, &blk);
	INIT_SKBTRACE_BLOCK(&b->blk, sk,
				skbtrace_action_tcp_connection,
				1 << state,
				sizeof(blk));
	ops->getname(sk, &b->addr.local, NULL, 0);
	skbtrace_probe(t, ctx, &b->blk);
SKBTRACE_SOCK_EVENT_END

static void skbtrace_tcp_active_conn(struct skbtrace_tracepoint *t,
							struct sock *sk)
SKBTRACE_SOCK_EVENT_BEGIN
	struct skbtrace_tcp_conn_blk blk, *b;
	struct skbtrace_context *ctx;

	ctx = skbtrace_context_get(sk);
	if (ctx) {
		if (ctx->active_conn_hit)
			return;
		ctx->active_conn_hit = 1;
	}

	b = skbtrace_block_get(t, ctx, &blk);
	INIT_SKBTRACE_BLOCK(&b->blk, sk,
			skbtrace_action_tcp_active_conn, 0, sizeof(blk));
	if (ctx && ctx->ops) {
		ctx->ops->getname(sk, &b->addr.local, NULL, 0);
		ctx->ops->getname(sk, &b->addr.peer, NULL, 1);
	} else
		memset(&b->addr, 0, sizeof(b->addr));
	skbtrace_probe(t, ctx, &b->blk);
SKBTRACE_SOCK_EVENT_END

static void skbtrace_tcp_rttm(struct skbtrace_tracepoint *t,
					struct sock *sk, u32 seq_rtt)
SKBTRACE_SOCK_EVENT_BEGIN
	struct tcp_sock *tp = tcp_sk(sk);
	struct skbtrace_tcp_rttm_blk blk, *b;
	struct skbtrace_context *ctx;

	ctx = skbtrace_context_get(sk);
	b = skbtrace_block_get(t, ctx, &blk);
	INIT_SKBTRACE_BLOCK(&b->blk, sk,
			skbtrace_action_tcp_rttm, 0, sizeof(blk));
	b->rtt_seq = tp->rtt_seq;
	b->snd_una = tp->snd_una;
	b->rtt = seq_rtt;
	b->srtt = tp->srtt;
	b->rttvar = tp->rttvar;
	b->mdev = tp->mdev;
	b->mdev_max = tp->mdev_max;
	skbtrace_probe(t, ctx, &b->blk);
SKBTRACE_SOCK_EVENT_END

static struct skbtrace_tracepoint_probe tcp_connection_probe_list[] = {
	{
		.name = "tcp_connection",
		.probe = skbtrace_tcp_connection,
	},
	{
		.name = "icsk_connection",
		.probe = skbtrace_icsk_connection,
	},
	EMPTY_SKBTRACE_TP_PROBE_LIST
};

static struct skbtrace_tracepoint tp_inet4[] = {
	{
		.trace_name = "tcp_congestion",
		.action = skbtrace_action_tcp_congestion,
		.block_size = sizeof(struct skbtrace_tcp_cong_blk),
		.probe = skbtrace_tcp_congestion,
		.has_sk_mark_option = 1,
		MASK_OPTION_INIT(tcp_cong_mask_names, tcp_cong_mask_values),
	},
	{
		.trace_name = "tcp_connection",
		.action = skbtrace_action_tcp_connection,
		.block_size = sizeof(struct skbtrace_tcp_conn_blk),
		.probe_list = tcp_connection_probe_list,
		.has_sk_mark_option = 1,
	},
	{
		.trace_name = "tcp_active_conn",
		.action = skbtrace_action_tcp_active_conn,
		.block_size = sizeof(struct skbtrace_tcp_conn_blk),
		.probe = skbtrace_tcp_active_conn,
		.has_sk_mark_option = 1,
	},
	{
		.trace_name = "tcp_rttm",
		.action = skbtrace_action_tcp_rttm,
		.block_size = sizeof(struct skbtrace_tcp_rttm_blk),
		.probe = skbtrace_tcp_rttm,
		.has_sk_mark_option = 1,
	},
	EMPTY_SKBTRACE_TP
};

static struct skbtrace_ops ops_inet4 = {
	.tw_getname = inet_tw_getname,
	.tw_filter_skb = inet_tw_filter_skb,
	.getname = inet_sock_getname,
	.filter_skb = inet_filter_skb,
};

static int skbtrace_ipv4_init(void)
{
	return skbtrace_register_proto(AF_INET, tp_inet4, &ops_inet4);
}

static void skbtrace_ipv4_cleanup(void)
{
	skbtrace_unregister_proto(AF_INET);
}

module_init(skbtrace_ipv4_init);
module_exit(skbtrace_ipv4_cleanup);
MODULE_ALIAS("skbtrace-af-" __stringify(AF_INET));
MODULE_LICENSE("GPL");
