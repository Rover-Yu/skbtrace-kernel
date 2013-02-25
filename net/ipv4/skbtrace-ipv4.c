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
	cond_local_bh_disable();

	ctx = tw->tw_skbtrace;
	if (ctx && (skbtrace_session != ctx->session))
		skbtrace_context_destroy(&tw->tw_skbtrace);

	if (!tw->tw_skbtrace)
		tw->tw_skbtrace = skbtrace_context_new(true, GFP_ATOMIC, ops);

	cond_local_bh_enable();
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

	cond_local_bh_disable();

	ops = skbtrace_ops_get(tw->tw_family);
	if (!ops || !ops->filter_skb) {
		cond_local_bh_enable();
		return NULL;
	}

	cpu = smp_processor_id();
	p_skb = __skbtrace_get_sock_filter_skb(cpu);
	if (unlikely(!*p_skb)) {
		*p_skb = alloc_skb(1500, GFP_ATOMIC);
		if (!*p_skb) {
			cond_local_bh_enable();
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

static char* tcp_sendlimit_mask_names[] = {
	"cwnd",
	"swnd",
	"nagle",
	"tso",
	"frag",
	"pushone",
	"other",
	"ok",
};

static int tcp_sendlimit_mask_values[] = {
	skbtrace_tcp_sndlim_cwnd,
	skbtrace_tcp_sndlim_swnd,
	skbtrace_tcp_sndlim_nagle,
	skbtrace_tcp_sndlim_tso,
	skbtrace_tcp_sndlim_frag,
	skbtrace_tcp_sndlim_pushone,
	skbtrace_tcp_sndlim_other,
	skbtrace_tcp_sndlim_ok,
};

static void skbtrace_tcp_sendlimit(struct skbtrace_tracepoint *t,
		struct sock *sk, int reason, int val)
SKBTRACE_SOCK_EVENT_BEGIN
	struct skbtrace_tcp_sendlim_blk blk, *b;
	struct tcp_sock *tp = tcp_sk(sk);
	struct skbtrace_context *ctx;

	if (t->mask & (1<<reason))
		return;

	if (skbtrace_tcp_sndlim_ok == reason && !val)
		return;

	ctx = skbtrace_context_get(sk);
	b = skbtrace_block_get(t, ctx, &blk);
	INIT_SKBTRACE_BLOCK(&b->blk, tp,
			skbtrace_action_tcp_sendlimit,
			1 << reason,
			sizeof(*b));

	b->val = val;
	b->count = 1;
	b->begin = current_kernel_time();

	b->snd_ssthresh = tp->snd_ssthresh;
	b->snd_cwnd = tp->snd_cwnd;
	b->snd_cwnd_cnt = tp->snd_cwnd_cnt;
	b->snd_wnd = tp->snd_wnd;

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

static char* tcp_ca_state_mask_names[] = {
	"open",
	"disorder",
	"cwr",
	"recovery",
	"loss",
};

static int tcp_ca_state_mask_values[] = {
	TCP_CA_Open,
	TCP_CA_Disorder,
	TCP_CA_CWR,
	TCP_CA_Recovery,
	TCP_CA_Loss,
};

static void skbtrace_tcp_ca_state(struct skbtrace_tracepoint *t,
					struct sock *sk, u8 state)
SKBTRACE_SOCK_EVENT_BEGIN
	struct tcp_sock *tp = tcp_sk(sk);
	struct skbtrace_tcp_ca_state_blk blk, *b;
	struct skbtrace_context *ctx;

	if (t->mask & (1<<state))
		return;

	ctx = skbtrace_context_get(sk);
	b = skbtrace_block_get(t, ctx, &blk);
	INIT_SKBTRACE_BLOCK(&b->blk, sk,
			skbtrace_action_tcp_ca_state, 1<<state, sizeof(blk));

	b->cwnd = tp->snd_cwnd;
	b->rto = inet_csk(sk)->icsk_rto;
	b->snduna = tp->snd_una;
	b->sndnxt = tp->snd_nxt;

	b->snd_ssthresh = tp->snd_ssthresh;
	b->snd_wnd = tp->snd_wnd;
	b->rcv_wnd = tp->rcv_wnd;
	b->high_seq = tp->high_seq;

	b->packets_out = tp->packets_out;
	b->lost_out = tp->lost_out;
	b->retrans_out = tp->retrans_out;
	b->sacked_out = tp->sacked_out;

	b->fackets_out = tp->fackets_out;
	b->prior_ssthresh = tp->prior_ssthresh;
	b->undo_marker = tp->undo_marker;
	b->undo_retrans = tp->undo_retrans;

	b->total_retrans =  tp->total_retrans;
	b->reordering = tp->reordering;
	b->prior_cwnd = tp->prior_cwnd;
	b->mss_cache = tp->mss_cache;

	skbtrace_probe(t, ctx, &b->blk);
SKBTRACE_SOCK_EVENT_END

static char* tcp_timer_mask_names[] = {
	"setup",
	"reset",
	"stop",

	"rexmit",
	"probe",
	"keepalive",
	"delack",
};

static int tcp_timer_mask_values[] = {
	skbtrace_sk_timer_setup,
	skbtrace_sk_timer_reset,
	skbtrace_sk_timer_stop,

	skbtrace_tcp_timer_rexmit,
	skbtrace_tcp_timer_probe,
	skbtrace_tcp_timer_keepalive,
	skbtrace_tcp_timer_delack,
};

static void skbtrace_tcp_timer(struct skbtrace_tracepoint *t,
			struct sock *sk, struct timer_list *timer, int action)
SKBTRACE_SOCK_EVENT_BEGIN
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct skbtrace_sk_timer_blk blk, *b;
	s32 f_timer, timeout;
	u32 timer_bits;
	struct skbtrace_context *ctx;

	if (IPPROTO_TCP != sk->sk_protocol)
		return;

	if (t->mask & (1<<action))
		return;

	if (timer == &icsk->icsk_retransmit_timer) {
		f_timer = (icsk->icsk_pending == ICSK_TIME_PROBE0 ?
				skbtrace_tcp_timer_probe : skbtrace_tcp_timer_rexmit);
	} else if (timer == &icsk->icsk_delack_timer)
		f_timer = skbtrace_tcp_timer_delack;
	else if (timer == &sk->sk_timer)
		f_timer = skbtrace_tcp_timer_keepalive;
	else
		f_timer = 0;
	timer_bits = f_timer ? (1<<f_timer) : 0;

	if (t->mask & timer_bits)
		return;

	/* TCP rexmit timer and probe0 share same timer_list  */
	if (f_timer == skbtrace_tcp_timer_rexmit
			&& action == skbtrace_sk_timer_setup) {
		if (t->mask & (1<<skbtrace_tcp_timer_probe))
			return;
		timer_bits |= 1<<skbtrace_tcp_timer_probe;
	}

	ctx = skbtrace_context_get(sk);
	b = skbtrace_block_get(t, ctx, &blk);
	INIT_SKBTRACE_BLOCK(&b->blk, sk,
			skbtrace_action_sk_timer, 1<<action, sizeof(blk));
	b->proto = IPPROTO_TCP;

	if (skbtrace_sk_timer_reset == action)
		timeout = jiffies_to_msecs(timer->expires - jiffies);
	else
		timeout = 0;

	b->blk.flags |= timer_bits;
	b->timeout = timeout;
	skbtrace_probe(t, ctx, &b->blk);
SKBTRACE_SOCK_EVENT_END

static void skbtrace_tcp_reset(struct skbtrace_tracepoint *t,
						struct sock *sk, u64 ptr)
SKBTRACE_SOCK_EVENT_BEGIN
	struct skbtrace_ops *ops;
	struct skbtrace_tcp_reset_blk blk, *b;
	struct skbtrace_context *ctx;

	if (!sk || !ptr)
		/* !sk, means we skip incoming RESET for non-existent connection */
		/* !ptr, means we skip non-RESET segments */
		return;
	ctx = skbtrace_context_get(sk);
	b = skbtrace_block_get(t, ctx, &blk);
	INIT_SKBTRACE_BLOCK(&b->blk, sk,
			skbtrace_action_tcp_reset, 0, sizeof(blk));
	b->location = ptr;
	b->state = sk->sk_state;
	ops = skbtrace_ops_get(sk->sk_family);
	if (TCP_TIME_WAIT == b->state) {
		ops->tw_getname(inet_twsk(sk), &b->addr.local, 0);
		ops->tw_getname(inet_twsk(sk), &b->addr.peer, 1);
	} else {
		ops->getname(sk, &b->addr.local, NULL, 0);
		if (TCP_LISTEN != b->state)
			ops->getname(sk, &b->addr.peer, NULL, 1);
	}
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
		.trace_name = "tcp_sendlimit",
		.action = skbtrace_action_tcp_sendlimit,
		.block_size = sizeof(struct skbtrace_tcp_sendlim_blk),
		.probe = skbtrace_tcp_sendlimit,
		.has_sk_mark_option = 1,
		MASK_OPTION_INIT(tcp_sendlimit_mask_names, tcp_sendlimit_mask_values),
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
	{
		.trace_name = "tcp_ca_state",
		.action = skbtrace_action_tcp_ca_state,
		.block_size = sizeof(struct skbtrace_tcp_ca_state_blk),
		.probe = skbtrace_tcp_ca_state,
		.has_sk_mark_option = 1,
		MASK_OPTION_INIT(tcp_ca_state_mask_names, tcp_ca_state_mask_values),
	},
	{
		.trace_name = "tcp_timer",
		.probe_name = "sk_timer",
		.action = skbtrace_action_sk_timer,
		.block_size = sizeof(struct skbtrace_sk_timer_blk),
		.probe = skbtrace_tcp_timer,
		.has_sk_mark_option = 1,
		MASK_OPTION_INIT(tcp_timer_mask_names, tcp_timer_mask_values),
	},
	{
		.trace_name = "tcp_reset",
		.action = skbtrace_action_tcp_reset,
		.block_size = sizeof(struct skbtrace_tcp_reset_blk),
		.probe = skbtrace_tcp_reset,
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
