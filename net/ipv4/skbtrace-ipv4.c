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

static struct skbtrace_tracepoint tp_inet4[] = {
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
