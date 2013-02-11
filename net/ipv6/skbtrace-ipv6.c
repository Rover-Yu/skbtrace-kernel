/*
 *  skbtrace - sk_buff trace for TCP/IPv6 protocol suite support
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
#include <net/inet6_connection_sock.h>
#include <net/ipv6.h>
#include <net/tcp.h>

static int is_mapped_ipv4(struct sock *sk)
{
	struct in6_addr mapped_prefix;
	struct ipv6_pinfo *np = inet6_sk(sk);

	if (sk->sk_gso_type == SKB_GSO_TCPV4 && sk->sk_state == TCP_SYN_RECV)
		return 1;

	ipv6_addr_set(&mapped_prefix, 0, 0, htonl(0x0000FFFF), 0);
	return ipv6_prefix_equal(&mapped_prefix, &np->saddr, 96);
}

static int inetX_sock_getname(struct sock *sk, struct sockaddr *uaddr,
			int *uaddr_len, int peer)
{
	if (is_mapped_ipv4(sk))
		return inet_sock_getname(sk, uaddr, uaddr_len, peer);
	return inet6_sock_getname(sk, uaddr, uaddr_len, peer);
}

static int __inet6_filter_skb(struct sock *sk, struct sk_buff *skb)
{
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct ipv6hdr *iph;

	skb_reset_network_header(skb);
	iph = ipv6_hdr(skb);

	*(__be32 *)iph = htonl(0x60000000);
	iph->hop_limit = 0;
	iph->nexthdr = sk->sk_protocol;
        iph->saddr = np->saddr;
	iph->daddr = np->daddr;
	iph->payload_len = htons(sizeof(struct ipv6hdr) + sizeof(struct tcphdr));

	return sizeof(struct ipv6hdr);
}

static int inetX_filter_skb(struct sock *sk, struct sk_buff *skb)
{
	int size, prot_size;

	if (!skb || !sk->sk_prot->filter_skb) {
		return -EINVAL;
	}

	if (is_mapped_ipv4(sk))
		return inet_filter_skb(sk, skb);

	size = __inet6_filter_skb(sk, skb);
	if (size < 0)
		return -EINVAL;
	skb->len += size;
	skb->data += size;
	skb->tail += size;

	prot_size = sk->sk_prot->filter_skb(sk, skb);
	if (prot_size < 0)
		return -EINVAL;
	skb->len += prot_size;
	skb->tail += prot_size;

	skb->data -= size;
	return 0;
}

static int inetX_tw_getname(struct inet_timewait_sock *tw,
				struct sockaddr *addr, int peer)
{
	struct sockaddr_in6 *in6 = (struct sockaddr_in6*)addr;
	struct inet6_timewait_sock *tw6;

	if (tw->tw_family == AF_INET)
		return inet_tw_getname(tw, addr, peer);

	tw6 = inet6_twsk((struct sock *)tw);
	in6->sin6_family = AF_INET6;
	if (!peer) {
		in6->sin6_port = tw->tw_sport;
		in6->sin6_addr = tw6->tw_v6_rcv_saddr;
	} else {
		in6->sin6_port = tw->tw_dport;
		in6->sin6_addr = tw6->tw_v6_daddr;
	}
	return 0;
}

static int __inet6_tw_filter_skb(struct inet_timewait_sock *tw,
						struct sk_buff *skb)
{
	struct ipv6hdr *iph;
	struct inet6_timewait_sock *tw6;

	tw6 = inet6_twsk((struct sock *)tw);

	skb_reset_network_header(skb);
	iph = ipv6_hdr(skb);
	*(__be32 *)iph = htonl(0x60000000);
	iph->hop_limit = 0;
	iph->nexthdr = IPPROTO_TCP;
	iph->saddr = tw6->tw_v6_rcv_saddr;
	iph->daddr = tw6->tw_v6_daddr;
	iph->payload_len = htons(sizeof(struct ipv6hdr) + sizeof(struct tcphdr));

	return sizeof(struct ipv6hdr);
}

static int inetX_tw_filter_skb(struct inet_timewait_sock *tw, struct sk_buff *skb)
{
	int size, prot_size;

	if (!skb)
		return -EINVAL;

	if (AF_INET == tw->tw_family)
		return inet_tw_filter_skb(tw, skb);

	size = __inet6_tw_filter_skb(tw, skb);
	if (size < 0)
		return -EINVAL;
	skb->len += size;
	skb->data += size;
	skb->tail += size;

	prot_size = tcp_tw_filter_skb(tw, skb);
	if (prot_size < 0)
		return -EINVAL;
	skb->len += prot_size;
	skb->tail += prot_size;

	skb->data -= size;
	return 0;
}

static struct skbtrace_ops ops_inet6 = {
	.tw_getname = inetX_tw_getname,
	.tw_filter_skb = inetX_tw_filter_skb,
	.getname = inetX_sock_getname,
	.filter_skb = inetX_filter_skb,
};

static int skbtrace_ipv6_init(void)
{
	return skbtrace_register_proto(AF_INET6, NULL, &ops_inet6);
}

static void skbtrace_ipv6_cleanup(void)
{
	skbtrace_unregister_proto(AF_INET6);
}

module_init(skbtrace_ipv6_init);
module_exit(skbtrace_ipv6_cleanup);
MODULE_ALIAS("skbtrace-af-" __stringify(AF_INET6));
MODULE_LICENSE("GPL");
