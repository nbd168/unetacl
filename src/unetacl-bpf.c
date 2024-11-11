// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024 Felix Fietkau <nbd@nbd.name>
 */
#define KBUILD_MODNAME "unetacl"
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/icmpv6.h>
#include <uapi/linux/filter.h>
#include <uapi/linux/pkt_cls.h>
#include <linux/ip.h>
#include <net/ndisc.h>
#include <net/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_skb_utils.h"
#include "unetacl-bpf.h"

static const volatile struct unetacl_bpf_config config = {};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct unetacl_bpf_client_key));
	__type(value, struct unetacl_bpf_client);
	__uint(max_entries, 1024);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} client SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(key_size, 4 + 4);
	__type(value, struct unetacl_bpf_network);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} network4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(key_size, 4 + 16);
	__type(value, struct unetacl_bpf_network);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} network6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(key_size, sizeof(struct unetacl_bpf_policy_key));
	__type(value, struct unetacl_bpf_policy);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} policy SEC(".maps");

static bool
is_dhcpv4_port(uint16_t port)
{
	return port == bpf_htons(67) || port == bpf_htons(68);
}

static __always_inline bool
check_ipv4_control(struct skb_parser_info *info)
{
	struct udphdr *udph;

	if (info->proto != IPPROTO_UDP)
		return false;

	udph = skb_info_ptr(info, sizeof(*udph));
	if (!udph)
		return false;

	return is_dhcpv4_port(udph->source) && is_dhcpv4_port(udph->dest);
}

static bool
is_dhcpv6_port(uint16_t port)
{
	return port == bpf_htons(546) || port == bpf_htons(547);
}

static bool
is_icmpv6_control(uint8_t type)
{
	switch (type) {
	case ICMPV6_PKT_TOOBIG:
	case NDISC_ROUTER_SOLICITATION:
	case NDISC_ROUTER_ADVERTISEMENT:
	case NDISC_NEIGHBOUR_SOLICITATION:
	case NDISC_NEIGHBOUR_ADVERTISEMENT:
	case NDISC_REDIRECT:
	case ICMPV6_MGM_QUERY:
	case ICMPV6_MGM_REPORT:
		return true;
	default:
		return false;
	}
}

static __always_inline bool
check_ipv6_control(struct skb_parser_info *info)
{
	if (info->proto == IPPROTO_UDP) {
		struct udphdr *udph;

		udph = skb_info_ptr(info, sizeof(*udph));
		if (!udph)
			return false;

		return is_dhcpv6_port(udph->source) && is_dhcpv6_port(udph->dest);
	}

	if (info->proto == IPPROTO_ICMPV6) {
		struct icmp6hdr *icmp6h;

		icmp6h = skb_info_ptr(info, sizeof(*icmp6h));
		if (!icmp6h)
			return false;

		return is_icmpv6_control(icmp6h->icmp6_type);
	}

	return false;
}

static __always_inline bool
check_dns(struct skb_parser_info *info, bool ingress)
{
	struct udphdr *udph;

	if (info->proto != IPPROTO_UDP)
		return false;

	udph = skb_info_ptr(info, sizeof(*udph));
	if (!udph)
		return false;

	if (ingress)
		return udph->dest == bpf_htons(53);

	return udph->source == bpf_htons(53);
}

static inline int
unetacl_handle_skb(struct __sk_buff *skb, bool ingress)
{
	struct unetacl_bpf_network_key net_key = {};
	struct unetacl_bpf_policy_key pkey = {
		.prefix_len = 32,
		.network_id = UNETACL_NETWORK_ID_DEFAULT,
	};
	struct unetacl_bpf_action act = {};
	struct unetacl_bpf_client cl = {}, *__cl;
	struct unetacl_bpf_policy *pol;
	struct unetacl_bpf_acct *stats;
	struct skb_parser_info info;
	uint32_t *net_match;
	struct ethhdr *eth;
	struct iphdr *iph;
	struct ipv6hdr *ip6h;
	bool addr_match = !ingress;
	bool uses_gateway = true;
	bool is_local = false;
	bool drop_multicast = false;
	bool has_vlan;
	bool is_dns;

	skb_parse_init(&info, skb);
	eth = skb_parse_ethernet(&info);
	if (!eth)
		return TC_ACT_UNSPEC;

	if (!ingress && (eth->h_dest[0] & 1))
		return TC_ACT_UNSPEC;

	__cl = bpf_map_lookup_elem(&client, ingress ? eth->h_source : eth->h_dest);
	if (__cl) {
		cl = *__cl;
		pkey.client_id = cl.id;

		if (!(cl.flags & UNETACL_CLIENT_FILTER_IPADDR))
			addr_match = true;

		if (ingress && (eth->h_dest[0] & 1) &&
		    (cl.flags & UNETACL_CLIENT_FILTER_MULTICAST))
			drop_multicast = true;
	}

	if (cl.flags & UNETACL_CLIENT_FORCE_GATEWAY)
		uses_gateway = !memcmp(cl.gateway, ingress ? eth->h_dest : eth->h_source, ETH_ALEN);

	has_vlan = skb_parse_vlan(&info);
	if ((iph = skb_parse_ipv4(&info, sizeof(struct udphdr))) != NULL) {
		__be32 dest_addr;

		net_key.prefix_len = 32;
		if (ingress) {
			if (iph->saddr == cl.ip4addr)
				addr_match = true;
			net_key.data[0] = iph->daddr;
			dest_addr = iph->saddr;
		} else {
			net_key.data[0] = iph->saddr;
			dest_addr = iph->daddr;
		}

		if (check_ipv4_control(&info)) {
			bpf_clone_redirect(skb, config.snoop_ifindex, BPF_F_INGRESS);
			return TC_ACT_UNSPEC;
		}

		if (!addr_match)
			return TC_ACT_SHOT;

		is_dns = check_dns(&info, ingress);
		is_local = !((dest_addr ^ cl.ip4addr) & cpu_to_be32(0xffffffff << (32 - cl.ip4mask)));

		net_match = bpf_map_lookup_elem(&network4, &net_key);
		if (net_match)
			pkey.network_id = *net_match;
	} else if ((ip6h = skb_parse_ipv6(&info, sizeof(struct icmp6hdr))) != NULL) {
		net_key.prefix_len = 128;
		if (ingress) {
			if (ipv6_addr_equal(&ip6h->saddr, (struct in6_addr *)&cl.ip6addr))
				addr_match = true;
			memcpy(&net_key.data, &ip6h->daddr, sizeof(net_key.data));
		} else {
			memcpy(&net_key.data, &ip6h->saddr, sizeof(net_key.data));
		}

		if (check_ipv6_control(&info)) {
			bpf_clone_redirect(skb, config.snoop_ifindex, BPF_F_INGRESS);
			return TC_ACT_UNSPEC;
		}

		if (!addr_match)
			return TC_ACT_SHOT;

		is_dns = check_dns(&info, ingress);
		net_match = bpf_map_lookup_elem(&network6, &net_key);
		if (net_match)
			pkey.network_id = *net_match;
	} else {
		return TC_ACT_UNSPEC;
	}

	if (drop_multicast)
		return TC_ACT_SHOT;

	if (!is_local && !uses_gateway)
		return TC_ACT_SHOT;

	if (is_dns) {
		bpf_clone_redirect(skb, config.snoop_ifindex, BPF_F_INGRESS);
		pkey.network_id = UNETACL_NETWORK_ID_DNS;
	}

	if (is_local && !uses_gateway && !is_dns &&
	    pkey.network_id == UNETACL_NETWORK_ID_DEFAULT &&
	    (cl.flags & UNETACL_CLIENT_FILTER_LOCAL))
		return TC_ACT_SHOT;

	pol = bpf_map_lookup_elem(&policy, &pkey);
	if (!pol && pkey.network_id != UNETACL_NETWORK_ID_DEFAULT) {
		pkey.network_id = UNETACL_NETWORK_ID_DEFAULT;
		pol = bpf_map_lookup_elem(&policy, &pkey);
	}

	if (!pol)
		return TC_ACT_UNSPEC;

	if (ingress)
		stats = &pol->rx;
	else
		stats = &pol->tx;

	stats->packets++;
	stats->bytes += skb->len;

	if (pol->action.flags & UNETACL_ACTION_DROP)
		return TC_ACT_SHOT;

	if (!ingress)
		return TC_ACT_UNSPEC;

	act = pol->action;

	if (act.flags & UNETACL_ACTION_SET_DEST_MAC) {
		eth = skb_ptr(skb, 0, sizeof(*eth));
		if (!eth)
			return TC_ACT_UNSPEC;

		memcpy(eth->h_dest, act.dest_mac, ETH_ALEN);
	}

	if (act.flags & UNETACL_ACTION_FWMARK)
		skb->mark = (skb->mark & ~act.fwmark_mask) | act.fwmark_val;

	if (act.flags & UNETACL_ACTION_REDIRECT) {
		if (act.flags & UNETACL_ACTION_REDIRECT_VLAN) {
			if (has_vlan && bpf_skb_vlan_pop(skb))
				return TC_ACT_UNSPEC;

			if (act.redirect_vlan_proto &&
			    bpf_skb_vlan_push(skb, act.redirect_vlan_proto, act.redirect_vlan))
				return TC_ACT_UNSPEC;
		}

		return bpf_redirect(act.redirect_ifindex, 0);
	}

	return TC_ACT_UNSPEC;
}


SEC("tc/ingress")
int unetacl_in(struct __sk_buff *skb)
{
	return unetacl_handle_skb(skb, true);
}

SEC("tc/egress")
int unetacl_out(struct __sk_buff *skb)
{
	return unetacl_handle_skb(skb, false);
}

char _license[] SEC("license") = "GPL";
