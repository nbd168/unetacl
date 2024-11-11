// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2024 Felix Fietkau <nbd@nbd.name>
 */
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include <libubox/utils.h>

#include "unetacl-ucode.h"

struct vlan_hdr {
	uint16_t tci;
	uint16_t proto;
};

static bool
proto_is_vlan(uint16_t proto)
{
	return proto == ETH_P_8021Q || proto == ETH_P_8021AD;
}

struct icmpv6_opt {
	uint8_t type;
	uint8_t len;
	uint8_t data[6];
};

#define icmpv6_for_each_option(opt, start, end)					\
	for (opt = (const struct icmpv6_opt*)(start);				\
	     (const void *)(opt + 1) <= (const void *)(end) && opt->len > 0 &&	\
	     (const void *)(opt + opt->len) <= (const void *)(end); opt += opt->len)

static void
uc_snoop_recv_icmpv6(struct uc_snoop *s, struct packet *pkt, struct ethhdr *eth)
{
	const void *data = pkt->buffer;
	size_t len = pkt->len;
	const void *src = eth->h_source;
	const struct nd_neighbor_advert *nd = data;
	const struct icmp6_hdr *hdr = data;
	const struct icmpv6_opt *opt;
	char addr[INET6_ADDRSTRLEN];
	uc_value_t *info;

	if (len < sizeof(*nd) || hdr->icmp6_code)
		return;

	if (hdr->icmp6_type != ND_NEIGHBOR_ADVERT)
		return;

	icmpv6_for_each_option(opt, &nd[1], data + len) {
		if (opt->type != ND_OPT_TARGET_LINKADDR || opt->len != 1)
			continue;

		if (memcmp(opt->data, src, ETH_ALEN))
			return;
	}

	if ((nd->nd_na_target.s6_addr[0] & 0xe0) != 0x20)
		return;

	if (opt != (const struct icmpv6_opt *)(data + len))
		return;

	info = ucv_object_new(_vm);
	ucv_object_add(info, "macaddr",
	               ucv_string_new(ether_ntoa(src)));

	inet_ntop(AF_INET6, &nd->nd_na_target, addr, sizeof(addr));
	ucv_object_add(info, "ip6addr",
	               ucv_get(ucv_string_new(addr)));

	uc_snoop_cb(s, "icmpv6", info);
}

void uc_snoop_recv(struct uc_snoop *s, struct packet *pkt)
{
	uint16_t proto, src_port, dst_port;
	struct ethhdr *eth;
	struct ip6_hdr *ip6;
	struct ip *ip;
	struct udphdr *udp;
	void *saddr;
	int af;

	eth = pkt_pull(pkt, sizeof(*eth));
	if (!eth)
		return;

	proto = be16_to_cpu(eth->h_proto);
	if (proto_is_vlan(proto)) {
		struct vlan_hdr *vlan;

		vlan = pkt_pull(pkt, sizeof(*vlan));
		if (!vlan)
			return;

		proto = be16_to_cpu(vlan->proto);
	}

	switch (proto) {
	case ETH_P_IP:
		ip = pkt_peek(pkt, sizeof(struct ip));
		if (!ip)
			return;

		if (!pkt_pull(pkt, ip->ip_hl * 4))
			return;

		proto = ip->ip_p;
		af = AF_INET;
		saddr = &ip->ip_src;
		break;
	case ETH_P_IPV6:
		ip6 = pkt_pull(pkt, sizeof(*ip6));
		if (!ip6)
			return;

		proto = ip6->ip6_nxt;
		if (proto == IPPROTO_ICMPV6) {
			if (ip6->ip6_hlim != 255)
				return;

			uc_snoop_recv_icmpv6(s, pkt, eth);
			return;
		}
		af = AF_INET6;
		saddr = &ip6->ip6_src;
		break;
	default:
		return;
	}

	if (proto != IPPROTO_UDP)
		return;

	udp = pkt_pull(pkt, sizeof(struct udphdr));
	if (!udp)
		return;

	src_port = ntohs(udp->uh_sport);
	dst_port = ntohs(udp->uh_dport);

	if (af == AF_INET && src_port == 67 && dst_port == 68)
		uc_snoop_dhcp_recv(s, pkt, eth);

	if (src_port == 53)
		uc_snoop_dns_recv(s, pkt, eth, af, saddr);
}
