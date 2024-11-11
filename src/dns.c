// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2024 Felix Fietkau <nbd@nbd.name>
 */
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <resolv.h>

#include "unetacl-ucode.h"

#define FLAG_RESPONSE		0x8000
#define FLAG_OPCODE		0x7800
#define FLAG_AUTHORATIVE	0x0400
#define FLAG_RCODE		0x000f

#define TYPE_A			0x0001
#define TYPE_CNAME		0x0005
#define TYPE_PTR		0x000c
#define TYPE_TXT		0x0010
#define TYPE_AAAA		0x001c
#define TYPE_SRV		0x0021
#define TYPE_ANY		0x00ff

#define IS_COMPRESSED(x)	((x & 0xc0) == 0xc0)

#define CLASS_FLUSH		0x8000
#define CLASS_UNICAST		0x8000
#define CLASS_IN		0x0001

#define MAX_NAME_LEN            256
#define MAX_DATA_LEN            8096

struct dns_header {
	uint16_t id;
	uint16_t flags;
	uint16_t questions;
	uint16_t answers;
	uint16_t authority;
	uint16_t additional;
} __packed;

struct dns_question {
	uint16_t type;
	uint16_t class;
} __packed;

struct dns_answer {
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rdlength;
} __packed;

static int
pkt_pull_name(struct packet *pkt, const void *hdr, char *dest)
{
	int len;

	if (dest)
		len = dn_expand(hdr, pkt->buffer + pkt->len, pkt->buffer,
				(void *)dest, MAX_NAME_LEN);
	else
		len = dn_skipname(pkt->buffer, pkt->buffer + pkt->len - 1);

	if (len < 0 || !pkt_pull(pkt, len))
		return -1;

	return 0;
}

static int
dns_parse_question(struct packet *pkt, struct dns_header *h, uc_value_t *info)
{
	char qname[MAX_NAME_LEN];

	if (pkt_pull_name(pkt, h, qname) ||
	    !pkt_pull(pkt, sizeof(struct dns_question)))
		return -1;

	ucv_object_add(info, "q", ucv_string_new(qname));
	return 0;
}

static int
dns_parse_answer(struct packet *pkt, struct dns_header *h, uc_value_t *arr)
{
	char record[MAX_NAME_LEN];
	struct dns_answer *a;
	const char *type;
	uc_value_t *info;
	void *rdata;
	int len;

	if (pkt_pull_name(pkt, h, NULL))
		return -1;

	a = pkt_pull(pkt, sizeof(*a));
	if (!a)
		return -1;

	len = be16_to_cpu(a->rdlength);
	rdata = pkt_pull(pkt, len);
	if (!rdata)
		return -1;

	switch (be16_to_cpu(a->type)) {
	case TYPE_CNAME:
		if (dn_expand((void *)h, pkt->buffer + pkt->len, rdata,
			      record, sizeof(record)) < 0)
			return -1;

		type = "cname";
		break;
	case TYPE_A:
		type = "a";
		inet_ntop(AF_INET, rdata, record, sizeof(record));
		break;
	case TYPE_AAAA:
		type = "aaaa";
		inet_ntop(AF_INET6, rdata, record, sizeof(record));
		break;
	default:
		return 0;
	}

	info = ucv_array_new(_vm);
	ucv_array_push(info, ucv_get(ucv_string_new(type)));
	ucv_array_push(info, ucv_get(ucv_string_new(record)));
	ucv_array_push(info, ucv_get(ucv_int64_new(be32_to_cpu(a->ttl))));

	ucv_array_push(arr, ucv_get(info));

	return 0;
}

static int
dns_parse_answers(struct packet *pkt, struct dns_header *h, uc_value_t *info)
{
	uc_value_t *arr = ucv_array_new(_vm);

	ucv_object_add(info, "a", ucv_get(arr));

	for (size_t i = 0; i < be16_to_cpu(h->answers); i++) {
		if (dns_parse_answer(pkt, h, arr)) {
			ucv_put(arr);
			return -1;
		}
	}

	return 0;
}

void uc_snoop_dns_recv(struct uc_snoop *s, struct packet *pkt, struct ethhdr *eth,
		       int af, const void *saddr)
{
	char addr[INET6_ADDRSTRLEN];
	struct dns_header *h;
	uc_vm_t *vm = _vm;
	uc_value_t *info;

	h = pkt_pull(pkt, sizeof(*h));
	if (!h)
		return;

	if ((h->flags & cpu_to_be16(FLAG_RESPONSE | FLAG_OPCODE | FLAG_RCODE)) !=
	    cpu_to_be16(FLAG_RESPONSE))
		return;

	if (h->questions != cpu_to_be16(1))
		return;

	info = ucv_get(ucv_object_new(vm));
	if (dns_parse_question(pkt, h, info) ||
	    dns_parse_answers(pkt, h, info)) {
		ucv_put(info);
		return;
	}

	ucv_object_add(info, "macaddr",
                   ucv_get(ucv_string_new(ether_ntoa((void *)eth->h_dest))));
	inet_ntop(af, saddr, addr, sizeof(addr));
	ucv_object_add(info, "server",
		       ucv_get(ucv_string_new(addr)));
	uc_snoop_cb(s, "dns", info);
}
