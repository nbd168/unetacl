// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2024 Felix Fietkau <nbd@nbd.name>
 */
#ifndef __UNETACL_UCODE_H
#define __UNETACL_UCODE_H

#include <libubox/utils.h>
#include <ucode/types.h>
#include <ucode/lib.h>

extern uc_vm_t *_vm;
struct uc_snoop;
struct ethhdr;

struct packet {
	void *head;
	void *buffer;
	unsigned int len;
};

static inline void *
pkt_peek(struct packet *pkt, unsigned int len)
{
	if (len > pkt->len)
		return NULL;

	return pkt->buffer;
}

static inline void *
pkt_pull(struct packet *pkt, unsigned int len)
{
	void *ret = pkt_peek(pkt, len);

	if (!ret)
		return NULL;

	pkt->buffer += len;
	pkt->len -= len;

	return ret;
}

void uc_snoop_dhcp_recv(struct uc_snoop *s, struct packet *pkt, struct ethhdr *eth);
void uc_snoop_dns_recv(struct uc_snoop *s, struct packet *pkt, struct ethhdr *eth,
		       int af, const void *saddr);
void uc_snoop_recv(struct uc_snoop *s, struct packet *pkt);
void uc_snoop_cb(struct uc_snoop *s, const char *type, uc_value_t *data);
uc_value_t *uc_cache(uc_vm_t *vm, size_t nargs);

void unetacl_cache_init(uc_vm_t *vm);

#endif
