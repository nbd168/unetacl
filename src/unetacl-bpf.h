// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024 Felix Fietkau <nbd@nbd.name>
 */
#ifndef __BPF_UNETACL_H
#define __BPF_UNETACL_H

struct unetacl_bpf_config {
	uint32_t snoop_ifindex;
};

struct unetacl_bpf_network_key {
	uint32_t prefix_len;
	uint32_t data[4];
};

/* trie, key: struct unetacl_bpf_network_key */
struct unetacl_bpf_network {
	uint32_t id;
};

struct unetacl_bpf_acct {
	uint64_t packets, bytes;
};

#define UNETACL_ACTION_FWMARK		(1 << 0)
#define UNETACL_ACTION_REDIRECT		(1 << 1)
#define UNETACL_ACTION_REDIRECT_VLAN    (1 << 2)
#define UNETACL_ACTION_SET_DEST_MAC	(1 << 3)
#define UNETACL_ACTION_DROP		(1 << 4)

#define UNETACL_NETWORK_ID_DEFAULT	0
#define UNETACL_NETWORK_ID_DNS		0xffff

struct unetacl_bpf_policy_key {
	uint32_t prefix_len;
	uint16_t client_id;
	uint16_t network_id;
};

struct unetacl_bpf_action {
	uint16_t flags;
	uint8_t dest_mac[6];

	uint32_t fwmark_val;
	uint32_t fwmark_mask;

	uint32_t redirect_ifindex;
	uint16_t redirect_vlan;
	uint16_t redirect_vlan_proto;
};

/* trie, key: struct unetacl_bpf_policy_key */
struct unetacl_bpf_policy {
	struct unetacl_bpf_acct rx, tx;
	struct unetacl_bpf_action action;
};

struct unetacl_bpf_client_key {
	uint8_t addr[6];
};

/* hashmap: key: struct unetacl_bpf_client_key */
struct unetacl_bpf_client {
	uint16_t id;
	uint16_t flags;

	uint8_t ip4mask;
	uint8_t _pad;

	uint8_t gateway[6];

	uint32_t ip4addr;
	uint32_t ip6addr[4];
};

#define UNETACL_CLIENT_FORCE_GATEWAY	(1 << 0)
#define UNETACL_CLIENT_FILTER_LOCAL	(1 << 1)
#define UNETACL_CLIENT_FILTER_IPADDR	(1 << 2)
#define UNETACL_CLIENT_FILTER_MULTICAST	(1 << 3)

#endif
