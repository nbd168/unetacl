// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2024 Felix Fietkau <nbd@nbd.name>
 */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <unistd.h>
#include <errno.h>

#include <libubox/uloop.h>
#include <ucode/module.h>
#include <ucode/lib.h>
#include "unetacl-ucode.h"

static uc_resource_type_t *snoop_type;
static uc_value_t *registry;
uc_vm_t *_vm;

struct uc_snoop {
	struct uloop_fd fd;
	unsigned int idx;
	uc_value_t *obj;
};

static uc_value_t *
uc_inet_pton(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *fam = uc_fn_arg(0);
	uc_value_t *addrstr = uc_fn_arg(1);
	union {
		struct in_addr in;
		struct in6_addr in6;
	} addr;
	size_t len = sizeof(addr.in);
	int af;

	if (ucv_type(addrstr) != UC_STRING ||
		ucv_type(fam) != UC_INTEGER)
		return NULL;

	af = ucv_int64_get(fam);
	if (af == 4) {
		af = AF_INET;
		len = sizeof(struct in_addr);
	} else if (af == 6) {
		af = AF_INET6;
		len = sizeof(struct in6_addr);
	} else {
		return NULL;
	}

	if (inet_pton(af, ucv_string_get(addrstr), &addr) != 1)
		return NULL;

	return ucv_string_new_length((const void *)&addr, len);
}


static uc_value_t *
uc_inet_ntop(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *fam = uc_fn_arg(0);
	uc_value_t *addrstr = uc_fn_arg(1);
	char buf[INET6_ADDRSTRLEN];
	size_t len;
	int af;

	if (ucv_type(addrstr) != UC_STRING ||
		ucv_type(fam) != UC_INTEGER)
		return NULL;

	af = ucv_int64_get(fam);
	if (af == 4) {
		af = AF_INET;
		len = sizeof(struct in_addr);
	} else if (af == 6) {
		af = AF_INET6;
		len = sizeof(struct in6_addr);
	} else {
		return NULL;
	}

	if (ucv_string_length(addrstr) != len)
		return NULL;

	if (!inet_ntop(af, ucv_string_get(addrstr), buf, sizeof(buf)))
		return NULL;

	return ucv_string_new(buf);
}

void uc_snoop_cb(struct uc_snoop *s, const char *type, uc_value_t *data)
{
	uc_vm_t *vm = _vm;
	uc_value_t *cb;

	cb = ucv_object_get(s->obj, "snoop_cb", NULL);
	if (!ucv_is_callable(cb))
		return;

	uc_value_push(ucv_get(s->obj));
	uc_value_push(ucv_get(cb));
	uc_value_push(ucv_get(ucv_string_new(type)));
	uc_value_push(ucv_get(data));

	if (uc_vm_call(vm, true, 2) != EXCEPTION_NONE)
		ucv_put(uc_vm_stack_pop(vm));
}

static void uc_snoop_socket_cb(struct uloop_fd *fd, unsigned int events)
{
	struct uc_snoop *s = container_of(fd, struct uc_snoop, fd);
	static uint8_t buf[8192];
	struct packet pkt = {
		.head = buf,
		.buffer = buf,
	};
	ssize_t len;

retry:
	len = recvfrom(fd->fd, buf, sizeof(buf), MSG_DONTWAIT, NULL, NULL);
	if (len < 0) {
		if (errno == EINTR)
			goto retry;
		return;
	}

	if (!len)
		return;

	pkt.len = len;
	uc_snoop_recv(s, &pkt);
}

static void snoop_free(void *ptr)
{
	struct uc_snoop *s = ptr;

	if (!s)
		return;

	ucv_put(s->obj);
	uloop_fd_delete(&s->fd);
	close(s->fd.fd);
	free(s);
}

static int
uc_snoop_open_socket(const char *name)
{
	struct sockaddr_ll sll = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_ALL),
		.sll_ifindex = if_nametoindex(name),
	};
	int sock;

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0)
		return -1;

	if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0 ||
	    setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name)) < 0) {
		close(sock);
		return -1;
	}

	fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK);

	return sock;
}

static uc_value_t *
uc_snoop_close(uc_vm_t *vm, size_t nargs)
{
	void **ptr = uc_fn_this("unetacl.snoop");

	snoop_free(*ptr);
	*ptr = NULL;

	return NULL;
}

static uc_value_t *
uc_snoop(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *ifname = uc_fn_arg(0);
	uc_value_t *obj = uc_fn_arg(1);
	struct uc_snoop *s;
	size_t len;
	int fd;

	if (ucv_type(ifname) != UC_STRING)
		return NULL;

	fd = uc_snoop_open_socket(ucv_string_get(ifname));
	if (fd < 0)
		return NULL;

	s = calloc(1, sizeof(*s));
	s->fd.fd = fd;
	s->fd.cb = uc_snoop_socket_cb;
	s->obj = ucv_get(obj);
	uloop_fd_add(&s->fd, ULOOP_READ);

	len = ucv_array_length(registry);
	for (size_t i = 0; i < len + 1; i++) {
		if (i < len && ucv_array_get(registry, i))
			continue;

		ucv_array_set(registry, i, obj);
		s->idx = i;

		break;
	}

	return uc_resource_new(snoop_type, s);
}

static const uc_function_list_t snoop_fns[] = {
	{ "close", uc_snoop_close },
};

static const uc_function_list_t global_fns[] = {
	{ "inet_pton", uc_inet_pton },
	{ "inet_ntop", uc_inet_ntop },
	{ "snoop", uc_snoop },
	{ "cache", uc_cache },
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	_vm = vm;

	uc_function_list_register(scope, global_fns);

	registry = ucv_array_new(vm);
	uc_vm_registry_set(vm, "unetacl.registry", registry);

	snoop_type = uc_type_declare(vm, "unetacl.snoop", snoop_fns, snoop_free);

	unetacl_cache_init(vm);
}
