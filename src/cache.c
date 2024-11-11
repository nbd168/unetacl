// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2024 Felix Fietkau <nbd@nbd.name>
 */
#include <libubox/avl.h>
#include "unetacl-ucode.h"

struct cache {
	struct avl_tree timeout_tree;
	struct avl_tree key_tree;
};

struct cache_key {
	size_t len;
	void *data;
};

struct cache_handle {
	struct cache *cache;
	struct list_head entries;
};

struct cache_entry {
	struct avl_node timeout_node;
	struct avl_node key_node;
	struct list_head handle_list;
	struct cache_key key;
	uint32_t value_len;
	char value[];
};

static uc_resource_type_t *cache_type, *handle_type;

static inline uint32_t ptr_to_u32(const void *ptr)
{
	return (uint32_t)(uintptr_t)ptr;
}

static inline const void *u32_to_ptr(uint32_t val)
{
	return (const void *)(uintptr_t)val;
}

static int avl_u32_cmp(const void *k1, const void *k2, void *ptr)
{
	uint32_t v1 = ptr_to_u32(k1);
	uint32_t v2 = ptr_to_u32(k2);

	return v1 - v2;
}

static int avl_key_cmp(const void *k1, const void *k2, void *ptr)
{
	const struct cache_key *ck1 = k1, *ck2 = k2;

	if (ck1->len != ck2->len)
		return ck1->len - ck2->len;

	return memcmp(ck1->data, ck2->data, ck1->len);
}

static void
cache_entry_free(struct cache *c, struct cache_entry *e)
{
	if (e->timeout_node.list.prev)
		avl_delete(&c->timeout_tree, &e->timeout_node);
	avl_delete(&c->key_tree, &e->key_node);
	if (!list_empty(&e->handle_list))
		list_del(&e->handle_list);
	free(e);
}

static bool
uc_cache_reuse_existing(struct cache *c, struct cache_entry *e,
			uc_value_t *timeout, struct cache_handle *h,
			void *value, uint32_t value_len)
{
	uint32_t new_timeout;
	int32_t diff;

	if (value_len != e->value_len ||
	    (value_len && memcmp(value, e->value, value_len))) {
		cache_entry_free(c, e);
		return false;
	}

	if (!timeout && e->timeout_node.list.prev) {
		avl_delete(&c->timeout_tree, &e->timeout_node);
		e->timeout_node.list.prev = NULL;
	}

	if (!e->timeout_node.list.prev)
		return true;

	if (h && !list_empty(&e->handle_list)) {
		list_del(&e->handle_list);
		list_add_tail(&e->handle_list, &h->entries);
	}

	new_timeout = (uint32_t)ucv_int64_get(timeout);
	diff = new_timeout - ptr_to_u32(e->timeout_node.key);
	if (diff > 0) {
		avl_delete(&c->timeout_tree, &e->timeout_node);
		e->timeout_node.key = u32_to_ptr(new_timeout);
		avl_insert(&c->timeout_tree, &e->timeout_node);
	}

	return true;
}

static uc_value_t *uc_cache_add(uc_vm_t *vm, size_t nargs)
{
	struct cache *c = uc_fn_thisval("unetacl.cache");
	uc_value_t *key_arg = uc_fn_arg(0);
	uc_value_t *handle_arg = uc_fn_arg(1);
	uc_value_t *timeout = uc_fn_arg(2);
	uc_value_t *value = uc_fn_arg(3);
	struct cache_handle *h = NULL;
	struct cache_entry *e;
	struct cache_key key = {};
	void *value_ptr = NULL;
	size_t value_len = 0;
	uint32_t new_timeout;

	if (!c || ucv_type(key_arg) != UC_STRING ||
	    (timeout && ucv_type(timeout) != UC_INTEGER) ||
	    (value && ucv_type(value) != UC_STRING))
		return NULL;

	if (value) {
		value_ptr = ucv_string_get(value);
		value_len = ucv_string_length(value);
	}

	if (handle_arg) {
		h = ucv_resource_data(handle_arg, "unetacl.handle");
		if (!h)
			return NULL;
	}

	key.len = ucv_string_length(key_arg);
	key.data = ucv_string_get(key_arg);
	e = avl_find_element(&c->key_tree, &key, e, key_node);
	if (e && uc_cache_reuse_existing(c, e, timeout, h, value_ptr, value_len))
		return ucv_boolean_new(false);

	e = calloc(1, sizeof(*e) + key.len + value_len);
	e->key_node.key = &e->key;
	e->key.len = key.len;
	e->key.data = ((void *)(e + 1)) + value_len;
	e->value_len = value_len;
	if (value_len)
		memcpy(e->value, value_ptr, value_len);
	memcpy(e->key.data, key.data, key.len);
	avl_insert(&c->key_tree, &e->key_node);
	if (timeout) {
		new_timeout = (uint32_t)ucv_int64_get(timeout);
		e->timeout_node.key = u32_to_ptr(new_timeout);
		avl_insert(&c->timeout_tree, &e->timeout_node);
	}

	if (h)
		list_add_tail(&e->handle_list, &h->entries);
	else
		INIT_LIST_HEAD(&e->handle_list);

	return ucv_boolean_new(true);
}

static uc_value_t *uc_cache_get(uc_vm_t *vm, size_t nargs)
{
	struct cache *c = uc_fn_thisval("unetacl.cache");
	uc_value_t *key_arg = uc_fn_arg(0);
	struct cache_key key = {};
	struct cache_entry *e;

	if (!c || ucv_type(key_arg) != UC_STRING)
		return NULL;

	key.len = ucv_string_length(key_arg);
	key.data = ucv_string_get(key_arg);
	e = avl_find_element(&c->key_tree, &key, e, key_node);
	if (!e || !e->value_len)
		return NULL;

	return ucv_string_new_length(e->value, e->value_len);
}

static uc_value_t *uc_cache_delete(uc_vm_t *vm, size_t nargs)
{
	struct cache *c = uc_fn_thisval("unetacl.cache");
	uc_value_t *key_arg = uc_fn_arg(0);
	struct cache_key key = {};
	struct cache_entry *e;

	if (!c || ucv_type(key_arg) != UC_STRING)
		return NULL;

	key.len = ucv_string_length(key_arg);
	key.data = ucv_string_get(key_arg);
	e = avl_find_element(&c->key_tree, &key, e, key_node);
	if (!e)
		return NULL;

	cache_entry_free(c, e);

	return ucv_boolean_new(true);
}

static void uc_cache_gc_entry(struct cache *c, struct cache_entry *e, uc_value_t *arr)
{
	uc_value_t *val;

	val = ucv_string_new_length(e->key.data, e->key.len);
	ucv_array_push(arr, ucv_get(val));
	cache_entry_free(c, e);
}

static uc_value_t *uc_cache_gc(uc_vm_t *vm, size_t nargs)
{
	struct cache *c = uc_fn_thisval("unetacl.cache");
	struct cache_entry *e, *tmp;
	uc_value_t *time = uc_fn_arg(0);
	uc_value_t *ret;
	uint32_t now;

	if (!c || ucv_type(time) != UC_INTEGER)
		return NULL;

	now = (uint32_t)ucv_int64_get(time);
	ret = ucv_array_new(vm);
	avl_for_each_element_safe(&c->timeout_tree, e, timeout_node, tmp) {
		int32_t diff = ptr_to_u32(e->timeout_node.key) - now;

		if (diff > 0)
			break;

		uc_cache_gc_entry(c, e, ret);
	}

	return ret;
}

static void __cache_free(struct cache *c)
{
	struct cache_entry *e;

	while (!avl_is_empty(&c->timeout_tree)) {
		e = avl_first_element(&c->timeout_tree, e, timeout_node);
		cache_entry_free(c, e);
	}
}

static void cache_free(void *ptr)
{
	struct cache *c = ptr;

	if (!c)
		return;

	__cache_free(c);
	free(c);
}

static uc_value_t *uc_cache_free(uc_vm_t *vm, size_t nargs)
{
	struct cache *c = uc_fn_thisval("unetacl.cache");

	if (c)
		__cache_free(c);

	return NULL;
}

static void handle_free(void *ptr)
{
	struct cache_handle *h = ptr;
	struct cache *c;
	struct cache_entry *e;

	if (!h)
		return;

	c = h->cache;
	while (!list_empty(&h->entries)) {
		e = list_first_entry(&h->entries, struct cache_entry, handle_list);
		cache_entry_free(c, e);
	}
	free(h);
}

static uc_value_t *uc_handle_free(uc_vm_t *vm, size_t nargs)
{
	struct cache_handle *h = uc_fn_thisval("unetacl.handle");
	struct cache_entry *e;
	struct cache *c;
	uc_value_t *ret;

	if (!h)
		return NULL;

	c = h->cache;
	ret = ucv_array_new(vm);
	while (!list_empty(&h->entries)) {
		e = list_first_entry(&h->entries, struct cache_entry, handle_list);
		uc_cache_gc_entry(c, e, ret);
	}

	return ret;
}

uc_value_t *uc_cache(uc_vm_t *vm, size_t nargs)
{
	struct cache *c;

	c = calloc(1, sizeof(*c));
	avl_init(&c->timeout_tree, avl_u32_cmp, true, NULL);
	avl_init(&c->key_tree, avl_key_cmp, false, NULL);

	return uc_resource_new(cache_type, c);
}

static uc_value_t *uc_cache_handle(uc_vm_t *vm, size_t nargs)
{
	struct cache *c = uc_fn_thisval("unetacl.cache");
	struct cache_handle *h;

	if (!c)
		return NULL;

	h = calloc(1, sizeof(*h));
	h->cache = c;
	INIT_LIST_HEAD(&h->entries);

	return uc_resource_new(handle_type, h);
}

static const uc_function_list_t cache_fns[] = {
	{ "handle", uc_cache_handle },
	{ "add", uc_cache_add },
	{ "get", uc_cache_get },
	{ "delete", uc_cache_delete },
	{ "gc", uc_cache_gc },
	{ "free", uc_cache_free },
};

static const uc_function_list_t handle_fns[] = {
	{ "free", uc_handle_free },
};

void unetacl_cache_init(uc_vm_t *vm)
{
	cache_type = uc_type_declare(vm, "unetacl.cache", cache_fns, cache_free);
	handle_type = uc_type_declare(vm, "unetacl.handle", handle_fns, handle_free);
}
