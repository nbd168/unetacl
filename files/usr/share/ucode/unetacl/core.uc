// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2024 Felix Fietkau <nbd@nbd.name>
 */
'use strict';
import * as bpf from "unetacl.bpf";
import * as utils from "unetacl.utils";
import * as uloop from "uloop";
import * as rtnl from "rtnl";

const vlist_proto = {
	update: function(values, ...args) {
		let data = this.data;
		let cb = this.cb;
		let seq = { };
		let new_data = {};
		let old_data = {};

		this.data = new_data;

		if (type(values) == "object") {
			for (let key in values) {
				old_data[key] = data[key];
				new_data[key] = values[key];
				delete data[key];
			}
		} else {
			for (let val in values) {
				let cur_key = val[0];
				let cur_obj = val[1];

				old_data[cur_key] = data[cur_key];
				new_data[cur_key] = val[1];
				delete data[cur_key];
			}
		}

		for (let key in data) {
			cb(key, null, data[key], ...args);
			delete data[key];
		}
		for (let key in new_data)
			cb(key, new_data[key], old_data[key], ...args);
	}
};

function vlist_new(cb, data)
{
	data ??= {};
	return proto({ cb, data }, vlist_proto);
}

function is_equal(val1, val2) {
	let t1 = type(val1);

	if (t1 != type(val2))
		return false;

	if (t1 == "array") {
		if (length(val1) != length(val2))
			return false;

		for (let i = 0; i < length(val1); i++)
			if (!is_equal(val1[i], val2[i]))
				return false;

		return true;
	} else if (t1 == "object") {
		for (let key in val1)
			if (!is_equal(val1[key], val2[key]))
				return false;
		for (let key in val2)
			if (val1[key] == null)
				return false;
		return true;
	} else {
		return val1 == val2;
	}
}

function id_alloc(mask)
{
	let idx = 0, ofs = 0;

	while (mask[idx] == 0xffffffff)
		idx++;

	let val = 1;
	while (mask[idx] & val) {
		val <<= 1;
		ofs++;
	}
	mask[idx] |= val;
	return idx * 32 + ofs + 1;
}

function id_free(mask, idx)
{
	idx--;
	mask[idx / 32] &= ~(1 << (idx % 32));
}

function array_to_map(arr)
{
	let map = {};
	for (let key in arr)
		map[key] = true;
	return map;
}

function resolve_network(core, name, val)
{
	if (!val)
		return -1;

	if (name == "#dns")
		return 0xffff;
	if (name == "#default")
		return 0;

	let net = core.networks.data[name];
	if (net)
		val.id = net.id;
	else
		val.id = -1;

	return val.id;
}

function client_policy_update(key, new_val, old_val, core, client)
{
	let prev_id = old_val ? old_val.id : -1;
	let new_id = resolve_network(core, key, new_val);

	if (new_id == prev_id) {
		if (new_id > 0 && is_equal(new_val.action, old_val.action))
			return;
	} else if (prev_id > 0) {
		core.bpf.policy_delete(client.id, prev_id);
	}

	if (new_id > 0)
		core.bpf.policy_set(client.id, new_id, new_val.action);
}

function network_host_add_addr(core, network, host, addr, timeout)
{
	let af = (index(addr, ":") >= 0) ? 6 : 4;

	let handle = host.addr;
	if (!handle)
		host.addr = handle = core.addr_cache.handle();

	let key = core.bpf.network_key(af, addr);
	if (core.addr_cache.add(key, handle, timeout))
		core.bpf.network_set(key, network.id);
}

function network_hosts_delete(core, list)
{
	for (let addr in list)
		core.bpf.network_delete(addr);
}

function core_network_gc()
{
	let now = time();
	this.icmp6_cache.gc(now);
	network_hosts_delete(this, this.addr_cache.gc(now));
}

function network_host_update_cb(key, new_val, old_val, core, network)
{
	if (new_val) {
		if (old_val)
			new_val.addr = old_val.addr;
		return;
	}

	let handle = old_val.addr;
	if (handle)
		network_hosts_delete(core, handle.free());
}

function network_addr_key(core, addr)
{
	let af = (index(addr, ":") >= 0) ? 6 : 4;
	addr = split(addr, "/");
	return core.bpf.network_key(af, addr[0], addr[1]);
}

function network_addr_add(core, network, addr, timeout)
{
	let handle = network.addr_handle;
	if (!handle)
		network.addr_handle = handle = core.addr_cache.handle();

	let key = network_addr_key(core, addr);
	core.addr_cache.add(key, handle, timeout);
	core.bpf.network_set(key, network.id);
}

function network_addr_delete(core, network, addr)
{
	let key = network_addr_key(core, addr);
	core.addr_cache.delete(key);
	core.bpf.network_delete(key);
}

function network_addr_update_cb(key, new_val, old_val, core, network)
{
	if (new_val && old_val)
		return;

	if (new_val)
		network_addr_add(core, network, key);
	else
		network_addr_delete(core, network, key);
}

function hosts_obj(list)
{
	let hosts = {};
	for (let host in list)
		hosts[host] = {};
	return hosts;
}

function network_update_cb(key, new_val, old_val, core)
{
	if (new_val) {
		let hosts = hosts_obj(new_val.hosts);
		let addrs = array_to_map(new_val.addr);

		if (old_val) {
			new_val.id = old_val.id;
			new_val.hosts = old_val.hosts;
			new_val.addr = old_val.addr;
			new_val.addr_handle = old_val.addr_handle;
		} else {
			new_val.id = id_alloc(core.network_ids);
			new_val.hosts = vlist_new(network_host_update_cb);
			new_val.addr = vlist_new(network_addr_update_cb);
		}

		new_val.hosts.update(hosts, core, new_val);
		new_val.addr.update(addrs, core, new_val);

		if (old_val)
			return;
	} else {
		id_free(core.network_ids, old_val.id);
		old_val.hosts.update({}, core, old_val);
		let handle = old_val.addr_handle;
		if (handle)
			network_hosts_delete(core, handle.free());
	}

	for (let macaddr, cl in core.clients) {
		let net = cl.policy.data[key];
		if (!key)
			continue;

		client_policy_update(key, net, net, core, cl);
	}
}

function get_client(core, macaddr)
{
	macaddr = lc(macaddr);
	let cl = core.clients[macaddr];
	if (!cl) {
		let id = id_alloc(core.client_ids);
		cl = {
			id,
			macaddr,
			policy: vlist_new(client_policy_update),
		};
		core.clients[macaddr] = cl;
	}

	return cl;
}

function core_network_add_addrs(name, addrs, timeout)
{
	let network = this.networks.data[name];
	if (!net)
		return;

	for (let addr in addrs)
		network_addr_add(this, network, addr, timeout);

	return true;
}

function core_network_delete_addrs(name, addrs)
{
	let network = this.networks.data[name];
	if (!net)
		return;

	for (let addr in addrs)
		network_addr_delete(this, network, addr);
}

function core_network_set_host_addrs(hosts, addrs, ttl)
{
	let timeout = time() + ttl;
	for (let name, net in this.networks.data) {
		for (let host_match, host_data in net.hosts.data) {
			for (let host in hosts) {
				let match = wildcard(host, host_match, true);
				if (match) {
					for (let addr in addrs)
						network_host_add_addr(this, net, host_data, addr, timeout);
					break;
				}
			}
		}
	}
}

function core_default_policy_set(val)
{
	this.bpf.policy_set(0, 0, val);
}

function core_client_set(macaddr, data)
{
	macaddr = lc(macaddr);
	if (!this.clients[macaddr] && this.cb.client_defaults)
		data = { ...this.cb.client_defaults(this, macaddr), ...data };

	let cl = get_client(this, macaddr);
	let bpf_update = false;

	for (let name, val in data) {
		switch (name) {
		case "ip4addr":
		case "ip6addr":
		case "flags":
			if (cl[name] != val)
				bpf_update = true;
			break;
		case "default_policy":
			val ??= {};
			this.bpf.policy_set(cl.id, 0, val);
			break;
		case "policy":
			let policy = {};
			for (let name, net in val)
				policy[name] = { action: net };

			cl.policy.update(policy, this, cl);
			continue;
		}

		if (is_equal(cl[name], val))
			continue;

		if (val == null)
			delete cl[name];
		else
			cl[name] = val;
	}

	if (bpf_update)
		this.bpf.client_set(macaddr, cl);
	if (this.cb.client_update)
		this.cb.client_update(this, macaddr);

	return cl;
}

function core_client_get(macaddr)
{
	if (macaddr == null) {
		let ret = {};
		for (let client in this.clients)
			ret[client] = this.client_get(client);
		return ret;
	}

	macaddr = lc(macaddr);
	let cl = this.clients[macaddr];
	if (!cl)
		return;

	let ret = this.bpf.client_get(macaddr);
	if (!ret)
		return;

	let networks = {};
	for (let net in cl.policy.data) {
		let netdata = this.networks.data[net];
		if (!netdata || !netdata.id)
			continue;

		networks[net] = this.bpf.policy_get(cl.id, netdata.id);
	}
	ret.networks = networks;
	ret.default = this.bpf.policy_get(cl.id, 0);

	return ret;
}

function core_client_delete(macaddr)
{
	macaddr = lc(macaddr);
	let cl = this.clients[macaddr];
	if (!cl)
		return;

	delete this.clients[macaddr];
	id_free(core.client_ids, cl.id);
	cl.policy.update({}, this, cl);
	this.bpf.policy_delete(cl.id, 0);
	this.bpf.client_delete(macaddr);
}

function core_handle_dns(core, data)
{
	let hosts = [ data.q ], addrs = [], ttl;

	for (let record in data.a) {
		switch (record[0]) {
		case "cname":
			push(hosts, record[1]);
			break;
		case "a":
		case "aaaa":
			push(addrs, record[1]);
			ttl = record[2];
			break;
		}
	}

	if (length(addrs) > 0)
		core.network_set_host_addrs(hosts, addrs, ttl);
}

function lookup_hwaddr(ipaddr)
{
	if (!ipaddr)
		return;

	let neigh = rtnl.request(
		rtnl.const.RTM_GETNEIGH,
		rtnl.const.NLM_F_DUMP,
		{ family: 2 });
	for (let result in neigh) {
		if (result.dst == ipaddr)
			return result.lladdr;
	}
}

export const default_cb = {
	dhcp: function(core, data) {
		let macaddr = lc(data.macaddr);
		core.client_set(macaddr, {
			ip4addr: data.ipaddr,
			ip4mask: data.mask,
			ip6addr: core.icmp6_cache.get(macaddr),
			gateway: lookup_hwaddr(data.gateway),
		});
	},
	icmpv6: function(core, data) {
		let macaddr = lc(data.macaddr);
		let timeout = time() + 30;
		core.icmp6_cache.add(macaddr, null, timeout, data.ip6addr);
		if (!core.clients[macaddr])
			return;

		core.client_set(macaddr, {
			ip6addr: data.ip6addr,
		});
	},
	dns: core_handle_dns,
};

function snoop_cb(type, data) {
	let core = this.core;
	let config = core.config;
	try {
		let cb = core.cb[type];
		if (cb)
			cb(core, data);
	} catch (e) {
		warn(`Exception: ${e}\n${e.stacktrace[0].context}`);
	}
}

function core_close() {
	this.gc_interval.cancel();
	this.icmp6_cache.free();
	this.addr_cache.free();
	delete this.bpf.core;
	delete this.bpf.clients;
	delete this.bpf.networks;
	this.bpf.close();
}

const core_proto = {
	default_policy_set: core_default_policy_set,
	client_set: core_client_set,
	client_get: core_client_get,
	client_delete: core_client_delete,
	network_add_addrs: core_network_add_addrs,
	network_delete_addrs: core_network_delete_addrs,
	network_set_host_addrs: core_network_set_host_addrs,
	network_update: function(networks) {
		this.networks.update(networks, this);
	},
	netdev_attach: function(netdev) {
		this.bpf.netdev_attach(netdev);
	},
	netdev_detach: function(netdev) {
		this.bpf.netdev_detach(netdev);
	},
	gc: core_network_gc,
	close: core_close,
};

export function init(config)
{
	config ??= {};
	let obj = {
		...config,
		cb: config.cb ?? default_cb,
		clients: {},
		networks: vlist_new(network_update_cb),
		addr_cache: utils.cache(),
		icmp6_cache: utils.cache(),

		client_ids: [],
		network_ids: [],
	};

	obj.bpf = bpf.init(snoop_cb, config.name);
	if (!obj.bpf)
		return;

	obj.bpf.core = obj;
	obj.gc_interval = uloop.interval((config.gc_interval ?? 5) * 1000, () => {
		obj.gc();
	});

	return proto(obj, core_proto);
};
