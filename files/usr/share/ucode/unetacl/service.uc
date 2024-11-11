// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2024 Felix Fietkau <nbd@nbd.name>
 */
'use strict';
import * as ubus from "ubus";
import * as uloop from "uloop";
import * as core from "unetacl.core";
import { readfile, writefile } from "fs";

function config_init(obj, config)
{
	config.config ??= {};
	config.networks ??= {};
	config.groups ??= {};
	config.clients ??= {};
	config.default_policy ??= { drop: true };
	obj.config = config;
}

function load_json(file)
{
	if (!file)
		return;

	let data = readfile(file);
	if (!data)
		return;

	return json(data);
}

export function config_set(obj, file)
{
	obj.config_file = file;

	return reload(obj);
};

function merge_arrays(...values)
{
	values = filter(values, (val) => length(val) > 0);
	if (!length(values))
		return [];
	if (length(values) == 1)
		return values[0];

	let ret = [];
	for (let val_arr in values)
		for (let val in val_arr)
			if (index(ret, val) < 0)
				push(ret, val);

	return ret;
}

function merge_objects(...values)
{
	values = filter(values, (val) => length(val) > 0);
	if (!length(values))
		return {};

	let ret = {};
	for (let val in values)
		ret = { ...ret, ...val };

	return ret;
}

function group_field_data(field, groups, data)
{
	return [ ...map(groups, (group) => group[field]), data[field] ];
}

function merge_group_array(field, groups, data)
{
	return merge_arrays(...group_field_data(field, groups, data));
}

function merge_group_object(field, groups, data)
{
	return merge_objects(...group_field_data(field, groups, data));
}

export function client_merge_data(obj, data, field)
{
	let orig_data = data;
	let groups = data.groups;

	data ??= {};
	if (!obj.config || !obj.config.groups || !groups)
		groups = [];

	groups = map(groups, (group) => (obj.config.groups[group] ?? {}));
	groups = filter(groups, (v) => !!v);

	data = merge_objects(...groups, data);
	delete data.groups;
	data.flags = merge_group_array("flags", groups, data);
	data.policy = merge_group_object("policy", groups, data);
	data.default_policy ??= {};
	if (field)
		data[field] = orig_data;

	return data;
};

function client_default_data(obj, macaddr)
{
	macaddr = lc(macaddr);
	let data = obj.config.clients[macaddr] ??
		   obj.config.clients.default ??
		   {};
	return data;
}

export function client_defaults(obj, macaddr)
{
	let data = client_default_data(obj, macaddr);
	return client_merge_data(obj, data, "default_data");
};

function __client_set_data(obj, macaddr, data, field)
{
	delete data.data;
	obj.client_set(macaddr, client_merge_data(obj, data, field));
}

function client_update_data(obj, client, macaddr)
{
	let data = client.data;
	let field;

	if (!data) {
		data = client_default_data(obj, macaddr);
		field = "default_data";
	}

	__client_set_data(obj, macaddr, data, field);
}

export function client_set_data(obj, macaddr, data)
{
	__client_set_data(obj, macaddr, data, "data");
};

export function reload(obj)
{
	let data = load_json(obj.config_file);
	if (!data)
		return ubus.STATUS_INVALID_ARGUMENT;

	config_init(obj, data);
	obj.network_update(data.networks);
	obj.default_policy_set(data.default_policy);

	for (let addr, cl in obj.clients)
		client_update_data(obj, cl, addr);

	return 0;
};

function client_state(cl)
{
	if (!cl)
		return;

	cl = { ...cl };
	delete cl.id;
	delete cl.policy;
	delete cl.default_policy;
	delete cl.macaddr;
	delete cl.flags;

	return cl;
}

function save_state(obj)
{
	if (!obj.state_file || !obj.config.global.save_client_state)
		return;

	let clients = {};

	for (let macaddr, cl in obj.clients)
		if (cl.data)
			clients[macaddr] = client_state(cl);

	writefile(obj.state_file, sprintf("%.J", { clients }));
}

export function client_update(obj, macaddr)
{
	save_state(obj);

	if (!obj.ubus_obj)
		return;

	let state = client_state(obj.clients[macaddr]);
	if (!state)
		return;

	state.macaddr = macaddr;
	obj.ubus_obj.notify("client_update", state);
};

function load_clients(obj, clients)
{
	if (!clients)
		return;

	for (let macaddr, data in clients) {
		client_set_data(obj, macaddr, data.data);
		obj.client_set(macaddr, data);
	}
}

function load_state(obj)
{
	if (!obj.config.global.save_client_state)
		return;

	let state = load_json(obj.state_file);
	if (!state)
		return;

	load_clients(obj, state.clients);
}

function client_get(obj, addr, cl)
{
	if (!cl)
		return;

	let ret = obj.client_get(addr);
	if (!ret)
		return;

	let config = cl.data ?? cl.default_data;
	if (config)
		ret.config = config;

	return ret;
}

function obj_wrap(obj, func)
{
	return (req) => {
		try {
			return func(obj, req);
		} catch (e) {
			warn(`Exception: ${e}\n${e.stacktrace[0].context}`);
			return libubus.STATUS_UNKNOWN_ERROR;
		}
	};
}

function ubus_object_methods(obj) {
	return {
		reload: {
			args: {},
			call: obj_wrap(obj, function(obj, req) {
				return reload(obj);
			})
		},

		config_set: {
			args: {
				file: "",
			},
			call: obj_wrap(obj, function(obj, req) {
				let file = req.args.file;
				if (!file)
					return ubus.STATUS_INVALID_ARGUMENT;

				return config_set(obj, file);
			})
		},

		network_add_ip: {
			args: {
				name: "",
				addr: [],
				ttl: 0
			},
			call: obj_wrap(obj, function(obj, req) {
				let name = req.args.name;
				let addr = req.args.addr;
				let timeout;

				if (!name || !addr)
					return ubus.STATUS_INVALID_ARGUMENT;

				if (req.args.ttl)
					timeout = time() + req.args.ttl;

				if (!obj.network_add_addrs(name, addr, timeout))
					return ubus.STATUS_INVALID_ARGUMENT;

				return 0;
			})
		},

		network_delete_ip: {
			args: {
				name: "",
				addr: [],
			},
			call: obj_wrap(obj, function(obj, req) {
				let name = req.args.name;
				let addr = req.args.addr;

				if (!name || !addr)
					return ubus.STATUS_INVALID_ARGUMENT;

				obj.network_delete_addrs(name, addr);
				return 0;
			})
		},

		client_get: {
			args: {
				macaddr: "",
			},
			call: obj_wrap(obj, function(obj, req) {
				let macaddr = req.args.macaddr;

				if (macaddr) {
					let cl = obj.clients[macaddr];
					let ret = client_get(obj, macaddr, cl);
					if (!ret)
						return ubus.STATUS_NOT_FOUND;

					return ret;
				}

				let ret = {};
				for (let addr, cl in obj.clients) {
					let cur = client_get(obj, addr, cl);
					if (!cur)
						continue;

					ret[addr] = cur;
				}
				return ret;
			})
		},

		client_set: {
			args: {
				macaddr: "",
				groups: [],
				flags: [],
				policy: {},
				default_policy: {},
			},
			call: obj_wrap(obj, function(obj, req) {
				let data = { ...req.args };
				let macaddr = data.macaddr;
				delete data.macaddr;

				if (!macaddr)
					return ubus.STATUS_INVALID_ARGUMENT;

				if (length(filter(data.groups, (v) => type(v) != "string")) > 0)
					return ubus.STATUS_INVALID_ARGUMENT;

				client_set_data(obj, macaddr, data);
				return 0;
			})
		},

		client_add_groups: {
			args: {
				macaddr: "",
				groups: [],
			},
			call: obj_wrap(obj, function(obj, req) {
				let macaddr = lc(req.args.macaddr);
				let groups = req.args.groups;

				if (!macaddr || !groups)
					return ubus.STATUS_INVALID_ARGUMENT;

				let cl = obj.clients[macaddr];
				if (!cl)
					return ubus.STATUS_NOT_FOUND;

				let data = cl.data ?? {};
				data.groups ??= [];
				for (let group in groups)
					if (index(data.groups, group) < 0)
						push(data.groups, group);

				client_set_data(obj, macaddr, data);
				return 0;
			})
		},

		netdev_add: {
			args: {
				name: "",
			},
			call: obj_wrap(obj, function(obj, req) {
				let name = req.args.name;
				if (!name)
					return ubus.STATUS_INVALID_ARGUMENT;

				obj.netdev_attach(name);
				return 0;
			})
		},

		netdev_remove: {
			args: {
				name: "",
			},
			call: obj_wrap(obj, function(obj, req) {
				let name = req.args.name;
				if (!name)
					return ubus.STATUS_INVALID_ARGUMENT;

				obj.netdev_detach(name);
				return 0;
			})
		},
	};
};

export function init(config, ubus)
{
	config ??= {};
	config.cb ??= { ...core.default_cb };
	config.cb.client_defaults ??= client_defaults;
	config.cb.client_update ??= client_update;

	let obj = core.init(config);
	let object_name = config.object_name ?? "unetacl";
	obj.ubus = ubus;
	obj.ubus_obj = ubus.publish(object_name, ubus_object_methods(obj));

	config_init(obj, {});
	reload(obj);
	load_state(obj);

	return obj;
};
