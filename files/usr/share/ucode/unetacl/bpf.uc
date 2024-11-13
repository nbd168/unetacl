// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2024 Felix Fietkau <nbd@nbd.name>
 */
'use strict';

import { readfile } from "fs";
let bpf = require("bpf");
let struct = require("struct");
let rtnl = require("rtnl");
let utils = require("unetacl.utils");
let rtc = rtnl.const;

let client_struct = struct.new("HHBB");
let mac_struct = struct.new("BBBBBB");
let u32_struct = struct.new("I");
let policy_key_struct = struct.new("IHH");
let action_struct = struct.new("HBBBBBBIIIH");
let vlan_proto_struct = struct.new(">H");
let acct_struct = struct.new("qq");

const UNETACL_ACTION_FWMARK =		1 << 0;
const UNETACL_ACTION_REDIRECT =		1 << 1;
const UNETACL_ACTION_REDIRECT_VLAN =	1 << 2;
const UNETACL_ACTION_SET_DEST_MAC =	1 << 3;
const UNETACL_ACTION_DROP =		1 << 4;

export const client_flags = {
	force_gateway: (1 << 0),
	filter_local: (1 << 1),
	filter_ipaddr: (1 << 2),
	filter_multicast: (1 << 3),
};

function netdev_ifindex(name)
{
	return +readfile(`/sys/class/net/${name}/ifindex`);
}

function mac_parse(mac)
{
	mac = map(split(mac, ":"), hex);
	return mac_struct.pack(...mac);
}

function mac_array_string(mac)
{
	return sprintf("%02x:%02x:%02x:%02x:%02x:%02x", ...mac);
}

function mac_string(mac)
{
	return mac_array_string(mac_struct.unpack(mac));
}

function __map_set(map, name, key, val)
{
	if (map.set(key, val) != null)
		return true;

	warn(`Error adding ${name} element: ${bpf.error()}\n`);
}

function map_set(obj, name, key, val)
{
	return __map_set(obj.maps[name], name, key, val);
}

function client_set(mac, data)
{
	let id = data.id ?? 0;
	let flags = 0;
	for (let flag in data.flags) {
		let cur = client_flags[flag];
		if (!cur)
			continue;
		flags |= cur;
	}
	let ip4addr = data.ip4addr ?? "0.0.0.0";
	let ip4mask = data.ip4mask ?? 32;
	let ip6addr = data.ip6addr ?? "::0";
	let gateway = data.gateway ?? "00:00:00:00:00:00";

	let key = mac_parse(mac);
	let val = client_struct.pack(id, flags, ip4mask, 0) +
		  mac_parse(gateway) +
		  utils.inet_pton(4, ip4addr) +
		  utils.inet_pton(6, ip6addr);

	return map_set(this, "client", key, val);
}

function client_get(mac)
{
	let val = this.maps.client.get(mac_parse(mac));
	if (!val)
		return null;

	let data = client_struct.unpack(substr(val, 0, 12));
	let flags = [];
	for (let name, val in client_flags)
		if (data[1] & val)
			push(flags, name);
	return {
		id: data[0],
		flags,
		ip4mask: data[2],
		gateway: mac_string(substr(val, 6, 6)),
		ip4addr: utils.inet_ntop(4, substr(val, 12, 4)),
		ip6addr: utils.inet_ntop(6, substr(val, 16, 16)),
	};
}

function client_delete(mac)
{
	return this.maps.client.delete(mac_parse(mac));
}

function network_map_name(key)
{
	if (length(key) > 8)
		return "network6";
	return "network4";
}

function network_map(obj, key)
{
	return obj.maps[network_map_name(key)];
}

function network_key(af, addr, prefix_len)
{
	if (prefix_len == null)
		prefix_len = (af == 6) ? 128 : 32;

	return u32_struct.pack(prefix_len) + utils.inet_pton(af, addr);
}

function network_set(key, id)
{
	let map_name = network_map_name(key);
	return __map_set(this.maps[map_name], map_name, key, u32_struct.pack(id));
}

function network_get(key)
{
	let val = network_map(this, key).get(key);
	if (!val)
		return;

	return u32_struct.unpack(val);
}

function network_delete(af, key)
{
	return network_map(this, key).delete(key);
}

function policy_key(client_id, network_id)
{
	let prefix_len = 32;
	if (!client_id)
		prefix_len = 0;
	else if (!network_id)
		prefix_len = 16;

	return policy_key_struct.pack(prefix_len, +client_id, +network_id);
}

function policy_get(client_id, network_id)
{
	let key = policy_key(client_id, network_id);
	let val = this.maps.policy.get(key);
	if (!val)
		return;

	let rx = acct_struct.unpack(substr(val, 0, 16));
	let tx = acct_struct.unpack(substr(val, 16, 16));
	let ret = {
		ul_packets: rx[0],
		ul_bytes: rx[1],
		dl_packets: tx[0],
		dl_bytes: tx[1],
	};

	val = substr(val, 32);
	let data = action_struct.unpack(substr(val, 0, 22));
	let flags = data[0];

	if (flags & UNETACL_ACTION_SET_DEST_MAC)
		ret.dest_mac = mac_array_string(slice(data, 1, 7));
	if (flags & UNETACL_ACTION_DROP)
		ret.drop = true;
	if (flags & UNETACL_ACTION_FWMARK) {
		ret.fwmark_val = data[7];
		ret.fwmark_mask = data[8];
	}
	if (flags & UNETACL_ACTION_REDIRECT)
		ret.ifindex = data[9];
	if (flags & UNETACL_ACTION_REDIRECT_VLAN) {
		ret.vlan = data[10];
		ret.vlan_proto = vlan_proto_struct.unpack(substr(val, 22))[0];
	}

	return ret;
}

function policy_set(client_id, network_id, action)
{
	let flags = 0;

	let mac = action.dest_mac;
	if (mac) {
		mac = map(split(mac, ":"), hex);
		if (length(mac) == 6)
			flags |= UNETACL_ACTION_SET_DEST_MAC;
		else
			flags = UNETACL_ACTION_DROP;
	}
	if (!mac) {
		mac = [ 0, 0, 0, 0, 0, 0 ];
	}

	let fwmark_val = action.fwmark_val ?? 0;
	let fwmark_mask = action.fwmark_mask ?? 0;
	if (fwmark_mask)
		flags |= UNETACL_ACTION_FWMARK;

	let ifindex = action.ifindex ?? 0;
	let vlan = action.vlan ?? 0;
	let vlan_proto = action.vlan_proto ?? 0x8100;
	if (ifindex) {
		flags |= UNETACL_ACTION_REDIRECT;
		if (vlan)
			flags |= UNETACL_ACTION_REDIRECT_VLAN;
	}

	if (action.drop)
		flags = UNETACL_ACTION_DROP;

	let data = [ flags,  ...mac, fwmark_val, fwmark_mask, ifindex, vlan ];
	let acct = acct_struct.pack(0, 0);

	let key = policy_key(client_id, network_id);
	let val = acct + acct + action_struct.pack(...data) + vlan_proto_struct.pack(vlan_proto);

	return map_set(this, "policy", key, val);
}

function policy_delete(client_id, network_id)
{
	let key = policy_key(client_id, network_id);
	return this.maps.policy.delete(key);
}

function __netdev_detach(name)
{
	bpf.tc_detach(name, "ingress", 0x300);
	bpf.tc_detach(name, "egress", 0x300);
}

function netdev_attach(name)
{
	let ifindex = netdev_ifindex(name);
	if (!name || this.netdevs[name] == ifindex)
		return;

	__netdev_detach(name);
	this.progs.unetacl_in.tc_attach(name, "ingress", 0x300);
	this.progs.unetacl_out.tc_attach(name, "egress", 0x300);
	this.netdevs[name] = ifindex;
}

function netdev_detach(name)
{
	let ifindex = netdev_ifindex(name);
	if (ifindex == this.netdevs[name])
		__netdev_detach(name);

	delete this.netdevs[name];
}

function del_iface(ifname)
{
	if (!ifname)
		return;

	rtnl.request(rtc.RTM_DELLINK, rtc.NLM_F_REQUEST, {
		dev: ifname,
	});
}

function network_map_dump(map, af)
{
	let network = {};
	map.foreach((key) => {
		let prefix_len = u32_struct.unpack(substr(key, 0, 4))[0];
		let addr = utils.inet_ntop(af, substr(key, 4));
		let val = map.get(key);
		if (val != null)
			val = u32_struct.unpack(val)[0];

		network[addr + "/" + prefix_len] = val;
	});
	return network;
}

function dump() {
	let service = this;

	let network4 = network_map_dump(this.maps.network4, 4);
	let network6 = network_map_dump(this.maps.network6, 6);

	let clients = {};
	this.maps.client.foreach((key) => {
		let mac = mac_string(key);
		clients[mac] = service.client_get(mac);
	});

	let policy = {};
	this.maps.policy.foreach((key) => {
		key = policy_key_struct.unpack(key);
		let id = "" + key[1];
		if (key[2])
			id += "/" + key[2];
		else if (!key[1])
			id = "default";
		policy[id] = service.policy_get(key[1], key[2]);
	});

	return { network4, network6, clients, policy };
}

const mod_proto = {
	client_set, client_get, client_delete,
	network_key, network_set, network_get, network_delete,
	policy_set, policy_get, policy_delete,
	netdev_attach, netdev_detach,
	dump,
	close: function() {
		for (let netdev in this.netdevs)
			if (netdev)
				this.netdev_detach(netdev);
		del_iface(this.ifname);
		delete this.maps;
		delete this.progs;
		delete this.mod;
	}
};

export function debug() {
	bpf.set_debug_handler((level, line) => {
		warn(line);
	});
};

export function init(snoop_cb, name) {
	let ifname = "unetacl";
	if (name)
		ifname += "-" + name;

	let error = (msg) => {
		del_iface(ifname);
		warn(msg);
	};

	if (readfile(`/sys/class/net/${ifname}/ifindex`))
		del_iface(ifname);

	rtnl.request(rtc.RTM_NEWLINK, rtc.NLM_F_REQUEST | rtc.NLM_F_CREATE, {
		ifname: ifname,
		linkinfo: {
			type: "ifb",
		},
	});
	let err = rtnl.error();
	if (err) {
		warn(`failed to create ifb device: ${err}\n`);
		return;
	}

	rtnl.request(rtc.RTM_SETLINK, rtc.NLM_F_REQUEST, {
		dev: ifname,
		change: 1,
		flags: 1,
	});
	err = rtnl.error();
	if (err) {
		warn(`failed to start ifb device: ${err}\n`);
		return;
	}

	let ifindex = +readfile(`/sys/class/net/${ifname}/ifindex`);
	if (!ifindex) {
		warn(`failed to get ifindex for device ${ifname}\n`);
		return;
	}

	let mod = bpf.open_module("/lib/bpf/unetacl-bpf.o", {
		rodata: u32_struct.pack(ifindex),
	});
	if (!mod)
		return error(`Failed to open BPF module\n`);

	let maps = {};
	for (let map_name in [ "client", "network4", "network6", "policy" ]) {
		let map = mod.get_map(map_name);
		if (!map)
			return error(`missing map ${map_name}\n`);

		maps[map_name] = map;
	}

	let progs = {};
	for (let prog_name in [ "unetacl_in", "unetacl_out" ]) {
		let prog = mod.get_program(prog_name);
		if (!prog)
			return error(`missing program ${prog_name}\n`);

		progs[prog_name] = prog;
	}

	let netdevs = {};
	let obj = proto({
		mod, maps, progs, ifname, ifindex, netdevs, snoop_cb,
	}, mod_proto);

	let snoop = utils.snoop(ifname, obj);
	if (!snoop)
		return error(`Could not create snoop instance\n`);

	obj.snoop = snoop;
	return obj;
};
