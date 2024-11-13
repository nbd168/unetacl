# unetacl - OpenWrt network access control

unetacl is a service that can be used to define per-client network access
policies. It is mainly used on wireless interfaces.
It is primarily written in ucode with some C helpers and uses an eBPF program
to handle the datapath.


## Configuration

unetacl can be enabled for a wifi interface by adding the following to a `wifi-iface`
section in `/etc/config/wireless`:
```
list tags 'unetacl'
```

The main configuration file is in `/etc/unetacl/config.json`. The JSON data
in this file contains the following options:

### `"global"`

Global configuration settings:
 - `"save_client_state"` (bool): If true, store persistent client state in `/etc/unetacl/state.json`

### `"networks"`

This defines networks which can be referenced from client/group policy.
Each network object can contain the following properties:

- `"hosts"` (array of strings): Defines fnmatch patterns for host names that
   match this network. DNS snooping is used to automatically add resolved
   IP addresses matching the patterns into the network address list.

- `"addr"` (array of strings): Defines IP addresses with optional subnet mask
   belonging to this network. Example: `192.168.42.0/24`, `fe80::1/8`


### `"groups"`

This defines sets of client policy/flags which can be referenced by name to apply
them to clients.
Each group can contain the following properties:

- `"flags"` (array of strings): client filter settings
  - `"filter_local"`: drop packets to the local network that are not covered by other
    network policy rules.
  - `"force_gateway"`: enforce that all packets sent to IP addresses outside of the
    local subnet need to go through the default gateway (discovered via DHCP).
  - `"filter_multicast"`: drop multicast for addresses not covered by other network
     policy rules
  - `"filter_ipaddr"`: prevent IP spoofing by only allowing source IP addresses
    configured or discovered via DHCP/NDISC snooping.

- `"policy"` (array of objects): per-network policy.

  The name is the same as the network name, or "#dns" for DNS specific policy.
  The objects can contain the following properties:
  - `"drop"` (bool): drop packets to this network
  - `"dest_mac"` (string): overwrite destination MAC address (e.g. for handling via routing or netfilter).
  - `"fwmark_val"` (int): modify packet fwmark
  - `"fwmark_mask"` (int): mask limiting fwmark changes
  - `"device"` (string): redirect to a network device referenced by name
  - `"ifindex"` (int): redirect to a network device referenced by ifindex
  - `"vlan"` (int): add VLAN tag with the given VLAN ID
  - `"vlan_proto"` (int): protocol for added VLAN tag


### `"default_policy"`

This defines the policy for received packets for which no client entry exists.
It uses the same properties as per-network policy from groups

### `"clients"`

This object defines policy automatically applied to newly created clients.
The name of each member object is either the lower-case MAC address, or `"default"`.
The properties of each member object are the same as the properties for each group from `"groups"`.

## TODO:

- allow setting destination mac by device name

