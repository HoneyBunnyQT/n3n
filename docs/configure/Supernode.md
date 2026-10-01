SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright 2020 n2n contributors

# Setting up a Custom Supernode

For the privacy of your data sent and to reduce the server load or reliance
on `supernode.ntop.org`, it is also suggested to set up a custom supernode.

You can create your own infrastructure by setting up a supernode on a public
server (e.g. a VPS). You just need to open a single port (1234 in the example
below) on your firewall (usually `iptables`).

1. Install the n3n package
2. Edit `/etc/n3n/supernode.conf` and add the following:
   ```
   [connection]
   bind=1234
   ```
3. Start the supernode service with `sudo systemctl start n3n-supernode`
4. Optionally enable supernode start on boot: `sudo systemctl enable n3n-supernode`

Now the supernode service should be up and running on port 1234, for IPv6 and
IPv4, UDP and TCP. On your edge nodes you can now specify
`-l your_supernode_ip:1234` to use it. All the edge nodes must use the same
supernode (or be part of the same [supernode federation](Federation.md))

`bind` takes several addresses, separated by spaces, and the supernode answers
edges on each of them alike, for example `bind=[::]:1234 [::]:1235` - open
both ports then.  A second port lets edges see whether their NAT maps each
destination to a port of its own (see [NAT Traversal](../advanced/NatTraversal.md)).
A port alone, or `[::]`, stands for IPv6 and IPv4; a given address only for
its own family.

Each address is for UDP and TCP, unless `udp://` or `tcp://` comes in front:
`bind=udp://[::]:7654 tcp://[::]:443` takes UDP on port 7654 and TCP on 443,
a port most firewalls let out.  The supernode needs at least one address for
UDP.  Tell the edges about the TCP port with a second line for the same host,
`supernode=tcp://sn.example.org:443`, next to `supernode=sn.example.org:7654`:
they then fall back to TCP on 443 when UDP does not get through.

## A Supernode That Is an Edge Too

A supernode can also be a member of one community, with a TAP device of its
own, so that the machine it runs on needs no separate edge:

```
[supernode]
tap = true

[community]
name = mynetwork
key = mysecretpass

[tuntap]
address = 10.1.2.1/24
address_mode = static
```

The `[community]` and `[tuntap]` options are those of an edge; without a
static address, the supernode gives one to itself as it does to the other
edges.  With user/password authentication, `auth.password` and
`connection.description` are its user name and password, and the supernode
needs that user in the community, as for any other edge; the public key of
the federation is that of its own.

The supernode's edge reaches the other edges of the community through the
supernode itself - directly for the edges registered at it, across the
federation for the others.  It has no sockets of its own, so peer-to-peer
connections, local peer discovery and hole punching do not apply to it.  The
supernode needs the privileges to open the TAP device at start, before it
drops them.  `get_edges` of the management API lists the supernode's edge at
`127.0.0.1:0`.  This is not available on Windows yet.
