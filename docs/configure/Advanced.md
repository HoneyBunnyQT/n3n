<!--
SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright 2022 n2n contributors
SPDX-FileCopyrightText: Copyright Hamish Coleman
-->

# Advanced Configuration

This document describes information about communities, support for multiple
supernodes, routing, traffic restrictions and how to run an edge as a service.

## Configuration Files

Read about [Configuration Files](ConfigurationFiles.md) as they might come in handy – especially, but not limited to, if edges or supernodes shall be run as a service (see below) or in case of bulk automated parameter generation for mass deployment.

## Running edge as a Service

edge can also be run as a service instead of cli:

1. Edit `/etc/n3n/edge.conf` with your custom options. See [a sample](../edge.conf.sample).
2. Start the service: `sudo systemctl start n3n-edge`
3. Optionally enable edge start on boot: `sudo systemctl enable n3n-edge`

You can run multiple edge service instances by creating `/etc/n3n/instance1.conf` and
starting it with `sudo systemctl start n3n-edge@instance1`.


## Communities

You might be interested to learn some
[details about Communities](Communities.md) and understand how to
limit supernodes' services to only a specified set of communities.


## Federation

It is available a special community which provides interconnection between
supernodes. Details about how it works and how you can use it are available in
[Federation](Federation.md).

## Virtual Network Device Configuration

The [TAP Configuration Guide](TapConfiguration.md) contains hints on
various settings that can be applied to the virtual network device, including
IPv6 addresses as well as notes on MTU and on how to draw IP addresses from
DHCP servers.


## Peers on the Same Network

Edges that are on the same network find each other without the supernode:
each edge sends its registration to a multicast group and listens there.
The connection to such a peer then stays inside the local network.

If that multicast leaves through the wrong interface - another VPN's device,
for example, which then carries it to peers on the far side - it can be
switched off with `connection.local_discovery=false`.  Edges then only find
each other through the supernode.

Where multicast does not work at all (it is often disabled on routers and on
guest WiFi), an edge can tell the supernode its local address instead, which
other edges then try: `connection.advertise_addr` takes an IPv4 or IPv6
address, or `detect` for the address the edge sends from towards the
supernode.  The default, `auto`, advertises nothing and relies on multicast.


## Bridging and Routing the Traffic

Reaching a remote network or tunneling all the internet traffic via n3n are
two common tasks which require a proper routing setup. n3n supports routing
needs by temporarily modifying the routing table (`tools/n3n-route`). Details
can be found in the [Routing document](../advanced/Routing.md).

Also, n3n supports [Bridging](../advanced/Bridging.md) of LANs, e.g. to connect
otherwise un-connected LANs by an encrypted n3n tunnel on level 2.


## Traffic Restrictions

It is possible to drop or accept specific packet transmit over edge network
interface by rules. Rules can be specified in the config with the `filter.rule`
option - multiple times if needed. Details can be found in the [Traffic
Restrictions](../advanced/TrafficRestrictions.md).


## NAT Traversal

How edges get through NATs to reach each other directly, how an edge tells
what kind of NAT it is behind, and what `connection.bind` and
`connection.punch_ports` do about it is described in
[NAT Traversal](../advanced/NatTraversal.md).


## Threads

An edge or a supernode with a lot of traffic can handle its packets on
several threads at once with the `daemon.threads` option.  Details can be
found in the [Threads document](../advanced/Threads.md).


## A Supernode That Is an Edge Too

A supernode can join one community with a TAP device of its own
(`supernode.tap`), so that the machine it runs on needs no separate edge.
See [Setting up a Custom Supernode](Supernode.md#a-supernode-that-is-an-edge-too).


## All the Options

Every option, with its default and description, is listed in
[Configuration Options](Options.md).
