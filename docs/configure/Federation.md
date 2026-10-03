SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright 2020 n2n contributors
SPDX-FileCopyrightText: Copyright Hamish Coleman

# Supernode Federation

## Idea
To enhance resilience in terms of backup and fail-over, also for load-balancing, multiple supernodes can easily interconnect and form a special community, called **federation**.


## Using Multiple Supernodes

### Form a Federation

To form a federation, multiple supernodes need to be aware of each other. To
get them connected, an additional `supernode.peer` option is required at
the supernode.

This option takes the IP address (or name) and the UDP port of another known
supernode, e.g. `192.168.1.1:1234`.  As the number of federated supernodes
increases, it gets more convenient to use a config file for this option.

### Use a Federation

Federated supernodes take care of propagating their knowledge about other supernodes to all other supernodes and the edges.

So, in the first place, edges only need to connect to one supernode (called
anchor supernode) using `community.supernode` option. This supernode needs to
be present at start-up.

Optionally, more anchor supernodes of the same federation can be provided to an
edge using several `community.supernode` options. This will counter scenarios
with reduced assured initial supernode availability.

## How It Works

Supernodes should be able to communicate among each other as regular edges already do. For this purpose, a special community called federation was introduced. The federation feature provides some mechanisms to inter-connect the supernodes of the network enhancing backup, fail-over and load-sharing, without any visible behavioral change.

The default name for the federation is `Federation`. Internally, a mandatory
special character is prepended to the name (`*`) that way, there is no way for
a regular community with the same name as the federation to conflict.
Optionally, a user can choose a federation name (same on all supernodes) and
provide it via the  `supernode.federation` option to the supernode.  Finally,
the federation name can be passed through the environment variable
`N3N_FEDERATION`.

Federated supernodes register to each other using REGISTER_SUPER message type. The answer, REGISTER_SUPER_ACK, contains a payload with information about other supernodes in the network.

This specific mechanism is also used during the registration process taking place between edges and supernodes, so edges are able to learn about other supernodes.

Once edges have received this information, it is up to them choosing the supernode they want to connect to. Each edge pings supernodes from time to time and receives information about them inside the answer. We decided to implement a work-load based selection strategy because it is more in line with the idea of keeping the workload low on supernodes. Moreover, this way, the entire network load is evenly distributed among all available supernodes.

An edge connects to the supernode with the lowest work-load and it is re-considered from time to time, with each re-registration. We use a stickyness factor to avoid too much jumping between supernodes.

Thanks to this feature, n3n is now able to handle security attacks such as DoS against supernodes and it can redistribute the entire load of the network in a fair manner between all the supernodes.

To serve scenarios in which an edge is supposed to select the supernode by
round trip time, i.e. choosing the "closest" one, the
`connection.supernode_selection=rtt` config option is available at the edge.
Note, that workload distribution among supernodes might not be so fair then.

Furthermore, `connection.supernode_selection=mac` would switch to a MAC address
based selection strategy choosing the supernode active with the lowest MAC
address.

### IPv4 and IPv6

An edge registered over IPv6 is known by its own address, not by its
NAT's - the address the supernode tells the other edges, through which
those with IPv6 too reach it directly, NAT or not.  Supernodes and edges
of this version go further: an edge registered over one family also
registers its address of the other family, where it knows the same
supernode by an address of that family too (`supernode =
198.51.100.1:7654` and `supernode = [2001:db8::1]:7654`).  The supernode
keeps both, and tells each edge that asks for another the address of a
family both have, IPv6 first: two edges with IPv6 reach each other over
it, one with IPv4 only still gets the other's IPv4 address.

So the selection is about the supernode, mostly: for any strategy, an
IPv4 entry counts half again as much as it is (load, round trip), and
loses a tie; by round trip, the current supernode counts a quarter less,
so that the edge only moves to one clearly faster.  A far IPv6 supernode
still loses to a near IPv4 one.  With a supernode that does not keep the
other address (an older one: it says so in its answers to the
registration), the edge registers over IPv6 wherever a supernode answers
there, as the family it registers over is all the others learn.

A supernode given by both its addresses is kept as two entries, each with
its own round trip.  An IPv6 address that does not answer, e.g. behind a
firewall, has no say.

Between the edges, the same order holds for the ways to a peer: its LAN
address (private IPv4, or a unique local IPv6 address) before public
IPv6, before public IPv4.  A peer heard from at a better address moves
there at once; one heard from at a worse one stays where it is, as long
as it answers there.

## Example

Two supernodes, at 198.51.100.1 and 198.51.100.2, each with this config, but
for the `peer` pointing at the other one:

```
[connection]
bind = 7654

[supernode]
federation = mySecretFederation
peer = 198.51.100.2:7654
```

and the edges given both:

```
[community]
name = mynetwork
key = mysecretpass
supernode = 198.51.100.1:7654
supernode = 198.51.100.2:7654
```

Edges at either supernode reach each other: what one supernode gets for an
edge registered at the other, it passes on.  With user/password
authentication, every supernode needs the same users (the same community
file or `[community NAME]` sections), and the edges the public key of the
federation (`auth.pubkey`, from `n3n-edge tools keygen <federation name>`).

## When a Supernode Goes Away

An edge whose supernode stops answering moves to another one of its list or
of the federation, within a few registration intervals
(`connection.register_interval`, 20 seconds by default), and authenticates
there again.  Peers that reach each other directly carry on meanwhile.  The
netns tests `failover-*` and `sn-tap-failover` check this, also with
encrypted headers, user/password authentication and TCP, see
[Testing behind NATs](../develop/netns_testing.md).
