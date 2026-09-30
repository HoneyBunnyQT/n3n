SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright Honey Bunny QT

# NAT Traversal

Edges send their traffic straight to each other where they can, and through
the supernode where they cannot.  Most edges sit behind a NAT, so to reach a
peer an edge needs to know the public address and port the peer's NAT uses
for it - and that NAT has to let the edge's packets in.

The supernode sees each edge at its public address and tells the edges about
each other.  Both edges then send REGISTERs to each other at the same time:
each NAT sees its own edge sending out to the other one first, and lets the
answer in.  Whether that works depends on how the NATs map the edges'
sockets.

## Sockets

By default an edge opens two UDP sockets, one for IPv6 and one for IPv4, on
ports the system picks (`connection.bind=[::]:0`).  Each packet leaves from
the socket for its destination's family, so an edge reaches supernodes and
peers of either family, whichever it registered over.  On a system without
IPv6 it keeps the IPv4 socket only.

`connection.bind` takes one or more addresses, separated by spaces, for
example to give a router's port forwarding a fixed port:

```
[connection]
bind=[::]:50001
```

`[::]` stands for IPv4 too: it opens `[::]` for IPv6 only and `0.0.0.0` on
the same port, unless an IPv4 address with that port is given as well.

A supernode takes the same list, by default `[::]:7654`, and answers edges
on each of the addresses alike, from the socket their packet came in on.

Loopback and local network traffic is not affected: packets to a local peer
leave from the same sockets, and edges in the same network still find each
other by multicast (see [Advanced Configuration](../configure/Advanced.md)).
IPv6 link-local peer addresses are not used, as they only work together with
their interface.

## How an edge's NAT maps it

Every answer from a supernode - to its registration and to the PING that
edges send to their supernodes every 30 seconds - tells the edge the
public address and port the supernode saw it at.  From the answers of
different supernodes, the edge sorts its NAT into one of these, separately
for IPv4 and IPv6:

| class | seen by the supernodes | meaning |
|-------|------------------------|---------|
| easy (port kept) | the same port, which is also the local one | no NAT, or one that keeps the port |
| easy (port changed) | the same public port towards every supernode | the usual home router, many carrier NATs |
| hard (ports lo-hi) | a new port for every destination | a peer would have to guess the port |
| several addresses | a different public address per supernode | more than one uplink, or a supernode in the local network |
| unknown | answers from fewer than two supernode addresses | |

Telling easy apart needs two supernodes with different addresses, for
example two federated ones: a NAT that maps per destination address shows
the same port towards two ports of one supernode.  A different port there
does show a hard NAT, so one supernode with two ports in its
`connection.bind` is enough to see that.

The class shows in the edge's management interface:

```
n3nctl get_info
    "nat4": "easy (port changed)",
    "nat6": "easy (port kept)",
```

and a change is logged, like `IPv4 NAT: hard (ports 20115-20228), as of
supernode [203.0.113.1:7654]`.

The edge also tells its peers: the REGISTER it sends through the supernode
carries a short hint with the class and, for a hard NAT, the range of ports,
rounded out to a multiple of 1024 below and a power of two in size.  An edge
shows the hint of a peer it does not reach directly yet as `nat` in
`get_edges`.  Older edges ignore the hint and send none.

## Getting through a hard NAT

| this edge | its peer | result |
|-----------|----------|--------|
| easy | easy | direct |
| easy or unknown | hard, range up to 4096 ports | direct after some rounds of guessing, see below |
| hard, range up to 4096 ports | easy or unknown | the same, the peer guesses |
| any | hard, wider range | through the supernode |
| hard | hard | through the supernode |
| any | several addresses | through the supernode |

Behind a hard NAT, the peer's REGISTERs to the edge's public port leave from
a public port of their own, one the edge has not sent to, so the edge's NAT
drops them.  But the peer tells the range of its ports, so in each round of
registrations - every `connection.register_interval`, 20 seconds by default -
the edge sends REGISTERs to a few more ports of that range, in a random
order.  Meanwhile the peer keeps sending a REGISTER to the edge's public
port every round, which keeps its own public port for the edge the same.
Once one of the edge's REGISTERs meets that port, the peer's NAT lets it
in, the peer answers, and the two are connected directly.

`connection.punch_ports` sets how many ports the edge tries per round, 16
by default; 0 turns it off.  At 16 ports every 20 seconds, the edge is
through a range of 1024 ports in 21 minutes, and meets the peer's port after
half of that on average; until then the traffic goes through the supernode
as before.  The rounds only happen while the two edges try to reach each
other.  Kept this slow, they add little to the REGISTERs sent anyway and do
not look like a burst of probes.

The range is the one the supernodes happened to see, rounded out.  A NAT
that hands out ports from a wider block may pick one outside it; the edge
then keeps going round without meeting it.

The edge keeps the port the peer answered from.  When the traffic goes one
way only, the sending edge drops the peer every half `register_interval`
and registers again, as with any peer; a REGISTER to the port it kept brings
the direct connection back at once, as long as the peer's NAT keeps the port.

Ranges wider than 4096 ports - a NAT that picks a random port from the
whole range for every destination - are not tried: guessing the one port
out of tens of thousands this way would hardly ever succeed.

Both edges need this version: the hard one to send its hint and keep its
port, the easy one to guess.

## Federation

With several federated supernodes, edges may be registered at different
ones.  A supernode passes an edge's question about a peer on to the other
supernodes, and the answer back, so edges on different supernodes reach
each other directly as well.  See [Federation](../configure/Federation.md).
