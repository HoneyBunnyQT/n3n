<!--
SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright Honey Bunny QT
-->

# Path MTU: notes for v4

**Postponed to v4 (decided 2026-10-11), nothing of it is code.**  This
began as a draft for v3 and stays as the groundwork for v4.  See the
[Roadmap](Roadmap.md) (the decision, and the item in the v4 list) and the
scenarios `mtu-1280*` in [netns_testing.md](netns_testing.md).

Why not in v3: the questions at the end of this page come from v3's wire
format, where the size of the same frame depends on the path it takes -
a relayed PACKET carries the sender's address (8 or 20 bytes more), IPv6
has 20 bytes more of header than IPv4 - while paths change under a flow:
IPv4 and IPv6 flip, peers go to a relay and come back.  A per-peer MTU
learned in-band would chase a moving target.  v4 is to do one of:

- **The same packet the same size on any path** - direct or relayed, IPv4
  or IPv6 - so that what fits does not change when the path does; then a
  single tunnel MTU per peer (or for all) is enough.
- **Explicit packets for finding the MTU of a path**, a message type of
  their own, which v4 can have; then the probes of K2 below without the
  disguise as a PACKET.

What follows was written under v3's constraint - no new message types,
no new fields - and is kept for its numbers and options.

## Until then, in v3

Where a path is smaller than usual, set the TAP device's MTU so that the
largest frame fits: on a path of 1280 bytes, `tuntap.mtu = 1128` fits in
every case (relayed over IPv6 with AES, the largest overhead); the table
below gives the overhead of each part.  See
[TAP or TUN](../configure/TapConfiguration.md#mtu).

## The problem

What an edge sends to a peer is an Ethernet frame from its TAP device,
wrapped:

| part | bytes |
|------|-------|
| the frame: the TAP's MTU and the Ethernet header | MTU + 14 (+ 4 with a VLAN tag) |
| common header (header encryption adds nothing) | 24 |
| PACKET: source and destination MAC, compression, transform | 14 |
| PACKET, relayed: the sender's address, added by the supernode | + 8 (IPv4), + 20 (IPv6) |
| the cipher: IV, padding | AES, Twofish up to 32; ChaCha20, Speck 16; none 0 |
| UDP, IP | 8 + 20 (IPv4), 8 + 40 (IPv6) |

With the default TAP MTU of 1290 that is 1290 + 14 + 38 + 32 + 28 = 1402
bytes (AES, direct, IPv4), up to 1442 (relayed, IPv6): fine on a path of
1500 or 1492 (PPPoE), too big on a path of 1280 (the IPv6 minimum, and
what tunnels in tunnels, DS-Lite or some mobile networks leave).  There
the TAP's MTU would have to be 1168 (direct, IPv4) or 1128 (relayed,
IPv6).

Today, with the default `connection.pmtu_discovery = false`, the edge's
sockets never set DF: the kernel fragments the outer packet, and that
works (`mtu-1280`) - until something on the path drops fragments, as some
firewalls and NATs do (`mtu-1280-nofrag`: one direction dead for large
frames, small ones pass, the worst kind of failure to debug).  With
`pmtu_discovery = true` the sends of large frames fail with "Message too
long" and the frame is gone, with nothing telling the inner sender
(`mtu-1280-df`).

Fragmentation is also slow and lossy where it works: two packets for one,
and losing either loses both.

## Two halves

1. **Knowing** the MTU of the path to each peer (and to the supernode, for
   relayed frames): "the tunnel MTU of peer P".
2. **Acting** on it: making the inner sender send packets that fit,
   instead of fragmenting the outer ones or losing them.

They are independent: the second half can start with the MTU known from
the configuration, and get better as the first half learns more.

## Knowing the path MTU

### K1: the kernel's own PMTU discovery

The outer sockets with DF set (`IP_PMTUDISC_DO`, `IPV6_PMTUDISC_DO`, as
`pmtu_discovery = true` does now) and `IP_RECVERR` / `IPV6_RECVERR`: when
a router answers with ICMP "fragmentation needed" / "packet too big", the
kernel notes the MTU for that destination, the next send of a bigger one
fails with EMSGSIZE, and the error queue (`MSG_ERRQUEUE`) says the MTU for
the destination (`ee_info`).  No wire change at all.

- For: standard, immediate, no traffic of its own.
- Against: depends on ICMP getting back through the NATs and firewalls of
  the path (it often does, NATs translate ICMP errors; it is not
  guaranteed - "PMTU black holes").  Linux and Android; other systems
  later or never.

### K2: in-band probes (packetization layer PMTUD, RFC 8899 in spirit)

The edge sends a probe of a given size to the peer, and the peer answers
that it got it.  Both are PACKETs as any other:

- **Destination: the peer's own MAC**, not a special one.  A PACKET to a
  group MAC goes to every edge of the community through the supernode,
  and one to a MAC nobody has goes to every supernode of the federation
  (`try_forward()` in `role_relay.c`); to the peer's own MAC it goes
  where a frame for the peer goes, direct or relayed - which is the path
  to be measured.
- **Marked by its EtherType and a magic**: EtherType 0x88B5 (IEEE "local
  experimental", meant for protocols like this) and a magic number with a
  version first in the payload, then the kind (probe, answer), an id, the
  size probed, and padding up to that size.
- **An edge that does not know them** (older n3n, n2n) writes the frame to
  its TAP device: addressed to its own MAC, with an EtherType no protocol
  of the host takes, the kernel drops it.  Nothing answers, so the
  sender stops probing that peer (one small probe first: no answer, no
  more).
- **An edge that knows them** takes them out before the TAP device (at
  egress from the network) and never sends such a frame that comes from
  its TAP device (at ingress), so that no host behind it can make up
  answers.  Only frames with the magic: other 0x88B5 traffic passes as
  before.
- **Encrypted** as every PACKET is, and so only from members of the
  community.

Probes need DF on the outer packet, or they get fragmented and only tell
that fragments get through.  Linux has no DF per packet for IPv4 UDP, only
per socket (`IP_PMTUDISC_PROBE`: DF, without the kernel's PMTU cache) -
so either the sockets set DF for everything (and the edge then has to keep
every frame below what it learned, which is the second half anyway), or
the probes go out of a socket of their own, which a NAT maps apart and so
measures another path.  The first is the clean one: DF on, the tunnel MTU
per peer known, nothing sent bigger.

- For: works where ICMP does not come back; measures exactly the path the
  frames take, relayed ones included.
- Against: traffic of its own (a handful of probes per peer, when it is
  found and when it moves, then every ten minutes or so); a binary search
  takes a few round trips; more code.

### K3: the peer tells what it receives fragmented

`IP_RECVFRAGSIZE` / `IPV6_RECVFRAGSIZE` (Linux 4.10): for a reassembled
datagram, the receiver learns the size of its largest fragment - which is
about the MTU of the path it came over.  An edge that receives fragments
from a peer can tell the peer, with the same answer as in K2 ("from you,
fragments of N bytes"), and the peer lowers its tunnel MTU for it.  Passive,
no probes, cheap - but only where fragments arrive at all, so a help for
K1/K2 rather than an alternative.

### K0: configured

`connection.path_mtu = N` (or a per peer list): the plain fallback, and
what the second half needs first.

## Acting on it

### A1: ICMP back into the TAP device, as kernel tunnels do

A frame from the TAP device to peer P, carrying an IP packet bigger than
P's tunnel MTU less the overhead:

- IPv4 with DF, and IPv6 (always): drop it, and write an ICMP
  "fragmentation needed" (type 3 code 4, with the MTU) / ICMPv6 "packet
  too big" (with the MTU) back into the TAP device, addressed to the
  sender, quoting the packet's header, from P's MAC and P's IP address.
  The host's kernel notes the MTU for that destination and TCP and the
  rest send smaller from then on - as on any other path with a smaller
  MTU.
- IPv4 without DF: fragment it (the inner packet, not the outer one), or
  leave it to the outer fragmentation as today.
- In TUN mode (Android) the same, without the Ethernet header.

No wire change; everything stays in the edge.  Works for TCP, UDP and the
rest alike, as long as the host honours ICMP - every usual system does.
Hosts behind the edge (`filter.allow_routing`) get the ICMP as from a
router on their path, which it is.

### A2: TCP MSS clamping per peer

Rewrite the MSS option of TCP SYNs to and from P to fit P's tunnel MTU
(and fix the checksum).  TCP only, but needs no ICMP to work, and the first
segment already fits.  A cheap addition to A1, as routers do it too.

### A3: the TAP MTU from the path

Set the TAP device's MTU to the smallest tunnel MTU of all peers.  Simple,
but one bad path lowers it for all, it changes at run time (Android:
a new `VpnService.Builder`), and it does not help the hosts behind.  At
most a start-up setting: `tuntap.mtu = auto`, from K0.

## A proposal (for v3, before it was postponed)

1. **A1 with K0 first**: a tunnel MTU per peer, from `connection.path_mtu`
   or else as today (1500 for the outer path); ICMP into the TAP device
   for what does not fit; the `mtu-1280*` scenarios with the setting pass,
   `mtu-1280-nofrag` included.  Then A2.
2. **K1**: DF on and the kernel's PMTU per destination, read from the
   error queue, taken as the peer's tunnel MTU (direct peers; for the
   relayed ones the supernode's).  The scenarios with ICMP from the
   router.
3. **K2** for black holes, and K3 where it comes for free.  The scenarios
   with ICMP dropped (a new `Site` setting).
4. `pmtu_discovery` then means "DF and learn" (K1/K2); without it, as
   today.

The questions, which led to postponing it:

- K2 and K3 are the only parts that two edges have to agree on: is
  EtherType 0x88B5 plus a magic in a PACKET to the peer's MAC acceptable
  as "in-band", or too close to a new message type?
- What should an inner IPv4 packet without DF do: inner fragmentation by
  the edge, or the outer fragmentation as today?
- Relayed frames: the path is edge - supernode - edge, two legs the
  sender does not see apart.  Probing end to end (K2) covers both; K1 sees
  only the first leg.  Good enough?
- Should the edge learn the tunnel MTU of its supernodes too (K1/K2 to
  the supernode), for what it relays through them, or only end to end?
