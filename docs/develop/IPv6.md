<!--
SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright Honey Bunny QT
-->

# IPv6 inside the tunnel

**A design, decided 2026-10-12, being built.**  How an edge gets an IPv6
address on its device without anything new on the wire - v3's supernode
hands out IPv4 addresses only, in a field of four bytes.  See the
[Roadmap](Roadmap.md) and [Mobile and TUN](MobileAndTun.md).

## Background, in short

- An IPv6 address is 128 bits: the upper 64 the network (the prefix), the
  lower 64 the interface on it.  A /64 is the usual size of a network.
- Private addresses, as 10.0.0.0/8 is for IPv4: `fd00::/8` (unique local
  addresses, RFC 4193) - `fd`, a global ID of 40 bits, and a subnet of 16
  bits make a /64.
- Neighbour discovery (RFC 4861) is IPv6's ARP: a neighbour solicitation
  (NS) to a multicast address asks who has an address, the neighbour
  advertisement (NA) answers with the MAC.  Over n3n's Ethernet it already
  works between TAP devices, multicast frames go to all the edges.
- Every interface gets a link-local address (`fe80::/64`) of its own; with
  a TAP device, that already works today between edges.

The address space is large enough that every edge can work out an address
of its own, with no one handing them out - so nothing on the wire needs to
change, and supernodes, older edges and n2n are none the wiser.

## The address

`tuntap.address6`, off unless set:

- `auto`: the prefix (below) and an interface ID of the edge's own:
  - its IPv4 address in the lowest 32 bits, when it has one (static, or
    from the supernode with `tuntap.address_mode = auto`):
    `fd6c:bcdb:8e7b::10.77.0.5`, which tools show as `fd6c:bcdb:8e7b::a4d:5`
    - as unique as the IPv4 addresses, which the supernode keeps unique for
    those it hands out;
  - else from the MAC as modified EUI-64 (RFC 4291: `ff:fe` in the middle,
    the universal/local bit flipped), as the kernel makes the link-local
    address - unique as the MACs of a community are, which the supernode
    keeps unique; it changes when the MAC does (a TAP device without
    `tuntap.macaddr` gets a new random MAC at each start).
- an address with its prefix length, e.g. `fd00:77::5/64`: taken as it is.

`tuntap.prefix6`: the /64 for `auto`.  Default: `fd` and 40 bits of a hash
of the community's name, subnet 0 - the same for every edge of a community,
with nothing to set, and two communities clash only if their hashes do
(one in 2^40).

## What each part does

- **TAP device** (Linux first): the address goes on the device; the kernel
  does neighbour discovery itself, over the community like ARP.
- **TUN device** (Android, `tuntap.type = tun`): there is no Ethernet on the
  device, so the edge does what the kernel does for a TAP device, as it
  does ARP already (`src/tun.c`):
  - an IPv6 packet from the device to a unicast address needs the MAC of
    the address: from the IPv4 ARP table if the address is in the prefix
    with an IPv4 address in its lowest 32 bits; from the address itself if
    its interface ID is an EUI-64 one; else from neighbour discovery - an
    NS goes out instead of the packet, which is lost, as the kernel would
    drop it after a while, and the NA that comes back is learned;
  - an NS for the edge's own address is answered with an NA;
  - multicast goes out to the multicast MAC (33:33:...), as now.
- **Android**: the app adds the address and the /64 to its
  `VpnService.Builder`, with the address worked out by the core, so that
  the app and the edge agree.  Android's static IPv4 address (the app needs
  one before the edge starts) gives the interface ID.

## Steps

1. Done: the address in the core: `tuntap.address6`, `tuntap.prefix6`,
   working it out (`src/ipv6.c`), `tests-ipv6`.
2. Done: the TUN edge's neighbour discovery (`src/tun.c`, fuzzed by
   `fuzz-tun`); the address on the Linux device (TUN and TAP, netlink);
   neighbour solicitations past `filter.allow_multicast`; netns scenarios
   `ipv6-tap`, `ipv6-tun-tap`, `ipv6-tun-tun` with a ping each way (they
   need IPv6 in the kernel: CI; locally `uml.sh`, whose 6.8 kernel does not
   boot on a host with AVX-512 - "ptrace set fp regs failed").
3. Done: the Android app adds the address and its /64 to the
   `VpnService.Builder`, as the core works it out (`Core.ipv6Address()`);
   not yet tried on a phone.
4. Later: other systems' devices; IPv6 through an exit peer.
