SPDX-License-Identifier: GPL-3.0-only
SPDX-FileCopyrightText: Copyright Honey Bunny QT

# Testing edges and supernodes behind NATs

`tests/netns/` builds a small internet out of Linux network namespaces and
runs the real `apps/n3n-edge` and `apps/n3n-supernode` in it: two federated
supernodes, and two sites, each an edge behind one or more NAT routers.
It sends counted frames through the VPN and checks what arrived, the
edges' p2p and supernode counters, the supernodes' forwarding counters,
the NAT class each edge sees (see [NAT Traversal](../advanced/NatTraversal.md))
and whether the edges reached each other directly or stayed relayed, as
they should for their NATs.

```
                      "internet" 203.0.113.0/24
      +-----------+-----------+-----------+-----------+
     sn1         sn2       router a    router b    (edges without NAT
  .1:7654      .2:7654       .11         .12        sit here, at .101+)
     federated supernodes      |           |
                            edge a      edge b
                        10.99.0.1/24  10.99.0.2/24
```

## Running

It needs root (namespaces, TAP devices, nftables), iproute2, nft and
`/dev/net/tun`, and Python 3 without further modules.

```
make test                       # includes the quick scenarios
make test.netns.full            # all of them
sudo tests/netns/run.py --list
sudo tests/netns/run.py easy-hard hard-hard
sudo tests/netns/run.py @quick -j 2
sudo tests/netns/run.py easy-hard -v 3 --punch-ports 16 --register-interval 20
sudo tests/netns/run.py --wrap 'valgrind --error-exitcode=99' easy-easy
sudo tests/netns/run.py --cleanup   # namespaces left by a killed run
```

`make test` runs it through sudo unless make runs as root already, and
prints `SKIP` instead if something it needs is missing.  Several scenarios
run at once (`-j`, 4 by default): the quick ones take about half a minute,
all of them a minute and a half.

Logs, the config files, the nftables rulesets with their drop counters,
the daemons' management output at the end (`state.json`) and the results
of each scenario (`result.json`) are kept in `tests/netns/out/<scenario>/`,
and all results in `tests/netns/out/results.json`.

## The kinds of NAT

All routers drop what comes in from outside unless it belongs to a
connection made from inside, as home routers and carrier NATs do.

| kind | maps | the edge should see |
|------|------|---------------------|
| (none) | the edge is on the internet itself | easy (port kept) |
| easy-kept | the inside port, for every destination (masquerade) | easy (port kept) |
| easy-changed | one other public port for every destination | easy (port changed) |
| hard-range | a random port per destination from 20224-20479 | hard (ports ...) |
| hard-wide | a random port per destination from 1024-65535 | hard (ports ...) |
| several | one public address towards sn1, one towards sn2, a third towards peers | several addresses |

A site can have several routers in a row, outermost first, like a home
router behind a carrier NAT.  The block of hard-range ends at a multiple of
1024, so the range an edge tells its peers covers all of it.

## The scenarios

| scenario | NAT a / b | expected |
|----------|-----------|----------|
| easy-easy | easy-kept / easy-kept | direct |
| easy-changed | easy-kept / easy-changed | direct |
| public-easy | none / easy-changed | direct |
| fed-split | easy-kept / easy-changed, each edge knowing only one supernode | direct |
| easy-hard | easy-kept / hard-range | direct, after guessing |
| hard-easy | hard-range / easy-changed | direct, after guessing |
| easy-hard-a2b, -b2a | as easy-hard, traffic one way only | direct |
| easy-hard-pool | as easy-hard, a guessing 16 ports a round | direct, as one of b's 32 sockets is met |
| cgnat-hard-ttl | as easy-hard-pool, b behind easy-kept and hard-range, punch_ttl=3 | direct |
| hard-hard | hard-range / hard-range | relayed |
| easy-wide | easy-kept / hard-wide | relayed |
| no-punch | as easy-hard, with punch_ports=0 | relayed |
| several | several / easy-kept | relayed |
| failover-relayed | hard-range / hard-range, a's supernode killed | relayed, through the other one |
| failover-direct | easy-kept / easy-changed, a's supernode killed | direct |
| failover-userpw | as failover-relayed, with user/password authentication | relayed, through the other one |
| failover-userpw-direct | as failover-direct, with user/password authentication | direct |
| failover-header-enc | as failover-relayed, with encrypted headers | relayed, through the other one |
| failover-tcp | easy-kept with connect_tcp / easy-changed, a's supernode killed | relayed, a over TCP to the other one |
| cgnat-both | easy-changed+easy-kept on both sides | direct |
| same-lan | both sites 192.168.1.0/24, the edges at the same address | direct |
| tcp-tcp | easy-kept / easy-changed, both edges with connect_tcp | relayed, over TCP both ways |
| tcp-udp | as tcp-tcp, only a with connect_tcp | relayed, between TCP and UDP |
| hard-hard-threads | as hard-hard, the supernodes with daemon.threads=3 | relayed |
| easy-hard-threads | as easy-hard, edges and supernodes with daemon.threads=3 | direct |
| header-enc | easy-kept / hard-range, encrypted headers | direct |
| userpw | as header-enc, with user/password authentication (ChaCha20) | direct |
| userpw-relayed | hard-range / hard-range, user/password, each edge at its own supernode | relayed, across the federation |
| userpw-conf | as userpw-relayed, the community and users in `[community NAME]` sections | relayed, across the federation |
| sn-tap | hard-range / the TAP device of sn2 (`supernode.tap`), the edge at sn2 | relayed |
| sn-tap-fed | easy-kept at sn1 / the TAP device of sn2 | relayed, across the federation |
| sn-tap-userpw | as sn-tap-fed, with user/password authentication | relayed, across the federation |
| sn-tap-failover | easy-kept at sn1 (`supernode_selection=mac`) / the TAP device of sn2, sn1 killed | relayed, a moves to sn2 |
| tcp-fallback | easy-kept without UDP (`block_udp`) / public | relayed, a over TCP by `tcp_fallback` |
| tcp-fallback-back | as tcp-fallback, then UDP let through again (`unblock_udp`) | direct, a back on UDP |
| tcp-fallback-userpw | as tcp-fallback-back, with user/password authentication | direct, a back on UDP |

An edge connected over TCP does not learn how its NAT maps it, so the NAT
class of tcp-tcp and tcp-udp is not checked for those edges (`expect_nat` of
a `Site`).  A `Site(block_udp=True)` drops the UDP its edge sends out of
`eth0` (but DNS), as some airport networks do: the scenario then checks that
the edge is on TCP (`transport` of `get_info`), and with `unblock_udp` of
the `Scenario` lets UDP through again and waits for the edge to go back.  `sn_conf` of a `Scenario` sets options of the supernodes.
`auth` of a `Scenario` turns on header encryption (`"header"`), or that
and user/password authentication (`"userpw"`): the supernodes then get a
community file, with a user for each edge whose public key comes from
`n3n-edge tools keygen`, as docs/configure/Authentication.md describes.
A `Site(on_supernode="sn2")` is the TAP device of that supernode, which then
runs with `supernode.tap` and the site's settings of the community, the
tuntap device and auth: it has no edge daemon of its own, so the checks that
need one take what the other side counted.
With `community_conf=True` the supernodes have them in a `[community
nettest]` section with `user` options instead, and the edges their
community in such a section too.

To keep runs short, the edges use `connection.register_interval=5` and
`connection.punch_ports=128` (instead of 20 and 16), so guessing through
1024 ports takes at most 8 rounds, 40 seconds.  `--register-interval` and
`--punch-ports` set others.  New scenarios go into
`tests/netns/n3ntest/scenarios.py`.

## What a run checks

1. the edges register, and each sees its NAT as the class above
2. a trickle of frames each way (10 per second) until the edges list each
   other as `p2p` in `get_edges` (within `--connect-timeout`, 90 seconds)
   - or, for the relayed ones, that they do not for 4 rounds of
   registration
3. a counted burst, 500 frames each way at 200 per second (`--frames`,
   `--rate`, `--size`), then:
   - `frames:` all arrived, give or take `--loss` (1 percent)
   - `counters:` direct, the sender counted them as p2p tx and the
     receiver as p2p rx, and next to none went through the supernodes;
     relayed, the other way round
   - `relay:supernodes:` the supernodes' `sn_fwd` counted next to none
     of them (direct), or all of them (relayed)
   - `path:after:` the edges are still on the path they should be
4. no daemon died along the way, and all of them exit cleanly on SIGTERM

The peers' MAC addresses are set as permanent neighbours and the TAP
devices have no IPv6, so no ARP or neighbour discovery frames get counted
along with the test frames.
