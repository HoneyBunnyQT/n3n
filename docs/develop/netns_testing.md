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

CI runs all the scenarios on every push (`netns.yml`; the runners' kernel
has IPv6), but those tagged `limits`, and the interop ones with the other
versions built (`interop.yml`); `sanitizers.yml` runs them with the
sanitizers built in.  A failed run uploads the logs of the scenarios.

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
all of them a few minutes (the outage ones run 90 seconds without
supernodes).  The scenarios tagged `limits` show what n3n cannot do (yet):
they fail, and a run without names leaves them out (`run.py @limits` runs
them).

### Other versions (interop)

The scenarios tagged `interop` run edges and supernodes of this tree
together with those of another version of n3n: `Site(version=NAME)` for an
edge, `Scenario(sn_versions={"sn1": NAME})` for supernodes.
`tests/netns/versions.sh` builds such a version into
`tests/netns/versions/NAME`:

```
tests/netns/versions.sh build n3n-3.4.6 3.4.6     # the last release
sudo tests/netns/run.py @interop
```

A run without names includes the interop scenarios of the versions that are
built.  An older version gets only the options it knows (from its `help
config`; the run names those it left out), its NAT class is not checked,
and with older supernodes neither is the edges'.  3.4.6 sends to IPv4
peers as IPv4-mapped IPv6 addresses, so it needs a kernel with IPv6 (UML
here, or the CI runners: `interop.yml`).  n2n (below) needs no IPv6.

| scenario | sites | expected |
|----------|-------|----------|
| interop-old-edge | a 3.4.6 (easy-kept) / b (easy-changed), supernodes of this tree | direct |
| interop-old-sn | edges of this tree, both supernodes 3.4.6 | direct |
| interop-old-sn-hard | as interop-old-sn, b behind hard-range | direct, this tree's port guessing |
| interop-fed | sn1 3.4.6, sn2 this tree; a 3.4.6 knows only sn1, b only sn2 | direct, across the mixed federation |
| interop-relayed | hard-range / hard-range, a and sn1 3.4.6 | relayed |
| interop-header-enc | encrypted headers, a 3.4.6, b easy-changed | direct |
| interop-userpw | user/password, a and the supernodes 3.4.6 | direct |

#### n2n 3.x

The scenarios tagged `n2n` (and `interop`) run n2n 3.1.1 along with this
tree.  `versions.sh` builds it from n2n's repository:

```
tests/netns/versions.sh build n2n-3.1.1 3.1.1 https://github.com/ntop/n2n
sudo tests/netns/run.py @n2n
```

n2n takes command line options: the harness gives it the same settings as
those, and names the ones n2n has none for (the `n3ntestN-NAME.conf` in
the scenario's log directory then holds its command line).  It talks to
n2n's own management interface, the JSON rows over UDP on the loopback of
the daemon's namespace (`n3ntest/n2nmgmt.py`); n2n reports no NAT class
and knows no TCP.  n2n has no IPv6, so these scenarios need none either,
and are all IPv4.  n2n 3.1.1 sets up the federation's header key before
it reads its options: with `-F` alone its supernode would keep the key of
the default name, and no other supernode would understand it.  The harness
gives the name in `N2N_FEDERATION` instead, which gets into the key.

| scenario | sites | expected |
|----------|-------|----------|
| interop-n2n-edge | a n2n (easy-kept) / b (easy-changed), supernodes of this tree | direct |
| interop-n2n-sn | edges of this tree, both supernodes n2n | direct |
| interop-n2n-fed | sn1 n2n, sn2 this tree; a n2n knows only sn1, b only sn2 | direct, across the mixed federation |
| interop-n2n-relayed | hard-range / hard-range, a and sn1 n2n | relayed |
| interop-n2n-header-enc | encrypted headers, a n2n, b easy-changed | direct |

### IPv6, in a kernel of its own

The scenarios tagged `ipv6` (`dual-stack`, `hard-hard-v6`,
`hard-hard-v6-blocked`, `v6-v4only`) need a kernel with IPv6, which
many containers lack; without it, the scenario fails at once ("this kernel
has no IPv6").  `tests/netns/uml.sh` runs the scenarios in User-Mode
Linux instead: a Linux kernel built as a program, which boots from the
host's file system and runs the harness inside, with its own namespaces,
links and nftables - no root on the host's network needed, and nothing of
the host's network touched.

```
apt install linux-source flex bison bc        # or any kernel source tree
tar xjf /usr/src/linux-source-*.tar.bz2 -C ~
tests/netns/uml.sh kernel ~/linux-source-*    # configure and build, once
tests/netns/uml.sh run @ipv6                  # run.py's arguments
tests/netns/uml.sh run @quick
tests/netns/uml.sh exec make test.integration # any command, e.g. upstream's
                                              # tests, which need IPv6 too
```

The UML kernel runs on one CPU and slower than the host, so `uml.sh`
passes `-j 1` and `--register-interval 10` unless given: with 5 seconds,
the peers' idle timeout (half of it) can pass while the senders of the
next flow start, and their first frames then go through the supernode.
The kernel is at `tests/netns/uml-linux`, or where `UML_KERNEL` says.
Even so, `fed-split` sometimes sends a few frames too many through the
supernodes there (base and changed builds alike, 0 to 28 of 1000).

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
| hard-range | a random port per destination from 20224-20479, towards each supernode from a slice of it of its own | hard (ports ...) |
| hard-wide | a random port per destination from 1024-65535 | hard (ports ...) |
| several | one public address towards sn1, one towards sn2, a third towards peers | several addresses |

A site can have several routers in a row, outermost first, like a home
router behind a carrier NAT.  The block of hard-range ends at a multiple of
1024, so the range an edge tells its peers covers all of it.

An edge sees how its NAT maps from the ports its supernodes see (two
here).  Drawn from the whole block of 256 ports, those two would be the
same one time in 256, and the edge would rightly see an easy NAT - with
a few dozen hard-range edges in a full run, a failed run every tenth time
or so.  So towards sn1 the hard-range router takes a port from the lower
half of the block, towards sn2 from the upper half; the peers still get
ports from all of it.

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
| no-punch | as easy-hard, with punch_ports=0 | relayed - or direct by luck, which passes too (`direct_ok`): the hard side's own REGISTERs may hit the port the easy NAT keeps for it |
| several | several / easy-kept | relayed |
| failover-relayed | hard-range / hard-range, a's supernode killed | relayed, through the other one |
| failover-direct | easy-kept / easy-changed, a's supernode killed | direct |
| failover-userpw | as failover-relayed, with user/password authentication | relayed, through the other one |
| failover-userpw-direct | as failover-direct, with user/password authentication | direct |
| failover-header-enc | as failover-relayed, with encrypted headers | relayed, through the other one |
| failover-tcp | easy-kept with connect_tcp / easy-changed, a's supernode killed | relayed, a over TCP to the other one |
| cgnat-both | easy-changed+easy-kept on both sides | direct |
| same-lan | both sites 192.168.1.0/24, the edges at the same address | direct |
| roam | easy-kept / easy-kept, register_interval 20; b moves to another network (its link down, another link and NAT up) while frames flow both ways | direct again; the longest gap each way at most 5s |
| roam-nowatch | as roam, with connection.watch_network = false: for comparison | direct again, after up to half the peers' timeout (gap at most 60s) |
| dual-stack | both edges public, with IPv4 and IPv6; a knows the supernode by IPv6, b by IPv4, and they find each other by multicast over both: each may hear the other from either family (needs IPv6, see `uml.sh`) | direct, the peers kept at one address |
| hard-hard-v6 | hard-range / hard-range, but each site with routed IPv6 behind its router's firewall, 20 ms slower than IPv4; the edges know the supernode by both, select by round trip (needs IPv6) | direct, over IPv6: registered over IPv4, each edge also tells the supernode its IPv6 address |
| v6-v4only | easy-kept / easy-kept, a with IPv6 too (registered over it), b with IPv4 only (needs IPv6) | direct, over IPv4: the supernode tells b a's IPv4 address |
| fed-peers46 | as fed-split, with IPv6: the supernodes know each other by both addresses (`Scenario(sn_peer_family=46)`) (needs IPv6) | direct; a supernode once took itself for a member of its federation there |
| fed-peers46-blocked | as fed-peers46, IPv6 blocked at the supernodes: their IPv6 entries for each other are dead (needs IPv6) | direct |
| fed-peers46-relayed | as fed-peers46-blocked, hard-range / hard-range (needs IPv6) | relayed, across the federation |
| hard-hard-v6-blocked | as hard-hard-v6, the supernodes' firewalls let nothing in over IPv6 (needs IPv6) | relayed, as hard-hard |
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
| tcp-port | as tcp-fallback-back, the supernodes with UDP on 7654 and TCP on 4443 only (`sn_tcp_port`) | direct, after a over TCP to 4443 |
| tcp-only | easy-kept with its supernodes as `tcp://` only (`tcp_only`) / public | relayed, a over TCP from the start |
| tun-tap | easy-kept with `tuntap.type=tun` / easy-changed with a TAP device | direct, the TUN edge building the frames |
| tun-tun | hard-range / hard-range, both with `tuntap.type=tun` | relayed |
| reload | easy-kept / easy-changed; a's configuration loses the supernode a is at and gets another description, then SIGHUP | a applies both while it runs and moves to the other supernode; direct |
| sn-outage | easy-kept / easy-changed; both supernodes killed while frames flow both ways, for 90s (longer than the registrations live) | direct throughout, the longest gap each way at most 3s |
| sn-outage-idle | as sn-outage, the frames stopping for 40s 10s into it | direct again at once (gap at most 3s): the edges keep their idle peers while no supernode answers |
| sn-outage-roam | as sn-outage, easy-kept / easy-kept, b moving to another network 10s into it (limits) | fails: with no supernode to tell a b's new address, a's NAT keeps b out |
| sn-outage-restart | as sn-outage, easy-kept / easy-kept, b's edge restarting 10s into it | direct again once b's device is up, the longest gap each way at most 20s |
| sn-outage-restart-userpw | as sn-outage-restart, with user/password authentication (limits) | fails: b waits for a supernode to vouch for it |
| mtu-1280 | easy-kept / easy-kept with a 1280 byte link, frames of 1200 bytes | direct, the packets fragmented |
| mtu-1280-nofrag | as mtu-1280, b's router dropping fragments (limits) | fails one way: b's large packets do not get out |
| mtu-1280-df | as mtu-1280, with connection.pmtu_discovery (limits) | fails: the large packets are refused ("Message too long") instead of fragmented |

An edge connected over TCP does not learn how its NAT maps it, so the NAT
class of tcp-tcp and tcp-udp is not checked for those edges (`expect_nat` of
a `Site`).  A `Site(block_udp=True)` drops the UDP its edge sends out of
`eth0` (but DNS), as some airport networks do: the scenario then checks that
the edge is on TCP (`transport` of `get_info`), and with `unblock_udp` of
the `Scenario` lets UDP through again and waits for the edge to go back.
`direct_ok` of a `Scenario` that expects relayed lets it go direct by luck
all the same: the reason is logged, and the rest of the checks go for
direct then.
`reload` of a `Scenario` names the site whose edge gets a changed
configuration file and SIGHUP after the warm-up (the check `reload:`).
`Site(link_mtu=1280)` gives the site's lan link (the edge's `eth0` and its
router's side) that MTU, and `drop_fragments` has its router drop IPv4
fragments before reassembly, as some firewalls do; `size` of a `Scenario`
sets the size of its frames.  `outage` of a `Scenario` kills all
supernodes after the warm-up, `outage_then` names what happens 10 seconds
into it (`("roam", site)`, `("restart", site)`, `("idle", seconds)`).
`sn_tcp_port` of a `Scenario` has the supernodes take TCP on that port only
(`bind = udp://... tcp://...`) and gives the edges `tcp://` entries for it;
`Site(tcp_only=True)` gives that edge only `tcp://` entries.  `sn_conf` of a `Scenario` sets options of the supernodes.
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
   - `description:` direct, each edge lists the other with its
   description (from the other's REGISTER, an edge of this tree only)
3. a counted burst, 500 frames each way at 200 per second (`--frames`,
   `--rate`, `--size`), then:
   - `frames:` all arrived, give or take `--loss` (1 percent)
   - `counters:` direct, the sender counted them as p2p tx and the
     receiver as p2p rx, and next to none went through the supernodes;
     relayed, the other way round
   - `relay:supernodes:` the supernodes' `sn_fwd` counted next to none
     of them (direct), or all of them (relayed)
   - `path:after:` the edges are still on the path they should be
   - `description after:` the edges still list each other with their
     descriptions: also after an edge lost its peer and found it again
     (idle, moved, restarted), when only the ACK to its REGISTER may
     come back, which tells nothing of who the peer is
   - `roam:` (roam) whether the edges are direct again after the move,
     and each way the longest time without a frame of the flow that ran
     across it
   - `outage:` (sn-outage...) each way the longest time without a frame of
     the flow that ran while the supernodes were gone; with a pause in it
     (sn-outage-idle), of the flow after the pause, counting from its first
     frame sent
   - `moves:` (dual-stack) with a trickle of frames each way for 4 more
     rounds of registration, how often each edge moved its peer to
     another address ("peer ... changed" in its log): at most once
4. no daemon died along the way, and all of them exit cleanly on SIGTERM

The peers' MAC addresses are set as permanent neighbours and the TAP
devices have no IPv6, so no ARP or neighbour discovery frames get counted
along with the test frames.
