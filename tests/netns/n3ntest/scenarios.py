#
# Copyright (C) Honey Bunny QT
# SPDX-License-Identifier: GPL-3.0-only
#
"""The scenarios, and the path each one should end up on

The expectations follow docs/advanced/NatTraversal.md.  Scenarios tagged
"quick" make up the set "make test" runs.
"""

from .scenario import Scenario, Site, version_built

# The release of upstream n3n the interop scenarios run against, see
# tests/netns/versions.sh: "tests/netns/versions.sh build n3n-3.4.6 3.4.6"
OLD = "n3n-3.4.6"
# The release of n2n they run against: IPv4 only, so a few basic ones
# "tests/netns/versions.sh build n2n-3.1.1 3.1.1 https://github.com/ntop/n2n"
N2N = "n2n-3.1.1"

SCENARIOS = [
    Scenario(
        "easy-easy",
        "both behind a port keeping NAT",
        Site(["easy-kept"]), Site(["easy-kept"]),
        "direct", tags=["quick"]),
    Scenario(
        "easy-changed",
        "port keeping NAT and a carrier NAT with one public port",
        Site(["easy-kept"]), Site(["easy-changed"]),
        "direct"),
    Scenario(
        "public-easy",
        "an edge without NAT and one behind a carrier NAT",
        Site([]), Site(["easy-changed"]),
        "direct"),
    Scenario(
        "fed-split",
        "each edge knows only its own supernode of the federation",
        Site(["easy-kept"], supernodes=["sn1"]),
        Site(["easy-changed"], supernodes=["sn2"]),
        "direct", tags=["quick"]),
    Scenario(
        "easy-hard",
        "easy NAT guesses the port of a peer behind a hard NAT",
        Site(["easy-kept"]), Site(["hard-range"]),
        "direct", tags=["quick"]),
    Scenario(
        "hard-easy",
        "hard NAT on the first edge, the second one guesses",
        Site(["hard-range"]), Site(["easy-changed"]),
        "direct"),
    Scenario(
        "easy-hard-a2b",
        "easy and hard NAT, only the easy side sends",
        Site(["easy-kept"]), Site(["hard-range"]),
        "direct", traffic="a2b"),
    Scenario(
        "easy-hard-b2a",
        "easy and hard NAT, only the hard side sends",
        Site(["easy-kept"]), Site(["hard-range"]),
        "direct", traffic="b2a"),
    Scenario(
        "easy-hard-pool",
        "16 guesses a round meet one of the ports of the hard side's sockets",
        Site(["easy-kept"], conf={"connection": {"punch_ports": 16}}),
        Site(["hard-range"]),
        "direct"),
    Scenario(
        "cgnat-hard-ttl",
        "the hard side behind a home router and a carrier NAT, its extra "
        "REGISTERs with a TTL to get through both",
        Site(["easy-kept"], conf={"connection": {"punch_ports": 16}}),
        Site(["hard-range", "easy-kept"],
             conf={"connection": {"punch_ttl": 3}}),
        "direct"),
    Scenario(
        "hard-hard",
        "hard NAT on both sides stays relayed",
        Site(["hard-range"]), Site(["hard-range"]),
        "relayed", tags=["quick"]),
    Scenario(
        "easy-wide",
        "a NAT with random ports from the whole range stays relayed",
        Site(["easy-kept"]), Site(["hard-wide"]),
        "relayed"),
    Scenario(
        "no-punch",
        "easy and hard NAT with port guessing turned off stays relayed",
        Site(["easy-kept"], conf={"connection": {"punch_ports": 0}}),
        Site(["hard-range"]),
        "relayed",
        direct_ok="the hard side's own REGISTERs may hit the port the "
        "easy NAT keeps for it"),
    Scenario(
        "several",
        "three uplinks, neither supernode sees the address peers see",
        Site(["several"]), Site(["easy-kept"]),
        "relayed"),
    Scenario(
        "failover-relayed",
        "relayed edges, the supernode of one gets killed",
        Site(["hard-range"]), Site(["hard-range"]),
        "relayed", failover="a"),
    Scenario(
        "failover-direct",
        "direct edges, the supernode of one gets killed",
        Site(["easy-kept"]), Site(["easy-changed"]),
        "direct", failover="a", tags=["quick"]),
    Scenario(
        "failover-userpw",
        "as failover-relayed, with user/password authentication: the "
        "edges authenticate again at the other supernode",
        Site(["hard-range"]), Site(["hard-range"]),
        "relayed", failover="a", auth="userpw"),
    Scenario(
        "failover-userpw-direct",
        "as failover-direct, with user/password authentication",
        Site(["easy-kept"]), Site(["easy-changed"]),
        "direct", failover="a", auth="userpw"),
    Scenario(
        "failover-header-enc",
        "as failover-relayed, with encrypted headers",
        Site(["hard-range"]), Site(["hard-range"]),
        "relayed", failover="a", auth="header"),
    Scenario(
        "failover-tcp",
        "an edge over TCP, its supernode gets killed: it connects to the "
        "other one",
        Site(["easy-kept"], conf={"connection": {"connect_tcp": True}},
             expect_nat=".*"),
        Site(["easy-changed"]),
        "relayed", failover="a"),
    Scenario(
        "cgnat-both",
        "home router behind a carrier NAT on both sides",
        Site(["easy-changed", "easy-kept"]),
        Site(["easy-changed", "easy-kept"]),
        "direct"),
    Scenario(
        "dual-stack",
        "both edges public with IPv4 and IPv6, a registers at the "
        "supernode over IPv6, b over IPv4: each learns the other at "
        "another family than it hears it from, and has to keep one",
        Site([], supernodes=["sn1"], sn_family=6, expect_nat="unknown"),
        Site([], supernodes=["sn1"], sn_family=4),
        "direct", ipv6=True, max_moves=1, tags=["ipv6"]),
    Scenario(
        "hard-hard-v6",
        "as hard-hard over IPv4, but each site has routed IPv6 behind its "
        "router's firewall, slower than IPv4 by 20 ms, and both edges know "
        "the supernode by IPv4 and IPv6 and pick by round trip: they "
        "should register over IPv6 all the same, and reach each other "
        "directly over it",
        Site(["hard-range"], supernodes=["sn1"], sn_family=46,
             expect_nat=".*"),
        Site(["hard-range"], supernodes=["sn1"], sn_family=46,
             expect_nat=".*"),
        "direct", ipv6=True, max_moves=1, delay6=20, tags=["ipv6"],
        conf={"connection": {"supernode_selection": "rtt"}}),
    Scenario(
        "fed-peers46",
        "as fed-split, with IPv6 too: the supernodes know each other by "
        "both addresses (supernode.peer twice).  A supernode once took "
        "itself for a member of its federation, at the address the other "
        "told it, and lost its edges' frames.  The NAT class may stay "
        "unknown: an edge may learn the other supernode by IPv6 only",
        Site(["easy-kept"], supernodes=["sn1"], expect_nat=".*"),
        Site(["easy-changed"], supernodes=["sn2"], expect_nat=".*"),
        "direct", ipv6=True, sn_peer_family=46, tags=["ipv6"]),
    Scenario(
        "fed-peers46-blocked",
        "as fed-peers46, the supernodes' firewalls let nothing in over "
        "IPv6: their IPv6 entries for each other are dead",
        Site(["easy-kept"], supernodes=["sn1"], expect_nat=".*"),
        Site(["easy-changed"], supernodes=["sn2"], expect_nat=".*"),
        "direct", ipv6=True, sn_peer_family=46, sn_block6=True,
        tags=["ipv6"]),
    Scenario(
        "fed-peers46-relayed",
        "as fed-peers46-blocked, hard-range / hard-range: the frames go "
        "across the federation",
        Site(["hard-range"], supernodes=["sn1"], expect_nat=".*"),
        Site(["hard-range"], supernodes=["sn2"], expect_nat=".*"),
        "relayed", ipv6=True, sn_peer_family=46, sn_block6=True,
        tags=["ipv6"]),
    Scenario(
        "hard-hard-v6-blocked",
        "as hard-hard-v6, but the supernodes' firewalls let nothing in over "
        "IPv6: the edges stay with IPv4, relayed as in hard-hard",
        Site(["hard-range"], supernodes=["sn1"], sn_family=46,
             expect_nat=".*"),
        Site(["hard-range"], supernodes=["sn1"], sn_family=46,
             expect_nat=".*"),
        "relayed", ipv6=True, delay6=20, sn_block6=True, tags=["ipv6"],
        conf={"connection": {"supernode_selection": "rtt"}}),
    Scenario(
        "v6-v4only",
        "a has IPv4 and IPv6 and registers over IPv6, b has IPv4 only, both "
        "behind port keeping NATs: the supernode has a's IPv4 address too "
        "and tells b that one, so they reach each other directly over IPv4",
        Site(["easy-kept"], supernodes=["sn1"], sn_family=46,
             expect_nat=".*"),
        Site(["easy-kept"], supernodes=["sn1"], sn_family=4, no_ipv6=True,
             expect_nat=".*"),
        "direct", ipv6=True, tags=["ipv6"]),
    Scenario(
        "roam",
        "b moves to another network (another NAT, its link and address "
        "gone) while frames flow both ways: the edge notices, registers "
        "again at once, and the edges are direct again within seconds",
        Site(["easy-kept"]),
        Site(["easy-kept"]),
        "direct", roam="b", roam_max_gap=5.0,
        # n3n's default: the edges' next round of registration is up to
        # 20s away, not the harness's 5s
        conf={"connection": {"register_interval": 20}}),
    Scenario(
        "roam-nowatch",
        "as roam, with connection.watch_network = false: the edges find "
        "each other again only with the next rounds of registration",
        Site(["easy-kept"]),
        Site(["easy-kept"]),
        "direct", roam="b", roam_max_gap=60.0, roam_direct=False,
        conf={"connection": {"register_interval": 20,
                             "watch_network": False}}),
    Scenario(
        "reload",
        "easy-kept / easy-changed; a's configuration loses the supernode a "
        "is at and gets another description, then a gets SIGHUP: it "
        "applies both while it runs, moves to the other supernode, and "
        "the edges stay direct",
        # a reload reads the file as the user the edge dropped to: in CI
        # the checkout, under the runner's home, is not readable for it
        Site(["easy-kept"], conf={"daemon": {"userid": 0, "groupid": 0}}),
        Site(["easy-changed"]),
        "direct", reload="a"),
    Scenario(
        "sn-outage",
        "both supernodes die while the edges are direct: the edges go on "
        "talking directly, for longer than their registrations live",
        Site(["easy-kept"]),
        Site(["easy-changed"]),
        "direct", outage=True, outage_max_gap=3.0),
    Scenario(
        "sn-outage-idle",
        "as sn-outage, and 10s into it the frames stop for 40s: the edges "
        "find each other again without a supernode",
        Site(["easy-kept"]),
        Site(["easy-changed"]),
        "direct", outage=True, outage_then=("idle", 40), outage_max_gap=3.0),
    Scenario(
        "sn-outage-roam",
        "as sn-outage, and 10s into it b moves to another network: with no "
        "supernode to tell a b's new address, a's NAT keeps b out",
        Site(["easy-kept"]),
        Site(["easy-kept"]),
        "direct", outage=True, outage_then=("roam", "b"), roam="b",
        tags=["limits"]),
    Scenario(
        "sn-outage-restart",
        "as sn-outage, and 10s into it b's edge restarts: it knows of no "
        "peer, and no supernode answers - a, which still knows b, gets it "
        "back (the gap counts the restart, ~10s without supernodes)",
        Site(["easy-kept"]),
        Site(["easy-kept"]),
        "direct", outage=True, outage_then=("restart", "b"),
        outage_max_gap=20.0),
    Scenario(
        "sn-outage-restart-userpw",
        "as sn-outage-restart, with user/password authentication: b waits "
        "for a supernode to vouch for it, and stays apart",
        Site(["easy-kept"]),
        Site(["easy-kept"]),
        "direct", outage=True, outage_then=("restart", "b"),
        auth="userpw", tags=["limits"]),
    Scenario(
        "mtu-1280",
        "b's link takes 1280 bytes (as PPPoE or a mobile network may), the "
        "frames are 1200: the packets between the edges get fragmented, "
        "and arrive",
        Site(["easy-kept"]),
        Site(["easy-kept"], link_mtu=1280),
        "direct", size=1200),
    Scenario(
        "mtu-1280-nofrag",
        "as mtu-1280, and b's router drops fragments, as some firewalls do: "
        "large frames do not get through",
        Site(["easy-kept"]),
        Site(["easy-kept"], link_mtu=1280, drop_fragments=True),
        "direct", size=1200, tags=["limits"]),
    Scenario(
        "mtu-1280-df",
        "as mtu-1280, with connection.pmtu_discovery: the edges send with "
        "DF, and what is too large gets dropped instead of fragmented",
        Site(["easy-kept"]),
        Site(["easy-kept"], link_mtu=1280),
        "direct", size=1200, tags=["limits"],
        conf={"connection": {"pmtu_discovery": True}}),
    Scenario(
        "interop-old-edge",
        "a is an edge of the last release (3.4.6), b and the supernodes are "
        "this tree: the edges go direct",
        Site(["easy-kept"], version=OLD),
        Site(["easy-changed"]),
        "direct", tags=["interop"]),
    Scenario(
        "interop-old-sn",
        "the supernodes are of the last release, the edges of this tree",
        Site(["easy-kept"]),
        Site(["easy-changed"]),
        "direct", sn_versions={"sn1": OLD, "sn2": OLD}, tags=["interop"]),
    Scenario(
        "interop-old-sn-hard",
        "as interop-old-sn, b behind a hard NAT: this tree's port guessing "
        "with supernodes of the last release",
        Site(["easy-kept"]),
        Site(["hard-range"]),
        "direct", sn_versions={"sn1": OLD, "sn2": OLD}, tags=["interop"]),
    Scenario(
        "interop-fed",
        "a federation of a supernode of the last release (sn1) and one of "
        "this tree (sn2), each edge knowing only one; a of the last release "
        "too",
        Site(["easy-kept"], supernodes=["sn1"], version=OLD),
        Site(["easy-changed"], supernodes=["sn2"]),
        "direct", sn_versions={"sn1": OLD}, tags=["interop"]),
    Scenario(
        "interop-relayed",
        "hard-range / hard-range, a of the last release, the supernodes "
        "one of each: the frames go through the supernodes",
        Site(["hard-range"], version=OLD),
        Site(["hard-range"]),
        "relayed", sn_versions={"sn1": OLD}, tags=["interop"]),
    Scenario(
        "interop-header-enc",
        "encrypted headers, a of the last release (which does not guess "
        "ports, so b's NAT is an easy one)",
        Site(["easy-kept"], version=OLD), Site(["easy-changed"]),
        "direct", auth="header", tags=["interop"]),
    Scenario(
        "interop-userpw",
        "user/password authentication, a and the supernodes of the last "
        "release",
        Site(["easy-kept"], version=OLD), Site(["easy-changed"]),
        "direct", auth="userpw", sn_versions={"sn1": OLD, "sn2": OLD},
        tags=["interop"]),
    Scenario(
        "interop-n2n-edge",
        "a is an edge of n2n 3.1.1, b and the supernodes are this tree: the "
        "edges go direct",
        Site(["easy-kept"], version=N2N),
        Site(["easy-changed"]),
        "direct", tags=["interop", "n2n"]),
    Scenario(
        "interop-n2n-sn",
        "the supernodes are of n2n 3.1.1, the edges of this tree",
        Site(["easy-kept"]),
        Site(["easy-changed"]),
        "direct", sn_versions={"sn1": N2N, "sn2": N2N},
        tags=["interop", "n2n"]),
    Scenario(
        "interop-n2n-fed",
        "a federation of a supernode of n2n 3.1.1 (sn1) and one of this "
        "tree (sn2), each edge knowing only one; a of n2n too",
        Site(["easy-kept"], supernodes=["sn1"], version=N2N),
        Site(["easy-changed"], supernodes=["sn2"]),
        "direct", sn_versions={"sn1": N2N}, tags=["interop", "n2n"]),
    Scenario(
        "interop-n2n-relayed",
        "hard-range / hard-range, a of n2n 3.1.1, the supernodes one of "
        "each: the frames go through the supernodes",
        Site(["hard-range"], version=N2N),
        Site(["hard-range"]),
        "relayed", sn_versions={"sn1": N2N}, tags=["interop", "n2n"]),
    Scenario(
        "interop-n2n-header-enc",
        "encrypted headers, a of n2n 3.1.1",
        Site(["easy-kept"], version=N2N), Site(["easy-changed"]),
        "direct", auth="header", tags=["interop", "n2n"]),
    Scenario(
        "same-lan",
        "both sites use 192.168.1.0/24, the edges at the same address",
        Site(["easy-kept"], lan="192.168.1.0/24"),
        Site(["easy-changed"], lan="192.168.1.0/24"),
        "direct"),
    Scenario(
        "tcp-tcp",
        "both edges reach the supernode over TCP only, which relays",
        Site(["easy-kept"], conf={"connection": {"connect_tcp": True}},
             expect_nat=".*"),
        Site(["easy-changed"], conf={"connection": {"connect_tcp": True}},
             expect_nat=".*"),
        "relayed", tags=["quick"]),
    Scenario(
        "tcp-udp",
        "one edge over TCP, the other over UDP, relayed between the two",
        Site(["easy-kept"], conf={"connection": {"connect_tcp": True}},
             expect_nat=".*"),
        Site(["easy-changed"]),
        "relayed"),
    Scenario(
        "hard-hard-threads",
        "relayed by supernodes that handle PACKETs on several threads",
        Site(["hard-range"]), Site(["hard-range"]),
        "relayed", sn_conf={"daemon": {"threads": 3}}),
    Scenario(
        "easy-hard-threads",
        "as easy-hard, edges and supernodes with packet threads, so the "
        "edges' control messages go through the queue to the main thread",
        Site(["easy-kept"]), Site(["hard-range"]),
        "direct", conf={"daemon": {"threads": 3}},
        sn_conf={"daemon": {"threads": 3}}),
    Scenario(
        "header-enc",
        "encrypted headers, the supernodes know the community from a file",
        Site(["easy-kept"]), Site(["hard-range"]),
        "direct", auth="header", tags=["quick"]),
    Scenario(
        "userpw",
        "encrypted headers and user/password authentication",
        Site(["easy-kept"]), Site(["hard-range"]),
        "direct", auth="userpw", tags=["quick"]),
    Scenario(
        "userpw-relayed",
        "user/password authentication, relayed by the federation",
        Site(["hard-range"], supernodes=["sn1"]),
        Site(["hard-range"], supernodes=["sn2"]),
        "relayed", auth="userpw"),
    Scenario(
        "userpw-conf",
        "user/password authentication, the community and its users in "
        "configuration sections instead of a file",
        Site(["hard-range"], supernodes=["sn1"]),
        Site(["hard-range"], supernodes=["sn2"]),
        "relayed", auth="userpw", community_conf=True, tags=["quick"]),
    Scenario(
        "sn-tap",
        "an edge behind a NAT and the TAP device of its supernode "
        "(supernode.tap)",
        Site(["hard-range"], supernodes=["sn2"]),
        Site(on_supernode="sn2"),
        "relayed", tags=["quick"]),
    Scenario(
        "sn-tap-fed",
        "as sn-tap, the edge at the other supernode of the federation",
        Site(["easy-kept"], supernodes=["sn1"]),
        Site(on_supernode="sn2"),
        "relayed"),
    Scenario(
        "sn-tap-userpw",
        "as sn-tap-fed, with user/password authentication",
        Site(["easy-kept"], supernodes=["sn1"]),
        Site(on_supernode="sn2"),
        "relayed", auth="userpw"),
    Scenario(
        "sn-tap-failover",
        "as sn-tap-fed, the edge's supernode gets killed: it moves to the "
        "supernode that is the other edge",
        Site(["easy-kept"], supernodes=["sn1", "sn2"],
             conf={"connection": {"supernode_selection": "mac"}}),
        Site(on_supernode="sn2"),
        "relayed", failover="a"),
    Scenario(
        "tcp-fallback",
        "an edge on a network without UDP reaches its supernode over TCP",
        Site(["easy-kept"], block_udp=True, expect_nat="unknown"),
        Site([]),
        "relayed", tags=["quick"]),
    Scenario(
        "tcp-fallback-back",
        "as tcp-fallback, then UDP gets through again: back to UDP, and "
        "direct",
        Site(["easy-kept"], block_udp=True),
        Site([]),
        "direct", unblock_udp=True),
    Scenario(
        "tcp-fallback-userpw",
        "as tcp-fallback-back, with user/password authentication",
        Site(["easy-kept"], block_udp=True),
        Site([]),
        "direct", unblock_udp=True, auth="userpw"),
    Scenario(
        "tcp-port",
        "as tcp-fallback-back, the supernodes with UDP on 7654 and TCP on "
        "4443 only, the edges told so by tcp:// entries",
        Site(["easy-kept"], block_udp=True),
        Site([]),
        "direct", unblock_udp=True, sn_tcp_port=4443, tags=["quick"]),
    Scenario(
        "tcp-only",
        "an edge given its supernodes as tcp:// only: over TCP from the "
        "start",
        Site(["easy-kept"], tcp_only=True, expect_nat="unknown"),
        Site([]),
        "relayed", sn_tcp_port=4443),
    Scenario(
        "tun-tap",
        "an edge with a TUN device (tuntap.type=tun) and one with a TAP "
        "device: the TUN edge builds the frames, both ways",
        Site(["easy-kept"], conf={"tuntap": {"type": "tun"}}),
        Site(["easy-changed"]),
        "direct", tags=["quick"]),
    Scenario(
        "tun-gateway",
        "a TUN edge with the TAP edge as its tuntap.gateway: an address "
        "outside the community, through the gateway edge",
        Site(["easy-kept"], conf={"tuntap": {"type": "tun"}}),
        Site(["easy-changed"]),
        "direct", gateway="b", tags=["quick"]),
    Scenario(
        "tun-tun",
        "two edges with TUN devices, relayed: each finds the other's MAC "
        "from what it announces",
        Site(["hard-range"], conf={"tuntap": {"type": "tun"}}),
        Site(["hard-range"], conf={"tuntap": {"type": "tun"}}),
        "relayed"),
]

BY_NAME = {s.name: s for s in SCENARIOS}


def _versions_built(sc):
    versions = [site.version for site in sc.sites.values() if site.version]
    return all(version_built(v)
               for v in versions + list(sc.sn_versions.values()))


def select(patterns):
    """Scenarios by name, fnmatch pattern or @tag; for none all but those
    tagged limits, which show what n3n cannot do (yet), and fail, and the
    interop ones of versions not built (tests/netns/versions.sh)"""
    import fnmatch
    if not patterns:
        return [s for s in SCENARIOS if "limits" not in s.tags
                and ("interop" not in s.tags or _versions_built(s))]
    out = []
    for pat in patterns:
        if pat.startswith("@"):
            found = [s for s in SCENARIOS if pat[1:] in s.tags]
        else:
            found = [s for s in SCENARIOS if fnmatch.fnmatch(s.name, pat)]
        if not found:
            raise KeyError(pat)
        out += [s for s in found if s not in out]
    return out
