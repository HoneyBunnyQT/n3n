#
# Copyright (C) Honey Bunny QT
# SPDX-License-Identifier: GPL-3.0-only
#
"""The scenarios, and the path each one should end up on

The expectations follow docs/advanced/NatTraversal.md.  Scenarios tagged
"quick" make up the set "make test" runs.
"""

from .scenario import Scenario, Site

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
        "relayed"),
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
        "tun-tun",
        "two edges with TUN devices, relayed: each finds the other's MAC "
        "from what it announces",
        Site(["hard-range"], conf={"tuntap": {"type": "tun"}}),
        Site(["hard-range"], conf={"tuntap": {"type": "tun"}}),
        "relayed"),
]

BY_NAME = {s.name: s for s in SCENARIOS}


def select(patterns):
    """Scenarios by name, fnmatch pattern or @tag; all for none"""
    import fnmatch
    if not patterns:
        return list(SCENARIOS)
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
