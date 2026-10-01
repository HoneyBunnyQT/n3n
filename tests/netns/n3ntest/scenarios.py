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
        Site(["hard-range", "easy-kept"], conf={"connection": {"punch_ttl": 3}}),
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
