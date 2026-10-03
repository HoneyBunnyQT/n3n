#
# Copyright (C) Honey Bunny QT
# SPDX-License-Identifier: GPL-3.0-only
#
"""The kinds of NAT a site's router can do, as nftables rulesets

Every router drops what comes in on its WAN side unless it belongs to a
connection made from inside, like a home router or a carrier NAT, so a
peer only gets in once the edge behind it has sent towards it.  The kinds
differ in how they map the inside port to a public one:

  easy-kept     the same public port for every destination, the inside
                port kept (Linux masquerade)
  easy-changed  the same public port for every destination, but another
                one than inside (a carrier NAT with one port per user)
  hard-range    a new random port for every destination, from a block of
                256 ports (a peer can guess it, see NatTraversal.md)
  hard-wide     a new random port for every destination, from all ports
  several       three uplinks: one public address towards sn1, one
                towards sn2, and a third towards everything else, so
                neither supernode sees the address the peers see

Each one also names the class the edge should see its NAT as.
"""

import re

# The fixed block the hard-range NAT takes ports from.  It ends at a
# multiple of 1024, so any port of it the supernodes see makes the edge's
# hint cover the whole block (the hint starts at a multiple of 1024 below
# the lowest port seen and is a power of two in size).
HARD_RANGE_LO = 20224
HARD_RANGE_HI = 20479

# The public port of the easy-changed NAT
EASY_CHANGED_PORT = 41000


class NatKind:
    def __init__(self, name, desc, rule, expect, wan_addrs=1):
        self.name = name
        self.desc = desc
        self._rule = rule
        self.expect = expect          # regex for the edge's nat4 class
        self.wan_addrs = wan_addrs

    def rule(self, wan, ctx):
        return self._rule(wan, ctx)


def _easy_kept(wan, ctx):
    return "masquerade"


def _easy_changed(wan, ctx):
    return (
        "meta l4proto udp snat ip to {}:{}\n"
        "        masquerade"
    ).format(wan[0], EASY_CHANGED_PORT)


def _hard_range(wan, ctx):
    return (
        "meta l4proto udp snat ip to {}:{}-{} random\n"
        "        masquerade"
    ).format(wan[0], HARD_RANGE_LO, HARD_RANGE_HI)


def _hard_wide(wan, ctx):
    return (
        "meta l4proto udp snat ip to {}:1024-65535 random\n"
        "        masquerade"
    ).format(wan[0])


def _several(wan, ctx):
    return (
        "ip daddr {} snat ip to {}\n"
        "        ip daddr {} snat ip to {}\n"
        "        snat ip to {}"
    ).format(ctx["sn1"], wan[0], ctx["sn2"], wan[1], wan[2])


KINDS = {k.name: k for k in [
    NatKind("easy-kept", "port kept, one port for all destinations",
            _easy_kept, r"^easy \(port kept\)$"),
    NatKind("easy-changed", "one public port, other than inside",
            _easy_changed, r"^easy \(port changed\)$"),
    NatKind("hard-range", "random port per destination, 256 port block",
            _hard_range, r"^hard \(ports \d+-\d+\)$"),
    NatKind("hard-wide", "random port per destination, any port",
            _hard_wide, r"^hard \(ports \d+-\d+\)$"),
    NatKind("several", "another public address per supernode and peers",
            _several, r"^several addresses$", wan_addrs=3),
]}

# Class of an edge without NAT
PUBLIC_EXPECT = r"^easy \(port kept\)$"


def ruleset(kind, wan, ctx):
    """The full nftables ruleset of a router doing this kind of NAT

    The inside is on "lan", the outside on "wan".
    """
    return """flush ruleset
table ip nat {{
    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
        oifname != "wan" accept
        {rule}
    }}
}}
table inet filter {{
    chain input {{
        type filter hook input priority filter; policy accept;
        iifname "wan" ct state established,related accept
        # neighbour discovery, without which no IPv6 gets routed here
        icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert }} accept
        iifname "wan" counter drop
    }}
    chain forward {{
        type filter hook forward priority filter; policy accept;
        iifname "wan" ct state established,related accept
        iifname "wan" counter drop
    }}
}}
""".format(rule=kind.rule(wan, ctx))


def expected_class(layers):
    """The class an edge behind these NATs (outermost first) should see"""
    if not layers:
        return PUBLIC_EXPECT
    names = set(layers)
    if "several" in names:
        return KINDS["several"].expect
    for hard in ("hard-wide", "hard-range"):
        if hard in names:
            return KINDS[hard].expect
    if names == {"easy-kept"}:
        return KINDS["easy-kept"].expect
    return KINDS["easy-changed"].expect


def hard_range_ok(nat4):
    """For a single hard-range NAT: is the range seen within the block?"""
    m = re.match(r"^hard \(ports (\d+)-(\d+)\)$", nat4)
    if not m:
        return False
    lo, hi = int(m.group(1)), int(m.group(2))
    return HARD_RANGE_LO <= lo <= hi <= HARD_RANGE_HI
