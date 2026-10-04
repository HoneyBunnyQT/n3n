#
# Copyright (C) Honey Bunny QT
# SPDX-License-Identifier: GPL-3.0-only
#
"""One test scenario: the network, the n3n daemons, the traffic, the checks

The network of a scenario:

                         "internet" 203.0.113.0/24 (a bridge)
       +-----------+-----------+----------+-----------+
      sn1         sn2       router a    router b    (an edge without NAT
   .1:7654      .2:7654       .11         .12        sits here, at .101+)
      federated supernodes      |           |
                             [more NAT   [more NAT
                              layers]     layers]
                                |           |
                             edge a      edge b
                         10.99.0.1/24  10.99.0.2/24  (the VPN)

A run of a scenario:

 1. build the namespaces, links and NAT rulesets
 2. start the supernodes, then the edges, and wait until they registered
 3. wait until each edge sorted its NAT into the expected class
 4. send a trickle of frames (the warm-up flow) until the edges reach each
    other directly - or, where they should not, watch that they stay
    relayed for a while
 5. send a counted burst of frames (the measured flow) and compare what
    arrived, and the edges' and supernodes' counters, with the path
    expected
 6. stop everything; a daemon that died or did not stop cleanly fails it
"""

import json
import os
import re
import signal
import subprocess
import sys
import time

from . import nat
from .lab import Lab, LabError, describe_exit, run, wait_for
from .node import Edge, MgmtError, Supernode, stats_delta

INET_NET = "203.0.113.{}"
INET_PREFIX = 24
# with Scenario(ipv6=True), the "internet" has IPv6 too (RFC 3849)
INET6_NET = "2001:db8::{}"
INET6_PREFIX = 64
# the IPv6 network of each site behind a router, routed, not translated
SITE6_NET = "2001:db8:{}::{}"
OVERLAY_NET = "10.99.0.{}"
OVERLAY_PREFIX = 24
# beyond the community, for tuntap.gateway (TEST-NET-1, RFC 5737)
GATEWAY_NET = "192.0.2.0/24"
GATEWAY_TARGET = "192.0.2.1"
EDGE_PORT = 50001
SN_PORT = 7654
TRAFFIC_PORT = 9000
COMMUNITY = "nettest"
KEY = "nettest-secret"
FEDERATION = "nettestfed"
PASSWORD = "nettest-password"

FLOW_WARM = 1
FLOW_MEAS = 2
FLOW_HOLD = 3
FLOW_ROAM = 4
# seconds of frames after the move, see Scenario.roam
ROAM_WATCH = 30

TRAFFIC_PY = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "traffic.py")


# A supernode's firewall that lets nothing in over IPv6 but neighbour
# discovery
SN_BLOCK6 = """table ip6 block6 {
    chain input {
        type filter hook input priority 0; policy accept;
        icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept
        iifname "eth0" drop
    }
}
"""

# What an airport's network lets out: no UDP but DNS (the overlay, on
# n3n0, is not the airport's)
AIRPORT = """table inet airport {
    chain output {
        type filter hook output priority 0; policy accept;
        oifname != "eth0" accept
        udp dport 53 accept
        meta l4proto udp drop
    }
}
"""


class Site:
    """An edge, and the NAT routers in front of it, outermost first.  Or,
    with on_supernode, the TAP device of that supernode (supernode.tap):
    no edge daemon, no NAT.  With block_udp, the edge cannot send UDP, as
    on some airport networks (see connection.tcp_fallback)."""

    def __init__(self, nat=(), lan=None, supernodes=("sn1", "sn2"),
                 conf=None, expect_nat=None, on_supernode=None,
                 block_udp=False, tcp_only=False, sn_family=4, no_ipv6=False):
        self.on_supernode = on_supernode
        # with Scenario(ipv6=True): this site has IPv4 only all the same
        self.no_ipv6 = no_ipv6
        # the address family the edge knows its supernodes by: 4, 6, or
        # 46 for both, each supernode twice (6 and 46 need
        # Scenario(ipv6=True))
        self.sn_family = sn_family
        self.block_udp = block_udp
        # the edge gets its supernodes as tcp://, at their TCP port
        self.tcp_only = tcp_only
        self.nat = list(nat)
        self.lan = lan                  # subnet of the innermost LAN
        self.supernodes = list(supernodes)
        self.conf = conf or {}          # {section: {option: value}}
        # the NAT class the edge should see, as a regular expression; by
        # default the one its NAT routers give, see nat.expected_class()
        self.expect_nat = expect_nat


class Scenario:
    def __init__(self, name, desc, a, b, expect, traffic="both",
                 tags=(), conf=None, connect_timeout=None, failover=None,
                 sn_conf=None, auth=None, community_conf=False,
                 unblock_udp=False, sn_tcp_port=None, gateway=None,
                 ipv6=False, max_moves=None, delay6=None, sn_block6=False,
                 roam=None, roam_max_gap=None, roam_direct=True):
        self.name = name
        self.desc = desc
        self.sites = {"a": a, "b": b}
        self.expect = expect            # "direct" or "relayed"
        self.traffic = traffic          # "both", "a2b" or "b2a"
        self.tags = set(tags)
        self.conf = conf or {}          # for all edges
        self.sn_conf = sn_conf or {}    # for all supernodes
        # None, "header" (header encryption: the supernodes know the
        # community from a community file) or "userpw" (also user/password
        # authentication: the file lists a user for each edge)
        self.auth = auth
        # With auth: the supernodes have the community, and its users, in
        # a [community NAME] section of their configuration instead of the
        # file, and the edges have theirs in such a section too
        self.community_conf = community_conf
        self.connect_timeout = connect_timeout
        # After the warm-up, kill (SIGKILL) the supernode this site's edge
        # is registered at, and measure once the edges moved to the other
        self.failover = failover
        # Once the edges of block_udp sites are on TCP, let UDP through
        # again and wait for them to go back to it
        self.unblock_udp = unblock_udp
        # The supernodes take UDP on SN_PORT and TCP on this port
        # (connection.bind udp:// and tcp://), and the edges know it
        # (community.supernode tcp://)
        self.sn_tcp_port = sn_tcp_port
        # The site whose edge is the other one's tuntap.gateway: it holds
        # GATEWAY_TARGET, outside the community, which the other pings
        self.gateway = gateway
        # The "internet", the supernodes and the edges on it without NAT
        # have IPv6 next to IPv4 (dual stack)
        self.ipv6 = ipv6
        # At most this many times an edge may move its peer to another
        # address ("peer ... changed" in its log) once they are direct
        self.max_moves = max_moves
        # Milliseconds more for IPv6 than IPv4 on the way out of each site
        # (its router's wan): IPv4 has the shorter round trip
        self.delay6 = delay6
        # The supernodes' firewalls drop what comes to them over IPv6
        self.sn_block6 = sn_block6
        # The site whose edge moves to another network while frames flow
        # both ways, as a laptop from one WiFi to another: its eth0 goes
        # down, eth1 up, behind a router of its own (a NAT of the kind of
        # the site's first one).  Then the longest time without a frame,
        # each way, should be at most roam_max_gap seconds.
        self.roam = roam
        self.roam_max_gap = roam_max_gap
        # whether the edges have to be direct again within ROAM_WATCH
        self.roam_direct = roam_direct

    def directions(self):
        return {
            "both": [("a", "b"), ("b", "a")],
            "a2b": [("a", "b")],
            "b2a": [("b", "a")],
        }[self.traffic]

    def nat_summary(self):
        def site(s):
            return "+".join(s.nat) if s.nat else "public"
        return "{} / {}".format(site(self.sites["a"]), site(self.sites["b"]))


class Settings:
    """What the command line sets for all scenarios"""

    def __init__(self, topdir, workdir, register_interval=5, punch_ports=128,
                 frames=500, rate=200, size=64, loss=0.01, verbose=2,
                 connect_timeout=90, relay_observe=None, wrap=()):
        self.topdir = topdir
        self.workdir = workdir
        self.edge_bin = os.path.join(topdir, "apps", "n3n-edge")
        self.sn_bin = os.path.join(topdir, "apps", "n3n-supernode")
        self.register_interval = register_interval
        self.punch_ports = punch_ports
        self.frames = frames
        self.rate = rate
        self.size = size
        self.loss = loss
        self.verbose = verbose
        self.connect_timeout = connect_timeout
        # How long relayed edges are watched for going direct: some rounds
        # of registration, by default
        self.relay_observe = relay_observe or 4 * register_interval + 2
        self.wrap = list(wrap)


class Check:
    def __init__(self, name, ok, detail):
        self.name = name
        self.ok = ok
        self.detail = detail

    def as_dict(self):
        return {"name": self.name, "ok": self.ok, "detail": self.detail}


class Run:
    def __init__(self, scenario, settings, prefix, log=None):
        self.sc = scenario
        self.st = settings
        self.prefix = prefix
        self.workdir = os.path.join(settings.workdir, scenario.name)
        self.lab = Lab(prefix, self.workdir)
        self.log_fn = log or (lambda msg: None)
        self.supernodes = {}
        self.edges = {}
        self.receivers = {}
        self.routers = {}
        self.checks = []
        self.killed = set()
        self.reported_dead = set()
        self.result = {
            "scenario": scenario.name,
            "desc": scenario.desc,
            "nat": scenario.nat_summary(),
            "expect": scenario.expect,
            "traffic": scenario.traffic,
        }
        self.t0 = time.monotonic()

    def log(self, msg):
        self.log_fn("[{} {:5.1f}s] {}".format(
            self.sc.name, time.monotonic() - self.t0, msg))

    def check(self, name, ok, detail):
        self.checks.append(Check(name, bool(ok), detail))
        self.log("{} {}: {}".format("ok  " if ok else "FAIL", name, detail))
        return ok

    # 1. The network

    def build(self):
        lab = self.lab
        if self.sc.ipv6 and not os.path.exists("/proc/sys/net/ipv6"):
            raise LabError("this kernel has no IPv6 (see tests/netns/uml.sh)")
        inet = lab.netns("inet")
        lab.bridge(inet, "br0")
        lab.addr(inet, "br0", "{}/{}".format(INET_NET.format(254),
                                             INET_PREFIX))
        if self.sc.ipv6:
            lab.addr(inet, "br0", "{}/{}".format(INET6_NET.format("fe"),
                                                 INET6_PREFIX))
            # the "internet" routes each site's IPv6 network to its router
            lab.sysctl(inet, "net.ipv6.conf.all.forwarding", 1)
        self.inet = inet

        for i, name in enumerate(("sn1", "sn2"), start=1):
            ns = lab.netns(name)
            lab.veth(inet, "x-" + name, ns, "eth0")
            lab.enslave(inet, "x-" + name, "br0")
            ip = INET_NET.format(i)
            lab.addr(ns, "eth0", "{}/{}".format(ip, INET_PREFIX))
            self.supernodes[name] = {"ns": ns, "ip": ip}
            if self.sc.ipv6:
                ip6 = INET6_NET.format(i)
                lab.addr(ns, "eth0", "{}/{}".format(ip6, INET6_PREFIX),
                         nodad=True)
                self.supernodes[name]["ip6"] = ip6
                self._route6(ns, "default", INET6_NET.format("fe"))
                if self.sc.sn_block6:
                    lab.nft(ns, SN_BLOCK6, name + "-block6")

        for i, (sname, site) in enumerate(sorted(self.sc.sites.items())):
            self._build_site(i, sname, site)
            if self.sc.roam == sname:
                self._build_roam(i, sname, site)

    def _build_site(self, i, sname, site):
        lab = self.lab
        if site.on_supernode:
            sn = self.supernodes[site.on_supernode]
            lab.sysctl(sn["ns"], "net.ipv6.conf.default.disable_ipv6", 1,
                       optional=True)
            self.edges[sname] = {
                "ns": sn["ns"],
                "ip": sn["ip"],
                "index": i,
                "overlay": OVERLAY_NET.format(i + 1),
                "mac": "02:00:00:99:00:{:02x}".format(i + 1),
                "on_supernode": site.on_supernode,
            }
            return
        up_ns, up_if = self.inet, "x-" + sname
        up_bridge = True
        up_net = None
        layers = site.nat
        ctx = {sn: v["ip"] for sn, v in self.supernodes.items()}

        for depth, kind_name in enumerate(layers):
            kind = nat.KINDS[kind_name]
            ns = lab.netns("{}-r{}".format(sname, depth))
            lab.sysctl(ns, "net.ipv4.ip_forward", 1)
            lab.veth(up_ns, up_if, ns, "wan")
            if up_bridge:
                lab.enslave(up_ns, up_if, "br0")
                # .11, .12, ... and further addresses at +20, +40
                wan = [INET_NET.format(11 + i + 20 * k)
                       for k in range(kind.wan_addrs)]
                for w in wan:
                    lab.addr(ns, "wan", "{}/{}".format(w, INET_PREFIX))
            else:
                if kind.wan_addrs > 1:
                    raise LabError("{} only works as the outermost NAT"
                                   .format(kind_name))
                lab.addr(up_ns, up_if, "{}/24".format(up_net.format(1)))
                wan = [up_net.format(2)]
                lab.addr(ns, "wan", "{}/24".format(wan[0]))
                lab.route(ns, "default", up_net.format(1))
            if self.sc.ipv6 and not site.no_ipv6:
                # IPv6 is routed, not translated: the site's own /64
                # behind the router's stateful firewall (nat.ruleset)
                if not up_bridge:
                    raise LabError("ipv6 takes one NAT layer at most")
                wan6 = INET6_NET.format(11 + i)
                lab.addr(ns, "wan", "{}/{}".format(wan6, INET6_PREFIX),
                         nodad=True)
                lab.sysctl(ns, "net.ipv6.conf.all.forwarding", 1)
                self._route6(ns, "default", INET6_NET.format("fe"))
                self._route6(self.inet, SITE6_NET.format(i + 1, "") +
                             "/64", wan6)
                if self.sc.delay6:
                    self._delay6(ns, "wan", self.sc.delay6)
            lab.nft(ns, nat.ruleset(kind, wan, ctx),
                    "{}-r{}".format(sname, depth))
            self.routers["{}-r{}".format(sname, depth)] = ns

            last = depth == len(layers) - 1
            if last and site.lan:
                base = site.lan.split("/")[0].rsplit(".", 1)[0]
            else:
                base = "10.{}.{}".format(i + 1, depth)
            up_net = base + ".{}"
            up_ns, up_if, up_bridge = ns, "lan", False

        ns = lab.netns(sname)
        lab.veth(up_ns, up_if, ns, "eth0")
        if up_bridge:
            lab.enslave(up_ns, up_if, "br0")
            ip = INET_NET.format(101 + i)
            lab.addr(ns, "eth0", "{}/{}".format(ip, INET_PREFIX))
            if self.sc.ipv6 and not site.no_ipv6:
                lab.addr(ns, "eth0", "{}/{}".format(
                    INET6_NET.format(101 + i), INET6_PREFIX), nodad=True)
                # as a LAN with a default route has: the edges find each
                # other by IPv4 multicast too (local_discovery), not only
                # by IPv6
                run(["ip", "-n", ns, "route", "add", "224.0.0.0/4",
                     "dev", "eth0"])
                self._route6(ns, "default", INET6_NET.format("fe"))
        else:
            lab.addr(up_ns, up_if, "{}/24".format(up_net.format(1)))
            ip = up_net.format(2)
            lab.addr(ns, "eth0", "{}/24".format(ip))
            lab.route(ns, "default", up_net.format(1))
            if self.sc.ipv6 and not site.no_ipv6:
                lab.addr(up_ns, up_if, "{}/64".format(
                    SITE6_NET.format(i + 1, "1")), nodad=True)
                lab.addr(ns, "eth0", "{}/64".format(
                    SITE6_NET.format(i + 1, "2")), nodad=True)
                self._route6(ns, "default", SITE6_NET.format(i + 1, "1"))
        # The TAP device comes up without IPv6, so no neighbour discovery
        # or MLD frames get counted alongside the test frames
        lab.sysctl(ns, "net.ipv6.conf.default.disable_ipv6", 1, optional=True)
        if site.block_udp:
            lab.nft(ns, AIRPORT, sname + "-airport")

        self.edges[sname] = {
            "ns": ns,
            "ip": ip,
            "index": i,
            "overlay": OVERLAY_NET.format(i + 1),
            "mac": "02:00:00:99:00:{:02x}".format(i + 1),
            "expect_nat": (site.expect_nat if site.expect_nat is not None
                           else nat.expected_class(layers)),
        }

    def _build_roam(self, i, sname, site):
        """The other network the edge of the site moves to, see roam"""
        lab = self.lab
        if len(site.nat) != 1:
            raise LabError("roam takes a site behind one NAT")
        kind = nat.KINDS[site.nat[0]]
        ns = lab.netns("{}-alt".format(sname))
        lab.sysctl(ns, "net.ipv4.ip_forward", 1)
        lab.veth(self.inet, "x-{}-alt".format(sname), ns, "wan")
        lab.enslave(self.inet, "x-{}-alt".format(sname), "br0")
        wan = [INET_NET.format(41 + i + 20 * k) for k in range(kind.wan_addrs)]
        for w in wan:
            lab.addr(ns, "wan", "{}/{}".format(w, INET_PREFIX))
        ctx = {sn: v["ip"] for sn, v in self.supernodes.items()}
        lab.nft(ns, nat.ruleset(kind, wan, ctx), sname + "-alt")
        self.routers[sname + "-alt"] = ns
        net = "10.{}.9.{{}}".format(i + 1)
        e = self.edges[sname]
        lab.veth(ns, "lan", e["ns"], "eth1")
        lab.addr(ns, "lan", net.format(1) + "/24")
        lab.addr(e["ns"], "eth1", net.format(2) + "/24")
        run(["ip", "-n", e["ns"], "link", "set", "eth1", "down"])
        e["roam_gw"] = net.format(1)

    def roam_switch(self, sname):
        """The edge's network goes, another one comes"""
        e = self.edges[sname]
        run(["ip", "-n", e["ns"], "link", "set", "eth0", "down"])
        run(["ip", "-n", e["ns"], "link", "set", "eth1", "up"])
        run(["ip", "-n", e["ns"], "route", "replace", "default",
             "via", e["roam_gw"]])

    def roam_phase(self):
        """Frames both ways while an edge moves to another network: how
        long each way goes without, and whether the edges are direct again
        after"""
        self.roam_flows = {(s, d): self.sender(s, d, FLOW_ROAM, 0, 20)
                           for s, d in self.sc.directions()}
        time.sleep(4)
        self.log("moving the edge of {} to another network".format(
            self.sc.roam))
        self.roam_switch(self.sc.roam)
        # long enough for a round of registration (20s by default) and
        # more: what goes missing shows as the longest gap
        time.sleep(ROAM_WATCH)
        for p in self.roam_flows.values():
            p.stop()
        direct = all(m == "p2p" for m in self.modes().values())
        self.check("roam:path", direct or not self.sc.roam_direct,
                   "{} {}s after the move".format(
                       self._modes_str(self.modes()), ROAM_WATCH))

    def check_roam(self, received):
        gaps = {}
        for (src, dst) in self.sc.directions():
            f = received.get(dst, {}).get(str(FLOW_ROAM), {})
            sent = self._read_json(self.roam_flows[(src, dst)].out.name)
            # between two frames, or from the last one to the end of the
            # flow, when none came any more
            gap = max(f.get("gap_max_ms", 0) / 1000.0,
                      sent.get("last", 0) - f.get("last", 0))
            gaps["{}->{}".format(src, dst)] = round(gap, 1)
            ok = bool(f) and gap <= self.sc.roam_max_gap
            self.check("roam:{}->{}".format(src, dst), ok,
                       "{} frames, longest gap {:.1f}s{}".format(
                           f.get("unique", 0), gap,
                           "" if ok else " (more than {}s)".format(
                               self.sc.roam_max_gap)))
        self.result["roam_gaps"] = gaps

    def _delay6(self, ns, dev, ms):
        """Delay the IPv6 packets leaving through dev by ms milliseconds"""
        tc = ["ip", "netns", "exec", ns, "tc"]
        run(tc + ["qdisc", "add", "dev", dev, "root", "handle", "1:",
                  "prio"])
        run(tc + ["qdisc", "add", "dev", dev, "parent", "1:3", "handle",
                  "30:", "netem", "delay", "{}ms".format(ms)])
        run(tc + ["filter", "add", "dev", dev, "parent", "1:0", "protocol",
                  "ipv6", "prio", "1", "u32", "match", "u32", "0", "0",
                  "flowid", "1:3"])

    def _route6(self, ns, dst, via):
        run(["ip", "-6", "-n", ns, "route", "add", dst, "via", via])

    # 2. The daemons

    def _session(self, name):
        return "{}{}".format(self.prefix, name)

    def _keygen(self, *args):
        """What "n3n-edge tools keygen" says, without the line's prefix"""
        argv = [self.st.edge_bin, "tools", "keygen"] + list(args)
        out = subprocess.run(argv, capture_output=True, text=True).stdout
        out = out.strip()
        return out.split()[-1].split("=")[-1]

    def _users(self):
        """The (name, public key) of the user of each edge"""
        if self.sc.auth != "userpw":
            return []
        return [(sname, self._keygen(sname, PASSWORD))
                for sname in sorted(self.sc.sites)]

    def _community_file(self):
        """The community file of the supernodes, None if they need none"""
        if not self.sc.auth or self.sc.community_conf:
            return None
        lines = [COMMUNITY]
        lines += ["* {} {}".format(*user) for user in self._users()]
        path = os.path.join(self.workdir, "community.list")
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        return path

    def start_supernodes(self):
        names = sorted(self.supernodes)
        community_file = self._community_file()
        users = self._users()
        for i, name in enumerate(names, start=1):
            sn = self.supernodes[name]
            peers = [("peer", "{}:{}".format(self.supernodes[o]["ip"],
                                             SN_PORT))
                     for o in names if o != name]
            sections = {
                "connection": [("bind", "[::]:{}".format(SN_PORT)
                                if not self.sc.sn_tcp_port else
                                "udp://[::]:{} tcp://[::]:{}".format(
                                    SN_PORT, self.sc.sn_tcp_port))],
                "supernode": [("federation", FEDERATION),
                              ("macaddr", "02:00:00:5e:00:{:02x}".format(i))]
                + peers,
                "daemon": [("background", False)],
                "logging": [("verbose", self.st.verbose)],
            }
            if community_file:
                sections["supernode"].append(
                    ("community_file", community_file))
            if self.sc.auth and self.sc.community_conf:
                sections["community " + COMMUNITY] = [
                    ("header_encryption", True)
                ] + [("user", "{} {}".format(*user)) for user in users]
            for sname, e in self.edges.items():
                if e.get("on_supernode") == name:
                    self._tap_sections(sections, sname, e)
            for section, options in self.sc.sn_conf.items():
                sections.setdefault(section, [])
                sections[section] = [
                    (o, v) for o, v in sections[section] if o not in options
                ] + list(options.items())
            d = Supernode(self.lab, name, sn["ns"], self._session(name),
                          self.st.sn_bin, sections, wrap=self.st.wrap)
            d.start()
            sn["daemon"] = d
        for name in names:
            d = self.supernodes[name]["daemon"]
            if not d.wait_mgmt():
                raise LabError("supernode {} did not start: {}".format(
                    name, describe_exit(d.proc.popen.poll()) +
                    "\n" + d.proc.log_tail()))

    def _tap_sections(self, sections, sname, e):
        """The settings of a supernode's own edge, see Site.on_supernode"""
        edge = dict(self._edge_sections(sname, self.sc.sites[sname], e))
        sections["supernode"].append(("tap", True))
        community = [k for k in edge if k.startswith("community")][0]
        sections[community] = sections.get(community, []) + [
            (o, v) for o, v in edge[community] if o != "supernode"]
        sections["tuntap"] = edge["tuntap"]
        sections["connection"] += [
            (o, v) for o, v in edge["connection"]
            if o in ("description", "register_interval")]
        if "auth" in edge:
            # the supernode knows the public key of its federation
            sections["auth"] = [(o, v) for o, v in edge["auth"]
                                if o != "pubkey"]

    def _edge_sections(self, sname, site, e):
        conf = {
            "community": {
                "name": COMMUNITY,
                "key": KEY,
            },
            "connection": {
                "bind": "[::]:{}".format(EDGE_PORT),
                "description": sname,
                "register_interval": self.st.register_interval,
                "punch_ports": self.st.punch_ports,
            },
            "daemon": {"background": False},
            "logging": {"verbose": self.st.verbose},
            "tuntap": {
                "name": "n3n0",
                "address_mode": "static",
                "address": "{}/{}".format(e["overlay"], OVERLAY_PREFIX),
                "macaddr": e["mac"],
            },
        }
        if self.sc.auth:
            conf["community"]["header_encryption"] = True
        if self.sc.auth == "userpw":
            # it takes ChaCha20 or Speck; the description is the user name
            conf["community"]["cipher"] = "ChaCha20"
            conf["auth"] = {
                "password": PASSWORD,
                "pubkey": self._keygen(FEDERATION),
            }
        for overrides in (self.sc.conf, site.conf):
            for section, options in overrides.items():
                conf.setdefault(section, {}).update(options)
        if self.sc.gateway == sname:
            conf.setdefault("filter", {})["allow_routing"] = True
        elif self.sc.gateway:
            conf["tuntap"]["gateway"] = self.edges[self.sc.gateway]["overlay"]
        community = "community"
        if self.sc.community_conf:
            # the edge's only community, from a named section
            community = "community " + conf["community"].pop("name")
            conf[community] = conf.pop("community")
        sections = {s: list(o.items()) for s, o in conf.items()}
        tcp_port = self.sc.sn_tcp_port or SN_PORT
        for sn in site.supernodes:
            ips = {4: [self.supernodes[sn]["ip"]],
                   6: ["[{}]".format(self.supernodes[sn].get("ip6"))],
                   46: [self.supernodes[sn]["ip"],
                        "[{}]".format(self.supernodes[sn].get("ip6"))],
                   }[site.sn_family]
            for ip in ips:
                if not site.tcp_only:
                    sections[community].append(
                        ("supernode", "{}:{}".format(ip, SN_PORT)))
                if site.tcp_only or self.sc.sn_tcp_port:
                    sections[community].append(
                        ("supernode", "tcp://{}:{}".format(ip, tcp_port)))
        return sections

    def start_edges(self):
        self.t_edges = time.monotonic()
        for sname, site in sorted(self.sc.sites.items()):
            e = self.edges[sname]
            if site.on_supernode:
                e["registered_at"] = "{}:{}".format(e["ip"], SN_PORT)
                continue
            d = Edge(self.lab, "edge-" + sname, e["ns"], self._session(sname),
                     self.st.edge_bin, self._edge_sections(sname, site, e),
                     wrap=self.st.wrap, overlay_ip=e["overlay"], mac=e["mac"])
            d.start()
            e["daemon"] = d
        for sname, e in sorted(self.edges.items()):
            if "daemon" not in e:
                continue
            d = e["daemon"]
            if not d.wait_mgmt():
                raise LabError("edge {} did not start: {}\n{}".format(
                    sname, describe_exit(d.proc.popen.poll()),
                    d.proc.log_tail()))
        for sname, e in sorted(self.edges.items()):
            if "daemon" not in e:
                continue
            d = e["daemon"]
            # without UDP, over TCP once the edge fell back to it
            tcp = self.sc.sites[sname].block_udp or \
                self.sc.sites[sname].tcp_only

            def ready():
                if not d.proc.alive():
                    return True
                if tcp and (d.mgmt.try_call("get_info") or {}) \
                        .get("transport") != "tcp":
                    return False
                return d.registered()
            if not wait_for(ready, 20 + (20 if tcp else 0)) \
                    or not d.proc.alive():
                raise LabError("edge {} did not register at a supernode\n{}"
                               .format(sname, d.proc.log_tail()))
            e["registered_at"] = d.current_supernode()
        self.result["registered_at"] = {
            s: e["registered_at"] for s, e in self.edges.items()}
        self.log("edges registered: " + ", ".join(
            "{} at {}".format(s, e["registered_at"])
            for s, e in sorted(self.edges.items())))

        # The peers' MACs are known up front: no ARP frames in the counts.
        # A TUN device has no neighbours: there the edge finds the MACs.
        for sname, e in self.edges.items():
            if self.sc.sites[sname].conf.get("tuntap", {}).get("type") \
                    == "tun":
                continue
            for oname, o in self.edges.items():
                if oname != sname:
                    run(["ip", "-n", e["ns"], "neigh", "replace",
                         o["overlay"], "lladdr", o["mac"], "dev", "n3n0",
                         "nud", "permanent"])

    def daemons(self):
        """The daemons started, less the ones killed on purpose"""
        out = [(n, s["daemon"]) for n, s in sorted(self.supernodes.items())
               if "daemon" in s]
        out += [("edge-" + n, e["daemon"])
                for n, e in sorted(self.edges.items()) if "daemon" in e]
        return [(n, d) for n, d in out if n not in self.killed]

    def check_alive(self, phase):
        dead = [(n, d) for n, d in self.daemons() if not d.proc.alive()]
        for n, d in dead:
            if n in self.reported_dead:
                continue
            self.reported_dead.add(n)
            self.check("alive:" + n, False, "died during {}: {}\n{}".format(
                phase, describe_exit(d.proc.popen.poll()), d.proc.log_tail()))
        return not dead

    # 3. NAT classes

    def wait_nat_classes(self, timeout):
        edges = {s: e for s, e in self.edges.items() if "daemon" in e}

        def settled():
            for e in edges.values():
                info = e["daemon"].mgmt.try_call("get_info") or {}
                e["nat4"] = info.get("nat4", "?")
            return all(re.match(e["expect_nat"], e["nat4"])
                       for e in edges.values())
        t = time.monotonic()
        wait_for(settled, timeout, interval=0.5)
        took = round(time.monotonic() - t, 1)
        for sname, e in sorted(edges.items()):
            ok = re.match(e["expect_nat"], e["nat4"])
            detail = "nat4 {!r}".format(e["nat4"])
            site = self.sc.sites[sname]
            if site.nat == ["hard-range"] and site.expect_nat is None and ok:
                ok = nat.hard_range_ok(e["nat4"])
                detail += ", NAT block {}-{}".format(nat.HARD_RANGE_LO,
                                                     nat.HARD_RANGE_HI)
            if not ok:
                detail += ", expected /{}/".format(e["expect_nat"])
            else:
                detail += " after {}s".format(took)
            self.check("nat:" + sname, ok, detail)
        self.result["nat4"] = {s: e["nat4"] for s, e in edges.items()}

    # 4. Traffic

    def start_receivers(self):
        for sname, e in self.edges.items():
            self.receivers[sname] = self.lab.spawn(
                "recv-" + sname, e["ns"],
                [sys.executable, TRAFFIC_PY, "recv", "--bind",
                 "{}:{}".format(e["overlay"], TRAFFIC_PORT)],
                stdout_path=os.path.join(self.workdir,
                                         "recv-{}.json".format(sname)))

    def sender(self, src, dst, flow, count, rate):
        s, d = self.edges[src], self.edges[dst]
        name = "send-{}{}-{}".format(src, dst, flow)
        return self.lab.spawn(
            name, s["ns"],
            [sys.executable, TRAFFIC_PY, "send",
             "--src", s["overlay"],
             "--to", "{}:{}".format(d["overlay"], TRAFFIC_PORT),
             "--flow", str(flow), "--count", str(count),
             "--rate", str(rate), "--size", str(self.st.size)],
            stdout_path=os.path.join(self.workdir, name + ".json"))

    def modes(self):
        """{(src, dst): mode} of each sending edge's entry for its peer"""
        out = {}
        for src, dst in self.sc.directions():
            if "daemon" not in self.edges[src]:
                # a supernode's own edge always goes through it
                out[(src, dst)] = "pSp"
                continue
            mode, _ = self.edges[src]["daemon"].peer(self.edges[dst]["mac"])
            out[(src, dst)] = mode
        return out

    def warm_up(self):
        warm = [self.sender(s, d, FLOW_WARM, 0, 10)
                for s, d in self.sc.directions()]
        t = time.monotonic()
        if self.sc.expect == "direct":
            timeout = self.sc.connect_timeout or self.st.connect_timeout
            reached = wait_for(
                lambda: all(m == "p2p" for m in self.modes().values())
                or not self.check_alive_quiet(),
                timeout, interval=0.5)
            # counted from the start of the edges, as edges that can reach
            # each other easily often do so before the first frame
            took = round(time.monotonic() - self.t_edges, 1)
            modes = self.modes()
            ok = reached and all(m == "p2p" for m in modes.values())
            self.result["time_to_direct"] = took if ok else None
            self.check("path", ok,
                       "direct {}s after the edges started".format(took)
                       if ok else
                       "still {} {}s after the edges started".format(
                           self._modes_str(modes), took))
            # Let a few frames go the new way before measuring
            time.sleep(1)
        else:
            went_direct = None
            end = t + self.st.relay_observe
            while time.monotonic() < end:
                modes = self.modes()
                if any(m == "p2p" for m in modes.values()):
                    went_direct = round(time.monotonic() - t, 1)
                    break
                if not self.check_alive_quiet():
                    break
                time.sleep(0.5)
            self.check("path", went_direct is None,
                       "relayed for {}s".format(self.st.relay_observe)
                       if went_direct is None else
                       "went direct after {}s".format(went_direct))
        for p in warm:
            p.stop()

    def transports(self):
        """{site: transport} of the edges"""
        return {s: (e["daemon"].mgmt.try_call("get_info") or {})
                .get("transport") for s, e in self.edges.items()
                if "daemon" in e}

    def check_transport(self):
        """The edges of block_udp and tcp_only sites on TCP, the others on
        UDP, and with unblock_udp the block_udp ones back on UDP once it
        gets through"""
        tcp = [s for s, site in self.sc.sites.items()
               if site.block_udp or site.tcp_only]
        blocked = [s for s, site in self.sc.sites.items() if site.block_udp]
        if not tcp:
            return
        now = self.transports()
        self.result["transport"] = now
        ok = all(now.get(s) == ("tcp" if s in tcp else "udp") for s in now)
        self.check("transport", ok, ", ".join(
            "{} {}".format(s, now.get(s)) for s in sorted(now)))
        if not ok or not self.sc.unblock_udp or not blocked:
            return
        for s in blocked:
            run(["nft", "delete", "table", "inet", "airport"],
                ns=self.edges[s]["ns"])
        t = time.monotonic()

        def back():
            if not self.check_alive_quiet():
                return "dead"
            now = self.transports()
            return "ok" if all(now.get(s) == "udp" for s in blocked) \
                else None
        # a probe every three register intervals
        ok = wait_for(back, 10 + 4 * self.st.register_interval,
                      interval=0.5) == "ok"
        took = round(time.monotonic() - t, 1)
        now = self.transports()
        self.result["transport_back"] = {"seconds": took, "transport": now}
        self.check("transport:back", ok, "{} after {}s".format(", ".join(
            "{} {}".format(s, now.get(s)) for s in sorted(now)), took))

    def check_alive_quiet(self):
        return all(d.proc.alive() for _, d in self.daemons())

    def failover(self):
        """Kill the supernode an edge is at, wait for the edges to move"""
        site = self.sc.failover
        at = self.edges[site]["daemon"].current_supernode() or ""
        victim = None
        for name, sn in self.supernodes.items():
            if at.startswith(sn["ip"] + ":"):
                victim = name
        if not victim:
            return self.check("failover", False,
                              "edge {} is at no known supernode ({!r})"
                              .format(site, at))
        hosted = [s for s, e in self.edges.items()
                  if e.get("on_supernode") == victim]
        if hosted:
            return self.check("failover", False,
                              "edge {} is at {}, which is the edge {} itself"
                              .format(site, victim, hosted[0]))
        self.supernodes[victim]["daemon"].proc.stop(sig=signal.SIGKILL)
        self.killed.add(victim)
        ip = self.supernodes[victim]["ip"] + ":"
        t = time.monotonic()

        def moved():
            if not self.check_alive_quiet():
                return "dead"
            for e in self.edges.values():
                if "daemon" not in e:
                    continue
                now = e["daemon"].current_supernode() or ip
                if now.startswith(ip) or not e["daemon"].registered():
                    return None
            return "ok"
        ok = wait_for(moved, 60 + 4 * self.st.register_interval,
                      interval=0.5) == "ok"
        took = round(time.monotonic() - t, 1)
        where = {s: (e["daemon"].current_supernode() if "daemon" in e
                     else e["registered_at"])
                 for s, e in self.edges.items()}
        self.result["failover"] = {"killed": victim, "seconds": took,
                                   "registered_at": where}
        self.check("failover", ok, "killed {}, edges at {} after {}s".format(
            victim, ", ".join("{} {}".format(s, w)
                              for s, w in sorted(where.items())), took))
        # A round of registrations for the peers to find each other again
        time.sleep(self.st.register_interval + 1)

    @staticmethod
    def _modes_str(modes):
        return ", ".join("{}->{} {}".format(s, d, m or "unknown")
                         for (s, d), m in sorted(modes.items()))

    # 5. The measured burst

    def snapshot(self):
        snap = {}
        for name, d in self.daemons():
            try:
                snap[name] = d.stats()
            except MgmtError as e:
                snap[name] = {"error": str(e)}
        return snap

    def measure(self):
        n = self.st.frames
        before = self.snapshot()
        senders = {(s, d): self.sender(s, d, FLOW_MEAS, n, self.st.rate)
                   for s, d in self.sc.directions()}
        limit = 10 + 2 * n / self.st.rate
        for p in senders.values():
            wait_for(lambda: not p.alive(), limit)
            p.stop()
        time.sleep(1.0)   # the last frames on their way
        after = self.snapshot()
        modes = self.modes()
        self.result["modes_after"] = {"{}->{}".format(s, d): m
                                      for (s, d), m in modes.items()}

        deltas = {}
        for name in after:
            if "error" in after[name] or "error" in before.get(name, {}):
                continue
            deltas[name] = stats_delta(before[name], after[name])
        self.result["counters"] = {
            name: {t: v for t, v in delta.items()
                   if t in ("transop", "p2p", "super", "sn_fwd",
                            "sn_broadcast") and any(v.values())}
            for name, delta in deltas.items()}

        sent = {}
        for key, p in senders.items():
            sent[key] = self._read_json(p.out.name).get("sent", 0)
        return n, sent, deltas, modes

    def _read_json(self, path):
        try:
            with open(path) as f:
                return json.loads(f.read().strip() or "{}")
        except (OSError, ValueError):
            return {}

    def stop_receivers(self):
        got = {}
        for sname, p in self.receivers.items():
            p.stop()
            got[sname] = self._read_json(p.out.name).get("flows", {})
        return got

    def evaluate(self, n, sent, deltas, modes, received):
        slack = max(5, int(0.02 * n))
        need = int(n * (1 - self.st.loss))
        sn_fwd = sum(deltas.get(sn, {}).get("sn_fwd", {}).get("tx_pkt", 0)
                     for sn in self.supernodes)
        frames = {}
        for (src, dst) in self.sc.directions():
            tag = "{}->{}".format(src, dst)
            meas = received.get(dst, {}).get(str(FLOW_MEAS), {})
            warm = received.get(dst, {}).get(str(FLOW_WARM), {})
            got = meas.get("unique", 0)
            frames[tag] = {
                "sent": sent.get((src, dst), 0),
                "received": got,
                "dup": meas.get("dup", 0),
                "reordered": meas.get("reordered", 0),
                "lat_avg_ms": meas.get("lat_avg_ms"),
                "lat_max_ms": meas.get("lat_max_ms"),
                "warmup_received": warm.get("unique", 0),
                "warmup_gaps": warm.get("gaps", 0),
            }
            self.check("frames:" + tag, got >= need and
                       sent.get((src, dst), 0) == n,
                       "{}/{} arrived ({} dup, {} reordered)".format(
                           got, n, meas.get("dup", 0),
                           meas.get("reordered", 0)))

            tx = deltas.get("edge-" + src, {})
            rx = deltas.get("edge-" + dst, {})
            tx_p2p = tx.get("p2p", {}).get("tx_pkt", 0)
            tx_sup = tx.get("super", {}).get("tx_pkt", 0)
            rx_p2p = rx.get("p2p", {}).get("rx_pkt", 0)
            rx_sup = rx.get("super", {}).get("rx_pkt", 0)
            # a supernode's own edge has no counters of its own: take what
            # the other side counted
            if "daemon" not in self.edges[src]:
                tx_p2p, tx_sup = rx_p2p, rx_sup
            if "daemon" not in self.edges[dst]:
                rx_p2p, rx_sup = tx_p2p, tx_sup
            counts = "{} tx p2p/super {}/{}, {} rx p2p/super {}/{}".format(
                src, tx_p2p, tx_sup, dst, rx_p2p, rx_sup)
            if self.sc.expect == "direct":
                ok = (tx_p2p >= n - slack and tx_sup <= slack and
                      rx_p2p >= got - slack and rx_sup <= slack)
            else:
                ok = (tx_sup >= n - slack and tx_p2p <= slack and
                      rx_sup >= got - slack and rx_p2p <= slack)
            self.check("counters:" + tag, ok, counts)
        self.result["frames"] = frames

        total = n * len(self.sc.directions())
        if self.sc.expect == "direct":
            ok = sn_fwd <= slack
        else:
            ok = sn_fwd >= total - slack
        self.check("relay:supernodes", ok,
                   "sn_fwd {} for {} frames sent".format(sn_fwd, total))

        want = "p2p" if self.sc.expect == "direct" else "pSp"
        stayed = all((m == "p2p") == (want == "p2p") for m in modes.values())
        self.check("path:after", stayed, self._modes_str(modes))

    def check_gateway(self):
        """An address beyond the community, through the gateway edge"""
        gw = self.sc.gateway
        src = [s for s in self.edges if s != gw][0]
        gw_ns, src_ns = self.edges[gw]["ns"], self.edges[src]["ns"]
        # on lo, which a new namespace has down
        run(["ip", "-n", gw_ns, "link", "set", "lo", "up"])
        run(["ip", "-n", gw_ns, "addr", "add", GATEWAY_TARGET + "/32",
             "dev", "lo"])
        run(["ip", "-n", src_ns, "route", "add", GATEWAY_NET, "dev", "n3n0"])
        recv = self.lab.spawn(
            "recv-gateway", gw_ns,
            [sys.executable, TRAFFIC_PY, "recv", "--bind",
             "{}:{}".format(GATEWAY_TARGET, TRAFFIC_PORT)],
            stdout_path=os.path.join(self.workdir, "recv-gateway.json"))
        time.sleep(0.5)
        # the first ones may go while the edge asks for the gateway's MAC
        subprocess.run(["ip", "netns", "exec", src_ns, sys.executable,
                        TRAFFIC_PY, "send",
                        "--src", self.edges[src]["overlay"],
                        "--to", "{}:{}".format(GATEWAY_TARGET, TRAFFIC_PORT),
                        "--flow", "9", "--count", "20", "--rate", "20"],
                       capture_output=True, timeout=30)
        time.sleep(0.5)
        recv.stop()
        flows = self._read_json(recv.out.name).get("flows", {})
        got = flows.get("9", {}).get("unique", 0)
        self.check("gateway", got >= 15,
                   "{} of 20 datagrams to {} through {}".format(
                       got, GATEWAY_TARGET, gw))

    # 6. All of it

    def execute(self):
        try:
            self.log("building {} ({})".format(self.sc.nat_summary(),
                                               self.sc.desc))
            self.build()
            self.start_supernodes()
            self.start_edges()
            self.check_transport()
            self.start_receivers()
            self.wait_nat_classes(timeout=45)
            if self.check_alive("nat classification"):
                self.warm_up()
            if self.sc.roam and self.check_alive("warm-up"):
                self.roam_phase()
            if self.sc.failover and self.check_alive("warm-up"):
                self.failover()
            if self.check_alive("warm-up"):
                n, sent, deltas, modes = self.measure()
                received = self.stop_receivers()
                self.evaluate(n, sent, deltas, modes, received)
                if self.sc.roam:
                    self.check_roam(received)
                self.check_alive("measurement")
            if self.sc.gateway and self.check_alive("measurement"):
                self.check_gateway()
            if self.sc.max_moves is not None:
                self.check_moves()
            self._dump_state()
        except LabError as e:
            self.check("setup", False, str(e))
        except Exception as e:   # keep the lab from leaking
            self.check("harness", False, "{}: {}".format(type(e).__name__, e))
            raise
        finally:
            self._teardown()
        self.result["checks"] = [c.as_dict() for c in self.checks]
        self.result["ok"] = all(c.ok for c in self.checks) and \
            bool(self.checks)
        self.result["seconds"] = round(time.monotonic() - self.t0, 1)
        self.result["workdir"] = self.workdir
        with open(os.path.join(self.workdir, "result.json"), "w") as f:
            json.dump(self.result, f, indent=2, sort_keys=True)
        return self.result

    def check_moves(self):
        """How often each edge moved its peer to another address: with
        more than one way to it, it should keep one while that one works
        (see check_known_peer_sock_change())"""
        # a few more rounds of registration, which bring the other ways
        # to each peer up again, with a trickle of frames both ways as
        # between edges in use
        hold = 4 * self.st.register_interval
        self.log("watching the peers' addresses for {}s".format(hold))
        trickle = [self.sender(s, d, FLOW_HOLD, 0, 10)
                   for s, d in self.sc.directions()]
        time.sleep(hold)
        for p in trickle:
            p.stop()
        for sname, e in sorted(self.edges.items()):
            if "daemon" not in e:
                continue
            with open(e["daemon"].proc.log_path, errors="replace") as f:
                moves = [line.strip() for line in f
                         if re.search(r"peer \S+ changed \[", line)]
            detail = "{} moves of its peer".format(len(moves))
            if moves:
                detail += ", the last: " + moves[-1].split("peer ", 1)[-1]
            self.check("moves:" + sname, len(moves) <= self.sc.max_moves,
                       detail)

    def _dump_state(self):
        state = {}
        for name, d in self.daemons():
            state[name] = {m: d.mgmt.try_call(m) for m in
                           ("get_info", "get_edges", "get_supernodes",
                            "get_packetstats")}
        with open(os.path.join(self.workdir, "state.json"), "w") as f:
            json.dump(state, f, indent=2)
        with open(os.path.join(self.workdir, "nft-counters.txt"), "w") as f:
            for name, ns in sorted(self.routers.items()):
                f.write("### {}\n{}\n".format(name, self.lab.nft_dump(ns)))

    def _teardown(self):
        # Stop the daemons through SIGTERM first, so a crash on the way
        # out shows up
        self.check_alive("the end of the run")
        daemons = self.daemons()
        for p in self.receivers.values():
            p.stop()
        exits = {}
        for name, d in reversed(daemons):
            if d.proc.stopped:
                continue
            was_alive = d.proc.alive()
            code = d.proc.stop()
            if was_alive:
                exits[name] = code
        for name, code in sorted(exits.items()):
            clean = code == 0 or code == -15
            if not clean:
                self.check("exit:" + name, False,
                           "on SIGTERM: {}".format(describe_exit(code)))
        self.lab.teardown()
