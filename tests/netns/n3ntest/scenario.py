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
OVERLAY_NET = "10.99.0.{}"
OVERLAY_PREFIX = 24
EDGE_PORT = 50001
SN_PORT = 7654
TRAFFIC_PORT = 9000
COMMUNITY = "nettest"
KEY = "nettest-secret"
FEDERATION = "nettestfed"
PASSWORD = "nettest-password"

FLOW_WARM = 1
FLOW_MEAS = 2

TRAFFIC_PY = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "traffic.py")


class Site:
    """An edge, and the NAT routers in front of it, outermost first"""

    def __init__(self, nat=(), lan=None, supernodes=("sn1", "sn2"),
                 conf=None, expect_nat=None):
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
                 sn_conf=None, auth=None):
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
        self.connect_timeout = connect_timeout
        # After the warm-up, kill (SIGKILL) the supernode this site's edge
        # is registered at, and measure once the edges moved to the other
        self.failover = failover

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
        inet = lab.netns("inet")
        lab.bridge(inet, "br0")
        lab.addr(inet, "br0", "{}/{}".format(INET_NET.format(254),
                                             INET_PREFIX))
        self.inet = inet

        for i, name in enumerate(("sn1", "sn2"), start=1):
            ns = lab.netns(name)
            lab.veth(inet, "x-" + name, ns, "eth0")
            lab.enslave(inet, "x-" + name, "br0")
            ip = INET_NET.format(i)
            lab.addr(ns, "eth0", "{}/{}".format(ip, INET_PREFIX))
            self.supernodes[name] = {"ns": ns, "ip": ip}

        for i, (sname, site) in enumerate(sorted(self.sc.sites.items())):
            self._build_site(i, sname, site)

    def _build_site(self, i, sname, site):
        lab = self.lab
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
        else:
            lab.addr(up_ns, up_if, "{}/24".format(up_net.format(1)))
            ip = up_net.format(2)
            lab.addr(ns, "eth0", "{}/24".format(ip))
            lab.route(ns, "default", up_net.format(1))
        # The TAP device comes up without IPv6, so no neighbour discovery
        # or MLD frames get counted alongside the test frames
        lab.sysctl(ns, "net.ipv6.conf.default.disable_ipv6", 1, optional=True)

        self.edges[sname] = {
            "ns": ns,
            "ip": ip,
            "index": i,
            "overlay": OVERLAY_NET.format(i + 1),
            "mac": "02:00:00:99:00:{:02x}".format(i + 1),
            "expect_nat": (site.expect_nat if site.expect_nat is not None
                           else nat.expected_class(layers)),
        }

    # 2. The daemons

    def _session(self, name):
        return "{}{}".format(self.prefix, name)

    def _keygen(self, *args):
        """What "n3n-edge tools keygen" says, without the line's prefix"""
        argv = [self.st.edge_bin, "tools", "keygen"] + list(args)
        out = subprocess.run(argv, capture_output=True, text=True).stdout
        out = out.strip()
        return out.split()[-1].split("=")[-1]

    def _community_file(self):
        """The community file of the supernodes, None if they need none"""
        if not self.sc.auth:
            return None
        lines = [COMMUNITY]
        if self.sc.auth == "userpw":
            lines += ["* {} {}".format(sname, self._keygen(sname, PASSWORD))
                      for sname in sorted(self.sc.sites)]
        path = os.path.join(self.workdir, "community.list")
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        return path

    def start_supernodes(self):
        names = sorted(self.supernodes)
        community_file = self._community_file()
        for i, name in enumerate(names, start=1):
            sn = self.supernodes[name]
            peers = [("peer", "{}:{}".format(self.supernodes[o]["ip"],
                                             SN_PORT))
                     for o in names if o != name]
            sections = {
                "connection": [("bind", "[::]:{}".format(SN_PORT))],
                "supernode": [("federation", FEDERATION),
                              ("macaddr", "02:00:00:5e:00:{:02x}".format(i))]
                + peers,
                "daemon": [("background", False)],
                "logging": [("verbose", self.st.verbose)],
            }
            if community_file:
                sections["supernode"].append(
                    ("community_file", community_file))
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
        sections = {s: list(o.items()) for s, o in conf.items()}
        sections["community"] += [
            ("supernode", "{}:{}".format(self.supernodes[sn]["ip"], SN_PORT))
            for sn in site.supernodes
        ]
        return sections

    def start_edges(self):
        self.t_edges = time.monotonic()
        for sname, site in sorted(self.sc.sites.items()):
            e = self.edges[sname]
            d = Edge(self.lab, "edge-" + sname, e["ns"], self._session(sname),
                     self.st.edge_bin, self._edge_sections(sname, site, e),
                     wrap=self.st.wrap, overlay_ip=e["overlay"], mac=e["mac"])
            d.start()
            e["daemon"] = d
        for sname, e in sorted(self.edges.items()):
            d = e["daemon"]
            if not d.wait_mgmt():
                raise LabError("edge {} did not start: {}\n{}".format(
                    sname, describe_exit(d.proc.popen.poll()),
                    d.proc.log_tail()))
        for sname, e in sorted(self.edges.items()):
            d = e["daemon"]
            if not wait_for(lambda: d.registered() or not d.proc.alive(), 20) \
                    or not d.proc.alive():
                raise LabError("edge {} did not register at a supernode\n{}"
                               .format(sname, d.proc.log_tail()))
            e["registered_at"] = d.current_supernode()
        self.result["registered_at"] = {
            s: e["registered_at"] for s, e in self.edges.items()}
        self.log("edges registered: " + ", ".join(
            "{} at {}".format(s, e["registered_at"])
            for s, e in sorted(self.edges.items())))

        # The peers' MACs are known up front: no ARP frames in the counts
        for sname, e in self.edges.items():
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
        def settled():
            for e in self.edges.values():
                info = e["daemon"].mgmt.try_call("get_info") or {}
                e["nat4"] = info.get("nat4", "?")
            return all(re.match(e["expect_nat"], e["nat4"])
                       for e in self.edges.values())
        t = time.monotonic()
        wait_for(settled, timeout, interval=0.5)
        took = round(time.monotonic() - t, 1)
        for sname, e in sorted(self.edges.items()):
            ok = re.match(e["expect_nat"], e["nat4"])
            detail = "nat4 {!r}".format(e["nat4"])
            if self.sc.sites[sname].nat == ["hard-range"] and ok:
                ok = nat.hard_range_ok(e["nat4"])
                detail += ", NAT block {}-{}".format(nat.HARD_RANGE_LO,
                                                     nat.HARD_RANGE_HI)
            if not ok:
                detail += ", expected /{}/".format(e["expect_nat"])
            else:
                detail += " after {}s".format(took)
            self.check("nat:" + sname, ok, detail)
        self.result["nat4"] = {s: e["nat4"] for s, e in self.edges.items()}

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
        self.supernodes[victim]["daemon"].proc.stop(sig=signal.SIGKILL)
        self.killed.add(victim)
        ip = self.supernodes[victim]["ip"] + ":"
        t = time.monotonic()

        def moved():
            if not self.check_alive_quiet():
                return "dead"
            for e in self.edges.values():
                now = e["daemon"].current_supernode() or ip
                if now.startswith(ip) or not e["daemon"].registered():
                    return None
            return "ok"
        ok = wait_for(moved, 60 + 4 * self.st.register_interval,
                      interval=0.5) == "ok"
        took = round(time.monotonic() - t, 1)
        where = {s: e["daemon"].current_supernode()
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

    # 6. All of it

    def execute(self):
        try:
            self.log("building {} ({})".format(self.sc.nat_summary(),
                                               self.sc.desc))
            self.build()
            self.start_supernodes()
            self.start_edges()
            self.start_receivers()
            self.wait_nat_classes(timeout=45)
            if self.check_alive("nat classification"):
                self.warm_up()
            if self.sc.failover and self.check_alive("warm-up"):
                self.failover()
            if self.check_alive("warm-up"):
                n, sent, deltas, modes = self.measure()
                received = self.stop_receivers()
                self.evaluate(n, sent, deltas, modes, received)
                self.check_alive("measurement")
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
