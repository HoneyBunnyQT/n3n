#
# Copyright (C) Honey Bunny QT
# SPDX-License-Identifier: GPL-3.0-only
#
"""n3n edges and supernodes in a lab, and their management interface"""

import http.client
import json
import os
import re
import socket
import subprocess

from .lab import wait_for

RUNDIR = "/run/n3n"


class MgmtError(Exception):
    pass


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__("localhost", timeout=timeout)
        self.unix_path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.unix_path)


class Mgmt:
    """JSON-RPC over the unix socket in the daemon's session dir

    The socket lives in the filesystem, so it is reachable from outside
    the daemon's network namespace.
    """

    def __init__(self, session):
        self.path = os.path.join(RUNDIR, session, "mgmt")
        self.id = 0

    def available(self):
        return os.path.exists(self.path)

    def call(self, method, params=None, timeout=3.0):
        self.id += 1
        body = json.dumps({
            "jsonrpc": "2.0",
            "id": self.id,
            "method": method,
            "params": params,
        })
        conn = _UnixHTTPConnection(self.path, timeout)
        try:
            conn.request("POST", "/v1", body,
                         {"Content-Type": "application/json"})
            r = conn.getresponse()
            data = r.read()
        except OSError as e:
            raise MgmtError("{}: {}".format(method, e))
        finally:
            conn.close()
        try:
            reply = json.loads(data.decode("utf8", errors="replace"))
        except ValueError:
            raise MgmtError("{}: bad json: {!r}".format(method, data[:200]))
        if "error" in reply:
            raise MgmtError("{}: {}".format(method, reply["error"]))
        return reply["result"]

    def try_call(self, method, params=None):
        try:
            return self.call(method, params)
        except MgmtError:
            return None


def packetstats(mgmt):
    """get_packetstats as {type: {tx_pkt:, rx_pkt:, ...}}"""
    stats = mgmt.call("get_packetstats")
    return {row["type"]: row for row in stats}


def stats_delta(before, after):
    out = {}
    for t, row in after.items():
        prev = before.get(t, {})
        out[t] = {k: v - prev.get(k, 0)
                  for k, v in row.items() if isinstance(v, int)}
    return out


_known = {}


def known_options(binary):
    """The "section.option"s a binary knows, from its "help config"; None
    if it does not say"""
    if binary not in _known:
        try:
            out = subprocess.run([binary, "help", "config"],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL,
                                 universal_newlines=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            out = ""
        known, section = set(), ""
        for line in out.splitlines():
            m = re.match(r"^\[([^\]\s]+)", line)
            if m:
                section = m.group(1)
                continue
            m = re.match(r"^#?([a-z0-9_]+)=", line)
            if m:
                known.add(section + "." + m.group(1))
        _known[binary] = known or None
    return _known[binary]


def write_conf(path, sections, known=None):
    """Write an n3n config file from {section: [(option, value), ...]};
    with known, the "section.option"s the binary knows, only those (an
    older version stops at an option it does not know).  Returns those
    left out."""
    left_out = []
    with open(path, "w") as f:
        for section, options in sections.items():
            f.write("[{}]\n".format(section))
            for option, value in options:
                # [community NAME] has the options of [community]
                key = section.split()[0] + "." + option
                if known is not None and key not in known:
                    left_out.append(key)
                    continue
                if isinstance(value, bool):
                    value = "true" if value else "false"
                f.write("{}={}\n".format(option, value))
            f.write("\n")
    return left_out


class Daemon:
    kind = None

    def __init__(self, lab, name, ns, session, binary, sections, wrap=()):
        self.lab = lab
        self.name = name
        self.ns = ns
        self.session = session
        self.binary = binary
        self.sections = sections
        self.wrap = list(wrap)
        self.mgmt = Mgmt(session)
        self.proc = None
        # The config file name gives the session name
        self.conf = os.path.join(lab.workdir, session + ".conf")

    def start(self):
        self.left_out = write_conf(self.conf, self.sections,
                                   known_options(self.binary))
        argv = self.wrap + [self.binary, "start", self.conf]
        self.proc = self.lab.spawn(self.name, self.ns, argv)

    def wait_mgmt(self, timeout=10):
        def ready():
            if not self.proc.alive():
                return "dead"
            if self.mgmt.available() and self.mgmt.try_call("get_info"):
                return "ok"
            return None
        return wait_for(ready, timeout) == "ok"

    def info(self):
        return self.mgmt.call("get_info")

    def stats(self):
        return packetstats(self.mgmt)


class Supernode(Daemon):
    kind = "supernode"


class Edge(Daemon):
    kind = "edge"

    def __init__(self, *args, overlay_ip, mac, **kwargs):
        super().__init__(*args, **kwargs)
        self.overlay_ip = overlay_ip
        self.mac = mac

    def registered(self):
        """True once the edge is registered at a supernode"""
        sns = self.mgmt.try_call("get_supernodes") or []
        return any(sn.get("current") == 1 for sn in sns)

    def current_supernode(self):
        sns = self.mgmt.try_call("get_supernodes") or []
        for sn in sns:
            if sn.get("current"):
                return sn.get("sockaddr")
        return None

    def peer(self, mac):
        """This edge's entry for a peer: (mode, row), mode p2p or pSp"""
        rows = self.mgmt.try_call("get_edges") or []
        found = None
        for row in rows:
            if row.get("macaddr", "").lower() == mac.lower():
                if row.get("mode") == "p2p":
                    return "p2p", row
                found = (row.get("mode"), row)
        return found if found else (None, None)
