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
import sys

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
    # run.py --keep-root: daemon.userid and groupid 0
    keep_root = False

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
        if self.keep_root:
            daemon = [(o, v) for o, v in self.sections.get("daemon", [])
                      if o not in ("userid", "groupid")]
            self.sections["daemon"] = daemon + [("userid", 0),
                                                ("groupid", 0)]
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


# n2n 3.x, for the interop scenarios (tests/netns/versions.sh builds it):
# the same configuration, given as its command line options, and its own
# management interface, JSON rows over UDP

N2N_EDGE_MGMT = 5644
N2N_SN_MGMT = 5645
# n2n's -A: the transform ids, which are n3n's as well
N2N_CIPHERS = {"null": 1, "twofish": 2, "aes": 3, "chacha20": 4, "speck": 5}
N2N_QUERY = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "n2nmgmt.py")


class N2nMgmt:
    """n2n's management interface: "r TAG method" over UDP, on the
    loopback of the daemon's network namespace - where the query runs
    (n2nmgmt.py)"""

    METHODS = {"get_edges": "edges", "get_supernodes": "supernodes",
               "get_packetstats": "packetstats",
               "get_communities": "communities"}
    SN_STATS = {"forward": "sn_fwd", "broadcast": "sn_broadcast",
                "reg_super": "sn_reg", "errors": "sn_errors"}

    def __init__(self, ns, port):
        self.ns = ns
        self.port = port

    def available(self):
        return True

    def _query(self, method, timeout):
        try:
            p = subprocess.run(
                ["ip", "netns", "exec", self.ns, sys.executable, N2N_QUERY,
                 str(self.port), method, str(timeout)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True, timeout=timeout + 5)
        except (OSError, subprocess.SubprocessError) as e:
            raise MgmtError("{}: {}".format(method, e))
        if p.returncode != 0:
            raise MgmtError("{}: {}".format(method, p.stderr.strip()))
        return json.loads(p.stdout)

    def call(self, method, params=None, timeout=3.0):
        if method == "get_info":
            # what n3n's get_info says that the scenarios ask for: n2n
            # neither knows its NAT nor TCP
            self._query("timestamps", timeout)
            return {"version": "n2n", "transport": "udp", "nat4": "?"}
        if method not in self.METHODS:
            raise MgmtError("{}: n2n has no such method".format(method))
        rows = self._query(self.METHODS[method], timeout)
        if method == "get_packetstats":
            # a supernode's counters, by n3n's names
            for row in rows:
                row["type"] = self.SN_STATS.get(row.get("type"),
                                                row.get("type"))
        return rows

    def try_call(self, method, params=None):
        try:
            return self.call(method, params)
        except MgmtError:
            return None


def _opts(sections, section):
    return dict(sections.get(section, []))


def _verbosity(sections):
    # n2n starts at "normal" (2), each -v one more, as n3n's verbose
    return ["-v"] * max(0, int(_opts(sections, "logging")
                               .get("verbose", 2)) - 2)


def _port(bind):
    """The port of a bind like "[::]:7654" (n2n binds IPv4 only)"""
    return str(bind).split()[0].rsplit(":", 1)[-1]


def n2n_edge_argv(binary, sections):
    """n2n's edge with the settings of n3n's sections: (argv, the
    "section.option"s it has no option for)"""
    argv = [binary, "-f", "-u", "0", "-g", "0", "-t", str(N2N_EDGE_MGMT)]
    left_out = []
    for section, options in sections.items():
        kind = section.split()[0]
        for option, value in options:
            key = kind + "." + option
            if kind == "community":
                if option == "name":
                    argv += ["-c", value]
                elif option == "key":
                    argv += ["-k", value]
                elif option == "cipher":
                    argv += ["-A{}".format(N2N_CIPHERS[value.lower()])]
                elif option == "header_encryption":
                    if value:
                        argv += ["-H"]
                elif option == "supernode":
                    if value.startswith("tcp://") or value.startswith("["):
                        left_out.append(key + " " + value)
                    else:
                        argv += ["-l", value.replace("udp://", "")]
                else:
                    left_out.append(key)
            elif key == "connection.bind":
                argv += ["-p", _port(value)]
            elif key == "connection.description":
                argv += ["-I", value]
            elif key == "connection.register_interval":
                argv += ["-i", str(value)]
            elif key == "tuntap.name":
                argv += ["-d", value]
            elif key == "tuntap.address":
                argv += ["-a", "static:" + value]
            elif key == "tuntap.macaddr":
                argv += ["-m", value]
            elif key in ("tuntap.address_mode", "daemon.background",
                         "daemon.userid", "daemon.groupid",
                         "logging.verbose"):
                pass
            else:
                left_out.append(key)
        if kind == "community":
            name = section.split(None, 1)[1:]
            if name:
                argv += ["-c", name[0]]
    return argv + _verbosity(sections), left_out


def n2n_supernode_argv(binary, sections):
    """n2n's supernode with the settings of n3n's sections"""
    argv = [binary, "-f", "-u", "0", "-g", "0", "-t", str(N2N_SN_MGMT)]
    env = []
    left_out = []
    for section, options in sections.items():
        for option, value in options:
            key = section + "." + option
            if key == "connection.bind":
                argv += ["-p", _port(value)]
            elif key == "supernode.federation":
                # n2n 3.1.1 sets up the federation's header key before it
                # reads its options: -F renames it, but its key stays the
                # one of the default name; only this gets into the key
                env = ["env", "N2N_FEDERATION=" + value]
            elif key == "supernode.peer":
                if value.startswith("["):
                    left_out.append(key + " " + value)
                else:
                    argv += ["-l", value]
            elif key == "supernode.community_file":
                argv += ["-c", value]
            elif key in ("daemon.background", "daemon.userid",
                         "daemon.groupid", "logging.verbose"):
                pass
            else:
                # supernode.macaddr: only with SN_MANUAL_MAC built in
                left_out.append(key)
    return env + argv + _verbosity(sections), left_out


class N2nDaemon:
    """Mixed into Edge and Supernode: n2n instead of n3n"""

    def start(self):
        argv, self.left_out = self.n2n_argv(self.binary, self.sections)
        with open(self.conf, "w") as f:
            f.write(" ".join(argv) + "\n")
        # its management interface is on the loopback
        subprocess.run(["ip", "-n", self.ns, "link", "set", "lo", "up"],
                       check=True)
        self.proc = self.lab.spawn(self.name, self.ns, self.wrap + argv)


class N2nEdge(N2nDaemon, Edge):
    n2n_argv = staticmethod(n2n_edge_argv)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mgmt = N2nMgmt(self.ns, N2N_EDGE_MGMT)


class N2nSupernode(N2nDaemon, Supernode):
    n2n_argv = staticmethod(n2n_supernode_argv)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mgmt = N2nMgmt(self.ns, N2N_SN_MGMT)
