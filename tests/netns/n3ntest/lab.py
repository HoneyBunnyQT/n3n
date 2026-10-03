#
# Copyright (C) Honey Bunny QT
# SPDX-License-Identifier: GPL-3.0-only
#
"""Network namespaces, links and processes of one test run.

Everything a Lab creates carries its prefix, so several labs can run side
by side, and teardown() - or cleanup_stale() after a crashed run - removes
all of it again.
"""

import os
import signal
import subprocess
import time


class LabError(Exception):
    pass


def run(argv, ns=None, input=None, check=True):
    """Run a short command, in a namespace if given, and return its stdout"""
    if ns:
        argv = ["ip", "netns", "exec", ns] + list(argv)
    p = subprocess.run(
        argv,
        input=input,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    if check and p.returncode != 0:
        raise LabError("{} failed ({}): {}".format(
            " ".join(argv), p.returncode, p.stderr.strip()))
    return p.stdout


def list_netns():
    out = run(["ip", "netns", "list"], check=False)
    return [line.split()[0] for line in out.splitlines() if line.strip()]


def cleanup_stale(prefix):
    """Remove the namespaces a crashed run left behind"""
    removed = []
    for ns in list_netns():
        if ns.startswith(prefix):
            kill_ns_pids(ns)
            run(["ip", "netns", "del", ns], check=False)
            removed.append(ns)
    return removed


def kill_ns_pids(ns):
    out = run(["ip", "netns", "pids", ns], check=False)
    for pid in out.split():
        try:
            os.kill(int(pid), signal.SIGKILL)
        except (ProcessLookupError, ValueError):
            pass


class Proc:
    """A long running process inside a namespace, its output in a log file"""

    def __init__(self, name, ns, argv, log_path, stdout_path=None):
        self.name = name
        self.ns = ns
        self.argv = argv
        self.log_path = log_path
        self.log = open(log_path, "w")
        if stdout_path:
            self.out = open(stdout_path, "w")
        else:
            self.out = self.log
        self.popen = subprocess.Popen(
            ["ip", "netns", "exec", ns] + list(argv),
            stdout=self.out,
            stderr=self.log,
            stdin=subprocess.DEVNULL,
        )
        self.stopped = False
        self.returncode = None

    def alive(self):
        return self.popen.poll() is None

    def send_signal(self, sig):
        if self.alive():
            self.popen.send_signal(sig)

    def stop(self, timeout=5.0, sig=signal.SIGTERM):
        """Stop the process, and return its exit code (negative: signal)"""
        if self.stopped:
            return self.returncode
        self.stopped = True
        if self.alive():
            self.popen.send_signal(sig)
            try:
                self.popen.wait(timeout)
            except subprocess.TimeoutExpired:
                self.popen.kill()
                self.popen.wait()
                self.returncode = "killed after timeout"
        if self.returncode is None:
            self.returncode = self.popen.returncode
        self.log.close()
        if self.out is not self.log:
            self.out.close()
        return self.returncode

    def log_tail(self, lines=20):
        try:
            with open(self.log_path, errors="replace") as f:
                return "".join(f.readlines()[-lines:])
        except OSError:
            return ""


def describe_exit(code):
    if isinstance(code, str):
        return code
    if code is None:
        return "running"
    if code < 0:
        try:
            return "signal {}".format(signal.Signals(-code).name)
        except ValueError:
            return "signal {}".format(-code)
    return "exit {}".format(code)


class Lab:
    def __init__(self, prefix, workdir):
        self.prefix = prefix
        self.workdir = workdir
        self.namespaces = []
        self.procs = []
        os.makedirs(workdir, exist_ok=True)

    # Namespaces and links

    def netns(self, name):
        full = self.prefix + name
        if full in list_netns():
            # left over from a crashed run with the same prefix
            kill_ns_pids(full)
            run(["ip", "netns", "del", full], check=False)
        run(["ip", "netns", "add", full])
        self.namespaces.append(full)
        run(["ip", "-n", full, "link", "set", "lo", "up"])
        # No router advertisements or DAD delays to wait for
        self.sysctl(full, "net.ipv6.conf.all.accept_ra", 0, optional=True)
        self.sysctl(full, "net.ipv6.conf.default.accept_ra", 0, optional=True)
        return full

    def sysctl(self, ns, key, value, optional=False):
        """Set a sysctl in a namespace; optional ones may not exist (IPv6)"""
        path = "/proc/sys/" + key.replace(".", "/")
        if optional:
            script = "[ ! -e {1} ] || echo {0} > {1}".format(value, path)
        else:
            script = "echo {} > {}".format(value, path)
        run(["sh", "-c", script], ns=ns)

    def veth(self, ns1, if1, ns2, if2):
        run(["ip", "link", "add", if1, "netns", ns1, "type", "veth",
             "peer", "name", if2, "netns", ns2])
        run(["ip", "-n", ns1, "link", "set", if1, "up"])
        run(["ip", "-n", ns2, "link", "set", if2, "up"])

    def bridge(self, ns, name):
        run(["ip", "-n", ns, "link", "add", name, "type", "bridge"])
        run(["ip", "-n", ns, "link", "set", name, "up"])

    def enslave(self, ns, dev, bridge):
        run(["ip", "-n", ns, "link", "set", dev, "master", bridge])

    def addr(self, ns, dev, cidr, nodad=False):
        # nodad: an IPv6 address usable at once, without duplicate
        # address detection first
        run(["ip", "-n", ns, "addr", "add", cidr, "dev", dev] +
            (["nodad"] if nodad else []))

    def route(self, ns, dst, via):
        run(["ip", "-n", ns, "route", "add", dst, "via", via])

    def nft(self, ns, ruleset, name):
        path = os.path.join(self.workdir, "nft-{}.conf".format(name))
        with open(path, "w") as f:
            f.write(ruleset)
        run(["nft", "-f", path], ns=ns)

    def nft_dump(self, ns):
        return run(["nft", "list", "ruleset"], ns=ns, check=False)

    # Processes

    def spawn(self, name, ns, argv, stdout_path=None):
        log = os.path.join(self.workdir, name + ".log")
        p = Proc(name, ns, argv, log, stdout_path)
        self.procs.append(p)
        return p

    def teardown(self):
        """Stop the processes and remove the namespaces

        Returns {name: exit} of the processes that were still running.
        """
        exits = {}
        for p in reversed(self.procs):
            if not p.stopped:
                exits[p.name] = p.stop()
        for ns in reversed(self.namespaces):
            kill_ns_pids(ns)
            run(["ip", "netns", "del", ns], check=False)
        self.namespaces = []
        return exits


def wait_for(predicate, timeout, interval=0.2):
    """Poll until predicate() returns something true, or None at timeout"""
    end = time.monotonic() + timeout
    while True:
        result = predicate()
        if result:
            return result
        if time.monotonic() >= end:
            return None
        time.sleep(interval)
