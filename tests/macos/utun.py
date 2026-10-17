#!/usr/bin/env python3
#
# Copyright (C) Honey Bunny QT
# SPDX-License-Identifier: GPL-3.0-only
#
"""The edge on macOS's own TUN device (tuntap.type = tun: utun), end to end

On one host: a supernode; edge a on a utun device; edge b on one end of a
socketpair (tuntap.fd), whose other end this script holds and answers
pings on.  The host pings b's addresses, IPv4 and IPv6, and the pings go
from the kernel into a's utun device, through a's ARP or neighbour
discovery for b, over the community to b, into the socketpair - and the
answers all the way back.

    sudo python3 tests/macos/utun.py [DIR]

DIR has n3n-edge and n3n-supernode (apps/ of the tree by default).  Needs
root: utun, ifconfig, route.
"""

import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))

A4, B4, PREFIX4 = "10.99.0.1", "10.99.0.2", 24
A6, B6, PREFIX6 = "fd99::1", "fd99::2", 64
SN_PORT = 7654
DAEMON = {"background": "false", "userid": 0, "groupid": 0}


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def echo_reply(pkt):
    """The answer to an echo request, IPv4 or IPv6; None for anything
    else"""
    if len(pkt) >= 28 and pkt[0] >> 4 == 4 and pkt[9] == 1:
        ihl = (pkt[0] & 15) * 4
        icmp = bytearray(pkt[ihl:])
        if icmp[0] != 8:
            return None
        icmp[0] = 0
        icmp[2:4] = b"\0\0"
        icmp[2:4] = struct.pack("!H", checksum(bytes(icmp)))
        ip = bytearray(pkt[:ihl])
        ip[12:16], ip[16:20] = pkt[16:20], pkt[12:16]
        ip[8] = 64
        ip[10:12] = b"\0\0"
        ip[10:12] = struct.pack("!H", checksum(bytes(ip)))
        return bytes(ip + icmp)
    if len(pkt) >= 48 and pkt[0] >> 4 == 6 and pkt[6] == 58 \
            and pkt[40] == 128:
        src, dst = pkt[8:24], pkt[24:40]
        icmp = bytearray(pkt[40:])
        icmp[0] = 129
        icmp[2:4] = b"\0\0"
        pseudo = dst + src + struct.pack("!I3xB", len(icmp), 58)
        icmp[2:4] = struct.pack("!H", checksum(pseudo + bytes(icmp)))
        ip = bytearray(pkt[:40])
        ip[7] = 64
        ip[8:24], ip[24:40] = dst, src
        return bytes(ip + icmp)
    return None


def answer(sock, stop):
    """b's host: answers the pings that come out of edge b"""
    sock.settimeout(0.5)
    while not stop.is_set():
        try:
            pkt = sock.recv(65536)
        except socket.timeout:
            continue
        except OSError:
            return
        reply = echo_reply(pkt)
        if reply:
            sock.send(reply)


def write_conf(path, sections):
    with open(path, "w") as f:
        for section, options in sections.items():
            f.write("[{}]\n".format(section))
            for option, value in options.items():
                f.write("{}={}\n".format(option, value))
            f.write("\n")


def edge_conf(a4, a6, tuntap):
    tuntap = dict(tuntap, type="tun", address_mode="static",
                  address="{}/{}".format(a4, PREFIX4),
                  address6="{}/{}".format(a6, PREFIX6))
    return {
        "community": {"name": "utuntest", "key": "utunsecret",
                      "supernode": "127.0.0.1:{}".format(SN_PORT)},
        "daemon": DAEMON,
        "logging": {"verbose": 3},
        "tuntap": tuntap,
    }


class Daemon:
    def __init__(self, workdir, name, binary, sections, pass_fds=()):
        conf = os.path.join(workdir, name + ".conf")
        write_conf(conf, sections)
        self.name = name
        self.log = os.path.join(workdir, name + ".log")
        with open(self.log, "w") as log:
            self.proc = subprocess.Popen([binary, "start", conf], stdout=log,
                                         stderr=subprocess.STDOUT,
                                         pass_fds=pass_fds)

    def text(self):
        with open(self.log, errors="replace") as f:
            return f.read()

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()


def wait_for(fn, secs):
    end = time.monotonic() + secs
    while time.monotonic() < end:
        result = fn()
        if result:
            return result
        time.sleep(0.5)
    return None


def ping_cmd(family):
    if family == 4:
        return ["ping"]
    return ["ping6"] if shutil.which("ping6") else ["ping", "-6"]


def ping(family, addr, count):
    """How many of count pings were answered"""
    cmd = ping_cmd(family) + ["-c", str(count), "-i", "0.2", addr]
    try:
        out = subprocess.run(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT,
                             universal_newlines=True,
                             timeout=count + 3).stdout
    except subprocess.TimeoutExpired:
        return 0
    m = re.search(r"(\d+) packets received", out)
    return int(m.group(1)) if m else 0


def main():
    apps = sys.argv[1] if len(sys.argv) > 1 \
        else os.path.join(HERE, "..", "..", "apps")
    edge_bin = os.path.join(apps, "n3n-edge")
    sn_bin = os.path.join(apps, "n3n-supernode")
    if os.geteuid() != 0:
        print("needs root: sudo python3 " + " ".join(sys.argv))
        return 2

    workdir = tempfile.mkdtemp(prefix="n3n-utun-")
    a_end, b_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    stop = threading.Event()
    responder = threading.Thread(target=answer, args=(a_end, stop))
    responder.start()
    daemons = []
    failed = []

    def check(what, ok):
        print("{} {}".format("ok  " if ok else "FAIL", what))
        if not ok:
            failed.append(what)
        return ok

    try:
        daemons.append(Daemon(workdir, "utun-sn", sn_bin,
                              {"daemon": DAEMON,
                               "logging": {"verbose": 3}}))
        time.sleep(1)
        b = Daemon(workdir, "utun-b", edge_bin,
                   edge_conf(B4, B6, {"fd": b_end.fileno()}),
                   pass_fds=(b_end.fileno(),))
        daemons.append(b)
        a = Daemon(workdir, "utun-a", edge_bin, edge_conf(A4, A6, {}))
        daemons.append(a)

        def utun_name():
            m = re.search(r"Interface (utun\d+) up and running", a.text())
            return m.group(1) if m else None
        dev = wait_for(utun_name, 15)
        if check("edge a opened a utun device ({})".format(dev), dev):
            ifc = subprocess.run(["ifconfig", dev], stdout=subprocess.PIPE,
                                 universal_newlines=True).stdout
            check("{} has {} and {}".format(dev, A4, A6),
                  A4 in ifc and A6 in ifc)

            for family, addr in ((4, B4), (6, B6)):
                first = wait_for(lambda: ping(family, addr, 1), 40)
                check("IPv{}: a ping to {} answered".format(family, addr),
                      first)
                if first:
                    n = ping(family, addr, 5)
                    check("IPv{}: then 5 of 5 ({})".format(family, n),
                          n == 5)

            a.stop()
            gone = wait_for(lambda: subprocess.run(
                ["ifconfig", dev], stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL).returncode != 0, 10)
            check("{} gone with edge a".format(dev), gone)
    finally:
        for d in daemons:
            d.stop()
        stop.set()
        responder.join()

    if failed:
        for d in daemons:
            print("----- {} -----".format(d.name))
            print(d.text()[-6000:])
        return 1
    shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
