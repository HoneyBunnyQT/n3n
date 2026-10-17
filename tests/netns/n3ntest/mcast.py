#!/usr/bin/env python3
#
# Copyright (C) Honey Bunny QT
# SPDX-License-Identifier: GPL-3.0-only
#
"""Multicast, broadcast and raw Ethernet frames through the VPN

Runs inside an edge's namespace, standalone (stdlib only):

    mcast.py listen ip4 --dev n3n0 --port 1900 --group 239.255.255.250
    mcast.py send ip4 --dev n3n0 --to 239.255.255.250 --port 1900

    mcast.py listen ip6 --dev n3n0 --port 1900 --group ff05::c
    mcast.py send ip6 --dev n3n0 --to ff05::c --port 1900

    mcast.py listen l2 --dev n3n0
    mcast.py send l2 --dev n3n0 --to 01:80:c2:00:00:0e

ip4 and ip6 are UDP datagrams to a group (joined on the device) or, for
ip4 without --group, to the subnet's broadcast address; l2 are Ethernet
frames of a type of their own (0x88b5, IEEE's for local experiments) to
any destination MAC, on a TAP device.  listen runs until SIGTERM and then
prints its counts as JSON - {"rx": N} for ip4/ip6, {MAC: N} for l2;
only what carries this tool's marker counts.
"""

import argparse
import fcntl
import ipaddress
import json
import signal
import socket
import struct
import sys
import time

MAGIC = b"N3NM"
ETH_TYPE = 0x88b5
SIOCGIFADDR = 0x8915
SIOCGIFNETMASK = 0x891b
SIOCGIFHWADDR = 0x8927


class Stop(Exception):
    pass


def _stop(signum, frame):
    raise Stop()


def _ifreq(sock, dev, req):
    return fcntl.ioctl(sock.fileno(), req,
                       struct.pack("256s", dev.encode()[:15]))


def dev_ip4(dev):
    """The device's IPv4 address and its subnet's broadcast address"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr = socket.inet_ntoa(_ifreq(s, dev, SIOCGIFADDR)[20:24])
    mask = socket.inet_ntoa(_ifreq(s, dev, SIOCGIFNETMASK)[20:24])
    s.close()
    net = ipaddress.ip_network("{}/{}".format(addr, mask), strict=False)
    return addr, str(net.broadcast_address)


def dev_mac(dev):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mac = _ifreq(s, dev, SIOCGIFHWADDR)[18:24]
    s.close()
    return mac


def mac_bytes(s):
    return bytes(int(x, 16) for x in s.split(":"))


def mac_str(b):
    return ":".join("{:02x}".format(x) for x in b)


def listen(args):
    counts = {}
    if args.kind == "l2":
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                             socket.htons(ETH_TYPE))
        sock.bind((args.dev, ETH_TYPE))
    elif args.kind == "ip4":
        addr, _ = dev_ip4(args.dev)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", args.port))
        if args.group:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                            socket.inet_aton(args.group)
                            + socket.inet_aton(addr))
    else:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", args.port))
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
                        socket.inet_pton(socket.AF_INET6, args.group)
                        + struct.pack("@I", socket.if_nametoindex(args.dev)))
    sock.settimeout(0.5)
    try:
        while True:
            try:
                data = sock.recv(65535)
            except socket.timeout:
                continue
            if args.kind == "l2":
                if data[14:18] == MAGIC:
                    key = mac_str(data[0:6])
                    counts[key] = counts.get(key, 0) + 1
            elif data[:4] == MAGIC:
                counts["rx"] = counts.get("rx", 0) + 1
    except (Stop, KeyboardInterrupt):
        pass
    json.dump(counts, sys.stdout)
    sys.stdout.write("\n")


def send(args):
    if args.kind == "l2":
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.bind((args.dev, 0))
        frame = mac_bytes(args.to) + dev_mac(args.dev) \
            + struct.pack("!H", ETH_TYPE) + MAGIC
        frame += b"\0" * (60 - len(frame))
        dest = None
    elif args.kind == "ip4":
        addr, bcast = dev_ip4(args.dev)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                        socket.inet_aton(addr))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.bind((addr, 0))
        dest = (args.to or bcast, args.port)
        frame = MAGIC
    else:
        index = socket.if_nametoindex(args.dev)
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, index)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 2)
        dest = (args.to, args.port, 0, index)
        frame = MAGIC
    sent = 0
    for _ in range(args.count):
        if dest:
            sock.sendto(frame, dest)
        else:
            sock.send(frame)
        sent += 1
        time.sleep(args.interval)
    json.dump({"sent": sent}, sys.stdout)
    sys.stdout.write("\n")


def main():
    signal.signal(signal.SIGTERM, _stop)
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("cmd", choices=("listen", "send"))
    ap.add_argument("kind", choices=("ip4", "ip6", "l2"))
    ap.add_argument("--dev", default="n3n0")
    ap.add_argument("--port", type=int, default=1900)
    ap.add_argument("--group", help="listen: the group to join")
    ap.add_argument("--to", help="send: group, or MAC for l2; ip4 "
                    "without it: the subnet's broadcast address")
    ap.add_argument("--count", type=int, default=10)
    ap.add_argument("--interval", type=float, default=0.05)
    args = ap.parse_args()
    if args.cmd == "listen":
        listen(args)
    else:
        send(args)


if __name__ == "__main__":
    main()
