#!/usr/bin/env python3
#
# Copyright (C) Honey Bunny QT
# SPDX-License-Identifier: GPL-3.0-only
#
"""Counted UDP frames through the VPN

Runs inside an edge's namespace, standalone (stdlib only):

    traffic.py recv --bind 10.99.0.2:9000
    traffic.py send --src 10.99.0.1 --to 10.99.0.2:9000 --flow 1 \\
        --count 500 --rate 100

Each datagram carries a flow number and a sequence number, so the receiver
counts per flow what arrived, twice, or out of order.  Each one is one
ethernet frame on the TAP device, and one PACKET in n3n.  Both print their
counts as JSON on stdout when they end; recv runs until SIGTERM/SIGINT,
send until it has sent --count frames (or SIGTERM with --count 0).
"""

import argparse
import json
import signal
import socket
import struct
import sys
import time

MAGIC = b"N3NT"
HEADER = struct.Struct("!4sHId")   # magic, flow, seq, send time


class Stop(Exception):
    pass


def _stop(signum, frame):
    raise Stop()


def addr(s):
    host, port = s.rsplit(":", 1)
    return host, int(port)


def cmd_recv(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    sock.bind(addr(args.bind))
    sock.settimeout(0.5)

    flows = {}
    other = 0
    try:
        while True:
            try:
                data, peer = sock.recvfrom(65535)
            except socket.timeout:
                continue
            now = time.time()
            if len(data) < HEADER.size:
                other += 1
                continue
            magic, flow, seq, sent = HEADER.unpack_from(data)
            if magic != MAGIC:
                other += 1
                continue
            f = flows.get(flow)
            if f is None:
                f = flows[flow] = {
                    "rx": 0, "dup": 0, "reordered": 0, "max_seq": -1,
                    "first": now, "last": now, "lat_sum": 0.0,
                    "lat_max": 0.0, "seen": set(),
                    "gap_max": 0.0, "gap_at": now,
                }
            f["rx"] += 1
            # the longest time without a frame of the flow, and when it
            # ended
            if now - f["last"] > f["gap_max"]:
                f["gap_max"] = now - f["last"]
                f["gap_at"] = now
            f["last"] = now
            if seq in f["seen"]:
                f["dup"] += 1
                continue
            f["seen"].add(seq)
            if seq < f["max_seq"]:
                f["reordered"] += 1
            f["max_seq"] = max(f["max_seq"], seq)
            lat = max(0.0, now - sent)
            f["lat_sum"] += lat
            f["lat_max"] = max(f["lat_max"], lat)
    except (Stop, KeyboardInterrupt):
        pass

    out = {"other": other, "flows": {}}
    for flow, f in flows.items():
        unique = len(f["seen"])
        out["flows"][str(flow)] = {
            "rx": f["rx"],
            "unique": unique,
            "dup": f["dup"],
            "reordered": f["reordered"],
            "max_seq": f["max_seq"],
            # frames before the last one received that never came
            "gaps": f["max_seq"] + 1 - unique,
            "first": f["first"],
            "last": f["last"],
            "lat_avg_ms": round(1000 * f["lat_sum"] / unique, 3),
            "lat_max_ms": round(1000 * f["lat_max"], 3),
            "gap_max_ms": round(1000 * f["gap_max"], 1),
            "gap_at": f["gap_at"],
        }
    json.dump(out, sys.stdout)
    sys.stdout.write("\n")


def cmd_send(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if args.src:
        sock.bind((args.src, 0))
    dest = addr(args.to)
    pad = b"\0" * max(0, args.size - HEADER.size)
    interval = 1.0 / args.rate if args.rate > 0 else 0
    sent = 0
    errors = 0
    first = time.time()
    start = time.monotonic()
    try:
        while args.count == 0 or sent < args.count:
            if interval:
                delay = start + sent * interval - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
            frame = HEADER.pack(MAGIC, args.flow, sent, time.time()) + pad
            try:
                sock.sendto(frame, dest)
            except OSError:
                errors += 1
            sent += 1
    except (Stop, KeyboardInterrupt):
        pass
    json.dump({"sent": sent, "errors": errors, "first": first,
               "last": time.time()}, sys.stdout)
    sys.stdout.write("\n")


def main():
    signal.signal(signal.SIGTERM, _stop)
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd")
    sub.required = True

    r = sub.add_parser("recv")
    r.add_argument("--bind", required=True, help="ip:port")

    s = sub.add_parser("send")
    s.add_argument("--to", required=True, help="ip:port")
    s.add_argument("--src", help="source ip")
    s.add_argument("--flow", type=int, default=1)
    s.add_argument("--count", type=int, default=100, help="0: until stopped")
    s.add_argument("--rate", type=float, default=100, help="frames/s")
    s.add_argument("--size", type=int, default=64, help="UDP payload bytes")

    args = ap.parse_args()
    if args.cmd == "recv":
        cmd_recv(args)
    else:
        cmd_send(args)


if __name__ == "__main__":
    main()
