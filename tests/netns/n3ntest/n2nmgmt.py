#
# Copyright (C) Honey Bunny QT
# SPDX-License-Identifier: GPL-3.0-only
#
"""One query of n2n's management interface, run in the daemon's network
namespace (see node.N2nMgmt): PORT METHOD [TIMEOUT], prints its rows as a
JSON list"""

import json
import socket
import sys
import time


def query(port, method, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    tag = "1"
    s.sendto("r {} {}".format(tag, method).encode(), ("127.0.0.1", port))
    rows = []
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        data, _ = s.recvfrom(65536)
        for reply in _objects(data.decode("utf8", errors="replace")):
            if reply.get("_tag") != tag:
                continue
            kind = reply.pop("_type", None)
            if kind == "error":
                raise RuntimeError(reply.get("error", "error"))
            if kind == "end":
                return rows
            if kind == "row":
                reply.pop("_tag", None)
                rows.append(reply)
    raise socket.timeout("no end of the reply")


def _objects(text):
    """The JSON objects of a datagram: the edge's may hold more than one,
    or what is left of an earlier reply after its end"""
    dec = json.JSONDecoder()
    i = text.find("{")
    while 0 <= i < len(text):
        try:
            obj, j = dec.raw_decode(text, i)
        except ValueError:
            return
        yield obj
        i = text.find("{", j)


def main():
    port, method = int(sys.argv[1]), sys.argv[2]
    timeout = float(sys.argv[3]) if len(sys.argv) > 3 else 3.0
    try:
        rows = query(port, method, timeout)
    except (OSError, ValueError, RuntimeError) as e:
        sys.stderr.write("{}\n".format(e))
        return 1
    json.dump(rows, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
