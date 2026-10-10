#!/usr/bin/env python3
#
# Copyright (C) Honey Bunny QT
# SPDX-License-Identifier: GPL-3.0-only
#
"""Run n3n edges and supernodes in network namespaces behind NATs

    sudo tests/netns/run.py                 # all scenarios
    sudo tests/netns/run.py @quick          # the ones "make test" runs
    sudo tests/netns/run.py easy-hard -v3   # one, with more logging
    tests/netns/run.py --list

Needs root (namespaces, TAP devices, nftables), iproute2 and nft.  See
docs/develop/netns_testing.md.
"""

import argparse
import concurrent.futures
import fcntl
import json
import os
import shlex
import shutil
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from n3ntest import lab as labmod             # noqa: E402
from n3ntest.scenario import Run, Settings    # noqa: E402
from n3ntest.scenarios import SCENARIOS, select   # noqa: E402
from n3ntest.node import Daemon               # noqa: E402

PREFIX = "n3ntest"
LOCKFILE = "/run/n3n-netns-test.lock"


def missing_prerequisites(settings):
    missing = []
    if os.geteuid() != 0:
        missing.append("root (try sudo)")
    for tool in ("ip", "nft"):
        if not shutil.which(tool):
            missing.append("the {} command".format(tool))
    if not os.path.exists("/dev/net/tun"):
        missing.append("/dev/net/tun")
    for b in (settings.edge_bin, settings.sn_bin):
        if not os.access(b, os.X_OK):
            missing.append("{} (run make)".format(b))
    return missing


def fmt_frames(result):
    parts = []
    for tag, f in sorted(result.get("frames", {}).items()):
        parts.append("{} {}/{}".format(tag, f["received"], f["sent"]))
    return ", ".join(parts) or "-"


def fmt_path(result):
    checks = {c["name"]: c for c in result.get("checks", [])}
    path = checks.get("path")
    if not path:
        return "-"
    if result["expect"] == "direct":
        t = result.get("time_to_direct")
        return "direct {}s".format(t) if t is not None else "NOT direct"
    return "relayed" if path["ok"] else "went direct"


def relayed_count(result):
    total = 0
    for name, c in result.get("counters", {}).items():
        total += c.get("sn_fwd", {}).get("tx_pkt", 0)
    return total


def print_summary(results, out=sys.stdout):
    rows = [("scenario", "NAT a / b", "nat4 a", "nat4 b", "path",
             "frames (rx/tx)", "sn_fwd", "")]
    for r in results:
        nat4 = r.get("nat4", {})
        rows.append((
            r["scenario"], r["nat"], nat4.get("a", "-"), nat4.get("b", "-"),
            fmt_path(r), fmt_frames(r), str(relayed_count(r)),
            "PASS" if r["ok"] else "FAIL",
        ))
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    for i, row in enumerate(rows):
        out.write("  ".join(c.ljust(w) for c, w in zip(row, widths))
                  .rstrip() + "\n")
        if i == 0:
            out.write("  ".join("-" * w for w in widths) + "\n")


def chown_to_sudo_user(path):
    uid = os.environ.get("SUDO_UID")
    gid = os.environ.get("SUDO_GID")
    if not uid or not gid:
        return
    for root, dirs, files in os.walk(path):
        for name in dirs + files:
            try:
                os.lchown(os.path.join(root, name), int(uid), int(gid))
            except OSError:
                pass
    try:
        os.lchown(path, int(uid), int(gid))
    except OSError:
        pass


def main():
    topdir = os.path.dirname(os.path.dirname(HERE))
    ap = argparse.ArgumentParser(
        description=__doc__.split("\n")[0],
        epilog="Scenarios are names, shell patterns or @tags (@quick).")
    ap.add_argument("scenarios", nargs="*")
    ap.add_argument("-l", "--list", action="store_true",
                    help="list the scenarios and exit")
    ap.add_argument("-j", "--jobs", type=int, default=4,
                    help="scenarios to run at once (default 4)")
    ap.add_argument("--frames", type=int, default=500,
                    help="frames each way in the measured burst")
    ap.add_argument("--rate", type=float, default=200,
                    help="frames/s of the measured burst")
    ap.add_argument("--size", type=int, default=64,
                    help="UDP payload bytes per frame")
    ap.add_argument("--loss", type=float, default=0.01,
                    help="share of the burst allowed to get lost")
    ap.add_argument("--register-interval", type=int, default=5,
                    help="connection.register_interval of the edges "
                    "(default 5, n3n's own default is 20)")
    ap.add_argument("--punch-ports", type=int, default=128,
                    help="connection.punch_ports of the edges "
                    "(default 128, n3n's own default is 16)")
    ap.add_argument("--connect-timeout", type=int, default=90,
                    help="seconds for edges to reach each other directly")
    ap.add_argument("-v", "--verbose", type=int, default=2, metavar="N",
                    help="logging.verbose of the daemons (default 2)")
    ap.add_argument("--wrap", default="",
                    help="command to run the daemons under, e.g. "
                    "'valgrind --error-exitcode=99'")
    ap.add_argument("--keep-root", action="store_true",
                    help="the daemons keep root (daemon.userid=0): for "
                    "LeakSanitizer, which cannot check a daemon that "
                    "dropped its privileges")
    ap.add_argument("--topdir", default=topdir,
                    help="where apps/n3n-edge is (default: this tree)")
    ap.add_argument("--workdir",
                    default=os.path.join(HERE, "out"),
                    help="logs, configs and results (default tests/netns/out)")
    ap.add_argument("--skip-missing", action="store_true",
                    help="exit 0 if root, ip, nft or TUN are missing")
    ap.add_argument("--cleanup", action="store_true",
                    help="remove namespaces a crashed run left, and exit")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="only print the summary")
    args = ap.parse_args()

    if args.list:
        for s in SCENARIOS:
            tags = " ".join("@" + t for t in sorted(s.tags))
            print("{:16} {:9} {:28} {}{}".format(
                s.name, s.expect, s.nat_summary(), s.desc,
                "  " + tags if tags else ""))
        return 0

    try:
        scenarios = select(args.scenarios)
    except KeyError as e:
        print("no scenario matches {}".format(e), file=sys.stderr)
        return 2

    settings = Settings(
        topdir=os.path.abspath(args.topdir),
        workdir=os.path.abspath(args.workdir),
        register_interval=args.register_interval,
        punch_ports=args.punch_ports,
        frames=args.frames,
        rate=args.rate,
        size=args.size,
        loss=args.loss,
        verbose=args.verbose,
        connect_timeout=args.connect_timeout,
        wrap=shlex.split(args.wrap),
    )
    Daemon.keep_root = args.keep_root

    missing = missing_prerequisites(settings)
    if missing:
        msg = "netns tests need: " + ", ".join(missing)
        if args.skip_missing:
            print("SKIP " + msg)
            return 0
        print(msg, file=sys.stderr)
        return 2

    lock = open(LOCKFILE, "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("another run of the netns tests is going on", file=sys.stderr)
        return 2

    removed = labmod.cleanup_stale(PREFIX)
    if args.cleanup:
        print("removed {} namespaces".format(len(removed)))
        return 0

    if os.path.isdir(settings.workdir):
        shutil.rmtree(settings.workdir)
    os.makedirs(settings.workdir)
    # The daemons' session directories go below it.  n3n makes it when it
    # is not there, but releases before 3.4.7 (interop) give up when
    # another daemon made it between their check and their mkdir().
    os.makedirs("/run/n3n", mode=0o755, exist_ok=True)

    print_lock = threading.Lock()

    def log(msg):
        if not args.quiet:
            with print_lock:
                print(msg, flush=True)

    def one(index, scenario):
        prefix = "{}{}-".format(PREFIX, index)
        return Run(scenario, settings, prefix, log).execute()

    t0 = time.monotonic()
    results = [None] * len(scenarios)
    with concurrent.futures.ThreadPoolExecutor(max(1, args.jobs)) as pool:
        futures = {pool.submit(one, i, s): i for i, s in enumerate(scenarios)}
        for fut in concurrent.futures.as_completed(futures):
            i = futures[fut]
            try:
                results[i] = fut.result()
            except Exception as e:
                results[i] = {"scenario": scenarios[i].name,
                              "nat": scenarios[i].nat_summary(),
                              "expect": scenarios[i].expect,
                              "ok": False, "checks": [{
                                  "name": "harness", "ok": False,
                                  "detail": "{}: {}".format(
                                      type(e).__name__, e)}]}
            r = results[i]
            log("[{}] {} in {}s".format(r["scenario"],
                                        "PASS" if r["ok"] else "FAIL",
                                        r.get("seconds", "?")))

    with open(os.path.join(settings.workdir, "results.json"), "w") as f:
        json.dump(results, f, indent=2, sort_keys=True)

    print()
    print_summary(results)
    failed = [r for r in results if not r["ok"]]
    for r in failed:
        print("\n{} failed (logs in {}):".format(
            r["scenario"], r.get("workdir", "?")))
        for c in r.get("checks", []):
            if not c["ok"]:
                print("  {}: {}".format(c["name"], c["detail"]))
    print("\n{} of {} scenarios passed in {:.0f}s".format(
        len(results) - len(failed), len(results), time.monotonic() - t0))
    chown_to_sudo_user(settings.workdir)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
