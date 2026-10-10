#!/usr/bin/env python3
#
# Copyright (C) Honey Bunny QT
# SPDX-License-Identifier: GPL-3.0-only
#
"""How fast frames go through n3n: iperf3 between two edges in namespaces

    sudo tests/netns/bench.py                       # all cases, 3 times each
    sudo tests/netns/bench.py --json before.json
    tests/netns/bench.py --compare before.json after.json

The lab is that of the netns scenarios (docs/develop/netns_testing.md): two
edges, each behind a NAT, and two supernodes.  "direct" has the edges reach
each other directly, "relayed" through a supernode (hard NATs on both
sides), "threads" is direct with daemon.threads.  In each, iperf3 sends
from edge a to edge b through the tunnel, as fast as it can:

  udp64     UDP with 64 byte payloads: the packets per second that arrive
  udp1200   UDP with 1200 byte payloads: the throughput
  tcp       one TCP connection: the throughput

and each daemon's CPU time is read from /proc, before and after, to give
the CPU it took per packet that arrived - the number least shaken by a
busy machine.  Needs root, iperf3, ip and nft, as run.py does.
"""

import argparse
import fcntl
import json
import os
import shlex
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from n3ntest import lab as labmod             # noqa: E402
from n3ntest.lab import wait_for              # noqa: E402
from n3ntest.scenario import Run, Scenario, Settings, Site   # noqa: E402

PREFIX = "n3nbench"
LOCKFILE = "/run/n3n-netns-test.lock"
PORT = 5201

CASES = {
    "direct": dict(nat=("easy-kept", "easy-kept"), expect="direct"),
    "relayed": dict(nat=("hard-range", "hard-range"), expect="relayed"),
    "threads": dict(nat=("easy-kept", "easy-kept"), expect="direct",
                    conf={"daemon": {"threads": 2}}),
}

TESTS = {
    "udp64": ["-u", "-b", "0", "-l", "64"],
    "udp1200": ["-u", "-b", "0", "-l", "1200"],
    "tcp": [],
}


def cpu_seconds(pid):
    """utime + stime of a process, all its threads, in seconds"""
    with open("/proc/{}/stat".format(pid)) as f:
        fields = f.read().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


def iperf(ns, args):
    out = subprocess.run(["ip", "netns", "exec", ns, "iperf3", "-J"] + args,
                         capture_output=True, text=True, timeout=120)
    try:
        return json.loads(out.stdout)
    except ValueError:
        raise RuntimeError("iperf3: " + (out.stderr or out.stdout)[-300:])


def one_test(run, test, seconds):
    a, b = run.edges["a"], run.edges["b"]
    pids = {"edge-a": a["daemon"].proc.popen.pid,
            "edge-b": b["daemon"].proc.popen.pid}
    for name, sn in run.supernodes.items():
        pids[name] = sn["daemon"].proc.popen.pid
    server = subprocess.Popen(
        ["ip", "netns", "exec", b["ns"], "iperf3", "-s", "-1", "-B",
         b["overlay"], "-p", str(PORT)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    try:
        cpu0 = {n: cpu_seconds(p) for n, p in pids.items()}
        t0 = time.monotonic()
        res = iperf(a["ns"], ["-c", b["overlay"], "-p", str(PORT), "-t",
                              str(seconds)] + TESTS[test])
        took = time.monotonic() - t0
        cpu = {n: cpu_seconds(p) - cpu0[n] for n, p in pids.items()}
    finally:
        server.wait(timeout=10)
    end = res["end"]
    if test.startswith("udp"):
        s = end["sum"]
        received = s["packets"] - s["lost_packets"]
        out = {"pps": received / s["seconds"],
               "mbit": s["bits_per_second"] * (1 - s["lost_percent"] / 100)
               / 1e6,
               "lost": s["lost_percent"], "packets": received}
    else:
        s = end["sum_received"]
        out = {"mbit": s["bits_per_second"] / 1e6,
               "packets": s["bytes"] / 1448}
    out["cpu_pct"] = {n: round(100 * c / took, 1) for n, c in cpu.items()}
    # what all the daemons together spent per packet that arrived
    out["cpu_us_per_pkt"] = 1e6 * sum(cpu.values()) / max(1, out["packets"])
    return out


def bench_case(name, settings, tests, seconds, repeat, log):
    case = CASES[name]
    sc = Scenario("bench-" + name, "benchmark " + name,
                  Site([case["nat"][0]]), Site([case["nat"][1]]),
                  case["expect"], conf=case.get("conf"))
    run = Run(sc, settings, PREFIX + "-", log)
    results = {}
    try:
        run.build()
        run.start_supernodes()
        run.start_edges()
        run.wait_nat_classes(timeout=45)
        # a short run to bring the edges to the path they settle on
        b = run.edges["b"]
        warm = subprocess.Popen(
            ["ip", "netns", "exec", b["ns"], "iperf3", "-s", "-1", "-B",
             b["overlay"], "-p", str(PORT)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
        want = "p2p" if case["expect"] == "direct" else "pSp"
        iperf(run.edges["a"]["ns"], ["-c", b["overlay"], "-p", str(PORT),
                                     "-u", "-b", "1M", "-t", "3"])
        warm.wait(timeout=10)
        if not wait_for(lambda: all(m == want
                                    for m in run.modes().values()), 60, 1):
            raise RuntimeError("the edges are not {} but {}".format(
                want, run.modes()))
        for test in tests:
            runs = []
            for i in range(repeat):
                r = one_test(run, test, seconds)
                log("{} {} #{}: {}".format(name, test, i + 1, fmt(r)))
                runs.append(r)
            results[test] = runs
    finally:
        run._teardown()
    return results


def fmt(r):
    s = "{:8.1f} Mbit/s".format(r["mbit"])
    if "pps" in r:
        s += " {:9.0f} pps, {:5.1f}% lost".format(r["pps"], r["lost"])
    s += "  {:6.2f} us CPU/pkt  ".format(r["cpu_us_per_pkt"])
    s += " ".join("{} {}%".format(n, c) for n, c in
                  sorted(r["cpu_pct"].items()))
    return s


def median(runs, key):
    return statistics.median(r[key] for r in runs)


def summary(data):
    rows = []
    for case, tests in data["results"].items():
        for test, runs in tests.items():
            row = {"case": case, "test": test,
                   "mbit": median(runs, "mbit"),
                   "cpu_us_per_pkt": median(runs, "cpu_us_per_pkt")}
            if "pps" in runs[0]:
                row["pps"] = median(runs, "pps")
            rows.append(row)
    return rows


def print_summary(data):
    print("{:8} {:8} {:>10} {:>10} {:>12}".format(
        "case", "test", "Mbit/s", "pps", "us CPU/pkt"))
    for r in summary(data):
        print("{:8} {:8} {:10.1f} {:>10} {:12.2f}".format(
            r["case"], r["test"], r["mbit"],
            "{:.0f}".format(r["pps"]) if "pps" in r else "-",
            r["cpu_us_per_pkt"]))


def compare(old, new):
    o = {(r["case"], r["test"]): r for r in summary(old)}
    print("{:8} {:8} {:>21} {:>25}".format(
        "case", "test", "Mbit/s (change)", "us CPU/pkt (change)"))
    for r in summary(new):
        p = o.get((r["case"], r["test"]))
        if not p:
            continue

        def pct(a, b):
            return "{:+.0f}%".format(100 * (b - a) / a) if a else "-"
        print("{:8} {:8} {:9.1f} -> {:6.1f} {:>5} {:8.2f} -> {:6.2f} {:>5}"
              .format(r["case"], r["test"], p["mbit"], r["mbit"],
                      pct(p["mbit"], r["mbit"]), p["cpu_us_per_pkt"],
                      r["cpu_us_per_pkt"],
                      pct(p["cpu_us_per_pkt"], r["cpu_us_per_pkt"])))


def main():
    topdir = os.path.dirname(os.path.dirname(HERE))
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--cases", default=",".join(CASES),
                    help="which of " + ", ".join(CASES))
    ap.add_argument("--tests", default=",".join(TESTS),
                    help="which of " + ", ".join(TESTS))
    ap.add_argument("-t", "--seconds", type=int, default=5,
                    help="seconds each iperf3 run (default 5)")
    ap.add_argument("-r", "--repeat", type=int, default=3,
                    help="runs of each test, the median counts (default 3)")
    ap.add_argument("--json", help="write the results to this file")
    ap.add_argument("--compare", nargs=2, metavar=("OLD", "NEW"),
                    help="compare two --json files, and exit")
    ap.add_argument("--topdir", default=topdir,
                    help="where apps/n3n-edge is (default: this tree)")
    ap.add_argument("--workdir", default=os.path.join(HERE, "out-bench"),
                    help="logs and configs (default tests/netns/out-bench)")
    ap.add_argument("--wrap", default="",
                    help="command to run the daemons under, e.g. "
                    "'perf record -g -o /tmp/perf.data'")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    if args.compare:
        with open(args.compare[0]) as f:
            old = json.load(f)
        with open(args.compare[1]) as f:
            new = json.load(f)
        compare(old, new)
        return 0

    if os.geteuid() != 0:
        print("needs root (namespaces, TAP devices, nftables)",
              file=sys.stderr)
        return 2
    lock = open(LOCKFILE, "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("another run of the netns tests is going on", file=sys.stderr)
        return 2
    labmod.cleanup_stale(PREFIX)
    os.makedirs(args.workdir, exist_ok=True)
    os.makedirs("/run/n3n", mode=0o755, exist_ok=True)

    settings = Settings(topdir=os.path.abspath(args.topdir),
                        workdir=os.path.abspath(args.workdir), verbose=1,
                        wrap=shlex.split(args.wrap))

    def log(msg):
        if not args.quiet:
            print(msg, flush=True)

    version = subprocess.run(
        [settings.edge_bin, "--version"], capture_output=True,
        text=True).stdout.split("\n")[0].strip()
    data = {"version": version, "seconds": args.seconds,
            "repeat": args.repeat, "results": {}}
    for case in args.cases.split(","):
        data["results"][case] = bench_case(
            case, settings, args.tests.split(","), args.seconds,
            args.repeat, log)
    print()
    print(version)
    print_summary(data)
    if args.json:
        with open(args.json, "w") as f:
            json.dump(data, f, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
