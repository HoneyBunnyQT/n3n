#!/bin/sh
#
# Copyright (C) Honey Bunny QT
# SPDX-License-Identifier: GPL-3.0-only
#
# The netns tests in a kernel of their own: User-Mode Linux, a Linux kernel
# built as a program that runs on this one.  For hosts whose kernel lacks
# what the tests need - IPv6 above all, as in many containers - and without
# root on the host's network: the namespaces, links and NAT rulesets all
# live inside the UML kernel.  It boots from the host's own file system
# (hostfs), so it finds n3n, python3, ip and nft where they are.
#
#   tests/netns/uml.sh kernel SRC      configure and build SRC (a Linux
#                                      source tree, e.g. Debian/Ubuntu's
#                                      linux-source package) as UML
#   tests/netns/uml.sh run [ARGS]      run tests/netns/run.py ARGS in it
#
# The kernel is SRC/linux; run takes it from $UML_KERNEL, or from
# tests/netns/out/linux, where "kernel" puts a link to it.

set -e

HERE=$(cd "$(dirname "$0")" && pwd)
TOP=$(cd "$HERE/../.." && pwd)
OUT=$HERE/out

kernel() {
    src=$1
    [ -f "$src/Makefile" ] || { echo "not a kernel source tree: $src" >&2; exit 1; }
    cd "$src"
    make -s ARCH=um defconfig
    # what the harness uses: namespaces, veth, a bridge, TUN/TAP, nftables
    # NAT with conntrack, IPv6, netem; hostfs for the root file system
    ./scripts/config \
        -e HOSTFS -e IPV6 -e NET_NS -e NAMESPACES -e UTS_NS -e IPC_NS -e PID_NS \
        -e VETH -e BRIDGE -e TUN -e UNIX -e PACKET -e IP_MULTICAST \
        -e IP_ADVANCED_ROUTER -e NETFILTER -e NETFILTER_ADVANCED \
        -e NF_CONNTRACK -e NF_NAT -e NF_TABLES -e NF_TABLES_INET \
        -e NF_TABLES_IPV4 -e NF_TABLES_IPV6 -e NFT_NAT -e NFT_MASQ -e NFT_CT \
        -e NFT_LIMIT -e NFT_NUMGEN -e NFT_HASH -e NFT_REDIR -e NFT_REJECT \
        -e NFT_COUNTER -e NET_SCHED -e NET_SCH_NETEM -e NET_SCH_TBF \
        -e DEVTMPFS -e TMPFS -e BINFMT_SCRIPT -e STDERR_CONSOLE \
        -e NULL_CHAN -e FUTEX -e EPOLL -e EVENTFD -e SIGNALFD -e TIMERFD \
        -e INOTIFY_USER -e FHANDLE -e SYSVIPC
    make -s ARCH=um olddefconfig
    make ARCH=um -j"$(nproc)" linux
    mkdir -p "$OUT"
    ln -sf "$src/linux" "$OUT/linux"
    echo "UML kernel: $src/linux"
}

run() {
    uml=${UML_KERNEL:-$OUT/linux}
    [ -x "$uml" ] || { echo "no UML kernel at $uml: see '$0 kernel'" >&2; exit 1; }
    mkdir -p "$OUT"
    status=$OUT/uml-status
    rm -f "$status"

    # what runs as init in the UML kernel: its own /proc, /sys, /dev
    # and /run over the host's directories (seen through hostfs, the
    # host's stay untouched), then the tests, then power off
    init=$OUT/uml-init
    {
        echo "#!/bin/sh"
        echo "mount -t proc proc /proc; mount -t sysfs sys /sys"
        echo "mountpoint -q /dev || mount -t devtmpfs dev /dev"
        echo "mount -t tmpfs run /run"
        echo "mkdir -p /run/netns /dev/net"
        echo "[ -e /dev/net/tun ] || mknod /dev/net/tun c 10 200"
        echo "ip link set lo up"
        echo "export PATH=$PATH HOME=/root"
        echo "cd '$TOP'"
        printf "python3 tests/netns/run.py"
        # slower than the host: starting the senders of a flow can take
        # longer than half the peers' timeout (the register interval), and
        # the first frames then go the supernode's way
        case " $* " in *" --register-interval"*) ;; *) printf " --register-interval 10" ;; esac
        # one CPU: scenarios at once starve each other
        case " $* " in *" -j"*|*" --jobs"*) ;; *) printf " -j 1" ;; esac
        for a in "$@"; do printf " '%s'" "$a"; done
        echo
        echo "echo \$? > '$status'"
        # LINUX_REBOOT_CMD_HALT: the UML process ends
        echo "exec python3 -c 'import ctypes; ctypes.CDLL(None).reboot(0xcdef0123)'"
    } >"$init"
    chmod +x "$init"

    # the time of the host; output as the tests write it, the kernel's own
    # messages left out (quiet)
    "$uml" mem=4G ubd0=/dev/null rootfstype=hostfs rootflags=/ rw init="$init" quiet \
        con=null con0=fd:0,fd:1 </dev/null || true
    [ -f "$status" ] || { echo "the UML kernel ended without a result" >&2; exit 1; }
    exit "$(cat "$status")"
}

case "$1" in
    kernel) shift; kernel "$@" ;;
    run) shift; run "$@" ;;
    *) sed -n '7,20p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
