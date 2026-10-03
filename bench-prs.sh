#!/bin/bash
#
# Before and after numbers of the builtin benchmark for the commits of the
# pr/* branches that touch code which runs per packet, for their commit
# messages (see docs/develop/testing.md upstream: "Contributing performance
# changes").
#
# Run it on a real machine, not a VM, as root - or as a user after
#   sudo sysctl kernel.perf_event_paranoid=1
# - so that the benchmark can read the CPU's counters (cycles, instructions).
# It clones the fork into ~/n3n-bench (or $WORK), builds each commit and its
# parent there, and writes everything to bench-<arch>.txt in the current
# directory.  Paste that file back.  Takes a few minutes; nothing is installed.
#
# Needs: git, autoconf, make, a C compiler (as for building n3n).

set -e

REPO=${REPO:-https://github.com/HoneyBunnyQT/n3n}
WORK=${WORK:-$HOME/n3n-bench}
ARCH=$(uname -m)
OUT="$PWD/bench-$ARCH.txt"

# branch | commit subject | benchmark tests | ./configure arguments | where
CASES=(
"pr/big-endian|Encrypt with Speck and ChaCha20 alike on big endian hosts|cc20_encr cc20_decr speck_encr speck_decr||arm"
"pr/big-endian|Read unaligned words through memcpy() in AES, Pearson and the edge|aes_encr aes_decr pearson_hash_64 tun2pdu pdu2tun||any"
"pr/big-endian|Give the same cipher outputs on every host|tf_encr aes_encr cc20_encr speck_encr||any"
"pr/big-endian|Decrypt Twofish alike on big endian hosts|tf_encr tf_decr||any"
"pr/big-endian|Read and write Twofish's words through memcpy()|tf_encr tf_decr||any"
"pr/pdu-length-checks|Let the decoders say when a PDU is too short for its fields|tun2pdu pdu2tun||any"
"pr/pdu-length-checks|Drop PDUs of the wrong length in the edge|tun2pdu pdu2tun||any"
"pr/arm-speck|Store Speck's SSE2 and AVX2 blocks where they are computed|speck_encr speck_decr||x86"
"pr/arm-speck|Store Speck's SSE2 and AVX2 blocks where they are computed|speck_encr speck_decr|CFLAGS=-O3 -march=native|x86"
"pr/arm-speck|Store Speck's NEON blocks where they are computed|speck_encr speck_decr|CFLAGS=-O2 -DSPECK_ARM_NEON|arm"
)

case "$ARCH" in
    x86_64|i?86) KIND=x86 ;;
    aarch64|arm*) KIND=arm ;;
    *) KIND=other ;;
esac

mkdir -p "$WORK"
cd "$WORK"
[ -d n3n ] || git clone -q "$REPO" n3n
cd n3n
git fetch -q origin '+refs/heads/pr/*:refs/remotes/origin/pr/*'

# build_and_run <commit> <configure args> <tests...>
build_and_run () {
    local commit=$1 conf=$2
    shift 2
    local dir="$WORK/build"
    rm -rf "$dir"
    git worktree prune
    git worktree add -q --detach "$dir" "$commit"
    (
        cd "$dir"
        ./autogen.sh >/dev/null 2>&1
        if [ -n "$conf" ]; then
            ./configure "$conf" >/dev/null
        else
            ./configure >/dev/null
        fi
        make -j"$(nproc)" apps >/dev/null 2>&1
        ./apps/n3n-edge test benchmark "$@"
    )
    rm -rf "$dir"
    git worktree prune
}

{
    echo "# $(uname -srm), $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ //')"
    echo "# $(${CC:-cc} --version | head -1)"
    echo "# perf_event_paranoid=$(cat /proc/sys/kernel/perf_event_paranoid), uid=$(id -u)"
} >"$OUT"

for c in "${CASES[@]}"; do
    IFS='|' read -r branch subject tests conf where <<<"$c"
    if [ "$where" != any ] && [ "$where" != "$KIND" ]; then
        continue
    fi
    commit=$(git log --format=%H --fixed-strings --grep="$subject" -1 "origin/$branch")
    if [ -z "$commit" ]; then
        echo "=== $subject: not found on $branch" | tee -a "$OUT"
        continue
    fi
    echo "running: $subject ${conf:+($conf)}"
    # shellcheck disable=SC2086
    {
        echo
        echo "=== $subject"
        echo "=== ./configure $conf"
        echo "--- before ($(git rev-parse --short "$commit~1"))"
        build_and_run "$commit~1" "$conf" $tests
        echo "--- after ($(git rev-parse --short "$commit"))"
        build_and_run "$commit" "$conf" $tests
    } >>"$OUT" 2>&1
done

echo "done: $OUT"
