#!/bin/bash
# Run upstream's integration tests on n42n/n3n main and on each pr/* branch.
#
# Needs: a Linux box with IPv6 on (the supernode binds [::] by default),
# sudo (the edges create tap devices), jq, curl, the build dependencies.
# Run it from a clone of HoneyBunnyQT/n3n.  It works in its own worktree,
# so your checkout is left alone.  Results: integ-results/<name>.log and a
# summary at the end.  Takes a few minutes per branch.
#
#   ./integ-prs.sh                 all, main first
#   ./integ-prs.sh big-endian      only main and that branch

set -u
BRANCHES=${*:-"build-housekeeping edge-runtime community-file pdu-length-checks management big-endian arm-speck crypto-tests sn-load-wire"}
TOP=$(git rev-parse --show-toplevel) || exit 1
OUT=$TOP/integ-results
WT=$TOP/../n3n-integ-wt
mkdir -p "$OUT"

for c in jq curl sudo; do
    command -v $c >/dev/null || { echo "missing: $c"; exit 1; }
done
[ -e /proc/net/if_inet6 ] || { echo "IPv6 is off on this host"; exit 1; }
sudo -v || exit 1

git remote get-url upstream >/dev/null 2>&1 || git remote add upstream https://github.com/n42n/n3n.git
git fetch -q upstream main && git fetch -q origin || exit 1
git worktree remove --force "$WT" 2>/dev/null
git worktree add -q --detach "$WT" upstream/main || exit 1

run() {   # run NAME REF
    local name=$1 ref=$2 rc
    echo -n "$name: "
    git -C "$WT" checkout -q --detach "$ref" && git -C "$WT" clean -qfdx
    (cd "$WT" && ./autogen.sh && ./configure && make -j"$(nproc)" apps tools) >"$OUT/$name.build.log" 2>&1 \
        || { echo "BUILD FAILED, see $OUT/$name.build.log"; return; }
    (cd "$WT" && timeout 600 make test.integration) >"$OUT/$name.log" 2>&1
    rc=$?
    # whatever a hung test left running
    sudo pkill -f "$WT/apps/n3n-" 2>/dev/null
    if [ $rc = 0 ]; then echo "ok"; elif [ $rc = 124 ]; then echo "TIMEOUT"; else echo "FAILED (rc=$rc)"; fi
}

run main upstream/main
for b in $BRANCHES; do
    run "$b" "origin/pr/$b"
done

git worktree remove --force "$WT"
echo
echo "Logs in $OUT; paste back the summary above and the .log of anything not ok."
