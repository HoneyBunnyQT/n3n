#!/bin/sh
#
# Copyright (C) Honey Bunny QT
# SPDX-License-Identifier: GPL-3.0-only
#
# Other versions of n3n, and n2n, for the interop scenarios of the netns
# tests:
#
#   tests/netns/versions.sh build NAME REF [REPO]
#       build REF (a tag, branch or commit) of REPO (default: upstream,
#       https://github.com/n42n/n3n) into tests/netns/versions/NAME, which
#       the scenarios find by NAME (Site(version=NAME)); REPO may be n2n's,
#       https://github.com/ntop/n2n (its edge and supernode)
#   tests/netns/versions.sh list
#
# The interop scenarios of a version that is not built are skipped.

set -e

HERE=$(cd "$(dirname "$0")" && pwd)
DIR=$HERE/versions

case "$1" in
    build)
        name=$2; ref=$3; repo=${4:-https://github.com/n42n/n3n}
        if [ -z "$name" ] || [ -z "$ref" ]; then
            sed -n '7,17p' "$0" | sed 's/^# \{0,1\}//'; exit 2
        fi
        mkdir -p "$DIR"
        src=$DIR/$name.src
        rm -rf "${src:?}" "${DIR:?}/${name:?}"
        git clone -q "$repo" "$src"
        git -C "$src" checkout -q "$ref"
        if [ -d "$src/apps" ]; then
            target=apps; bins="apps/n3n-edge apps/n3n-supernode"
        else
            # n2n: its edge and supernode at the top
            target="edge supernode"; bins="edge supernode"
        fi
        # shellcheck disable=SC2086 # the targets are words
        (cd "$src" && ./autogen.sh && ./configure && make -j4 $target) >"$DIR/$name.log" 2>&1 || {
            echo "build of $ref failed, see $DIR/$name.log" >&2; exit 1; }
        mkdir -p "$DIR/$name"
        for b in $bins; do
            # a link may stand for the one binary: copy what it points to
            cp -L "$src/$b" "$DIR/$name/$(basename "$b")"
        done
        echo "$(git -C "$src" describe --tags --always) ($ref)" >"$DIR/$name/VERSION"
        rm -rf "$src"
        echo "built $name: $(cat "$DIR/$name/VERSION")"
        ;;
    list)
        for v in "$DIR"/*/VERSION; do
            [ -e "$v" ] && echo "$(basename "$(dirname "$v")"): $(cat "$v")"
        done
        ;;
    *)
        sed -n '7,17p' "$0" | sed 's/^# \{0,1\}//'; exit 2
        ;;
esac
