#!/bin/sh
#
# Copyright (C) Honey Bunny QT
# SPDX-License-Identifier: GPL-3.0-only
#
# Other versions of n3n, for the interop scenarios of the netns tests:
#
#   tests/netns/versions.sh build NAME REF [REPO]
#       build REF (a tag, branch or commit) of REPO (default: upstream,
#       https://github.com/n42n/n3n) into tests/netns/versions/NAME, which
#       the scenarios find by NAME (Site(version=NAME))
#   tests/netns/versions.sh list
#
# The interop scenarios of a version that is not built are skipped.

set -e

HERE=$(cd "$(dirname "$0")" && pwd)
DIR=$HERE/versions

case "$1" in
    build)
        name=$2; ref=$3; repo=${4:-https://github.com/n42n/n3n}
        [ -n "$name" ] && [ -n "$ref" ] || { sed -n '7,15p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
        mkdir -p "$DIR"
        src=$DIR/$name.src
        rm -rf "${src:?}" "${DIR:?}/${name:?}"
        git clone -q "$repo" "$src"
        git -C "$src" checkout -q "$ref"
        (cd "$src" && ./autogen.sh && ./configure && make -j4 apps) >"$DIR/$name.log" 2>&1 || {
            echo "build of $ref failed, see $DIR/$name.log" >&2; exit 1; }
        mkdir -p "$DIR/$name"
        for b in n3n-edge n3n-supernode; do
            # a link may stand for the one binary: copy what it points to
            cp -L "$src/apps/$b" "$DIR/$name/$b"
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
        sed -n '7,15p' "$0" | sed 's/^# \{0,1\}//'; exit 2
        ;;
esac
