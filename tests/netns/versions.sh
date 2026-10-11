#!/bin/sh
#
# Copyright (C) Honey Bunny QT
# SPDX-License-Identifier: GPL-3.0-only
#
# Other versions of n3n, n2n, and this tree for other CPUs, for the
# interop and cross scenarios of the netns tests:
#
#   tests/netns/versions.sh build NAME REF [REPO]
#       build REF (a tag, branch or commit) of REPO (default: upstream,
#       https://github.com/n42n/n3n) into tests/netns/versions/NAME, which
#       the scenarios find by NAME (Site(version=NAME)); REPO may be n2n's,
#       https://github.com/ntop/n2n (its edge and supernode)
#   tests/netns/versions.sh cross NAME ARCH [CFLAGS]
#       build this tree (with the changes to its files not committed) for
#       another CPU into tests/netns/versions/NAME, to run under qemu-user:
#       ARCH s390x (big endian), mips (big endian, 32 bit), arm64 or
#       armhf; needs gcc-HOST, libc6-dev-ARCH-cross and qemu-user
#   tests/netns/versions.sh list
#
# The interop and cross scenarios of a version that is not built are
# skipped.

set -e

HERE=$(cd "$(dirname "$0")" && pwd)
DIR=$HERE/versions

case "$1" in
    build)
        name=$2; ref=$3; repo=${4:-https://github.com/n42n/n3n}
        if [ -z "$name" ] || [ -z "$ref" ]; then
            sed -n '7,22p' "$0" | sed 's/^# \{0,1\}//'; exit 2
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
    cross)
        name=$2; arch=$3; cflags=$4
        case "$arch" in
            s390x) host=s390x-linux-gnu; qemu="qemu-s390x" ;;
            mips) host=mips-linux-gnu; qemu="qemu-mips" ;;
            arm64) host=aarch64-linux-gnu; qemu="qemu-aarch64" ;;
            armhf) host=arm-linux-gnueabihf; qemu="qemu-arm" ;;
            *) sed -n '7,22p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
        esac
        if [ -z "$name" ]; then
            sed -n '7,22p' "$0" | sed 's/^# \{0,1\}//'; exit 2
        fi
        mkdir -p "$DIR"
        src=$DIR/$name.src
        rm -rf "${src:?}" "${DIR:?}/${name:?}"
        mkdir -p "$src" "$DIR/$name"
        # the tree as it is: a commit of the changes, if there are any
        top=$(cd "$HERE/../.." && pwd)
        ref=$(git -C "$top" stash create)
        git -C "$top" archive "${ref:-HEAD}" | tar -x -C "$src"
        (cd "$src" && ./autogen.sh && ./configure --host="$host" \
            CFLAGS="-g -O2 $cflags" && make -j4 apps) >"$DIR/$name.log" 2>&1 || {
            echo "build for $arch failed, see $DIR/$name.log" >&2; exit 1; }
        cp -L "$src/apps/n3n" "$DIR/$name/n3n"
        # n3n-edge and n3n-supernode, as the scenarios run them: the one
        # binary under qemu, its role from the name it is given
        for b in n3n-edge n3n-supernode; do
            cat >"$DIR/$name/$b" <<EOT
#!/bin/sh
exec $qemu -L /usr/$host -0 $b "\$(dirname "\$0")/n3n" "\$@"
EOT
            chmod +x "$DIR/$name/$b"
        done
        echo "$arch" >"$DIR/$name/ARCH"
        echo "$(git -C "$top" describe --tags --always --dirty) for $arch${cflags:+ $cflags}" \
            >"$DIR/$name/VERSION"
        rm -rf "$src"
        echo "built $name: $(cat "$DIR/$name/VERSION")"
        ;;
    list)
        for v in "$DIR"/*/VERSION; do
            [ -e "$v" ] && echo "$(basename "$(dirname "$v")"): $(cat "$v")"
        done
        ;;
    *)
        sed -n '7,22p' "$0" | sed 's/^# \{0,1\}//'; exit 2
        ;;
esac
