#!/bin/bash
#
# Copyright (C) Hamish Coleman
# SPDX-License-Identifier: GPL-3.0-only
#
# Run builtin commands to generate test data
#

[ -z "$TOPDIR" ] && TOPDIR=.
[ -z "$BINDIR" ] && BINDIR=.

docmd() {
    echo "### test: $*"
    "$@"
    local S=$?
    echo
    return $S
}

docmd "$BINDIR"/apps/n3n-edge test check

docmd "$BINDIR"/apps/n3n-edge test config roundtrip

# Sections with instances, and options given more than once
echo "### test: load_dump tests/conf/communities.conf (community parts)"
"$BINDIR"/apps/n3n-edge debug config load_dump "$TOPDIR"/tests/conf/communities.conf \
    | sed -n -e '/^\[community/,/^$/p' -e '/^community_regex/p'
echo

# -O for a community's section: over the file's (home, lab-2.x), and one
# that only the command line has, a dot in its name; written with a space
# or a dot after "community"
echo "### test: load_dump tests/conf/communities.conf -O ... (community parts)"
"$BINDIR"/apps/n3n-edge \
    -O "community home.network=10.78.0.0/16" \
    -O "community.lab-2.x.user=carol nHWum+r42k1qDXdIeH-WFKeylK5UyLStRzxofRNAgpG" \
    -O "community new.net.key=secret3" \
    -O community.new.net.cipher=Speck \
    debug config load_dump "$TOPDIR"/tests/conf/communities.conf \
    | sed -n -e '/^\[community/,/^$/p'
echo

# udp:// and tcp:// in front of addresses; the same address for both is one
echo "### test: load_dump tests/conf/transports.conf (bind, supernode)"
"$BINDIR"/apps/n3n-edge debug config load_dump "$TOPDIR"/tests/conf/transports.conf \
    | grep -E '^(bind|supernode)='
echo

docmd "$BINDIR"/apps/n3n-edge tools keygen logan 007
docmd "$BINDIR"/apps/n3n-edge tools keygen secretFed
