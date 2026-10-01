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

docmd "$BINDIR"/apps/n3n-edge tools keygen logan 007
docmd "$BINDIR"/apps/n3n-edge tools keygen secretFed
