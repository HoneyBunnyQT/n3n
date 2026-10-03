#!/bin/sh
#
# Copyright (C) Honey Bunny QT
# SPDX-License-Identifier: GPL-3.0-only
#
# n3n-qr: what goes into the code, and that a QR reader (zbarimg) reads
# back the same from the image.  Needs n3n-qr (libqrencode and libpng at
# ./configure time) and zbarimg (zbar-tools).
#

# boilerplate so we can support whaky cmake dirs
[ -z "$TOPDIR" ] && TOPDIR=.
[ -z "$BINDIR" ] && BINDIR=.

set -e

QR="$(cd "$BINDIR" && pwd)/tools/n3n-qr"
CONF="$(cd "$TOPDIR" && pwd)/tests/conf/qr.conf"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "### the text in the code"
"$QR" -p "$CONF" | tee "$TMP/expected"

echo "### the default name of the image"
(cd "$TMP" && "$QR" "$CONF" 2>/dev/null && ls -- *.png)

echo "### read back from the image"
zbarimg -q --raw "$TMP/qr.qr.png" 2>/dev/null >"$TMP/read"
if cmp -s "$TMP/expected" "$TMP/read"; then
    echo "the same"
else
    diff -u "$TMP/expected" "$TMP/read"
fi
