#!/bin/sh
#
# Copyright (C) Hamish Coleman
# SPDX-License-Identifier: GPL-3.0-only
#
# Output the current version number
#

usage() {
    echo "Usage: $0 [date|short|hash]"
    echo
    echo "Determine the correct version number for the current build"
    exit 1
}

# We assume this script is in the TOPDIR/scripts directory and use that
# to find any other files we need
TOPDIR=$(dirname "$0")/..

VER_FILE_SHORT=$(cat "${TOPDIR}/VERSION")

if [ -d "$TOPDIR/.git" ]; then
    # If there is a .git directory in our TOPDIR, then this is assumed to be
    # real git checkout

    cd "$TOPDIR" || exit 1

    VER_HASH=$(git rev-parse --short HEAD)

    if VER_GIT_SHORT=$(git describe --abbrev=0 2>/dev/null); then
        if [ "$VER_FILE_SHORT" != "$VER_GIT_SHORT" ]; then
            echo "WARNING: VERSION file does not match tag version ($VER_FILE_SHORT != $VER_GIT_SHORT)" 1>&2
        fi

        VER_SHORT="$VER_GIT_SHORT"
        VER=$(git describe --abbrev=7 --dirty)
    else
        # A checkout without tags, such as a shallow clone: the version
        # is the VERSION file's, with the commit (an empty one would stop
        # configure with a misleading error)
        echo "WARNING: no tags in this git checkout, the version is from the VERSION file" 1>&2

        VER_SHORT="$VER_FILE_SHORT"
        VER="$VER_FILE_SHORT-g$(git describe --always --abbrev=7 --dirty)"
    fi

    if git diff --quiet; then
        # In a clean build dir, use the last commit date
        DATE=$(git log -1 --format=%cd)
    else
        # if dirty, use the current date
        DATE=$(date)
    fi
else
    # If there is no .git directory in our TOPDIR, we fall back on relying on
    # the VERSION file

    echo "WARNING: no .git dir, versions are just guesses" 1>&2

    VER_SHORT="$VER_FILE_SHORT"
    VER_HASH="unknown"
    VER="$VER_FILE_SHORT"
    DATE=$(date)
fi

case "$1" in
    date)
        echo "$DATE"
        ;;
    hash)
        echo "$VER_HASH"
        ;;
    short)
        echo "$VER_SHORT"
        ;;
    "")
        echo "$VER"
        ;;
    *)
        usage
        ;;
esac
