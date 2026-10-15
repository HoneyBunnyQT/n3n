// Copyright (C) Honey Bunny QT
// SPDX-License-Identifier: GPL-3.0-only

package dev.n3n.android

/** What the app asks the core in libn3n directly, so that both agree */
object Core {

    init {
        System.loadLibrary("n3n")
    }

    /**
     * The edge's IPv6 address (src/ipv6.c) from tuntap.address6 and
     * tuntap.prefix6, the community's name and the IPv4 address: as
     * "address/length", null if there is none to be, "" if the options
     * cannot be used
     */
    external fun ipv6Address(address6: String, prefix6: String, community: String, ipv4: String): String?

    /** The core's version: git describe of the tree it was built from */
    external fun version(): String
}
