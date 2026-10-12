/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The edge's IPv6 address inside the tunnel, see docs/develop/IPv6.md
 */

#ifndef N3N_IPV6_H
#define N3N_IPV6_H

#include <stdint.h>          // for uint8_t, uint32_t

// The default of tuntap.prefix6: fd, 40 bits of a hash of the community's
// name, subnet 0 - a /64 of unique local addresses, the same for every
// edge of the community
void n3n_ipv6_prefix_default (const char *community, uint8_t prefix[16]);

// The edge's address from tuntap.address6 (NULL or "" for none, "auto",
// or an address with its prefix length) and tuntap.prefix6 (NULL or "" for
// the default): with "auto", the prefix and as interface ID the IPv4
// address (network order, 0 for none) in its lowest 32 bits, or else the
// modified EUI-64 of the MAC.  0 with addr and len set; 1 if there is no
// IPv6 address to be; -1, after a line in the log, if address6 or prefix6
// cannot be used.
int n3n_ipv6_address (const char *address6, const char *prefix6, const char *community,
                      uint32_t ipv4, const uint8_t mac[6], uint8_t addr[16], uint8_t *len);

#endif
