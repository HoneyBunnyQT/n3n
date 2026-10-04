/*
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Noticing that the host's network changed: an address, a link or the
 * default route (netlink, Linux), or that the host slept.  The edge then
 * registers again at once, see edge_network_change().
 */

#ifndef _NETWATCH_H_
#define _NETWATCH_H_

#include <stdbool.h>

// Why the network is looked at again, ORed together
#define NETWATCH_ADDRESS    0x01    // an address came or went
#define NETWATCH_LINK       0x02    // a link went up or down
#define NETWATCH_ROUTE      0x04    // the default route changed
#define NETWATCH_RESUME     0x08    // the host slept
#define NETWATCH_EXTERNAL   0x10    // the embedding app says so, n3n_edge_network_changed()

// A socket for the changes of the network, not of the device named
// own_dev (the edge's TAP device): -1 where there is none (not Linux, or
// not allowed, as for apps on Android)
int netwatch_open (const char *own_dev);
void netwatch_close (int fd);

// Read all that came on fd: NETWATCH_* of what changed, 0 for nothing
// that matters
unsigned netwatch_read (int fd);

// Whether the host slept since the last call (Linux: the clock that counts
// the sleep, CLOCK_BOOTTIME, got ahead of the one that does not)
bool netwatch_resumed (void);

// What a set of NETWATCH_* reads as, for the log
const char *netwatch_str (unsigned why, char *buf, int len);

#endif
