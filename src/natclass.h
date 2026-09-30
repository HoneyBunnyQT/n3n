/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * How the edge's NAT maps its sockets, as its supernodes see it
 *
 * Every PONG and REGISTER_SUPER_ACK tells the edge the public address the
 * supernode saw it at. The same public port towards every supernode means
 * that the NAT keeps one mapping per socket (easy): a peer that learns the
 * port from a supernode can send to it. A new port per destination means a
 * mapping per destination (hard): a peer would have to guess the port, in
 * about the range the supernodes saw. Several public addresses - more than
 * one uplink, or a supernode in the local network, which sees the local
 * address - leave nothing to guess.
 *
 * Nothing depends on the class yet; get_info shows it and it is logged when it
 * changes. It is a first step towards punching through hard NATs.
 */

#ifndef N3N_NATCLASS_H
#define N3N_NATCLASS_H

#include <stdbool.h>
#include <stddef.h>          // for size_t
#include <stdint.h>          // for uint16_t
#include <time.h>            // for time_t

#include "n2n_typedefs.h"    // for nat_view, n3n_sock_t

// A sample older than this is left out: the supernodes are PINGed every
// SWEEP_TIME, so it takes a few lost PONGs in a row.
#define NAT_SAMPLE_AGE 120

// Forget all samples, for a socket that is new, with this local port (0: no
// socket of that family).
void nat_view_reset (struct nat_view *view, uint16_t local_port);

// Add what the supernode at 'to' saw of the socket: 'seen'. Returns true if
// the class changed.
bool nat_view_add (struct nat_view *view, const n3n_sock_t *to, const n3n_sock_t *seen, time_t now);

// "unknown", "easy (port kept)", "hard (ports 40100-40180)", ...
const char *nat_view_str (char *buf, size_t size, const struct nat_view *view);

#endif
