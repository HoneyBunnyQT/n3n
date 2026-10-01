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
 * get_info shows the class and it is logged when it changes. The peers learn
 * it from a hint in the REGISTERs that go through the supernode (see
 * nat_view_hint()) and show it in get_edges, and towards a peer behind a hard
 * NAT, an edge guesses its port (see punch_hard_peer() in edge_utils.c).
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

// The class as a hint for a peer, in the bits N2N_REG_COOKIE_HINT_MASK of
// the cookie of the REGISTER that goes through the supernode; 0 if unknown.
// The peer learns the sender's public address from the supernode anyway, the
// hint adds how that address can be reached:
//   bits 0-1   the enum nat_class
//   easy:      bit 2 set if the port is kept
//   hard:      the ports seen, rounded out to at least [lo, hi]: bits 2-7 the
//              lowest of them divided by 1024, bits 8-11 the exponent e of
//              the size of the range, 2 << e ports
n2n_cookie_t nat_view_hint (const struct nat_view *view);

// the hint as the string nat_view_str() would give, the port range rounded
const char *nat_hint_str (char *buf, size_t size, n2n_cookie_t hint);

// The entry of a peer in the table of NAT_PEERS, or NULL; with create, a new
// one if there is none, in place of the one heard from the longest ago
struct nat_peer *nat_peer_find (struct nat_peer *table, const n2n_mac_t mac, bool create);

// The class in a hint
enum nat_class nat_hint_class (n2n_cookie_t hint);

// The range of ports in a hint of a hard NAT, a power of two in size unless
// it reaches the top; false for any other class
bool nat_hint_range (n2n_cookie_t hint, unsigned int *lo, unsigned int *size);

// How many ports to try per round towards a peer behind a hard NAT, by
// default (connection.punch_ports), and the largest range to try at all: at
// 16 ports every 20 seconds, 4096 ports take an hour and a half. Beyond that,
// trying ports one by one hardly ever meets the one mapping of the peer.
#define NAT_PUNCH_PORTS_DFL 16
#define NAT_PUNCH_MAX_RANGE 4096

// Behind a hard NAT, how many sockets to open towards a peer that guesses, by
// default (connection.punch_sockets): each is one more port its guesses can
// meet. With 32 of them in a range of 1024 ports, 16 guesses meet one in 40%
// of the rounds; with the one socket of before, in 1.6%.
#define NAT_PUNCH_SOCKETS_DFL 32

#endif
