/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-25 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Hole punching: getting through the NATs between two edges
 */

#ifndef N3N_PUNCH_H
#define N3N_PUNCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "n2n_typedefs.h"
#include "pdu_in.h"

// The socket bound to dest, if there is one
const struct punch_bound *punch_bound_find (const struct n3n_runtime_data *eee, const n3n_sock_t *dest);
void punch_close_all (struct n3n_runtime_data *eee);
// A packet came in on sock, one of the pool or bound ones
void punch_note_rx (struct n3n_runtime_data *eee, SOCKET sock,
                    const struct sockaddr *sender, time_t now);
// Close the bound sockets that have been quiet for a while
void punch_sweep (struct n3n_runtime_data *eee, time_t now);
// One round of punching towards a peer, as its NAT and ours need it
void punch_round (struct n3n_runtime_data *eee, struct peer_info *peer, time_t now);

#endif
