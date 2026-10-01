/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-25 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The tap role: the TAP device, and the PACKETs between it and the peers
 */

#ifndef N3N_ROLE_TAP_H
#define N3N_ROLE_TAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "n2n_typedefs.h"
#include "pdu_in.h"

// The read functions return 1 if they consumed a packet, 0 if there was
// nothing queued and -1 if the fd went bad
int edge_read_from_tap (struct n3n_runtime_data *eee);

// Reads up to max frames and returns how many it took off the tap queue
int edge_read_from_tap_batch (struct n3n_runtime_data *eee, int max);

void send_grat_arps (struct n3n_runtime_data * eee);

// The handler of a PACKET, on any thread
void edge_rx_packet (struct n3n_runtime_data *eee, struct pdu_ctx *c);

#endif
