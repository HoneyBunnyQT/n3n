/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-25 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The federation of supernodes: registering with the other supernodes, and what they send
 */

#ifndef N3N_ROLE_FEDERATE_H
#define N3N_ROLE_FEDERATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "n2n_typedefs.h"
#include "pdu_in.h"

// Register with the other supernodes of the federation from time to time,
// and forget those that went quiet
int re_register_and_purge_supernodes (struct n3n_runtime_data *sss, struct sn_community *comm, time_t *p_last_re_reg_and_purge, time_t now, uint8_t forced);
// The handlers of the PDUs from the other supernodes
void sn_rx_register_super_ack (struct n3n_runtime_data *sss, struct pdu_ctx *c);
void sn_rx_register_super_nak (struct n3n_runtime_data *sss, struct pdu_ctx *c);
void sn_rx_peer_info (struct n3n_runtime_data *sss, struct pdu_ctx *c);

#endif
