/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-25 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The relay role: the PDUs of the edges, registering them and passing their packets on
 */

#ifndef N3N_ROLE_RELAY_H
#define N3N_ROLE_RELAY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "n2n_typedefs.h"
#include "pdu_in.h"

// Registering the edges
uint16_t reg_lifetime (struct n3n_runtime_data *sss);
int get_local_auth (struct n3n_runtime_data *sss, n2n_auth_t *auth);
int update_edge (struct n3n_runtime_data *sss,
                 const n2n_common_t* cmn,
                 const n2n_REGISTER_SUPER_t* reg,
                 struct sn_community *comm,
                 const n3n_sock_t *sender_sock,
                 const SOCKET socket_fd,
                 n2n_auth_t *answer_auth,
                 int skip_add,
                 time_t now);
bool community_appends_hash (const struct sn_community *comm);
// The handlers of the PDUs from the edges, see sn_pdu_handlers; also of a
// REGISTER_SUPER and a PACKET another supernode passes on
void sn_rx_packet (struct n3n_runtime_data *sss, struct pdu_ctx *c);
void sn_rx_register (struct n3n_runtime_data *sss, struct pdu_ctx *c);
void sn_rx_register_ack (struct n3n_runtime_data *sss, struct pdu_ctx *c);
void sn_rx_register_super (struct n3n_runtime_data *sss, struct pdu_ctx *c);
void sn_rx_unregister_super (struct n3n_runtime_data *sss, struct pdu_ctx *c);
void sn_rx_query_peer (struct n3n_runtime_data *sss, struct pdu_ctx *c);

// Which supernode of the federation an edge is registered at
void update_node_supernode_association (struct sn_community *comm,
                                        n2n_mac_t *edgeMac,
                                        const struct sockaddr *sender_sock,
                                        socklen_t sock_size,
                                        time_t now);

#endif
