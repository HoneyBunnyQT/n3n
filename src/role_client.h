/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-25 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The client role: registering with the supernodes and with the peers
 */

#ifndef N3N_ROLE_CLIENT_H
#define N3N_ROLE_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "n2n_typedefs.h"
#include "pdu_in.h"

// Registrations with the supernodes and the peers
void reset_sup_attempts (struct n3n_runtime_data *eee);
void supernode_disconnect (struct n3n_runtime_data *eee);
void transport_probe_close (struct n3n_runtime_data *eee);
size_t encode_register_pkt (struct n3n_runtime_data * eee,
                            uint8_t *pktbuf,
                            const n2n_mac_t peer_mac,
                            const n2n_cookie_t cookie);
void send_register (struct n3n_runtime_data * eee,
                    const n3n_sock_t * remote_peer,
                    const n2n_mac_t peer_mac,
                    const n2n_cookie_t cookie);
bool is_link_local (const n3n_sock_t *sock);
int is_valid_peer_sock (const n3n_sock_t *sock);
void check_peer_registration_needed (struct n3n_runtime_data *eee,
                                     uint8_t from_supernode,
                                     uint8_t via_multicast,
                                     const n2n_mac_t mac,
                                     const n2n_cookie_t cookie,
                                     const n2n_ip_subnet_t *dev_addr,
                                     const n2n_desc_t *dev_desc,
                                     const n3n_sock_t *peer);
void check_known_peer_sock_change (struct n3n_runtime_data *eee,
                                   uint8_t from_supernode,
                                   uint8_t via_multicast,
                                   const n2n_mac_t mac,
                                   const n2n_ip_subnet_t *dev_addr,
                                   const n2n_desc_t *dev_desc,
                                   const n3n_sock_t *peer,
                                   time_t when);
void send_unregister_super (struct n3n_runtime_data *eee);
void sort_supernodes (struct n3n_runtime_data *eee, time_t now);
int check_query_peer_info (struct n3n_runtime_data *eee, time_t now, const n2n_mac_t mac);
int query_peer_fast (struct n3n_runtime_data *eee, time_t now, const n2n_mac_t mac);

// The handlers of the control messages, on the main thread
void edge_rx_register (struct n3n_runtime_data *eee, struct pdu_ctx *c);
void edge_rx_register_ack (struct n3n_runtime_data *eee, struct pdu_ctx *c);
void edge_rx_register_super_ack (struct n3n_runtime_data *eee, struct pdu_ctx *c);
void edge_rx_register_super_nak (struct n3n_runtime_data *eee, struct pdu_ctx *c);
void edge_rx_peer_info (struct n3n_runtime_data *eee, struct pdu_ctx *c);
void edge_rx_re_register_super (struct n3n_runtime_data *eee, struct pdu_ctx *c);

#endif
