/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-25 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The communities of a supernode: from the configuration and the community file, their keys and address ranges, purging and sorting them
 */

#ifndef N3N_SN_COMMUNITIES_H
#define N3N_SN_COMMUNITIES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "n2n_typedefs.h"
#include "pdu_in.h"

// The addresses the auto ip address service hands out
int assign_one_ip_addr (struct sn_community *comm, n2n_desc_t dev_desc, n2n_ip_subnet_t *ip_addr);
// Regular work on the table of communities
int purge_expired_communities (struct n3n_runtime_data *sss,
                               time_t* p_last_purge,
                               time_t now);
int64_t number_enc_packets (const struct sn_community *comm);
int sort_communities (struct n3n_runtime_data *sss,
                      time_t* p_last_sort,
                      time_t now);

uint8_t mask2bitlen (uint32_t mask);

// The keys of user/password authentication
void calculate_dynamic_keys (struct n3n_runtime_data *sss);
void send_re_register_super (struct n3n_runtime_data *sss);

#endif
