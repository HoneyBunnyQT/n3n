/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The management page, see management_page.c
 */

#ifndef N3N_MANAGEMENT_PAGE_H
#define N3N_MANAGEMENT_PAGE_H

#include <connslot/strbuf.h>    // for strbuf_t
#include <stdbool.h>

struct n3n_runtime_data;

// The page of the process whose management interface rt has: a section for
// the edge and one for the supernode, each where it runs (NULL: does not).
// Unlocked (the password was given), it shows the names of communities
// with header encryption, see mgmt_name_hidden().
void mgmt_page_render (strbuf_t **b, struct n3n_runtime_data *rt, struct n3n_runtime_data *edge,
                       struct n3n_runtime_data *relay, bool unlocked);

#endif
