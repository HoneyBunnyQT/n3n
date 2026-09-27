/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Packet counters with one slot per thread
 *
 * Every thread counts into a slot of its own, so no counter is ever written
 * by two threads at once. Whoever wants the totals adds the slots up with
 * n3n_stats_sum(). The main thread uses slot 0, see n3n_thread_slot.
 */

#ifndef N3N_STATS_H
#define N3N_STATS_H

#include <stddef.h>          // for size_t
#include <stdint.h>          // for uint32_t
#include <string.h>          // for memset

#include "counter.h"         // for COUNTER_INC, COUNTER_READ
#include "n2n_typedefs.h"    // for n2n_edge_stats, n3n_runtime_data
#include "thread_local.h"    // for n3n_thread_slot, N3N_THREADS_MAX

#if N3N_STATS_SLOTS != N3N_THREADS_MAX
#error "N3N_STATS_SLOTS must match N3N_THREADS_MAX"
#endif

// the slot the calling thread counts into
#define N3N_STATS_THIS_SLOT n3n_thread_slot

// count one event in the calling thread's slot
#define STATS_INC(rt, field) COUNTER_INC((rt)->stats_slot[N3N_STATS_THIS_SLOT].field)

// Add up all slots into *out. Every member of struct n2n_edge_stats is a
// uint32_t, so this walks the struct word by word and a counter added to it
// later is summed without anyone having to remember this function.
static inline void n3n_stats_sum (const struct n3n_runtime_data *rt,
                                  struct n2n_edge_stats *out) {

    const size_t words = sizeof(struct n2n_edge_stats) / sizeof(uint32_t);
    uint32_t *sum = (uint32_t *)out;
    size_t slot, i;

    memset(out, 0, sizeof(*out));

    for(slot = 0; slot < N3N_STATS_SLOTS; slot++) {
        const uint32_t *s = (const uint32_t *)&rt->stats_slot[slot];
        for(i = 0; i < words; i++) {
            sum[i] += COUNTER_READ(s[i]);
        }
    }
}

#endif
