/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Freeing what a module set up for one thread
 */

#include <stdlib.h>          // for abort

#include "thread_local.h"


// Only a handful of modules keep something per thread, so a small fixed list
// is enough. Running out is a programming error, not a runtime condition.
#define N3N_THREAD_CLEANUP_MAX 8

static N3N_THREAD_LOCAL n3n_thread_cleanup_f cleanup_fn[N3N_THREAD_CLEANUP_MAX];
static N3N_THREAD_LOCAL int cleanup_count;


void n3n_thread_on_cleanup (n3n_thread_cleanup_f fn) {

    if(cleanup_count >= N3N_THREAD_CLEANUP_MAX) {
        abort();
    }
    cleanup_fn[cleanup_count++] = fn;
}


void n3n_thread_cleanup () {

    // newest first, the reverse of the order things were set up in
    while(cleanup_count) {
        cleanup_fn[--cleanup_count]();
    }
}
