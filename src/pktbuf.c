/**
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Routines for handling a pool of packet-sized buffers
 */

#include <n3n/metrics.h>
#include <stdlib.h>
#include <string.h>

#include "pktbuf.h"
#include "counter.h"       // for COUNTER_INC, COUNTER_READ
#include "thread_local.h"  // for N3N_THREAD_LOCAL

struct metrics {
    uint32_t alloc;     // n3n_pktbuf_alloc() is called
    uint32_t free;      // n3n_pktbuf_free() is called
};

// The metrics page shows this: the counters of all pools added up
static struct metrics metrics;

static struct n3n_metrics_items_llu32 metrics_items = {
    .name = "count",
    .desc = "Track the pktbuf pool",
    .name1 = "event",
    .items = {
        {
            .val1 = "alloc",
            .offset = offsetof(struct metrics, alloc),
        },
        {
            .val1 = "free",
            .offset = offsetof(struct metrics, free),
        },
        { },
    },
};

static void metrics_prepare (struct n3n_metrics_module *module);

static struct n3n_metrics_module metrics_module_static = {
    .name = "pktbuf",
    .data = &metrics,
    .items_llu32 = &metrics_items,
    .type = n3n_metrics_type_llu32,
    .prepare = metrics_prepare,
};

// Every thread that handles packets has a pool of its own, so allocating and
// freeing never touches anything another thread uses. A buffer must be freed
// by the thread that allocated it.
struct pktbuf_pool {
    struct pktbuf_pool *next;   // the list of all pools, for the metrics
    void *buf;
    struct n3n_pktbuf *items;
    struct n3n_pktbuf *item_next_search;
    struct n3n_pktbuf *item_max;
    ssize_t item_size;
    int item_count;
    struct metrics metrics;
};

// the calling thread's pool
static N3N_THREAD_LOCAL struct pktbuf_pool *pool;

// All pools ever created, newest first. Pools are only ever added, never
// removed: a thread that finishes leaves its pool empty but listed, so that
// its counts stay in the totals. That makes the list safe to walk from any
// thread while others add to it.
static struct pktbuf_pool *all_pools;

// The shape every pool gets, set by n3n_pktbuf_initialise() before any other
// thread is started
static ssize_t shape_mtu;
static int shape_count;

static void pool_fill (struct pktbuf_pool *p, ssize_t mtu, int count) {

    // Round up to a multiple
    int item_size = (mtu + 2047) & ~0x7ff;

    p->buf = calloc(count, item_size);
    if(!p->buf) {
        abort();
    }

    p->items = calloc(count, sizeof(struct n3n_pktbuf));
    if(!p->items) {
        abort();
    }

    p->item_size = item_size;
    p->item_count = count;
    p->item_next_search = p->items;
    p->item_max = &p->items[count - 1];

    int i;
    for(i=0; i < p->item_count; i++) {
        p->items[i].buf = (uint8_t *)p->buf + i * item_size;
        *(short *)&p->items[i].capacity = item_size;
        p->items[i].owner = n3n_pktbuf_owner_none;
        n3n_pktbuf_zero(&p->items[i]);
    }
}

static void pool_empty (struct pktbuf_pool *p) {
    free(p->items);
    free(p->buf);
    p->items = NULL;
    p->buf = NULL;
    p->item_size = 0;
    p->item_count = 0;
    p->item_next_search = NULL;
    p->item_max = NULL;
}

// Give the calling thread a pool, if it has none yet and the shape is known
void n3n_pktbuf_thread_init () {
    if(pool || !shape_count) {
        return;
    }

    pool = calloc(1, sizeof(*pool));
    if(!pool) {
        abort();
    }
    pool_fill(pool, shape_mtu, shape_count);

    // add it to the front of the list; another thread may be doing the same
    struct pktbuf_pool *head = __atomic_load_n(&all_pools, __ATOMIC_RELAXED);
    do {
        pool->next = head;
    } while(!__atomic_compare_exchange_n(&all_pools, &head, pool, 1,
                                         __ATOMIC_RELEASE, __ATOMIC_RELAXED));
}

void n3n_pktbuf_initialise (ssize_t mtu, int count) {
    if(pool) {
        if(pool->metrics.alloc != pool->metrics.free) {
            // Simplify logic by not allowing the pool shape to change while
            // there are any users
            return;
        }
        pool_empty(pool);
        shape_mtu = mtu;
        shape_count = count;
        pool_fill(pool, mtu, count);
        return;
    }

    shape_mtu = mtu;
    shape_count = count;
    n3n_pktbuf_thread_init();
}

// Release the calling thread's buffers. The pool itself stays listed with its
// counts, and is filled again if the thread allocates once more.
void n3n_pktbuf_deinitialise () {
    if(!pool) {
        return;
    }
    pool_empty(pool);
}

struct n3n_pktbuf *n3n_pktbuf_alloc (ssize_t size) {
    if(!pool) {
        n3n_pktbuf_thread_init();
        if(!pool) {
            return NULL;
        }
    }
    if(!pool->items && shape_count) {
        pool_fill(pool, shape_mtu, shape_count);
    }

    // We only have one pool, so we can use a simple check
    if(size > pool->item_size) {
        return NULL;
    }

    struct n3n_pktbuf *p = pool->item_next_search;
    int count = pool->item_count;

    while(count) {
        if(p > pool->item_max) {
            p = pool->items;
        }

        if(p->owner == n3n_pktbuf_owner_none) {
            p->owner = n3n_pktbuf_owner_alloc;
            n3n_pktbuf_zero(p);

            pool->item_next_search = p + 1;
            COUNTER_INC(pool->metrics.alloc);
            return p;
        }

        p++;
        count--;
    }
    return NULL;
}

void n3n_pktbuf_free (struct n3n_pktbuf *p) {
    if(!pool || !pool->items) {
        return;
    }

    // Confirm we are within the pool boundaries - of this thread's pool
    if(p < pool->items) {
        return;
    }
    if(p > pool->item_max) {
        return;
    }

    p->owner = n3n_pktbuf_owner_none;
    pool->item_next_search = p;
    COUNTER_INC(pool->metrics.free);
}

// add up the counters of all pools just before the metrics page shows them
static void metrics_prepare (struct n3n_metrics_module *module) {
    struct pktbuf_pool *p;

    metrics.alloc = 0;
    metrics.free = 0;
    for(p = __atomic_load_n(&all_pools, __ATOMIC_ACQUIRE); p; p = p->next) {
        metrics.alloc += COUNTER_READ(p->metrics.alloc);
        metrics.free += COUNTER_READ(p->metrics.free);
    }
}

void n3n_pktbuf_zero (struct n3n_pktbuf *p) {
    p->offset_start = 0;
    p->offset_end = 0;
}

ssize_t n3n_pktbuf_getbufsize (const struct n3n_pktbuf *p) {
    return p->offset_end - p->offset_start;
}

ssize_t n3n_pktbuf_getbufavail (const struct n3n_pktbuf *p) {
    return p->capacity - p->offset_end;
}

void *n3n_pktbuf_getbufptr (const struct n3n_pktbuf *p) {
    return (void *)&p->buf[p->offset_start];
}

int n3n_pktbuf_prepend (struct n3n_pktbuf *p, ssize_t prepend) {
    if(prepend < 0) {
        return -1;
    }
    if(prepend > p->capacity) {
        return -1;
    }
    p->offset_start = prepend;
    return 1;
}

int n3n_pktbuf_append (struct n3n_pktbuf *p, ssize_t size, void *buf) {
    int new_end = p->offset_end + size;
    if(new_end > p->capacity) {
        return -1;
    }
    p->offset_end = new_end;
    memcpy((void *)&p->buf[p->offset_end], buf, size);
    return 1;
}

void n3n_initfuncs_pktbuf () {
    n3n_metrics_register(&metrics_module_static);
}

void n3n_deinitfuncs_pktbuf () {
    n3n_pktbuf_deinitialise();
}
