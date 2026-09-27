/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Handling received PACKETs on several threads - see edge_threads.h
 */

#include "config.h"          // for HAVE_LIBPTHREAD

#include <n3n/logging.h>     // for traceEvent
#include <stdlib.h>          // for calloc, free
#include <string.h>          // for memcpy

#include "counter.h"         // for COUNTER_INC, COUNTER_READ
#include "edge_threads.h"
#include "n2n.h"             // for n3n_runtime_data
#include "thread_local.h"    // for n3n_thread_slot, N3N_THREADS_MAX

#ifdef HAVE_LIBPTHREAD

#include <errno.h>           // for errno, EAGAIN
#include <fcntl.h>           // for fcntl, O_NONBLOCK
#include <pthread.h>         // for pthread_rwlock_*
#include <unistd.h>          // for pipe, read, write, close


// Items a worker hands to the main thread, per worker, oldest first. A power
// of two. Control messages and peer table changes are rare - a worker queues
// one when something about a peer changes, not for every packet - so this
// only fills up if the main thread is stuck.
#define QUEUE_SLOTS 64

enum queue_kind {
    QUEUE_EVENT = 1,
    QUEUE_CONTROL,
};

struct queue_item {
    enum queue_kind kind;
    struct edge_event ev;
    struct pdu_control ctl;
    size_t len;
    uint8_t buf[N2N_PKT_BUF_SIZE];      // CONTROL: the copy of the PDU
};

// One producer (the worker), one consumer (the main thread): each index is
// only ever written by one side, so a release store and an acquire load on
// it are all the synchronisation needed.
struct worker_queue {
    uint32_t head;                      // next to take, written by the main thread
    uint32_t tail;                      // next to fill, written by the worker
    uint32_t dropped;                   // queue was full
    struct queue_item item[QUEUE_SLOTS];
};

struct edge_threads {
    pthread_rwlock_t lock;
    int wake_pipe[2];                   // a worker writes a byte to wake the main thread
    struct worker_queue *queue[N3N_THREADS_MAX];   // indexed by n3n_thread_slot
};


void edge_threads_main_release (struct n3n_runtime_data *eee) {

    if(eee->threads) {
        pthread_rwlock_unlock(&eee->threads->lock);
    }
}


void edge_threads_main_acquire (struct n3n_runtime_data *eee) {

    if(eee->threads) {
        pthread_rwlock_wrlock(&eee->threads->lock);
    }
}


// the calling worker's next free slot, or NULL if its queue is full
static struct queue_item *queue_reserve (struct edge_threads *t) {

    struct worker_queue *q = t->queue[n3n_thread_slot];
    uint32_t head = __atomic_load_n(&q->head, __ATOMIC_ACQUIRE);

    if(q->tail - head >= QUEUE_SLOTS) {
        COUNTER_INC(q->dropped);
        return NULL;
    }

    return &q->item[q->tail & (QUEUE_SLOTS - 1)];
}


// publish the slot queue_reserve() returned, and wake the main thread
static void queue_commit (struct edge_threads *t) {

    struct worker_queue *q = t->queue[n3n_thread_slot];
    uint8_t one = 1;

    __atomic_store_n(&q->tail, q->tail + 1, __ATOMIC_RELEASE);

    // One byte per item is fine: items are rare. If the pipe is full, the
    // main thread is going to wake up anyway.
    if(write(t->wake_pipe[1], &one, 1) < 0) {
        // nothing to do
    }
}


void edge_threads_post_event (struct n3n_runtime_data *eee, const struct edge_event *ev) {

    struct queue_item *it = queue_reserve(eee->threads);

    if(!it) {
        return;
    }
    it->kind = QUEUE_EVENT;
    it->ev = *ev;
    queue_commit(eee->threads);
}


void edge_threads_post_control (struct n3n_runtime_data *eee, const struct pdu_control *c) {

    struct queue_item *it;

    if(c->size > sizeof(it->buf)) {
        return;
    }
    it = queue_reserve(eee->threads);
    if(!it) {
        return;
    }
    it->kind = QUEUE_CONTROL;
    it->ctl = *c;
    it->len = c->size;
    memcpy(it->buf, c->buf, c->size);
    queue_commit(eee->threads);
}


void edge_threads_drain (struct n3n_runtime_data *eee) {

    struct edge_threads *t = eee->threads;
    int slot;
    uint8_t scratch[64];

    if(!t) {
        return;
    }

    // empty the wake pipe first: anything queued after this writes again
    while(read(t->wake_pipe[0], scratch, sizeof(scratch)) > 0) {
        // nothing to do
    }

    for(slot = 1; slot < N3N_THREADS_MAX; slot++) {
        struct worker_queue *q = t->queue[slot];
        uint32_t tail, head;

        if(!q) {
            continue;
        }

        tail = __atomic_load_n(&q->tail, __ATOMIC_ACQUIRE);
        for(head = q->head; head != tail; head++) {
            struct queue_item *it = &q->item[head & (QUEUE_SLOTS - 1)];

            switch(it->kind) {
                case QUEUE_EVENT:
                    edge_event_apply(eee, &it->ev);
                    break;
                case QUEUE_CONTROL:
                    it->ctl.buf = it->buf;
                    it->ctl.size = it->len;
                    process_pdu_control(eee, &it->ctl);
                    break;
            }
        }
        __atomic_store_n(&q->head, head, __ATOMIC_RELEASE);
    }
}


#else // HAVE_LIBPTHREAD -------------------------------------------------------


void edge_threads_main_release (struct n3n_runtime_data *eee) {
}

void edge_threads_main_acquire (struct n3n_runtime_data *eee) {
}

void edge_threads_post_event (struct n3n_runtime_data *eee, const struct edge_event *ev) {
}

void edge_threads_post_control (struct n3n_runtime_data *eee, const struct pdu_control *c) {
}

void edge_threads_drain (struct n3n_runtime_data *eee) {
}


#endif // HAVE_LIBPTHREAD
