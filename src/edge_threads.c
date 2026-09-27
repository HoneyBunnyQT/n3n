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
#include <n3n/mainloop.h>    // for mainloop_register_fd, mainloop_unregister_fd
#include <poll.h>            // for poll, pollfd, POLLIN
#include <pthread.h>         // for pthread_rwlock_*, pthread_create, pthread_join
#include <sys/socket.h>      // for getsockname, sockaddr_storage
#include <time.h>            // for time
#include <unistd.h>          // for pipe, read, write, close

#include "edge_utils.h"      // for edge_read_proto3_udp
#include "pktbuf.h"          // for n3n_pktbuf_alloc, n3n_pktbuf_thread_init


#ifndef _WIN32
// Another wonderful gift from the world of POSIX compliance is not worth much
#define closesocket(a) close(a)
#endif

// how many packets a worker takes from its socket per batch - the same cap as
// the main loop's drain
#define WORKER_DRAIN_MAX 32


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
    uint32_t posted;                    // items queued so far, reported at the end
    struct queue_item item[QUEUE_SLOTS];
};

struct worker {
    struct n3n_runtime_data *eee;
    int slot;                           // its n3n_thread_slot
    SOCKET sock;                        // its own socket, bound to the main socket's address
    pthread_t id;
    int started;
    uint32_t packets;                   // taken off its socket, reported at the end
};

struct edge_threads {
    pthread_rwlock_t lock;
    int wake_pipe[2];                   // a worker writes a byte to wake the main thread
    int stop_pipe[2];                   // the main thread writes a byte to stop the workers
    int stop;
    int requested;                      // threads asked for, the main thread included
    struct worker_queue *queue[N3N_THREADS_MAX];   // indexed by n3n_thread_slot
    struct worker worker[N3N_THREADS_MAX];         // indexed by n3n_thread_slot
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
    q->posted++;

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


static void *worker_main (void *arg) {

    struct worker *w = (struct worker *)arg;
    struct n3n_runtime_data *eee = w->eee;
    struct edge_threads *t = eee->threads;
    struct pollfd pfd[2];

    n3n_thread_slot = w->slot;
    n3n_pktbuf_thread_init();

    pfd[0].fd = w->sock;
    pfd[0].events = POLLIN;
    pfd[1].fd = t->stop_pipe[0];
    pfd[1].events = POLLIN;

    while(!__atomic_load_n(&t->stop, __ATOMIC_ACQUIRE)) {
        struct n3n_pktbuf *pkt;
        int drain = WORKER_DRAIN_MAX;
        time_t now;

        if(poll(pfd, 2, 1000) <= 0) {
            continue;
        }
        if(pfd[1].revents) {
            break;
        }
        if(!(pfd[0].revents & POLLIN)) {
            continue;
        }

        pkt = n3n_pktbuf_alloc(N2N_PKT_BUF_SIZE);
        if(!pkt) {
            continue;
        }
        pkt->owner = n3n_pktbuf_owner_rx_pdu;

        // one batch: whatever is queued on the socket, up to the cap
        pthread_rwlock_rdlock(&t->lock);
        now = time(NULL);
        while(drain && (edge_read_proto3_udp(eee, w->sock, pkt, now) > 0)) {
            drain--;
        }
        pthread_rwlock_unlock(&t->lock);
        w->packets += WORKER_DRAIN_MAX - drain;

        n3n_pktbuf_free(pkt);
    }

    n3n_thread_cleanup();
    return NULL;
}


static void edge_threads_free (struct n3n_runtime_data *eee) {

    struct edge_threads *t = eee->threads;
    int slot;

    for(slot = 1; slot < N3N_THREADS_MAX; slot++) {
        if(t->worker[slot].sock >= 0) {
            closesocket(t->worker[slot].sock);
        }
        free(t->queue[slot]);
    }
    if(t->wake_pipe[0] >= 0) {
        mainloop_unregister_fd(t->wake_pipe[0]);
        close(t->wake_pipe[0]);
        close(t->wake_pipe[1]);
    }
    if(t->stop_pipe[0] >= 0) {
        close(t->stop_pipe[0]);
        close(t->stop_pipe[1]);
    }
    pthread_rwlock_destroy(&t->lock);
    free(t);
    eee->threads = NULL;
}


int edge_threads_start (struct n3n_runtime_data *eee, int threads) {

    struct edge_threads *t;
    struct sockaddr_storage local;
    socklen_t local_len = sizeof(local);
    pthread_rwlockattr_t attr;
    int slot, started = 0;

    if(threads <= 1) {
        return 1;
    }
    if(threads > N3N_THREADS_MAX) {
        traceEvent(TRACE_WARNING, "at most %d threads, using %d", N3N_THREADS_MAX, N3N_THREADS_MAX);
        threads = N3N_THREADS_MAX;
    }
#ifndef __linux__
    // other systems do not spread one port's traffic over several sockets
    traceEvent(TRACE_WARNING, "threads are only supported on Linux, using one");
    return 1;
#endif
    if(eee->conf.connect_tcp) {
        traceEvent(TRACE_WARNING, "threads do not work with a TCP connection to the supernode, using one");
        return 1;
    }
    if((eee->sock < 0) || getsockname(eee->sock, (struct sockaddr *)&local, &local_len)) {
        traceEvent(TRACE_WARNING, "no main socket to share with threads, using one");
        return 1;
    }

    t = calloc(1, sizeof(*t));
    if(!t) {
        return 1;
    }
    t->requested = threads;
    t->wake_pipe[0] = t->wake_pipe[1] = -1;
    t->stop_pipe[0] = t->stop_pipe[1] = -1;
    for(slot = 0; slot < N3N_THREADS_MAX; slot++) {
        t->worker[slot].sock = -1;
    }

    pthread_rwlockattr_init(&attr);
#ifdef __GLIBC__
    // A waiting main thread must not be overtaken by one batch after the
    // other, or it could wait forever: new readers wait behind a writer.
    pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
#endif
    pthread_rwlock_init(&t->lock, &attr);
    pthread_rwlockattr_destroy(&attr);

    eee->threads = t;

    if(pipe(t->wake_pipe) || pipe(t->stop_pipe)) {
        traceEvent(TRACE_WARNING, "cannot create the pipes for threads, using one");
        edge_threads_free(eee);
        return 1;
    }
    fcntl(t->wake_pipe[0], F_SETFL, O_NONBLOCK);
    fcntl(t->wake_pipe[1], F_SETFL, O_NONBLOCK);

    // every socket bound to the same address and port with SO_REUSEPORT -
    // open_socket() sets it - gets a share of the senders
    for(slot = 1; slot < threads; slot++) {
        t->worker[slot].sock = open_socket((struct sockaddr *)&local, local_len, 0);
        if(t->worker[slot].sock < 0) {
            traceEvent(TRACE_WARNING, "cannot open a socket for thread %d", slot);
            break;
        }
        t->queue[slot] = calloc(1, sizeof(struct worker_queue));
        if(!t->queue[slot]) {
            break;
        }
        t->worker[slot].eee = eee;
        t->worker[slot].slot = slot;
    }

    mainloop_register_fd(t->wake_pipe[0], fd_info_proto_wakeup);

    // the main thread is awake, so it holds the lock from now on
    pthread_rwlock_wrlock(&t->lock);

    for(slot = 1; slot < threads; slot++) {
        if(!t->queue[slot]) {
            break;
        }
        if(pthread_create(&t->worker[slot].id, NULL, worker_main, &t->worker[slot])) {
            traceEvent(TRACE_WARNING, "cannot start thread %d", slot);
            break;
        }
        t->worker[slot].started = 1;
        started++;
    }

    if(!started) {
        pthread_rwlock_unlock(&t->lock);
        edge_threads_free(eee);
        return 1;
    }

    traceEvent(TRACE_NORMAL, "handling received packets with %d threads", started + 1);

    return started + 1;
}


void edge_threads_stop (struct n3n_runtime_data *eee) {

    struct edge_threads *t = eee->threads;
    uint8_t one = 1;
    int slot;

    if(!t) {
        return;
    }

    // whatever the workers queued so far still counts
    edge_threads_drain(eee);

    __atomic_store_n(&t->stop, 1, __ATOMIC_RELEASE);
    if(write(t->stop_pipe[1], &one, 1) < 0) {
        // the flag is checked at least once a second anyway
    }

    // A worker may be waiting for the read side; let go of the write side,
    // or it could never finish its batch and see the flag.
    pthread_rwlock_unlock(&t->lock);

    for(slot = 1; slot < N3N_THREADS_MAX; slot++) {
        if(t->worker[slot].started) {
            pthread_join(t->worker[slot].id, NULL);
            traceEvent(TRACE_NORMAL, "thread %d handled %u received packets, "
                       "passed %u to the main thread, dropped %u",
                       slot, t->worker[slot].packets,
                       t->queue[slot]->posted, COUNTER_READ(t->queue[slot]->dropped));
        }
    }

    edge_threads_free(eee);
}


void edge_threads_socket_changed (struct n3n_runtime_data *eee) {

    int threads;

    if(!eee->threads) {
        return;
    }

    // The main socket was opened again, maybe on another port: move the
    // workers along by starting them again. This only happens after the
    // supernode has not answered for a while.
    threads = eee->threads->requested;
    edge_threads_stop(eee);
    edge_threads_start(eee, threads);
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

int edge_threads_start (struct n3n_runtime_data *eee, int threads) {

    if(threads > 1) {
        traceEvent(TRACE_WARNING, "built without pthreads (./configure --enable-pthread), using one thread");
    }
    return 1;
}

void edge_threads_stop (struct n3n_runtime_data *eee) {
}

void edge_threads_socket_changed (struct n3n_runtime_data *eee) {
}


#endif // HAVE_LIBPTHREAD
