/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Handling PACKETs on several threads - see edge_threads.h
 */

#ifdef __linux__
#define _GNU_SOURCE          // for sched_getaffinity
#endif

#include "config.h"          // for HAVE_LIBPTHREAD

#include <n3n/logging.h>     // for traceEvent
#include <stdio.h>           // for snprintf, fopen, fscanf
#include <stdlib.h>          // for calloc, free
#include <string.h>          // for memcpy

#ifdef __linux__
#include <sched.h>           // for sched_getaffinity, cpu_set_t, CPU_ISSET
#endif

#include "counter.h"         // for COUNTER_INC, COUNTER_READ
#include "edge_threads.h"
#include "n2n.h"             // for n3n_runtime_data
#include "thread_local.h"    // for n3n_thread_slot, N3N_THREADS_MAX

#if N3N_THREADS_MAX > N2N_TUNTAP_QUEUES_MAX
#error "every thread needs a tap queue of its own"
#endif


#ifdef __linux__
// read one number from a file in /sys, -1 if there is none
static int sys_read_int (const char *fmt, int cpu) {

    char path[128];
    FILE *f;
    int value = -1;

    snprintf(path, sizeof(path), fmt, cpu);
    f = fopen(path, "r");
    if(f) {
        if(fscanf(f, "%d", &value) != 1) {
            value = -1;
        }
        fclose(f);
    }
    return value;
}


// The physical cores the process may run on: the logical CPUs it is allowed
// on, with the hyperthreads of one core counted once. The kernel tells which
// core, in which package, a logical CPU belongs to.
static int physical_cores (void) {

    static int package[CPU_SETSIZE], core[CPU_SETSIZE];
    cpu_set_t allowed;
    int cpu, i, cores = 0;

    if(sched_getaffinity(0, sizeof(allowed), &allowed)) {
        return 1;
    }
    for(cpu = 0; cpu < CPU_SETSIZE; cpu++) {
        int p, c;

        if(!CPU_ISSET(cpu, &allowed)) {
            continue;
        }
        p = sys_read_int("/sys/devices/system/cpu/cpu%d/topology/physical_package_id", cpu);
        c = sys_read_int("/sys/devices/system/cpu/cpu%d/topology/core_id", cpu);
        if((p < 0) || (c < 0)) {
            // no topology: count every logical CPU as a core
            p = -1;
            c = cpu;
        }
        for(i = 0; i < cores; i++) {
            if((package[i] == p) && (core[i] == c)) {
                break;
            }
        }
        if(i == cores) {
            package[cores] = p;
            core[cores] = c;
            cores++;
        }
    }
    return cores ? cores : 1;
}
#endif


// threads=0: half the physical cores, rounded up - the other half is left
// for the kernel, which does much of the work of every packet
static int threads_auto (void) {

#ifdef __linux__
    return (physical_cores() + 1) / 2;
#else
    return 1;
#endif
}


int edge_threads_possible (const n2n_edge_conf_t *conf) {

    int threads = conf->threads ? (int)conf->threads : threads_auto();

    if(threads <= 1) {
        return 1;
    }
#if !defined(HAVE_LIBPTHREAD) || !defined(__linux__)
    // other systems do not spread one port's traffic over several sockets
    return 1;
#endif
    if(conf->connect_tcp) {
        return 1;
    }
    if(threads > N3N_THREADS_MAX) {
        return N3N_THREADS_MAX;
    }
    return threads;
}


int edge_threads_wanted (const n2n_edge_conf_t *conf) {

    int threads;

    if(conf->threads) {
        // asked for a number: try that, and warn if it does not work here
        return conf->threads;
    }

    // automatic: quietly as many as work here
    threads = edge_threads_possible(conf);
#ifdef __linux__
    traceEvent(TRACE_NORMAL, "threads=0: %d physical cores, %d threads",
               physical_cores(), threads);
#endif
    return threads;
}


#ifdef HAVE_LIBPTHREAD

#include <errno.h>           // for errno, EAGAIN
#include <fcntl.h>           // for fcntl, O_NONBLOCK
#include <n3n/mainloop.h>    // for mainloop_register_fd, mainloop_unregister_fd
#include <n3n/pktbuf.h>      // for n3n_pktbuf_alloc, n3n_pktbuf_thread_init
#include <poll.h>            // for poll, pollfd, POLLIN
#include <pthread.h>         // for pthread_rwlock_*, pthread_create, pthread_join
#include <sys/socket.h>      // for getsockname, sockaddr_storage
#include <time.h>            // for time
#include <unistd.h>          // for pipe, read, write, close

#include "edge_utils.h"      // for edge_read_proto3_udp


#ifndef _WIN32
// Another wonderful gift from the world of POSIX compliance is not worth much
#define closesocket(a) close(a)
#endif

// how many packets a worker takes from its socket, and how many frames from
// its tap queue, per batch - the same cap as the main loop's drain
#define WORKER_DRAIN_MAX 32


// Items a worker hands to the main thread, per worker, oldest first. A power
// of two. Control messages and peer table changes are rare - a worker queues
// one when something about a peer changes, not for every packet.
//
// Nothing is ever dropped: control messages keep holes punched, so losing
// one is not an option. If the ring is full, items go to an overflow list;
// and before each batch a worker checks that the main thread has caught up
// with it, and otherwise leaves the packets in its socket for a moment - where
// they wait just as they do for a single busy thread. So the overflow list
// never holds more than one batch's worth.
#define QUEUE_SLOTS 64

enum queue_kind {
    QUEUE_EVENT = 1,
    QUEUE_CONTROL,
    QUEUE_PDU,
};

struct queue_item {
    enum queue_kind kind;
    struct edge_event ev;
    struct pdu_control ctl;
    struct sockaddr_storage sender;     // PDU
    socklen_t sender_len;               // PDU
    uint64_t note[EDGE_THREADS_NOTE_MAX / sizeof(uint64_t)];   // PDU, aligned for any struct
    size_t len;
    uint8_t buf[N2N_PKT_BUF_SIZE];      // CONTROL, PDU: the copy of the PDU
};

struct overflow_item {
    struct overflow_item *next;
    struct queue_item item;
};

// One producer (the worker), one consumer (the main thread): each ring index
// is only ever written by one side, so a release store and an acquire load on
// it are all the synchronisation needed. The overflow list, rarely used, has
// a mutex.
//
// Order: the worker uses the overflow list as long as it holds anything, and
// the main thread empties the ring before the overflow list. So an item on
// the ring is always older than anything on the list, and the main thread
// sees everything in the order the worker queued it.
struct worker_queue {
    uint32_t head;                      // next to take, written by the main thread
    uint32_t tail;                      // next to fill, written by the worker
    uint32_t overflow_count;            // items on the overflow list
    pthread_mutex_t overflow_lock;
    struct overflow_item *overflow_first;
    struct overflow_item *overflow_last;
    uint32_t posted;                    // items queued so far, reported at the end
    uint32_t overflowed;                // of those, via the overflow list
    uint32_t lost;                      // no memory for an overflow item
    struct queue_item item[QUEUE_SLOTS];
};

struct worker {
    struct n3n_runtime_data *eee;
    int slot;                           // its n3n_thread_slot
    SOCKET sock[N3N_BIND_MAX];          // its own sockets: for the main socket's address, and
                                        // on the supernode for each further one of connection.bind
    int nsock;
    int tap;                            // its own tap queue, -1 if it has none
    pthread_t id;
    int started;
    uint32_t packets;                   // taken off its socket, reported at the end
    uint32_t frames;                    // taken off its tap queue, reported at the end
    uint32_t waited;                    // batches put off until the main thread caught up
};

struct edge_threads {
    pthread_rwlock_t lock;
    int wake_pipe[2];                   // a worker writes a byte to wake the main thread
    int stop_pipe[2];                   // the main thread writes a byte to stop the workers
    int stop;
    int tap_failed;                     // a worker's tap queue failed
    int requested;                      // threads asked for, the main thread included
    const struct edge_thread_ops *ops;
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


// how many items of this worker the main thread has not taken yet
static uint32_t queue_backlog (struct worker_queue *q) {

    return (q->tail - __atomic_load_n(&q->head, __ATOMIC_ACQUIRE))
           + __atomic_load_n(&q->overflow_count, __ATOMIC_ACQUIRE);
}


// Where the calling worker's next item goes: the next ring slot - unless the
// ring is full or the overflow list still holds items, then a new overflow
// item, returned in *ov. NULL only if there is no memory for that.
static struct queue_item *queue_reserve (struct edge_threads *t, struct overflow_item **ov) {

    struct worker_queue *q = t->queue[n3n_thread_slot];
    uint32_t head = __atomic_load_n(&q->head, __ATOMIC_ACQUIRE);

    *ov = NULL;
    if(!__atomic_load_n(&q->overflow_count, __ATOMIC_ACQUIRE)
       && (q->tail - head < QUEUE_SLOTS)) {
        return &q->item[q->tail & (QUEUE_SLOTS - 1)];
    }

    *ov = malloc(sizeof(**ov));
    if(!*ov) {
        COUNTER_INC(q->lost);
        return NULL;
    }
    return &(*ov)->item;
}


// publish the item queue_reserve() returned, and wake the main thread
static void queue_commit (struct edge_threads *t, struct overflow_item *ov) {

    struct worker_queue *q = t->queue[n3n_thread_slot];
    uint8_t one = 1;

    if(!ov) {
        __atomic_store_n(&q->tail, q->tail + 1, __ATOMIC_RELEASE);
    } else {
        ov->next = NULL;
        pthread_mutex_lock(&q->overflow_lock);
        if(q->overflow_last) {
            q->overflow_last->next = ov;
        } else {
            q->overflow_first = ov;
        }
        q->overflow_last = ov;
        __atomic_store_n(&q->overflow_count, q->overflow_count + 1, __ATOMIC_RELEASE);
        pthread_mutex_unlock(&q->overflow_lock);
        q->overflowed++;
    }
    q->posted++;

    // One byte per item is fine: items are rare. If the pipe is full, the
    // main thread is going to wake up anyway.
    if(write(t->wake_pipe[1], &one, 1) < 0) {
        // nothing to do
    }
}


void edge_threads_post_event (struct n3n_runtime_data *eee, const struct edge_event *ev) {

    struct overflow_item *ov;
    struct queue_item *it = queue_reserve(eee->threads, &ov);

    if(!it) {
        return;
    }
    it->kind = QUEUE_EVENT;
    it->ev = *ev;
    queue_commit(eee->threads, ov);
}


void edge_threads_post_control (struct n3n_runtime_data *eee, const struct pdu_control *c) {

    struct overflow_item *ov;
    struct queue_item *it;

    if(c->size > sizeof(it->buf)) {
        return;
    }
    it = queue_reserve(eee->threads, &ov);
    if(!it) {
        return;
    }
    it->kind = QUEUE_CONTROL;
    it->ctl = *c;
    it->len = c->size;
    memcpy(it->buf, c->buf, c->size);
    queue_commit(eee->threads, ov);
}


void edge_threads_post_pdu (struct n3n_runtime_data *eee,
                            const struct sockaddr *sender, socklen_t sender_len,
                            const uint8_t *buf, size_t size,
                            const void *note, size_t note_size) {

    struct overflow_item *ov;
    struct queue_item *it;

    if((size > sizeof(it->buf)) || (note_size > sizeof(it->note))
       || (sender_len > sizeof(it->sender))) {
        return;
    }
    it = queue_reserve(eee->threads, &ov);
    if(!it) {
        return;
    }
    it->kind = QUEUE_PDU;
    memcpy(&it->sender, sender, sender_len);
    it->sender_len = sender_len;
    memcpy(it->note, note, note_size);
    it->len = size;
    memcpy(it->buf, buf, size);
    queue_commit(eee->threads, ov);
}


static void queue_item_apply (struct n3n_runtime_data *eee, struct queue_item *it) {

    switch(it->kind) {
        case QUEUE_EVENT:
            edge_event_apply(eee, &it->ev);
            break;
        case QUEUE_CONTROL:
            it->ctl.buf = it->buf;
            it->ctl.size = it->len;
            process_pdu_control(eee, &it->ctl);
            break;
        case QUEUE_PDU:
            eee->threads->ops->process_pdu(eee, (struct sockaddr *)&it->sender, it->sender_len,
                                           it->buf, it->len, it->note);
            break;
    }
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

        // the ring first: anything on it is older than the overflow list
        tail = __atomic_load_n(&q->tail, __ATOMIC_ACQUIRE);
        for(head = q->head; head != tail; head++) {
            queue_item_apply(eee, &q->item[head & (QUEUE_SLOTS - 1)]);
        }
        __atomic_store_n(&q->head, head, __ATOMIC_RELEASE);

        if(__atomic_load_n(&q->overflow_count, __ATOMIC_ACQUIRE)) {
            struct overflow_item *ov, *next;

            pthread_mutex_lock(&q->overflow_lock);
            ov = q->overflow_first;
            q->overflow_first = NULL;
            q->overflow_last = NULL;
            __atomic_store_n(&q->overflow_count, 0, __ATOMIC_RELEASE);
            pthread_mutex_unlock(&q->overflow_lock);

            for(; ov; ov = next) {
                next = ov->next;
                queue_item_apply(eee, &ov->item);
                free(ov);
            }
        }
    }
}


static void *worker_main (void *arg) {

    struct worker *w = (struct worker *)arg;
    struct n3n_runtime_data *eee = w->eee;
    struct edge_threads *t = eee->threads;
    // its sockets first, then the stop pipe and its tap queue
    struct pollfd pfd[N3N_BIND_MAX + 2];
    struct pollfd *stop = &pfd[w->nsock];
    struct pollfd *tap = &pfd[w->nsock + 1];
    int npfd = w->nsock + 2;
    struct n3n_pktbuf *pkt;

    n3n_thread_slot = w->slot;
    n3n_pktbuf_thread_init();

    for(int i = 0; i < w->nsock; i++) {
        pfd[i].fd = w->sock[i];
        pfd[i].events = POLLIN;
    }
    stop->fd = t->stop_pipe[0];
    stop->events = POLLIN;
    tap->fd = w->tap;                   // poll() skips it if -1
    tap->events = POLLIN;

    // the one buffer this worker reads into
    pkt = n3n_pktbuf_alloc(N2N_PKT_BUF_SIZE);
    if(!pkt) {
        traceEvent(TRACE_ERROR, "thread %d has no packet buffer, stopping", w->slot);
        n3n_thread_cleanup();
        return NULL;
    }
    pkt->owner = n3n_pktbuf_owner_rx_pdu;

    while(!__atomic_load_n(&t->stop, __ATOMIC_ACQUIRE)) {
        bool readable = false;
        time_t now;

        if(poll(pfd, npfd, 1000) <= 0) {
            continue;
        }
        if(stop->revents) {
            break;
        }
        for(int i = 0; i < w->nsock; i++) {
            readable |= (pfd[i].revents & POLLIN) != 0;
        }
        if(!readable && !tap->revents) {
            continue;
        }

        // The main thread has not caught up with this worker yet: leave the
        // packets in the socket for a moment instead of queueing more.
        if(queue_backlog(t->queue[w->slot]) >= QUEUE_SLOTS) {
            w->waited++;
            poll(stop, 1, 5);
            continue;
        }

        // one batch: whatever is queued on the socket and on the tap queue,
        // up to the cap for each
        pthread_rwlock_rdlock(&t->lock);
        now = time(NULL);
        for(int i = 0; i < w->nsock; i++) {
            if(pfd[i].revents & POLLIN) {
                int drain = WORKER_DRAIN_MAX;
                while(drain && (t->ops->read_udp(eee, w->sock[i], pkt, now) > 0)) {
                    drain--;
                }
                w->packets += WORKER_DRAIN_MAX - drain;
            }
        }
        if(tap->revents) {
            w->frames += edge_read_from_tap_batch(eee, WORKER_DRAIN_MAX);
        }
        pthread_rwlock_unlock(&t->lock);

        // the main thread is going to open the device again, and start the
        // workers again with it
        if(__atomic_load_n(&t->tap_failed, __ATOMIC_ACQUIRE)) {
            tap->fd = -1;
        }
    }

    n3n_pktbuf_free(pkt);
    n3n_thread_cleanup();
    return NULL;
}


static void edge_threads_free (struct n3n_runtime_data *eee) {

    struct edge_threads *t = eee->threads;
    int slot;

    for(slot = 1; slot < N3N_THREADS_MAX; slot++) {
        for(int i = 0; i < t->worker[slot].nsock; i++) {
            if(t->worker[slot].sock[i] >= 0) {
                closesocket(t->worker[slot].sock[i]);
            }
        }
        if(t->queue[slot]) {
            pthread_mutex_destroy(&t->queue[slot]->overflow_lock);
            free(t->queue[slot]);
        }
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


// A socket on the address of another one, to share its port: with
// SO_REUSEPORT, and IPv6 only if that one is - the kernel groups only
// sockets alike.
static SOCKET open_like (SOCKET like) {

    struct sockaddr_storage local;
    socklen_t local_len = sizeof(local);
    int v6only = 0;
    socklen_t optlen = sizeof(v6only);
    int one = 1;
    SOCKET sock;

    if(getsockname(like, (struct sockaddr *)&local, &local_len)) {
        return -1;
    }
    if(local.ss_family == AF_INET6) {
        getsockopt(like, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, &optlen);
    }
    sock = socket(local.ss_family, SOCK_DGRAM, 0);
    if(sock < 0) {
        return -1;
    }
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
    if(local.ss_family == AF_INET6) {
        setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
    }
    if(bind(sock, (struct sockaddr *)&local, local_len)) {
        closesocket(sock);
        return -1;
    }
    return sock;
}


// Worker sockets opened ahead of the workers by edge_threads_open_early().
// The kernel shares a port's traffic only between SO_REUSEPORT sockets of
// the same user, and the daemons drop their privileges before the workers
// start: sockets opened then belong to another user than the main thread's,
// get a group of their own, and the kernel hands every datagram to one of
// the two groups only.
static SOCKET early_sock[N3N_THREADS_MAX][N3N_BIND_MAX];
static int early_slots;                     // slots 1 up to early_slots - 1
static int early_nsock;


// the main thread's socket that a worker's socket i shares a port with
static SOCKET like_sock (struct n3n_runtime_data *eee, int i) {

    return i ? eee->bind_sock[i] : eee->sock;
}


void edge_threads_open_early (struct n3n_runtime_data *eee) {

    // as many as edge_threads_wanted() will ask for, without its log line
    int threads = eee->conf.threads ? (int)eee->conf.threads : edge_threads_possible(&eee->conf);

#ifndef __linux__
    return;
#endif
    if(threads > N3N_THREADS_MAX) {
        threads = N3N_THREADS_MAX;
    }
    if((threads <= 1) || eee->conf.connect_tcp || (eee->sock < 0)) {
        return;
    }
    early_nsock = eee->bind_count ? eee->bind_count : 1;
    for(int slot = 1; slot < threads; slot++) {
        for(int i = 0; i < early_nsock; i++) {
            early_sock[slot][i] = open_like(like_sock(eee, i));
        }
    }
    early_slots = threads;
}


// Take the socket opened early for a worker's socket i, if it is still on
// the address of the main thread's one - which may have been opened again
// since, then as the same user as a new one.
static SOCKET take_early (struct n3n_runtime_data *eee, int slot, int i) {

    struct sockaddr_storage now, then;
    socklen_t now_len = sizeof(now), then_len = sizeof(then);
    SOCKET sock;

    if((slot >= early_slots) || (i >= early_nsock) || (early_sock[slot][i] < 0)) {
        return -1;
    }
    sock = early_sock[slot][i];
    early_sock[slot][i] = -1;
    if(!getsockname(like_sock(eee, i), (struct sockaddr *)&now, &now_len)
       && !getsockname(sock, (struct sockaddr *)&then, &then_len)
       && (now_len == then_len) && !memcmp(&now, &then, now_len)) {
        return sock;
    }
    closesocket(sock);
    return -1;
}


// the early sockets no worker took, e.g. when fewer threads started
static void close_early_sockets (void) {

    for(int slot = 1; slot < early_slots; slot++) {
        for(int i = 0; i < early_nsock; i++) {
            if(early_sock[slot][i] >= 0) {
                closesocket(early_sock[slot][i]);
            }
        }
    }
    early_slots = 0;
}


// The sockets a worker shares with the main thread: its main socket's, and
// on the supernode those of the further addresses of connection.bind.
static int open_worker_sockets (struct n3n_runtime_data *eee, struct worker *w) {

    int n = eee->bind_count ? eee->bind_count : 1;

    for(w->nsock = 0; w->nsock < n; w->nsock++) {
        SOCKET sock = take_early(eee, w->slot, w->nsock);

        if(sock < 0) {
            sock = open_like(like_sock(eee, w->nsock));
        }
        w->sock[w->nsock] = sock;
        if(sock < 0) {
            return -1;
        }
    }
    return 0;
}


static int threads_start (struct n3n_runtime_data *eee, int threads,
                          const struct edge_thread_ops *ops) {

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
    t->ops = ops;
    t->wake_pipe[0] = t->wake_pipe[1] = -1;
    t->stop_pipe[0] = t->stop_pipe[1] = -1;
    // calloc() leaves every worker with nsock 0, no sockets to close

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
    // open_like() sets it - gets a share of the senders
    for(slot = 1; slot < threads; slot++) {
        t->worker[slot].slot = slot;
        if(open_worker_sockets(eee, &t->worker[slot]) < 0) {
            traceEvent(TRACE_WARNING, "cannot open a socket for thread %d", slot);
            break;
        }
        t->queue[slot] = calloc(1, sizeof(struct worker_queue));
        if(!t->queue[slot]) {
            break;
        }
        pthread_mutex_init(&t->queue[slot]->overflow_lock, NULL);
        t->worker[slot].eee = eee;
        t->worker[slot].tap = -1;
#ifdef __linux__
        if(ops->tap) {
            t->worker[slot].tap = eee->device.queue_fd[slot];
        }
#endif
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

    traceEvent(TRACE_NORMAL, "handling packets with %d threads", started + 1);

    return started + 1;
}


int edge_threads_start (struct n3n_runtime_data *eee, int threads,
                        const struct edge_thread_ops *ops) {

    int started = threads_start(eee, threads, ops);

    close_early_sockets();

#ifdef __linux__
    if(ops->tap) {
        tuntap_close_queues(&eee->device, started);
    }
#endif
    return started;
}


void edge_threads_stop (struct n3n_runtime_data *eee) {

    struct edge_threads *t = eee->threads;
    uint8_t one = 1;
    int slot;

    if(!t) {
        return;
    }

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
            traceEvent(TRACE_NORMAL, "thread %d handled %u received packets and %u frames, "
                       "passed %u to the main thread (%u via overflow), waited %u times",
                       slot, t->worker[slot].packets, t->worker[slot].frames, t->queue[slot]->posted,
                       t->queue[slot]->overflowed, t->worker[slot].waited);
            if(COUNTER_READ(t->queue[slot]->lost)) {
                traceEvent(TRACE_WARNING, "thread %d lost %u items for lack of memory",
                           slot, COUNTER_READ(t->queue[slot]->lost));
            }
        }
    }

    // The workers are gone now; whatever they queued, up to their last
    // batch, still counts - also when they are only being restarted.
    edge_threads_drain(eee);

    edge_threads_free(eee);
}


void edge_threads_socket_changed (struct n3n_runtime_data *eee) {

    const struct edge_thread_ops *ops;
    int threads;

    if(!eee->threads) {
        return;
    }

    // The main socket was opened again, maybe on another port: move the
    // workers along by starting them again. This only happens after the
    // supernode has not answered for a while.
    threads = eee->threads->requested;
    ops = eee->threads->ops;
    edge_threads_stop(eee);
    edge_threads_start(eee, threads, ops);
}


SOCKET edge_threads_sock (struct n3n_runtime_data *eee) {

    return eee->threads->worker[n3n_thread_slot].sock[0];
}


SOCKET edge_threads_bind_sock (struct n3n_runtime_data *eee, int i) {

    return eee->threads->worker[n3n_thread_slot].sock[i];
}


void edge_threads_tap_error (struct n3n_runtime_data *eee) {

    struct edge_threads *t = eee->threads;
    uint8_t one = 1;

    __atomic_store_n(&t->tap_failed, 1, __ATOMIC_RELEASE);
    if(write(t->wake_pipe[1], &one, 1) < 0) {
        // the main thread wakes up at least once a second anyway
    }
}


int edge_threads_tap_failed (struct n3n_runtime_data *eee) {

    return eee->threads && __atomic_load_n(&eee->threads->tap_failed, __ATOMIC_ACQUIRE);
}


int edge_threads_wake_fd (struct n3n_runtime_data *eee) {

    return eee->threads ? eee->threads->wake_pipe[0] : -1;
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

void edge_threads_post_pdu (struct n3n_runtime_data *eee,
                            const struct sockaddr *sender, socklen_t sender_len,
                            const uint8_t *buf, size_t size,
                            const void *note, size_t note_size) {
}

void edge_threads_drain (struct n3n_runtime_data *eee) {
}

void edge_threads_open_early (struct n3n_runtime_data *eee) {
}

int edge_threads_start (struct n3n_runtime_data *eee, int threads,
                        const struct edge_thread_ops *ops) {

    if(threads > 1) {
        traceEvent(TRACE_WARNING, "built without pthreads (./configure --enable-pthread), using one thread");
    }
    return 1;
}

void edge_threads_stop (struct n3n_runtime_data *eee) {
}

void edge_threads_socket_changed (struct n3n_runtime_data *eee) {
}

SOCKET edge_threads_sock (struct n3n_runtime_data *eee) {

    return eee->sock;
}

SOCKET edge_threads_bind_sock (struct n3n_runtime_data *eee, int i) {

    return eee->bind_sock[i];
}

void edge_threads_tap_error (struct n3n_runtime_data *eee) {
}

int edge_threads_tap_failed (struct n3n_runtime_data *eee) {

    return 0;
}

int edge_threads_wake_fd (struct n3n_runtime_data *eee) {

    return -1;
}


#endif // HAVE_LIBPTHREAD
