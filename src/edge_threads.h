/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Handling PACKETs on several threads
 *
 * The main thread owns everything: the peer tables, the registration state,
 * the timers. Worker threads only handle PACKETs, each on a socket of its own
 * bound to the same port, and each on a queue of its own of the tap device -
 * the frames it reads there it sends from its socket, the PACKETs it
 * receives it writes into its queue. What a worker cannot do itself - a
 * control message, or a change to the peer tables - it copies into a queue
 * for the main thread.
 *
 * The two sides are kept apart by one read-write lock. The main thread holds
 * the write side whenever it is awake and lets go of it only while it waits in
 * select(); a worker takes the read side for each batch of packets. So
 * whatever the main thread does, no worker is in the middle of a batch.
 *
 * With one thread - the default - none of this is set up and nothing here
 * costs anything.
 *
 * The supernode uses the same threads, without the tap device: its workers
 * relay PACKETs between edges, and hand every other PDU to the main thread.
 */

#ifndef N3N_EDGE_THREADS_H
#define N3N_EDGE_THREADS_H

#include "edge_utils.h"      // for edge_event, pdu_ctx
#include "n2n_typedefs.h"    // for n2n_edge_conf_t, SOCKET

struct n3n_runtime_data;
struct n3n_pktbuf;
struct sockaddr;

// What the workers do, set by the edge or the supernode
struct edge_thread_ops {
    // take one PDU off sock and handle it; 1 if there was one, 0 if not
    int (*read_udp)(struct n3n_runtime_data *eee, SOCKET sock,
                    struct n3n_pktbuf *pkt, time_t now);
    // on the main thread: a PDU that a worker handed over with
    // edge_threads_post_pdu(), its buf, size, sender_sock and sock_size set
    // again to the copies
    void (*process_pdu)(struct n3n_runtime_data *eee, struct pdu_ctx *c);
    // whether every worker also reads a queue of the tap device
    int tap;
};

// How many threads can handle packets with this configuration, the main
// thread included: 1 unless it asks for more and they work here.
// daemon.threads=0 asks for half the physical cores, rounded up.
int edge_threads_possible (const n2n_edge_conf_t *conf);

// How many threads to start with: what daemon.threads asks for, or with
// daemon.threads=0 as many as edge_threads_possible() says
int edge_threads_wanted (const n2n_edge_conf_t *conf);

// Around the main thread's wait in select(). Both do nothing unless workers
// are running.
void edge_threads_main_release (struct n3n_runtime_data *eee);
void edge_threads_main_acquire (struct n3n_runtime_data *eee);

// From a worker: hand an event or a PDU to the main thread. The PDU and its
// sender's address are copied, so the worker may reuse its buffers.
// Nothing is dropped - see QUEUE_SLOTS in edge_threads.c.
void edge_threads_post_event (struct n3n_runtime_data *eee, const struct edge_event *ev);
void edge_threads_post_pdu (struct n3n_runtime_data *eee, const struct pdu_ctx *c);

// On the main thread, holding the lock: apply everything the workers queued.
void edge_threads_drain (struct n3n_runtime_data *eee);

// Open the workers' sockets now, for edge_threads_start() to use later: to be
// called once the main sockets are open and before dropping privileges, as
// sockets opened after that do not share their port's traffic with them.
void edge_threads_open_early (struct n3n_runtime_data *eee);

// Start threads-1 workers beside the main thread; returns how many threads
// handle packets now, the main thread included - 1 if threads are not
// possible here. The tap queues beyond that are closed. Called by the main
// thread, which from then on holds the lock while it is awake.
int edge_threads_start (struct n3n_runtime_data *eee, int threads,
                        const struct edge_thread_ops *ops);

// Stop the workers again, applying what they queued. Called by the main thread.
void edge_threads_stop (struct n3n_runtime_data *eee);

// The main socket was opened again: move the workers to the new one.
void edge_threads_socket_changed (struct n3n_runtime_data *eee);

// From a worker: the socket it receives on and sends from.
SOCKET edge_threads_sock (struct n3n_runtime_data *eee);

// From a worker of the supernode: its socket for address i of connection.bind.
SOCKET edge_threads_bind_sock (struct n3n_runtime_data *eee, int i);

// From a worker: its tap queue failed. Only the main thread can open the
// device again; it finds out with edge_threads_tap_failed().
void edge_threads_tap_error (struct n3n_runtime_data *eee);

// On the main thread: has the tap queue of a worker failed?
int edge_threads_tap_failed (struct n3n_runtime_data *eee);

// The fd a main thread with a select() loop of its own has to watch: a
// worker writes to it when it has queued something. -1 without workers.
int edge_threads_wake_fd (struct n3n_runtime_data *eee);

#endif
