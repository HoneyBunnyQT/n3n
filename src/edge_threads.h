/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Handling received PACKETs on several threads
 *
 * The main thread owns everything: the peer tables, the registration state,
 * the timers. Worker threads only handle PACKETs, each on a socket of its own
 * bound to the same port. What a worker cannot do itself - a control message,
 * or a change to the peer tables - it copies into a queue for the main thread.
 *
 * The two sides are kept apart by one read-write lock. The main thread holds
 * the write side whenever it is awake and lets go of it only while it waits in
 * select(); a worker takes the read side for each batch of packets. So
 * whatever the main thread does, no worker is in the middle of a batch.
 *
 * With one thread - the default - none of this is set up and nothing here
 * costs anything.
 */

#ifndef N3N_EDGE_THREADS_H
#define N3N_EDGE_THREADS_H

#include "edge_utils.h"      // for edge_event, pdu_control

struct n3n_runtime_data;

// Around the main thread's wait in select(). Both do nothing unless workers
// are running.
void edge_threads_main_release (struct n3n_runtime_data *eee);
void edge_threads_main_acquire (struct n3n_runtime_data *eee);

// From a worker: hand an event or a control message to the main thread. The
// control message's PDU is copied, so the worker may reuse its buffer. If the
// queue is full, the item is dropped and counted - the protocol repeats all
// control messages, and a lost event is redone by the next packet.
void edge_threads_post_event (struct n3n_runtime_data *eee, const struct edge_event *ev);
void edge_threads_post_control (struct n3n_runtime_data *eee, const struct pdu_control *c);

// On the main thread, holding the lock: apply everything the workers queued.
void edge_threads_drain (struct n3n_runtime_data *eee);

#endif
