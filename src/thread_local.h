/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * N3N_THREAD_LOCAL gives every thread its own copy of a variable.
 */

#ifndef N3N_THREAD_LOCAL_H
#define N3N_THREAD_LOCAL_H

#if defined(_MSC_VER)
#define N3N_THREAD_LOCAL __declspec(thread)
#elif defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
#define N3N_THREAD_LOCAL _Thread_local
#else
#define N3N_THREAD_LOCAL __thread
#endif

// The most threads that handle packets: the main thread plus the workers
#define N3N_THREADS_MAX 16

// Which of those the calling thread is: 0 for the main thread (and any
// thread that does not handle packets), 1 .. N3N_THREADS_MAX-1 for the
// workers. Things kept once per packet thread, like the packet counters,
// are indexed with it.
extern N3N_THREAD_LOCAL int n3n_thread_slot;

// Scratch memory that a module allocates for each thread on first use - so
// that no two threads ever work in the same buffer - is registered here with
// the function that frees it.
typedef void (*n3n_thread_cleanup_f)(void);

// run fn when the calling thread calls n3n_thread_cleanup()
void n3n_thread_on_cleanup (n3n_thread_cleanup_f fn);

// free everything the calling thread registered: a thread calls this before
// it ends, the main thread at shutdown
void n3n_thread_cleanup ();

#endif
