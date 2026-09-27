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
