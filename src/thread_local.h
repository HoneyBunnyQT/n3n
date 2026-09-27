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

#endif
