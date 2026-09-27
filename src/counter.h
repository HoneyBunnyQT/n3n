/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Counters with one writer and any number of readers
 *
 * A counter that only its own thread increments, but that another thread
 * reads (the management and metrics pages), is still a data race when plain
 * loads and stores are used. Relaxed atomic loads and stores remove the race
 * without a locked instruction: with a single writer nothing can be lost, so
 * an increment is a plain load, add and store, and a reader sees the old or
 * the new value, never a torn one.
 *
 * n3n already needs gcc or clang (it uses __attribute__), so these use their
 * __atomic builtins, which also work where <stdatomic.h> does not.
 */

#ifndef N3N_COUNTER_H
#define N3N_COUNTER_H

// add one - only ever from the thread that owns the counter
#define COUNTER_INC(c) \
    __atomic_store_n(&(c), __atomic_load_n(&(c), __ATOMIC_RELAXED) + 1, __ATOMIC_RELAXED)

// read from any thread
#define COUNTER_READ(c) __atomic_load_n(&(c), __ATOMIC_RELAXED)

#endif
