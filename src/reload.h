/*
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Reading the configuration again while running: on SIGHUP, or by the
 * management API's "reload" (n3nctl reload).  What can change while
 * running is applied, the rest waits for a restart, see reload.c.
 */

#ifndef _RELOAD_H_
#define _RELOAD_H_

#include <stdbool.h>

struct n3n_runtime_data;
struct strbuf;

// How the program loads its configuration into conf (an n2n_edge_conf_t
// it was given, zeroed), all the way as at its start: 0 if it could
typedef int (*n3n_reload_load_fn)(void *conf);

// At the start, once rt runs with conf: the configuration as loaded, and
// how to load it again
void n3n_reload_setup (struct n3n_runtime_data *rt, const void *conf, n3n_reload_load_fn load);

// From a signal handler: reload at the next turn of the main loop
void n3n_reload_request (void);

// In the main loop: the requested reload, if there is one
void n3n_reload_pending (void);

// Reload now; what came of it, as a JSON object, is added to out if
// given (else logged): 0 if the configuration could be loaded
int n3n_reload (struct strbuf **out);

#endif
