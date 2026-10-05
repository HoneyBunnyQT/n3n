/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Telling a service manager (systemd, Type=notify) how the daemon is doing,
 * see notify.c.  Without $NOTIFY_SOCKET these do nothing.
 */

#ifndef N3N_NOTIFY_H
#define N3N_NOTIFY_H

struct n3n_runtime_data;

// One message, e.g. "STOPPING=1"
void n3n_notify (const char *msg);

// Up and running: READY=1, with the first status line
void n3n_notify_ready (struct n3n_runtime_data *rt);

// From the main loop: the watchdog, and the status when it changed
void n3n_notify_tick (struct n3n_runtime_data *rt);

// On the way out: STOPPING=1, and a status that is not the last peer count
void n3n_notify_stopping (void);

#endif
