/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Telling a service manager how the daemon is doing: systemd's notification
 * protocol, which is a datagram of "KEY=value" lines to the Unix socket
 * named in $NOTIFY_SOCKET.  Nothing here needs systemd, or links against it:
 * without that variable - no systemd, a unit with Type=simple, any other
 * init system, a shell - every function here does nothing.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>          // for snprintf
#include <string.h>
#include <time.h>
#include "n2n.h"            // for n3n_monotonic_us
#include "notify.h"

#ifdef __linux__

#include <stddef.h>         // for offsetof
#include <stdlib.h>         // for getenv, strtoull, atoi
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>         // for getpid
#include <n3n/strings.h>    // for sock_to_cstr
#include <n3n/edge.h>       // for edge_is_registered
#include "local_link.h"     // for local_link_edge
#include "n2n_typedefs.h"
#include "peer_info.h"
#include "uthash.h"


static bool tried;
static int notify_fd = -1;
static struct sockaddr_un notify_addr;
static socklen_t notify_len;
static uint64_t watchdog_us;        // from WATCHDOG_USEC, 0: no watchdog
static uint64_t watchdog_last;
static uint64_t status_last;
static char status_sent[256];


static bool notify_open (void) {

    if(tried) {
        return notify_fd >= 0;
    }
    tried = true;

    const char *path = getenv("NOTIFY_SOCKET");
    size_t len = path ? strlen(path) : 0;

    // a path, or an abstract socket ("@name")
    if(!len || ((path[0] != '/') && (path[0] != '@')) || (len >= sizeof(notify_addr.sun_path))) {
        return false;
    }
    memset(&notify_addr, 0, sizeof(notify_addr));
    notify_addr.sun_family = AF_UNIX;
    memcpy(notify_addr.sun_path, path, len);
    if(path[0] == '@') {
        notify_addr.sun_path[0] = 0;
    }
    notify_len = offsetof(struct sockaddr_un, sun_path) + len;

    notify_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if(notify_fd < 0) {
        return false;
    }

    const char *wd = getenv("WATCHDOG_USEC");
    const char *wd_pid = getenv("WATCHDOG_PID");
    if(wd && (!wd_pid || (atoi(wd_pid) == getpid()))) {
        watchdog_us = strtoull(wd, NULL, 10);
    }
    return true;
}


void n3n_notify (const char *msg) {

    if(notify_open()) {
        sendto(notify_fd, msg, strlen(msg), MSG_NOSIGNAL, (struct sockaddr *)&notify_addr, notify_len);
    }
}


// One line on what the process is doing, for "systemctl status"
static void status_text (char *buf, size_t size, struct n3n_runtime_data *rt) {

    struct n3n_runtime_data *edge = rt->conf.is_edge ? rt : local_link_edge();
    size_t used = 0;

    buf[0] = 0;
    if(rt->conf.is_supernode) {
        struct sn_community *comm, *tmp;
        int communities = 0;
        int edges = 0;

        HASH_ITER(hh, rt->relay.communities, comm, tmp) {
            if(!comm->is_federation) {
                communities++;
                edges += HASH_COUNT(comm->edges);
            }
        }
        used += snprintf(buf + used, size - used, "supernode: %d edge%s in %d communit%s",
                         edges, (edges == 1) ? "" : "s", communities, (communities == 1) ? "y" : "ies");
    }
    if(edge && (used < size)) {
        int direct = HASH_COUNT(edge->client.known_peers);
        int peers = direct + HASH_COUNT(edge->client.pending_peers);
        struct peer_info *sn = edge->client.curr_sn;
        n3n_sock_str_t sockbuf;

        if(used) {
            used += snprintf(buf + used, size - used, "; ");
        }
        if(rt->conf.is_supernode) {
            snprintf(buf + used, size - used, "its edge: %d peer%s", peers, (peers == 1) ? "" : "s");
        } else if(edge_is_registered(edge, time(NULL))) {
            snprintf(buf + used, size - used, "registered at %s over %s, %d peer%s (%d direct)",
                     sock_to_cstr(sockbuf, &sn->sock), edge->client.tcp ? "TCP" : "UDP",
                     peers, (peers == 1) ? "" : "s", direct);
        } else {
            snprintf(buf + used, size - used, "looking for a supernode");
        }
    }
}


void n3n_notify_ready (struct n3n_runtime_data *rt) {

    char msg[300];

    if(!notify_open()) {
        return;
    }
    status_text(status_sent, sizeof(status_sent), rt);
    snprintf(msg, sizeof(msg), "READY=1\nSTATUS=%s", status_sent);
    n3n_notify(msg);
    status_last = n3n_monotonic_us();
}


void n3n_notify_tick (struct n3n_runtime_data *rt) {

    uint64_t now;

    if(!notify_open()) {
        return;
    }
    now = n3n_monotonic_us();

    // the watchdog expects a sign of life at least every WATCHDOG_USEC:
    // twice as often, from the main loop, so a hung loop is noticed
    if(watchdog_us && (now - watchdog_last >= watchdog_us / 2)) {
        n3n_notify("WATCHDOG=1");
        watchdog_last = now;
    }

    // the status, when it changed, every few seconds at most
    if(now - status_last >= 5000000) {
        char status[sizeof(status_sent)];
        char msg[sizeof(status) + 8];

        status_last = now;
        status_text(status, sizeof(status), rt);
        if(strcmp(status, status_sent)) {
            memcpy(status_sent, status, sizeof(status_sent));
            snprintf(msg, sizeof(msg), "STATUS=%s", status);
            n3n_notify(msg);
        }
    }
}


void n3n_notify_stopping (void) {

    // STOPPING=1 moves the unit to "deactivating"; the STATUS line stays as
    // "systemctl status" shows it, so leave no stale "registered ... N peers"
    // behind - the daemon is on its way out, not still connected
    n3n_notify("STOPPING=1\nSTATUS=shutting down");
    status_sent[0] = 0;
}

#else

void n3n_notify (const char *msg) {
}

void n3n_notify_ready (struct n3n_runtime_data *rt) {
}

void n3n_notify_tick (struct n3n_runtime_data *rt) {
}

void n3n_notify_stopping (void) {
}

#endif
