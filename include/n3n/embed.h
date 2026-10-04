/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Running an edge inside another program - the Android app, or any other
 * that brings its own TUN device - instead of as the n3n-edge daemon.
 * Linux and Android only, see src/embed.c.
 */

#ifndef N3N_EMBED_H
#define N3N_EMBED_H

#include <stdbool.h>

struct n3n_embed {
    void *ctx;                  // handed to every callback

    // Every socket the edge opens towards the network, before it is used.
    // On Android: VpnService.protect(fd), so that what the edge sends does
    // not go back into the VPN.  false: the edge does without the socket.
    // NULL: none.
    bool (*protect)(void *ctx, int fd);

    // Every line of the log, with its level (0 error .. 4 debug), instead
    // of stderr.  NULL: stderr.
    void (*log)(void *ctx, int level, const char *line);

    // Where the session directory with the management socket goes, instead
    // of /run/n3n - the app's own directory.  NULL: /run/n3n.
    const char *rundir;

    // The name of the session (its directory, the management socket's);
    // NULL: "edge"
    const char *session;
};

// Run an edge with a configuration in the INI format of the configuration
// files (config) on the TUN device tun_fd, until n3n_edge_stop().  The
// device must be set up already, with the address of tuntap.address - which
// so has to be given (address_mode static).  The edge takes over tun_fd and
// closes it.  Returns 0 after a stop, else a negative number at once.  One
// edge per process at a time.
int n3n_edge_run (const char *config, int tun_fd, const struct n3n_embed *e);

// Stop the edge that n3n_edge_run() runs, from any thread
void n3n_edge_stop (void);

// The host's network changed (another WiFi, mobile data, back): the edge
// registers again at once, with the supernode and its peers, instead of at
// its next round.  For an app that hears of it from the system - as on
// Android, where an app may not watch netlink itself; on Linux the edge
// notices on its own (connection.watch_network).  From any thread.
void n3n_edge_network_changed (void);

#endif
