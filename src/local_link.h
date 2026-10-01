/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The link between an edge and the supernode in the same process
 */

#ifndef N3N_LOCAL_LINK_H
#define N3N_LOCAL_LINK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "n2n_typedefs.h"

/* A supernode with a TAP device of its own (supernode.tap) runs an edge in
 * the same process, with a runtime of its own.  The edge has no sockets: it
 * talks to its supernode only, through this link, as if over UDP - the same
 * PDUs, from and to the address 127.0.0.1 port 0 at either side, which no
 * real peer has, and which other edges do not take for one to reach directly
 * (see is_valid_peer_sock()).  What the supernode receives on the link comes
 * in on the "socket" LOCAL_LINK_FD.
 *
 * A PDU on the link is queued and handed on once the handler that sent it
 * has returned - by the mainloop, see local_link_drain() - so no handler
 * runs inside another, maybe while that one walks a table the other changes.
 * The link is used by the main thread only. */

#define LOCAL_LINK_FD (-2)

// Connect the two runtimes
void local_link_init (struct n3n_runtime_data *relay, struct n3n_runtime_data *edge);

// The address of the other side, as either side sees it
void local_link_sock (n3n_sock_t *out);
bool local_link_is_sock (const n3n_sock_t *sock);

// Queue a PDU for the other side; false if it was dropped
bool local_link_to_relay (const uint8_t *buf, size_t size);
bool local_link_to_edge (const uint8_t *buf, size_t size);

// Hand the queued PDUs on, also those their handlers queue in turn
void local_link_drain (time_t now);

#endif
