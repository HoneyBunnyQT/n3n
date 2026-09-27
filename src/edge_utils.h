/**
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef _EDGE_UTILS_H_
#define _EDGE_UTILS_H_

#include <stdint.h>
#include <time.h>       // for time_t

#include "n2n_typedefs.h"  // for n2n_mac_t, n3n_sock_t, n2n_common_t
#include "pktbuf.h"     // for n3n_pktbuf

// Forward declare so that this header can stay small
struct n3n_runtime_data;


/* Changes to the peer tables that the PACKET path asks for.
 *
 * Handling a PACKET mostly reads the peer tables; now and then it has to
 * change them - a pending peer turns out to be reachable, a peer shows up at
 * a new socket, a bridged host moves to another edge. Such a change is
 * described in an event, by value, and applied by edge_event_apply() with
 * the same code as before. Once PACKETs are handled by several threads, the
 * events go to the main thread, which is the only one changing the tables;
 * while there is one thread, edge_event_post() applies them at once.
 *
 * Refreshing a time stamp on an entry that is already there and unchanged -
 * what nearly every packet does - is not an event: the packet path does it
 * itself with SHARED_STORE().
 */
enum edge_event_type {
    EDGE_EVENT_PENDING_REMOVE,      /* the peer answered directly, stop registering */
    EDGE_EVENT_PEER_SEEN,           /* check_peer_registration_needed() */
    EDGE_EVENT_HOST_SEEN,           /* learn a bridged host behind an edge */
};

struct edge_event {
    enum edge_event_type type;
    n2n_mac_t mac;                  /* the peer edge */
    n2n_mac_t host;                 /* HOST_SEEN: the bridged host behind it */
    n3n_sock_t sock;                /* PEER_SEEN: where the packet came from */
    n2n_cookie_t cookie;            /* PEER_SEEN */
    uint8_t from_supernode;         /* PEER_SEEN */
    uint8_t via_multicast;          /* PEER_SEEN */
    time_t now;                     /* HOST_SEEN */
};

// apply a change described in an event - on the thread that owns the tables
void edge_event_apply (struct n3n_runtime_data *eee, const struct edge_event *ev);


/* What the control path needs from process_pdu(), all by value - nothing in
 * here points into the peer tables, so it stays valid on its way to another
 * thread. buf is the PDU itself, with its header already decrypted. */
struct pdu_control {
    uint8_t *buf;
    size_t size;
    n2n_common_t cmn;
    size_t rem;                 /* decoding position after the common header */
    size_t idx;
    n3n_sock_t sender;
    uint8_t from_supernode;
    uint8_t via_multicast;
    uint64_t stamp;
    uint8_t hash_buf[16];       /* of the still encrypted PDU, user/pw auth only */
    time_t now;
};

// handle a control message - on the thread that owns the tables
void process_pdu_control (struct n3n_runtime_data *eee, struct pdu_control *c);


// The read functions return 1 if they consumed a packet, 0 if there was
// nothing queued and -1 if the fd went bad

int edge_read_from_tap (struct n3n_runtime_data *eee);

// Reads up to max frames and returns how many it took off the tap queue
int edge_read_from_tap_batch (struct n3n_runtime_data *eee, int max);

int edge_read_proto3_udp (struct n3n_runtime_data *eee,
                          SOCKET sock,
                          struct n3n_pktbuf *pktbuf,
                          time_t now);
void edge_read_proto3_tcp (struct n3n_runtime_data *eee,
                           SOCKET sock,
                           uint8_t *pktbuf,
                           ssize_t pktbuf_len,
                           time_t now);

#endif
