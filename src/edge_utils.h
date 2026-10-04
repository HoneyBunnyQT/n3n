/**
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 */

#ifndef _EDGE_UTILS_H_
#define _EDGE_UTILS_H_

#include <n3n/pktbuf.h>     // for n3n_pktbuf
#include <stdint.h>
#include <time.h>       // for time_t

#include "n2n_typedefs.h"  // for n2n_mac_t, n3n_sock_t
#include "pdu_in.h"        // for pdu_ctx

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
    EDGE_EVENT_PEER_EXPIRE,         /* no PACKET from the peer for too long */
    EDGE_EVENT_QUERY_PEER,          /* check_query_peer_info() */
};

struct edge_event {
    enum edge_event_type type;
    n2n_mac_t mac;                  /* the peer edge */
    n2n_mac_t host;                 /* HOST_SEEN: the bridged host behind it */
    n3n_sock_t sock;                /* PEER_SEEN: where the packet came from */
    n2n_cookie_t cookie;            /* PEER_SEEN */
    uint8_t from_supernode;         /* PEER_SEEN */
    uint8_t via_multicast;          /* PEER_SEEN */
    time_t now;                     /* HOST_SEEN, PEER_EXPIRE, QUERY_PEER */
};

// apply a change described in an event - on the thread that owns the tables
void edge_event_apply (struct n3n_runtime_data *eee, const struct edge_event *ev);


// handle a PDU that came in on in_sock from sender_sock
void edge_process_pdu (struct n3n_runtime_data *eee,
                       const struct sockaddr *sender_sock,
                       const SOCKET in_sock,
                       uint8_t *udp_buf,
                       size_t udp_size,
                       time_t now);

// handle a control message - on the thread that owns the tables
void process_pdu_control (struct n3n_runtime_data *eee, struct pdu_ctx *c);


// The read functions return 1 if they consumed a packet, 0 if there was
// nothing queued and -1 if the fd went bad

int edge_read_proto3_udp (struct n3n_runtime_data *eee,
                          SOCKET sock,
                          struct n3n_pktbuf *pktbuf,
                          time_t now);
void edge_read_proto3_tcp (struct n3n_runtime_data *eee,
                           SOCKET sock,
                           uint8_t *pktbuf,
                           ssize_t pktbuf_len,
                           time_t now);

char* intoa (uint32_t /* host order */ addr, char* buf, uint16_t buf_len);

// The tap device failed: open it again, after a pause
void edge_tap_reopen (struct n3n_runtime_data *eee);
void edge_nat_reset (struct n3n_runtime_data *eee);

// The sockets of the edge, see also punch.h
void set_sock_options (struct n3n_runtime_data *eee, SOCKET sock, int family, bool quiet);
int detect_local_ip_address (n3n_sock_t* out_sock, const struct n3n_runtime_data* eee);
int open_udp_sockets (struct n3n_runtime_data *eee);
void close_sockets (struct n3n_runtime_data *eee);
void edge_sendto_sock (struct n3n_runtime_data *eee, const void * buf,
                       size_t len, const n3n_sock_t * dest);

// Changes of the peer tables, from any thread: on the main thread they are
// made at once, a packet thread hands them to the main thread
void edge_event_post (struct n3n_runtime_data *eee, const struct edge_event *ev);
int peer_is_pending (struct n3n_runtime_data *eee, const n2n_mac_t mac);
int peer_seen_fast (struct n3n_runtime_data *eee,
                    uint8_t from_supernode,
                    uint8_t via_multicast,
                    const n2n_mac_t mac,
                    const n2n_cookie_t cookie);

#endif
