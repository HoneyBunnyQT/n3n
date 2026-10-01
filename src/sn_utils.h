/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * What the mainloop calls in the supernode
 */

#ifndef N3N_SN_UTILS_H
#define N3N_SN_UTILS_H

#include <n3n/pktbuf.h>      // for n3n_pktbuf
#include <stdint.h>          // for uint8_t
#include <time.h>            // for time_t

#include "n2n.h"             // for n3n_runtime_data, SOCKET

#ifndef _WIN32
#include <sys/socket.h>      // for sockaddr, socklen_t
#endif

#define HASH_FIND_COMMUNITY(head, name, out) HASH_FIND_STR(head, name, out)

// Take one PDU off a UDP socket and handle it: 1 if there was one, 0 if not
int sn_read_proto3_udp (struct n3n_runtime_data *sss, SOCKET sock,
                        struct n3n_pktbuf *pktbuf, time_t now);

// Handle a PDU that came in on a TCP connection.  pktbuf NULL: the connection
// is gone, its socket closed already.
void sn_read_proto3_tcp (struct n3n_runtime_data *sss, SOCKET sock,
                         uint8_t *pktbuf, ssize_t pktbuf_len, time_t now);

// A PDU from the edge in this process, see local_link.h
void sn_process_local_pdu (struct n3n_runtime_data *sss,
                           const struct sockaddr *sender_sock, socklen_t sock_size,
                           uint8_t *buf, size_t size, time_t now);

// A TCP connection was accepted from addr
void sn_accepted_proto3_tcp (struct n3n_runtime_data *sss, SOCKET sock,
                             const struct sockaddr *addr, socklen_t addr_len);

// Forget an edge, and close its TCP connection, if any
void remove_edge (struct n3n_runtime_data *sss, struct sn_community *comm, struct peer_info *edge);
// Sending: from the socket for the family of an address, to an address, to
// a peer by its socket or address
SOCKET family_sock (struct n3n_runtime_data *sss, int family);
ssize_t sn_sendto_sock (struct n3n_runtime_data *sss,
                        SOCKET socket_fd,
                        const struct sockaddr *socket,
                        const uint8_t *pktbuf,
                        size_t pktsize);
ssize_t sn_sendto_peer (struct n3n_runtime_data *sss,
                        const struct peer_info *peer,
                        const uint8_t *pktbuf,
                        size_t pktsize);

#endif
