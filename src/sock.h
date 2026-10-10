/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Sending datagrams from the sockets of connection.bind, for the edge and
 * the supernode alike
 *
 * Both open a UDP socket for each address of connection.bind (see
 * n3n_open_bind_sockets()), and with several threads every packet thread has
 * its own socket for each of them, bound to the same address and port.  What
 * is here picks the right one of these and sends from it.
 */

#ifndef N3N_SOCK_H
#define N3N_SOCK_H

#include <stddef.h>          // for size_t
#include <stdint.h>          // for uint8_t
#include <sys/types.h>       // for ssize_t
#include <time.h>            // for time_t

#include "n2n.h"             // for n3n_runtime_data, SOCKET

#ifndef _WIN32
#include <sys/socket.h>      // for sockaddr, socklen_t
#endif

// The address of connection.bind to send to a destination of this family
// from: the first one of that family, or for IPv4 the first IPv6 one that
// takes mapped IPv4 addresses too.  -1 if there is none.
int bind_entry_for_family (const struct n3n_runtime_data *rt, int family);

// Which address of connection.bind a UDP socket is for: the main thread's
// socket for it, or a packet thread's own on the same port.  -1 for anything
// else, e.g. a TCP connection.
int bind_entry_of_sock (struct n3n_runtime_data *rt, SOCKET sock);

// The calling thread's UDP socket for address i of connection.bind
SOCKET bind_thread_sock (struct n3n_runtime_data *rt, int i);

// sendto(), and a line in the log if it fails.  The bytes sent, or -1.
ssize_t sendto_logged (SOCKET sock, const void *buf, size_t len,
                       const struct sockaddr *dest, socklen_t dest_len);

// Send a datagram to dest from the calling thread's socket for address i of
// connection.bind; an IPv6 socket sends to an IPv4 destination as a mapped
// address.  The bytes sent, or -1.
ssize_t sendto_bind (struct n3n_runtime_data *rt, int i, const void *buf,
                     size_t len, const struct sockaddr *dest);

// While a batch is open on the calling thread, what sendto_logged() is given
// is copied and collected instead of sent, and goes out with one sendmmsg()
// for as many as there are for the same socket in a row, when the batch
// ends - or is full.  Batches nest: the outermost end sends.  Where there is
// no sendmmsg() (other systems than Linux), each goes at once as before.
void sock_batch_begin (void);
void sock_batch_end (void);

struct n3n_pktbuf;
// A role's read of one datagram off sock, as n3n_role_ops.read_udp: 1 if
// one was taken, 0 if not
typedef int (*udp_read_fn)(struct n3n_runtime_data *rt, SOCKET sock,
                           struct n3n_pktbuf *pkt, time_t now);
// A role's handling of a datagram that came in on sock
typedef void (*udp_rx_fn)(struct n3n_runtime_data *rt, SOCKET sock,
                          struct sockaddr *from, socklen_t from_len,
                          uint8_t *buf, size_t len, time_t now);

// Take up to max datagrams off sock and hand each to rx: with one
// recvmmsg() for several on a socket of connection.bind, else one by one
// with read into pkt, as also where there is no recvmmsg() or it fails
// other than for want of datagrams.  How many were taken.
int udp_drain (struct n3n_runtime_data *rt, SOCKET sock, struct n3n_pktbuf *pkt,
               int max, time_t now, udp_read_fn read, udp_rx_fn rx);

#endif
