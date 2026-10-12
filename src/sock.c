/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Sending and receiving datagrams on the sockets of connection.bind - see
 * sock.h
 */

#ifdef __linux__
#define _GNU_SOURCE          // for sendmmsg, recvmmsg
#endif

#include <errno.h>           // for errno, EAFNOSUPPORT
#include <n3n/logging.h>     // for traceEvent
#include <n3n/pktbuf.h>      // for n3n_pktbuf
#include <n3n/strings.h>     // for sockaddr_to_str
#include <stdlib.h>          // for calloc, free
#include <string.h>          // for strerror, memcpy

#include "edge_threads.h"    // for edge_threads_bind_sock
#include "n2n_define.h"      // for N2N_PKT_BUF_SIZE
#include "sock.h"
#include "thread_local.h"    // for n3n_thread_slot, n3n_thread_on_cleanup

#ifdef _WIN32
#include "win32/defs.h"
#else
#include <sys/socket.h>      // for sendto, sendmmsg, recvmmsg, sockaddr_storage
#endif
#ifdef __linux__
#include <netinet/in.h>      // for IPPROTO_UDP
#include <netinet/udp.h>     // for UDP_SEGMENT
#endif

// sendmmsg() and recvmmsg(): Linux (glibc, musl, Bionic)
#ifdef __linux__
#define SOCK_MMSG 1
#endif

#ifdef SOCK_MMSG
// Datagrams a batch holds, see sock_batch_begin()
#define SOCK_TX_BATCH 32
// Datagrams one recvmmsg() takes, see udp_drain()
#define SOCK_RX_BATCH 16

// UDP GSO (Linux 4.18): datagrams of a batch for one destination, of one
// size, go to the kernel as one, which cuts them apart again only at the
// end of its path - the route, the firewall and the queues are passed once
// for them all.  The datagrams on the wire are the same.
#ifdef UDP_SEGMENT
#define SOCK_GSO 1
// what one send of several may carry: a datagram of IPv4 or IPv6 at most
// (65535 bytes) less the headers
#define SOCK_GSO_BYTES (65535 - 40 - 8)
// sockets of a thread whose GSO is known, see gso_usable()
#define SOCK_GSO_SOCKS 8
#endif

// A copy of each datagram: what the callers send from may be gone by the
// time the batch goes, a buffer on the stack of a control message's sender
static N3N_THREAD_LOCAL struct sock_tx_batch {
    int open;           // sock_batch_begin() without its end yet
    int count;
    SOCKET sock;
    struct mmsghdr msg[SOCK_TX_BATCH];
    struct iovec iov[SOCK_TX_BATCH];
    struct sockaddr_storage dest[SOCK_TX_BATCH];
    uint8_t buf[SOCK_TX_BATCH][N2N_PKT_BUF_SIZE];
#ifdef SOCK_GSO
    // what goes to sendmmsg(): one message for each run of datagrams
    struct mmsghdr out[SOCK_TX_BATCH];
    int out_first[SOCK_TX_BATCH];       // the first datagram of each
    int out_count[SOCK_TX_BATCH];       // how many
    union {
        char buf[CMSG_SPACE(sizeof(uint16_t))];
        struct cmsghdr align;
    } ctl[SOCK_TX_BATCH];
    SOCKET gso_sock[SOCK_GSO_SOCKS];    // 0 for none yet
    bool gso_ok[SOCK_GSO_SOCKS];
#endif
} *tx;

static N3N_THREAD_LOCAL struct sock_rx_batch {
    struct mmsghdr msg[SOCK_RX_BATCH];
    struct iovec iov[SOCK_RX_BATCH];
    struct sockaddr_storage from[SOCK_RX_BATCH];
    uint8_t buf[SOCK_RX_BATCH][N2N_PKT_BUF_SIZE];
} *rx;

static void batches_free (void) {

    free(tx);
    tx = NULL;
    free(rx);
    rx = NULL;
}

// The batches of this thread, made on first use and freed when it ends
static bool batches_alloc (void) {

    if(tx && rx) {
        return true;
    }
    if(!tx && !rx) {
        n3n_thread_on_cleanup(batches_free);
    }
    if(!tx) {
        tx = calloc(1, sizeof(*tx));
    }
    if(!rx) {
        rx = calloc(1, sizeof(*rx));
    }
    return tx && rx;
}
#endif


int bind_entry_for_family (const struct n3n_runtime_data *rt, int family) {

    for(int i = 0; i < rt->bind_count; i++) {
        if((rt->bind_family[i] == family) || ((family == AF_INET) && !rt->bind_v6only[i])) {
            return i;
        }
    }
    return -1;
}


int bind_entry_of_sock (struct n3n_runtime_data *rt, SOCKET sock) {

    if(sock < 0) {
        return -1;
    }
    for(int i = 0; i < rt->bind_count; i++) {
        if(sock == rt->bind_sock[i]) {
            return i;
        }
        if(n3n_thread_slot && (sock == edge_threads_bind_sock(rt, i))) {
            return i;
        }
    }
    return -1;
}


SOCKET bind_thread_sock (struct n3n_runtime_data *rt, int i) {

    return n3n_thread_slot ? edge_threads_bind_sock(rt, i) : rt->bind_sock[i];
}


// A send failed: a line in the log
static void send_failed (const struct sockaddr *dest) {

    // a destination of the custom AF_INVALID, e.g. a supernode whose name is
    // not resolved yet, is not worth a warning
    int level = (errno == EAFNOSUPPORT) ? TRACE_DEBUG : TRACE_WARNING;
#ifdef _WIN32
    int werrno = WSAGetLastError();
    if(werrno == WSAEAFNOSUPPORT) {
        level = TRACE_DEBUG;
    }
    traceEvent(level, "WSAGetLastError(): %u", werrno);
#endif

    n3n_sock_str_t sockbuf;
    traceEvent(level, "sendto(%s) failed (%d) %s",
               sockaddr_to_str(sockbuf, sizeof(sockbuf), dest),
               errno, strerror(errno));

    // TODO: metrics for errors
}


#ifdef SOCK_MMSG
#ifdef SOCK_GSO
// Whether a socket takes UDP_SEGMENT: asked of the kernel once per socket
// and thread.  A kernel without GSO would send what is meant to be cut up
// as one big datagram instead.
static bool gso_usable (SOCKET sock) {

    int free_slot = -1;

    for(int i = 0; i < SOCK_GSO_SOCKS; i++) {
        if(tx->gso_sock[i] == sock + 1) {
            return tx->gso_ok[i];
        }
        if(!tx->gso_sock[i] && (free_slot < 0)) {
            free_slot = i;
        }
    }

    int size = 0;
    socklen_t len = sizeof(size);
    bool ok = getsockopt(sock, IPPROTO_UDP, UDP_SEGMENT, &size, &len) == 0;

    if(free_slot < 0) {
        // more sockets than slots: ask again next time, the oldest goes
        free_slot = 0;
    }
    // stored as sock + 1, so that 0 is a free slot
    tx->gso_sock[free_slot] = sock + 1;
    tx->gso_ok[free_slot] = ok;
    return ok;
}

// A send with GSO failed for good on this socket (EIO: a device that does
// not compute the checksums), so the datagrams go one by one from now on
static void gso_off (SOCKET sock) {

    for(int i = 0; i < SOCK_GSO_SOCKS; i++) {
        if(tx->gso_sock[i] == sock + 1) {
            tx->gso_ok[i] = false;
        }
    }
    traceEvent(TRACE_INFO, "UDP GSO does not work on this socket, sending without it");
}

// The datagrams first, ... of the batch as one message for sendmmsg(), with
// UDP_SEGMENT if there are more than one
static void gso_message (int j, int first, int count) {

    struct msghdr *hdr = &tx->out[j].msg_hdr;

    memset(&tx->out[j], 0, sizeof(tx->out[j]));
    *hdr = tx->msg[first].msg_hdr;
    hdr->msg_iovlen = count;
    tx->out_first[j] = first;
    tx->out_count[j] = count;
    if(count > 1) {
        uint16_t size = tx->iov[first].iov_len;

        hdr->msg_control = tx->ctl[j].buf;
        hdr->msg_controllen = sizeof(tx->ctl[j].buf);
        struct cmsghdr *cm = CMSG_FIRSTHDR(hdr);
        cm->cmsg_level = IPPROTO_UDP;
        cm->cmsg_type = UDP_SEGMENT;
        cm->cmsg_len = CMSG_LEN(sizeof(size));
        memcpy(CMSG_DATA(cm), &size, sizeof(size));
    }
}

// Whether datagram k can go with the run of datagrams first, ...: to the
// same destination, as big as the first - the last of a run may be smaller
// - and all of them not too big for one send
static bool gso_joins (int first, int k, size_t bytes) {

    size_t size = tx->iov[first].iov_len;

    return (tx->msg[k].msg_hdr.msg_namelen == tx->msg[first].msg_hdr.msg_namelen)
           && !memcmp(&tx->dest[k], &tx->dest[first], tx->msg[first].msg_hdr.msg_namelen)
           && (tx->iov[k].iov_len <= size)
           && (tx->iov[k - 1].iov_len == size)
           && (bytes + tx->iov[k].iov_len <= SOCK_GSO_BYTES);
}
#endif

// Send what the batch holds, all for one socket: sendmmsg() stops at a
// datagram it cannot send, which is logged and skipped, as sendto_logged()
// would have
static void tx_flush (void) {

    int done = 0;

#ifdef SOCK_GSO
    if((tx->count > 1) && gso_usable(tx->sock)) {
        int nout = 0;

        for(int k = 0; k < tx->count;) {
            int first = k;
            size_t bytes = tx->iov[k].iov_len;

            for(k++; (k < tx->count) && gso_joins(first, k, bytes); k++) {
                bytes += tx->iov[k].iov_len;
            }
            gso_message(nout++, first, k - first);
        }
        while(done < nout) {
            int n = sendmmsg(tx->sock, &tx->out[done], nout - done, 0);
            if(n >= 0) {
                done += n;
                continue;
            }
            // a run that cannot go as one: EINVAL for datagrams too big
            // for the path to go unfragmented, EIO for a device that does
            // not do the checksums.  Its datagrams go one by one.
            int first = tx->out_first[done], count = tx->out_count[done];
            if((count > 1) && (errno == EIO)) {
                gso_off(tx->sock);
            }
            for(int k = first; k < first + count; k++) {
                if(sendmsg(tx->sock, &tx->msg[k].msg_hdr, 0) < 0) {
                    send_failed((const struct sockaddr *)&tx->dest[k]);
                }
            }
            done++;
        }
        tx->count = 0;
        return;
    }
#endif

    while(done < tx->count) {
        int n = sendmmsg(tx->sock, &tx->msg[done], tx->count - done, 0);
        if(n < 0) {
            send_failed((const struct sockaddr *)&tx->dest[done]);
            done++;
            continue;
        }
        done += n;
    }
    tx->count = 0;
}
#endif


void sock_batch_begin (void) {

#ifdef SOCK_MMSG
    if(batches_alloc()) {
        tx->open++;
    }
#endif
}


void sock_batch_end (void) {

#ifdef SOCK_MMSG
    if(tx && tx->open && !--tx->open) {
        tx_flush();
    }
#endif
}


ssize_t sendto_logged (SOCKET sock, const void *buf, size_t len,
                       const struct sockaddr *dest, socklen_t dest_len) {

#ifdef SOCK_MMSG
    if(tx && tx->open && tx->count && ((tx->sock != sock) || (tx->count == SOCK_TX_BATCH)
                                       || (len > sizeof(tx->buf[0])))) {
        // what is in the batch goes first, in the order it came
        tx_flush();
    }
    if(tx && tx->open && (dest_len <= sizeof(tx->dest[0])) && (len <= sizeof(tx->buf[0]))) {
        int k = tx->count++;
        tx->sock = sock;
        memcpy(&tx->dest[k], dest, dest_len);
        memcpy(tx->buf[k], buf, len);
        tx->iov[k].iov_base = tx->buf[k];
        tx->iov[k].iov_len = len;
        memset(&tx->msg[k], 0, sizeof(tx->msg[k]));
        tx->msg[k].msg_hdr.msg_name = &tx->dest[k];
        tx->msg[k].msg_hdr.msg_namelen = dest_len;
        tx->msg[k].msg_hdr.msg_iov = &tx->iov[k];
        tx->msg[k].msg_hdr.msg_iovlen = 1;
        return len;
    }
#endif

    ssize_t sent = sendto(sock, buf, len, 0 /* flags */, dest, dest_len);

    if(sent >= 0) {
        traceEvent(TRACE_DEBUG, "sent=%d", (signed int)sent);
        return sent;
    }
    send_failed(dest);
    return -1;
}


ssize_t sendto_bind (struct n3n_runtime_data *rt, int i, const void *buf,
                     size_t len, const struct sockaddr *dest) {

    struct sockaddr_storage dest_addr = {0};
    socklen_t dest_len = prepare_sockaddr_for_send(&dest_addr, rt->bind_family[i], dest);

    if(dest_len == 0) {
        // a family this socket cannot send to, already logged
        return -1;
    }

    return sendto_logged(bind_thread_sock(rt, i), buf, len,
                         (const struct sockaddr *)&dest_addr, dest_len);
}



int udp_drain (struct n3n_runtime_data *rt, SOCKET sock, struct n3n_pktbuf *pkt,
               int max, time_t now, udp_read_fn read, udp_rx_fn rx_fn) {

    int taken = 0;

#ifdef SOCK_MMSG
    // only the sockets of connection.bind, which carry the packets: the
    // others (the TCP fallback's probe, the punch pools) are read one by
    // one, whose errors tell their roles something
    if((bind_entry_of_sock(rt, sock) >= 0) && batches_alloc()) {
        while(taken < max) {
            int want = (max - taken < SOCK_RX_BATCH) ? max - taken : SOCK_RX_BATCH;

            for(int k = 0; k < want; k++) {
                rx->iov[k].iov_base = rx->buf[k];
                rx->iov[k].iov_len = sizeof(rx->buf[k]);
                memset(&rx->msg[k], 0, sizeof(rx->msg[k]));
                rx->msg[k].msg_hdr.msg_name = &rx->from[k];
                rx->msg[k].msg_hdr.msg_namelen = sizeof(rx->from[k]);
                rx->msg[k].msg_hdr.msg_iov = &rx->iov[k];
                rx->msg[k].msg_hdr.msg_iovlen = 1;
            }
            int n = recvmmsg(sock, rx->msg, want, MSG_DONTWAIT, NULL);
            if(n < 0) {
                if((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
                    // the role's own read meets the error too, and knows
                    // what to make of it
                    taken += read(rt, sock, pkt, now);
                }
                return taken;
            }
            // what handling them sends - a supernode forwarding, an edge
            // answering - goes out together as well
            for(int k = 0; k < n; k++) {
                if(rx->msg[k].msg_len > 0) {
                    rx_fn(rt, sock, (struct sockaddr *)&rx->from[k],
                          rx->msg[k].msg_hdr.msg_namelen,
                          rx->buf[k], rx->msg[k].msg_len, now);
                }
            }
            taken += n;
            if(n < want) {
                // the socket is empty
                return taken;
            }
        }
        return taken;
    }
#endif

    while((taken < max) && (read(rt, sock, pkt, now) > 0)) {
        taken++;
    }
    return taken;
}
