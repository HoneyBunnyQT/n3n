/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Sending datagrams from the sockets of connection.bind - see sock.h
 */

#include <errno.h>           // for errno, EAFNOSUPPORT
#include <n3n/logging.h>     // for traceEvent
#include <n3n/strings.h>     // for sockaddr_to_str
#include <string.h>          // for strerror

#include "edge_threads.h"    // for edge_threads_bind_sock
#include "sock.h"
#include "thread_local.h"    // for n3n_thread_slot

#ifdef _WIN32
#include "win32/defs.h"
#else
#include <sys/socket.h>      // for sendto, sockaddr_storage
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


ssize_t sendto_logged (SOCKET sock, const void *buf, size_t len,
                       const struct sockaddr *dest, socklen_t dest_len) {

    ssize_t sent = sendto(sock, buf, len, 0 /* flags */, dest, dest_len);

    if(sent >= 0) {
        traceEvent(TRACE_DEBUG, "sent=%d", (signed int)sent);
        return sent;
    }

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
