/**
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 */

#include <assert.h>
#include <connslot/connslot.h>  // for slots_fdset
#include <errno.h>              // for errno
#include <n2n_typedefs.h>       // for n3n_runtime_data
#include <n3n/edge.h>           // for edge_read_proto3_udp
#include <n3n/logging.h>        // for traceEvent
#include <n3n/mainloop.h>       // for fd_info_proto
#include <n3n/metrics.h>
#include <n3n/pktbuf.h>
#include <n3n/strings.h>        // for sockaddr_to_str
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>             // for calloc, realloc, free, abort
#include <string.h>             // for memmove, memset, strerror

#ifndef _WIN32
#include <sys/select.h>         // for select, FD_ZERO,
#include <unistd.h>             // for close
#endif

#ifdef DEBUG_MALLOC
#ifdef __GLIBC__
#include <malloc.h>             // for mallinfo2, malloc_info
#endif
#endif

#include "local_link.h"         // for local_link_drain
#include "edge_utils.h"         // for edge_read_proto3_udp
#include "role_tap.h"           // for edge_read_from_tap_batch
#include "edge_threads.h"       // for edge_threads_main_release, ...
#include "management.h"         // for readFromMgmtSocket
#include "netwatch.h"           // for netwatch_read
#include "notify.h"             // for n3n_notify_tick
#include "reload.h"             // for n3n_reload_pending
#include "role_client.h"        // for edge_network_change
#include "minmax.h"             // for min, max
#include "portable_endian.h"    // for htobe16

#ifndef _WIN32
#include <netinet/in.h>         // for IPPROTO_TCP
#include <netinet/tcp.h>        // for TCP_NODELAY
#include <sys/resource.h>       // for getrlimit, RLIMIT_NOFILE
#endif

#ifndef _WIN32
// Another wonderful gift from the world of POSIX compliance is not worth much
#define closesocket(a) close(a)
#endif

#ifdef _WIN32
// Winsock has no per call non blocking read flag, so draining is not possible
// there - a second read would block the whole mainloop
#define FD_DRAIN_MAX 1
#else
// How many packets to take from one fd before returning to the mainloop.
// select() only tells us that at least one packet is waiting, but under load
// there is usually a queue behind it and reading the queue out in one go
// avoids a select() call per packet.  The cap is what stops a busy fd from
// starving the other fds, the management interface and the timers
#define FD_DRAIN_MAX 32
#endif

static struct metrics {
    uint32_t mainloop;      // mainloop_runonce() is called
    uint32_t register_fd;   // mainloop_register_fd() is called
    uint32_t unregister_fd; // mainloop_unregister_fd() is called
    uint32_t connlist_alloc;
    uint32_t connlist_free;
    uint32_t send_queue_fail;   // Attempted to send v3tcp but buffer in use
} metrics;

static struct n3n_metrics_items_llu32 metrics_items = {
    .name = "count",
    .desc = "Track the events in the lifecycle of mainloop objects",
    .name1 = "event",
    .items = {
        {
            .val1 = "mainloop",
            .offset = offsetof(struct metrics, mainloop),
        },
        {
            .val1 = "register_fd",
            .offset = offsetof(struct metrics, register_fd),
        },
        {
            .val1 = "unregister_fd",
            .offset = offsetof(struct metrics, unregister_fd),
        },
        {
            .val1 = "connlist_alloc",
            .offset = offsetof(struct metrics, connlist_alloc),
        },
        {
            .val1 = "connlist_free",
            .offset = offsetof(struct metrics, connlist_free),
        },
        {
            .val1 = "send_queue_fail",
            .offset = offsetof(struct metrics, send_queue_fail),
        },
        { },
    },
};

static char *proto_str[] = {
    [fd_info_proto_unknown] = "?",
    [fd_info_proto_tuntap] = "tuntap",
    [fd_info_proto_listen_http] = "listen_http",
    [fd_info_proto_v3udp] = "v3udp",
    [fd_info_proto_v3tcp] = "v3tcp",
    [fd_info_proto_http] = "http",
    [fd_info_proto_wakeup] = "wakeup",
    [fd_info_proto_listen_v3tcp] = "listen_v3tcp",
    [fd_info_proto_netwatch] = "netwatch",
};

struct fd_info {
    int fd;                     // The file descriptor for this connection
    int stats_reads;            // The number of ready to read events
    enum fd_info_proto proto;   // What protocol to use on a read event
    int8_t connnr;              // which connlist[] is being used as buffer
    bool close_after;           // http: close once the reply is sent
    struct n3n_runtime_data *rt;    // whose it is, NULL: of mainloop_run()
};

// The known file descriptors.  The table starts big enough for an edge's own
// sockets, the management connections and the sockets it opens behind a hard
// NAT (NAT_PUNCH_POOL_MAX + NAT_PUNCH_BOUND), and grows when it is full - a
// supernode's TCP connections need more - up to what select() can take.
#define FDLIST_INITIAL 96
#define FDLIST_MAX FD_SETSIZE
static struct fd_info *fdlist;
static int fdlist_size;
static int fdlist_next_search;

// The buffers of the connections that have them (v3tcp and http).  Each is
// allocated on its own, so that a pointer to one stays valid when the table
// grows.
// TODO: need pools of struct conn, for each expected buffer size
#define CONNLIST_INITIAL 8
static struct conn **connlist;
static int connlist_size;
static int connlist_next_search;

// At most this many management connections at once
#define HTTP_CONN_MAX 8

// TCP connections that are accepted stop 16 descriptors short of what
// FD_SET() and the process's limit allow, leaving room for everything else
// that goes into the fd sets: the UDP and listening sockets and the
// management connections
#define TCP_FD_HEADROOM 16

// The regular work of the daemons, see mainloop_register_tick()
#define MAX_TICKS 16
static struct tick {
    mainloop_tick_fn fn;
    int interval;
    time_t last;
    struct n3n_runtime_data *rt;    // whose it is, NULL: of mainloop_run()
} ticks[MAX_TICKS];
static int ticks_count;

// accept() failed, most likely for want of file descriptors: the listening
// sockets are left alone until then instead of spinning on the pending
// connection
static time_t listen_pause_until;

static void metrics_callback (strbuf_t **reply, const struct n3n_metrics_module *module) {
    int slot = 0;
    char buf[16];
    while(slot < fdlist_size) {
        if(fdlist[slot].fd == -1) {
            slot++;
            continue;
        }

        snprintf(buf, sizeof(buf), "%i", fdlist[slot].fd);

        n3n_metrics_render_u32tags(
            reply,
            module,
            "fd_reads",
            (char *)&fdlist[slot].stats_reads - (char *)module->data,
            2,  // number of tag+val pairs
            "fd",
            buf,
            "proto",
            proto_str[fdlist[slot].proto]
        );
        // TODO:
        // - do we need to keep each fd lifecycle clear by tracking and
        // outputting the open timestamp?
        slot++;
    }
}

#ifdef DEBUG_MALLOC
#ifdef __GLIBC__
static struct mallinfo2 metrics_mi;

static void metrics_mallinfo2 (strbuf_t **reply, const struct n3n_metrics_module *module) {
    metrics_mi = mallinfo2();

    n3n_metrics_render_u32tags(
        reply,
        module,
        "bytes",
        offsetof(struct mallinfo2, arena),
        1,  // number of tag+val pairs
        "field",
        "arena"
    );
    n3n_metrics_render_u32tags(
        reply,
        module,
        "bytes",
        offsetof(struct mallinfo2, uordblks),
        1,  // number of tag+val pairs
        "field",
        "uordblks"
    );
    n3n_metrics_render_u32tags(
        reply,
        module,
        "bytes",
        offsetof(struct mallinfo2, fordblks),
        1,  // number of tag+val pairs
        "field",
        "fordblks"
    );
    n3n_metrics_render_u32tags(
        reply,
        module,
        "bytes",
        offsetof(struct mallinfo2, keepcost),
        1,  // number of tag+val pairs
        "field",
        "keepcost"
    );
}

static struct n3n_metrics_module metrics_module_mallinfo2 = {
    .name = "mallinfo2",
    .data = &metrics_mi,
    .cb = &metrics_mallinfo2,
    .type = n3n_metrics_type_cb,
};
#endif
#endif

static struct n3n_metrics_module metrics_module_dynamic = {
    .name = "mainloop",
    .data = NULL,       // fdlist, wherever it is at the moment
    .cb = &metrics_callback,
    .type = n3n_metrics_type_cb,
};

static struct n3n_metrics_module metrics_module_static = {
    .name = "mainloop",
    .data = &metrics,
    .items_llu32 = &metrics_items,
    .type = n3n_metrics_type_llu32,
};

static void connlist_init () {
    connlist = calloc(CONNLIST_INITIAL, sizeof(*connlist));
    if(!connlist) {
        abort();
    }
    connlist_size = CONNLIST_INITIAL;
    connlist_next_search = 0;
}

static void connlist_deinit () {
    int conn = 0;
    while(conn < connlist_size) {
        if(connlist[conn]) {
            // TODO: this crosses the layer boundaries
            free(connlist[conn]->request);
            free(connlist[conn]->reply_header);
            free(connlist[conn]);
        }
        conn++;
    }
    free(connlist);
    connlist = NULL;
    connlist_size = 0;
}

// A free entry of connlist[], set up for use; the table grows if there is
// none.  -1 if it cannot grow any more.
static int connlist_alloc (enum conn_proto proto) {
    int conn = connlist_next_search % connlist_size;
    int count = connlist_size;
    while(count) {
        if(!connlist[conn]) {
            connlist[conn] = calloc(1, sizeof(struct conn));
            if(!connlist[conn] || (conn_init(connlist[conn], 4000, 1000) != 0)) {
                abort();
            }
        }
        if(connlist[conn]->proto == CONN_PROTO_UNK) {
            connlist[conn]->proto = proto;
            connlist_next_search = conn + 1;
            metrics.connlist_alloc++;
            return conn;
        }
        conn = (conn + 1) % connlist_size;
        count--;
    }

    if(connlist_size >= FDLIST_MAX) {
        return -1;
    }
    int new_size = MIN(connlist_size * 2, FDLIST_MAX);
    struct conn **p = realloc(connlist, new_size * sizeof(*connlist));
    if(!p) {
        return -1;
    }
    memset(&p[connlist_size], 0, (new_size - connlist_size) * sizeof(*connlist));
    connlist_next_search = connlist_size;
    connlist = p;
    connlist_size = new_size;
    return connlist_alloc(proto);
}

// The reply buffer of a v3tcp connection is the mainloop's own, see
// mainloop_send_v3tcp(); that of an http connection is not
static void conn_free_reply (struct conn *conn) {
    if((conn->proto == CONN_PROTO_BE16LEN) && conn->reply) {
        free(conn->reply);
        conn->reply = NULL;
    }
}

static void connlist_free (int connnr) {
    if((connnr < 0) || (connnr >= connlist_size)) {
        // TODO: error!
        return;
    }
    struct conn *conn = connlist[connnr];
    conn_free_reply(conn);
    conn->fd = -1;
    conn->proto = CONN_PROTO_UNK;
    conn->state = CONN_EMPTY;
    connlist_next_search = connnr;
    metrics.connlist_free++;
}

// Mark entries from..to-1 as free
static void fdlist_clear (int from, int to) {
    for(int slot = from; slot < to; slot++) {
        fdlist[slot].connnr = -1;
        fdlist[slot].fd = -1;
        fdlist[slot].proto = fd_info_proto_unknown;
        fdlist[slot].stats_reads = 0;
        fdlist[slot].close_after = false;
    }
}

// Used only to initialise the array at startup
static void fdlist_zero () {
    fdlist = calloc(FDLIST_INITIAL, sizeof(*fdlist));
    if(!fdlist) {
        abort();
    }
    fdlist_size = FDLIST_INITIAL;
    fdlist_clear(0, fdlist_size);
    fdlist_next_search = 0;
    metrics_module_dynamic.data = fdlist;
}

// Make room for more fds, false if there can be no more
static bool fdlist_grow () {
    if(fdlist_size >= FDLIST_MAX) {
        return false;
    }
    int new_size = MIN(fdlist_size * 2, FDLIST_MAX);
    struct fd_info *p = realloc(fdlist, new_size * sizeof(*fdlist));
    if(!p) {
        return false;
    }
    fdlist = p;
    fdlist_clear(fdlist_size, new_size);
    fdlist_next_search = fdlist_size;
    fdlist_size = new_size;
    metrics_module_dynamic.data = fdlist;
    return true;
}

static int fdlist_allocslot (int fd, enum fd_info_proto proto, struct n3n_runtime_data *rt) {
#ifndef _WIN32
    if(fd >= FD_SETSIZE) {
        // FD_SET() would write beyond the end of the fd_set
        traceEvent(TRACE_ERROR, "fd %i is too high for select()", fd);
        return -1;
    }
#endif
    int slot = fdlist_next_search % fdlist_size;
    int count = fdlist_size;
    while(count) {
        if(fdlist[slot].fd == -1) {
            int connnr = -1;

            if(proto == fd_info_proto_v3tcp) {
                connnr = connlist_alloc(CONN_PROTO_BE16LEN);
                if(connnr == -1) {
                    return -1;
                }
                conn_accept(connlist[connnr], fd, CONN_PROTO_BE16LEN);
            }

            metrics.register_fd++;
            fdlist[slot].fd = fd;
            fdlist[slot].proto = proto;
            fdlist[slot].stats_reads = 0;
            fdlist[slot].connnr = connnr;
            fdlist[slot].close_after = false;
            fdlist[slot].rt = rt;

            fdlist_next_search = slot + 1;
            return slot;
        }
        slot = (slot + 1) % fdlist_size;
        count--;
    }

    if(!fdlist_grow()) {
        traceEvent(TRACE_ERROR, "no room for fd %i in the mainloop", fd);
        return -1;
    }
    return fdlist_allocslot(fd, proto, rt);
}

static int fdlist_findslot (int fd) {
    if(fd == -1) {
        return -1;
    }
    for(int slot = 0; slot < fdlist_size; slot++) {
        if(fdlist[slot].fd == fd) {
            return slot;
        }
    }
    return -1;
}

static void fdlist_freefd (int fd) {
    int slot = 0;
    if(fd == -1) {
        // Cannot release an error fd!
        return;
    }
    while(slot < fdlist_size) {
        if(fdlist[slot].fd != fd) {
            slot++;
            continue;
        }
        metrics.unregister_fd++;
        if(fdlist[slot].connnr != -1) {
            connlist_free(fdlist[slot].connnr);
            fdlist[slot].connnr = -1;
        }
        fdlist[slot].fd = -1;
        fdlist[slot].proto = fd_info_proto_unknown;
        fdlist[slot].rt = NULL;
        fdlist_next_search = slot;
        return;
    }

    // TODO:
    // - could assert or similar
}

// Close the socket of a slot, and its connection if it has one, and forget
// the slot
static void fdlist_close_slot (int slot) {
    int fd = fdlist[slot].fd;
    int connnr = fdlist[slot].connnr;

    if(connnr != -1) {
        conn_free_reply(connlist[connnr]);
        conn_close(connlist[connnr], fd);
    } else {
        closesocket(fd);
    }
    fdlist_freefd(fd);
}

static void read_proto3_tcp (struct n3n_runtime_data *eee, int fd,
                             uint8_t *buf, int size, time_t now);

// A v3tcp connection got closed, or has gone idle: close it, and tell the
// upper layer that its fd is gone
static void v3tcp_closed (struct n3n_runtime_data *eee, int slot, time_t now) {
    int fd = fdlist[slot].fd;

    fdlist_close_slot(slot);
    read_proto3_tcp(eee, fd, NULL, 0, now);
}

static int fdlist_fd_set (fd_set *rd, fd_set *wr, time_t now) {
    int max_sock = 0;
    int slot = 0;
    while(slot < fdlist_size) {
        if(fdlist[slot].fd == -1) {
            slot++;
            continue;
        }

        if((fdlist[slot].proto == fd_info_proto_listen_v3tcp) && (now < listen_pause_until)) {
            slot++;
            continue;
        }

        if(fdlist[slot].connnr == -1) {
            FD_SET(fdlist[slot].fd, rd);
            max_sock = MAX(max_sock, fdlist[slot].fd);
        } else {
            if(connlist[fdlist[slot].connnr]->reply_sendpos == 0) {
                // Only select for reading if we have finished previous write
                // FIXME:
                // this check assumes that the conn_write() that kicks off
                // a sending event will have made at least some progress
                FD_SET(fdlist[slot].fd, rd);
                max_sock = MAX(max_sock, fdlist[slot].fd);
            }
        }

        if(fdlist[slot].connnr == -1) {
            slot++;
            continue;
        }

        if(conn_iswriter(connlist[fdlist[slot].connnr])) {
            FD_SET(fdlist[slot].fd, wr);
        }

        slot++;
    }
    return max_sock;
}

// A PDU waits on a v3 socket: the role of the runtime takes it
static int read_proto3_udp (struct n3n_runtime_data *eee, int fd,
                            struct n3n_pktbuf *pkt, time_t now) {
    return eee->ops->read_udp(eee, fd, pkt, now);
}

// A PDU that came in on a v3tcp connection; buf NULL: the connection is gone,
// fd is closed already
static void read_proto3_tcp (struct n3n_runtime_data *eee, int fd,
                             uint8_t *buf, int size, time_t now) {
    eee->ops->read_tcp(eee, fd, buf, size, now);
}

#ifndef _WIN32
// The highest fd a TCP connection can be accepted on, see TCP_FD_HEADROOM
static int tcp_fd_limit () {
    int limit = FD_SETSIZE;
    struct rlimit nofile;
    if((getrlimit(RLIMIT_NOFILE, &nofile) == 0) && (nofile.rlim_cur < (rlim_t)FD_SETSIZE)) {
        limit = nofile.rlim_cur;
    }
    return limit - TCP_FD_HEADROOM;
}
#endif

static void accept_v3tcp (struct n3n_runtime_data *eee, int listen_fd, time_t now) {
    struct sockaddr_storage sas;
    socklen_t sas_len = sizeof(sas);
    n3n_sock_str_t sockbuf;

    SOCKET client = accept(listen_fd, (struct sockaddr *)&sas, &sas_len);
#ifdef _WIN32
    bool failed = (client == INVALID_SOCKET);
    // a Windows fd_set holds up to FD_SETSIZE sockets, of any value
    int used = 0;
    for(int slot = 0; slot < fdlist_size; slot++) {
        used += (fdlist[slot].fd != -1);
    }
    bool too_many = ((used + TCP_FD_HEADROOM) >= FD_SETSIZE);
#else
    bool failed = (client < 0);
    bool too_many = (client >= tcp_fd_limit());
#endif
    if(failed) {
        // Most likely out of file descriptors. The connection stays pending,
        // so do not ask select() about the listening sockets for a second
        // instead of spinning on it.
        traceEvent(TRACE_WARNING, "accept() failed: %s", strerror(errno));
        listen_pause_until = now + 1;
        return;
    }

    if(too_many || (fdlist_allocslot(client, fd_info_proto_v3tcp, eee) < 0)) {
        traceEvent(
            TRACE_WARNING,
            "denied incoming TCP connection from [%s] due to max connections limit hit",
            sockaddr_to_str(sockbuf, sizeof(sockbuf), (struct sockaddr *)&sas)
        );
        closesocket(client);
        return;
    }

    // the length and the PDU go out in one write, see mainloop_send_v3tcp(),
    // so there is nothing to wait for
    int nodelay = 1;
    setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (void *)&nodelay, sizeof(nodelay));

    if(!eee->ops->accepted_tcp) {
        mainloop_close_fd(client);
        return;
    }
    eee->ops->accepted_tcp(eee, client, (struct sockaddr *)&sas, sas_len);
}

static void handle_fd (const time_t now, int slot, struct n3n_runtime_data *eee) {
    const struct fd_info info = fdlist[slot];

    switch(info.proto) {
        case fd_info_proto_unknown:
            // should not happen!
            assert(false);
            return;

        case fd_info_proto_wakeup:
            // a packet thread queued something; the edge loop takes it
            // right after this loop iteration, see edge_threads_drain()
            return;

        case fd_info_proto_netwatch:
            // acted on a little later, once all of a change came in
            edge_network_change(netwatch_read(info.fd));
            return;

        case fd_info_proto_tuntap:
            // read ethernet frames from the TAP socket; write on the IP
            // socket
            // TODO: change API to tell it which fd
            edge_read_from_tap_batch(eee, FD_DRAIN_MAX);
            return;

        case fd_info_proto_listen_http: {
            int client = accept(info.fd, NULL, 0);
            if(client == -1) {
                // TODO:
                // - increment error stats
                return;
            }

            int http_conns = 0;
            for(int i = 0; i < fdlist_size; i++) {
                http_conns += (fdlist[i].proto == fd_info_proto_http);
            }
            if(http_conns >= HTTP_CONN_MAX) {
                send(client, "HTTP/1.1 503 full\r\n", 19, 0);
                closesocket(client);
                return;
            }

            int slotnr = fdlist_allocslot(client, fd_info_proto_http, eee);
            if(slotnr < 0) {
                // TODO:
                // - increment error stats
                send(client, "HTTP/1.1 503 full\r\n", 19, 0);
                closesocket(client);
                return;
            }

            int connnr = connlist_alloc(CONN_PROTO_HTTP);
            if(connnr < 0) {
                // TODO:
                // - increment error stats
                send(client, "HTTP/1.1 503 full\r\n", 19, 0);
                closesocket(client);
                fdlist_freefd(client);
                return;
            }

            fdlist[slotnr].connnr = connnr;
            conn_accept(connlist[connnr], client, CONN_PROTO_HTTP);

            return;
        }

        case fd_info_proto_listen_v3tcp:
            accept_v3tcp(eee, info.fd, now);
            return;

        case fd_info_proto_v3udp: {
            struct n3n_pktbuf *pkt = n3n_pktbuf_alloc(N2N_PKT_BUF_SIZE);
            if(!pkt) {
                abort();
            }
            pkt->owner = n3n_pktbuf_owner_rx_pdu;

            int drain = FD_DRAIN_MAX;
            while(drain && (read_proto3_udp(eee, info.fd, pkt, now) > 0)) {
                drain--;
            }

            n3n_pktbuf_free(pkt);
            return;
        }

        case fd_info_proto_v3tcp: {
            struct conn *conn = connlist[info.connnr];
            conn_read(conn, info.fd);

            switch(conn->state) {
                case CONN_EMPTY:
                case CONN_READING:
                    // These states dont require us to do anything
                    // TODO:
                    // - handle reading/sending simultaneous?
                    return;

                case CONN_ERROR:
                case CONN_CLOSED:
                    v3tcp_closed(eee, slot, now);
                    return;

                case CONN_READY:
                    // the buffer can hold several PDUs: hand over each one
                    // that is complete
                    while(conn->state == CONN_READY) {
                        int size = ntohs(*(uint16_t *)&conn->request->str);

                        read_proto3_tcp(
                            eee,
                            info.fd,
                            (uint8_t *)&conn->request->str[2],
                            size,
                            now
                        );

                        if((fdlist[slot].fd != info.fd) || (fdlist[slot].connnr != info.connnr)) {
                            // the upper layer closed the connection meanwhile
                            return;
                        }

                        // TODO: this crosses layers by reaching inside the
                        // conn object
                        int more = sb_len(conn->request) - (size + 2);
                        if(more <= 0) {
                            // We read exactly one packet
                            sb_zero(conn->request);
                            conn->state = CONN_EMPTY;
                            return;
                        }

                        // Our buffer contains data beyond the single packet
                        traceEvent(TRACE_DEBUG, "packet has %i more bytes", more);
                        memmove(
                            conn->request->str,
                            &conn->request->str[size + 2],
                            more
                        );
                        conn->request->rd_pos = 0;
                        conn->request->wr_pos = more;
                        conn->state = CONN_READING;
                        conn_check_ready(conn);
                    }
                    return;
            }
            return;
        }

        case fd_info_proto_http: {
            struct conn *conn = connlist[info.connnr];
            conn_read(conn, info.fd);

            switch(conn->state) {
                case CONN_EMPTY:
                case CONN_READING:
                    // These states dont require us to do anything
                    // TODO:
                    // - handle reading/sending simultaneous?
                    return;

                case CONN_READY: {
                    bool close_after = mgmt_api_handler(eee, conn);
                    if(conn->reply_sendpos == 0) {
                        // Looks like we have finished a write, so we can clean up
                        sb_zero(conn->request);
                    }
                    if(close_after && !conn_iswriter(conn)) {
                        fdlist_close_slot(slot);
                    } else {
                        fdlist[slot].close_after = close_after;
                    }
                    return;
                }

                case CONN_ERROR:
                case CONN_CLOSED:
                    fdlist_close_slot(slot);
            }
            return;
        }
    }
}

/* TODO: decide if this quick helper is actually useful and needed
 * It was added to try and provide an action to do if select returns an error,
 * but it didnt end up closing connections - and the original error was traced
 * to an alloc without matching free
 */
// Close a connection that has been idle for too long
static void fdlist_closeidle_slot (const time_t now, int slot, struct n3n_runtime_data *eee) {
    if(fdlist[slot].connnr == -1) {
        return;
    }
    int timeout = 60;
    struct conn *conn = connlist[fdlist[slot].connnr];
    if((now - conn->activity) <= timeout) {
        return;
    }
    // TODO: metrics timeouts ++
    if(fdlist[slot].proto == fd_info_proto_v3tcp) {
        v3tcp_closed(eee, slot, now);
    } else {
        fdlist_close_slot(slot);
    }
}

/* TODO: decide if this quick helper is actually useful and needed
 * It was added to try and provide an action to do if select returns an error,
 * but it didnt end up closing connections - and the original error was traced
 * to an alloc without matching free
 */
static void fdlist_closeidle (const time_t now, struct n3n_runtime_data *eee) {
    // A linear scan is not ideal, but until we support things other than
    // select() it will need to suffice
    for(int slot = 0; slot < fdlist_size; slot++) {
        if(fdlist[slot].fd != -1) {
            fdlist_closeidle_slot(now, slot, eee);
        }
    }
}

static void fdlist_check_ready (fd_set *rd, fd_set *wr, const time_t now, struct n3n_runtime_data *eee) {
    int slot = 0;
    // A linear scan is not ideal, but until we support things other than
    // select() it will need to suffice
    while(slot < fdlist_size) {
        int fd = fdlist[slot].fd;
        if(fd == -1) {
            slot++;
            continue;
        }
        // the runtime the fd belongs to
        struct n3n_runtime_data *rt = fdlist[slot].rt ? fdlist[slot].rt : eee;

        if(FD_ISSET(fd, rd)) {
            fdlist[slot].stats_reads++;
            handle_fd(now, slot, rt);
        }
        if((fdlist[slot].fd == fd) && FD_ISSET(fd, wr)) {
            // We should not be listening on this socket if there is no
            // connnr assigned, but paranoia..
            if(fdlist[slot].connnr == -1) {
                traceEvent(TRACE_DEBUG, "writer bad connnr");
                slot++;
                continue;
            }

            struct conn *conn = connlist[fdlist[slot].connnr];

            // TODO: track the stats on writes?
            conn_write(conn, fd);

            if(conn->reply_sendpos == 0) {
                // Looks like we have finished a write, so we can clean up
                sb_zero(conn->request);
            }
            if(fdlist[slot].close_after && !conn_iswriter(conn)) {
                fdlist_close_slot(slot);
                slot++;
                continue;
            }
        }

        if(fdlist[slot].fd == fd) {
            fdlist_closeidle_slot(now, slot, rt);
        }
        slot++;
    }
}

#ifdef DEBUG_MALLOC
#ifdef __GLIBC__
static time_t last_mallinfo;
#endif
#endif

int mainloop_runonce (struct n3n_runtime_data *eee) {
    fd_set rd;
    fd_set wr;

    metrics.mainloop++;

    FD_ZERO(&rd);
    FD_ZERO(&wr);
    int maxfd = fdlist_fd_set(&rd, &wr, time(NULL));

    // FIXME:
    // unlock the windows tun reader thread before select() and lock it
    // again after select().  It currently works by accident, but the
    // structures it manipulates are not thread-safe, so try to make it
    // work by /design/

    struct timeval wait_time;
    if(eee->client.sn_wait) {
        wait_time.tv_sec = (SOCKET_TIMEOUT_INTERVAL_SECS / 10 + 1);
    } else {
        wait_time.tv_sec = (SOCKET_TIMEOUT_INTERVAL_SECS);
    }
    wait_time.tv_usec = 0;

    // Packet threads, if any, may run only while the main thread waits
    edge_threads_main_release(eee);
    int ready = select(maxfd + 1, &rd, &wr, NULL, &wait_time);
    edge_threads_main_acquire(eee);

    // One timestamp to use for this entire loop iteration
    time_t now = time(NULL);

    if((ready == -1) && (errno == EINTR)) {
        // a signal: SIGHUP for a reload, or one to stop
        return 0;
    }
    if(ready == -1) {
        traceEvent(TRACE_ERROR, "select errno=%i", errno);
        fdlist_closeidle(now, eee);
        return -1;
    }

    if(ready < 1) {
        // Nothing ready
        return ready;
    }

    fdlist_check_ready(&rd, &wr, now, eee);

#ifdef DEBUG_MALLOC
#ifdef __GLIBC__
    if(getTraceLevel() >= TRACE_DEBUG) {
        if((now & ~0x3f) > last_mallinfo) {
            last_mallinfo = now;
            struct mallinfo2 mi = mallinfo2();
            traceEvent(
                TRACE_DEBUG,
                "mallinfo: area=%i uordblks=%i, fordblks=%i, keepcost=%i",
                mi.arena,
                mi.uordblks,
                mi.fordblks,
                mi.keepcost
            );

            fprintf(stderr,"===malloc_info start===\n");
            malloc_info(0, stderr);
            fprintf(stderr,"===malloc_info end===\n");
        }
    }
#endif
#endif

    return ready;
}

void mainloop_dump (strbuf_t **buf) {
    int i;
    sb_reprintf(buf, "i : fd(read) pr connnr\n");
    for(i=0; i<fdlist_size; i++) {
        sb_reprintf(
            buf,
            "%02i: %2i(%4i) %i %i\n",
            i,
            fdlist[i].fd,
            fdlist[i].stats_reads,
            fdlist[i].proto,
            fdlist[i].connnr
        );
    }
    sb_reprintf(buf, "\n");
    for(i=0; i<connlist_size; i++) {
        if(!connlist[i]) {
            continue;
        }
        sb_reprintf(buf,"%i: ",i);
        conn_dump(buf, connlist[i]);
    }
}

bool mainloop_send_v3tcp (int fd, const void *buf, int bufsize) {
    // TODO:
    // - avoid the linear scan by changing the params to pass a fdlist slottnr
    //   instead of a filehandle
    int slot = fdlist_findslot(fd);
    if(slot == -1) {
        // Couldnt find this fd
        return false;
    }

    if((fdlist[slot].proto != fd_info_proto_v3tcp) || (fdlist[slot].connnr == -1)) {
        // No buffer associated with this fd
        return false;
    }

    struct conn *conn = connlist[fdlist[slot].connnr];

    if(!conn->reply) {
        conn->reply = sb_malloc(N2N_PKT_BUF_SIZE + 2, N2N_PKT_BUF_SIZE + 2);
    } else {
        if(sb_len(conn->reply)) {
            // send buffer already in use
            metrics.send_queue_fail++;
            return false;
        }
        sb_zero(conn->reply);
    }

    uint16_t pktsize16 = htobe16(bufsize);
    sb_append(conn->reply, &pktsize16, sizeof(pktsize16));

    // TODO:
    // - avoid memcpy by using a global buffer pool and transferring ownership
    sb_append(conn->reply, buf, bufsize);

    // TODO:
    // - check bufsize for N2N_PKT_BUF_SIZE overflow

    conn_write(conn, fd);
    return true;
}

int mainloop_register_fd (int fd, enum fd_info_proto proto) {
    return fdlist_allocslot(fd, proto, NULL);
}

int mainloop_register_fd_rt (int fd, enum fd_info_proto proto, struct n3n_runtime_data *rt) {
    return fdlist_allocslot(fd, proto, rt);
}

void mainloop_unregister_fd (int fd) {
    fdlist_freefd(fd);
}

void mainloop_close_fd (int fd) {
    int slot = fdlist_findslot(fd);
    if(slot == -1) {
        closesocket(fd);
        return;
    }
    fdlist_close_slot(slot);
}

int mainloop_register_tick_rt (mainloop_tick_fn fn, int interval, struct n3n_runtime_data *rt) {
    for(int i = 0; i < ticks_count; i++) {
        if((ticks[i].fn == fn) && (ticks[i].rt == rt)) {
            ticks[i].interval = interval;
            return 0;
        }
    }
    if(ticks_count == MAX_TICKS) {
        return -1;
    }
    ticks[ticks_count].fn = fn;
    ticks[ticks_count].interval = interval;
    ticks[ticks_count].last = 0;
    ticks[ticks_count].rt = rt;
    ticks_count++;
    return 0;
}

int mainloop_register_tick (mainloop_tick_fn fn, int interval) {
    return mainloop_register_tick_rt(fn, interval, NULL);
}

static void run_ticks (struct n3n_runtime_data *rt, time_t now) {
    for(int i = 0; i < ticks_count; i++) {
        struct tick *t = &ticks[i];
        if(t->interval && ((now - t->last) < t->interval)) {
            continue;
        }
        t->last = now;
        t->fn(t->rt ? t->rt : rt, now);
    }
}

void mainloop_run (struct n3n_runtime_data *rt) {
    while(*rt->keep_running) {
        // what the edge and the supernode of this process sent each other,
        // if they are, before waiting for anything else
        local_link_drain(time(NULL));

        mainloop_runonce(rt);

        // what the packet threads handed over, if there are any
        edge_threads_drain(rt);

        // If anything we recieved caused us to stop..
        if(!(*rt->keep_running)) {
            break;
        }

        run_ticks(rt, time(NULL));

        // the configuration again, if SIGHUP asked for it
        n3n_reload_pending();

        // systemd's watchdog and status, if it asked for them
        n3n_notify_tick(rt);
    }
    n3n_notify("STOPPING=1");
}

void n3n_initfuncs_mainloop () {
    connlist_init();
    fdlist_zero();
    n3n_metrics_register(&metrics_module_dynamic);
#ifdef DEBUG_MALLOC
#ifdef __GLIBC__
    n3n_metrics_register(&metrics_module_mallinfo2);
#endif
#endif
    n3n_metrics_register(&metrics_module_static);
}

void n3n_deinitfuncs_mainloop () {
    connlist_deinit();
    free(fdlist);
    fdlist = NULL;
    fdlist_size = 0;
    // TODO: once the metrics framework supports it
    // n3n_metrics_unregister(&metrics_module_dynamic);
    // n3n_metrics_unregister(&metrics_module_static);
}
