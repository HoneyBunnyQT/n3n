/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-25 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Hole punching: getting through the NATs between two edges
 */

#ifdef _WIN32
#include "win32/defs.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <n3n/logging.h>
#include <n3n/mainloop.h>
#include <n3n/random.h>
#include <n3n/strings.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <stddef.h>

#include "config.h"
#include "edge_utils.h"
#include "minmax.h"
#include "n2n_wire.h"
#include "natclass.h"
#include "role_client.h"
#include "role_tap.h"
#include "punch.h"
#include "sn_selection.h"
#include "sock.h"
#include "n2n_define.h"

#ifdef _WIN32
#include <direct.h>

#include "win32/edge_utils_win32.h"
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pwd.h>
#include <sys/select.h>
#include <sys/socket.h>
#endif

#ifndef _WIN32
// Another wonderful gift from the world of POSIX compliance is not worth much
#define closesocket(a) close(a)
#endif


/* Behind a hard NAT, the sockets towards a peer that guesses our port (see
 * punch_pool_round()). The main thread reads them as it reads its own. The
 * first packet from the peer that one of them receives binds that one to the
 * peer's address: the NAT lets the peer in to that public port only, so from
 * then on everything to that address leaves from it, also from the packet
 * threads, and the rest of the pool is closed. The tables change only on the
 * main thread, while the packet threads wait, see edge_threads.h. */

// how long a socket bound to a peer stays open without a packet from it
#define NAT_PUNCH_BOUND_IDLE (2 * REGISTRATION_TIMEOUT)

const struct punch_bound *punch_bound_find (const struct n3n_runtime_data *eee, const n3n_sock_t *dest) {

    for(int i = 0; i < NAT_PUNCH_BOUND; i++) {
        const struct punch_bound *b = &eee->client.punch_bound[i];
        if(b->dest.family && sock_equal(&b->dest, dest)) {
            return b;
        }
    }
    return NULL;
}


static void punch_bound_close (struct n3n_runtime_data *eee, struct punch_bound *b) {

    mainloop_unregister_fd(b->fd);
    closesocket(b->fd);
    memset(b, 0, sizeof(*b));
    eee->client.punch_bound_count--;
}


static void punch_pool_close (struct n3n_runtime_data *eee, struct punch_pool *p) {

    for(int i = 0; i < p->count; i++) {
        if(p->fd[i] >= 0) {
            mainloop_unregister_fd(p->fd[i]);
            closesocket(p->fd[i]);
            eee->client.punch_pool_fds--;
        }
    }
    memset(p, 0, sizeof(*p));
}


void punch_close_all (struct n3n_runtime_data *eee) {

    for(int i = 0; i < NAT_PUNCH_POOLS; i++) {
        if(eee->client.punch_pool[i].used) {
            punch_pool_close(eee, &eee->client.punch_pool[i]);
        }
    }
    for(int i = 0; i < NAT_PUNCH_BOUND; i++) {
        if(eee->client.punch_bound[i].dest.family) {
            punch_bound_close(eee, &eee->client.punch_bound[i]);
        }
    }
}


// the option for the TTL (IPv4) or hop limit (IPv6) of a socket
static void ttl_option (int family, int *level, int *name) {

    *level = IPPROTO_IP;
    *name = IP_TTL;
#ifdef IPV6_UNICAST_HOPS
    if(family == AF_INET6) {
        *level = IPPROTO_IPV6;
        *name = IPV6_UNICAST_HOPS;
    }
#endif
}


/* What arrived on sock, on the main thread: on a socket of a pool, the peer
 * got through. The REGISTER it sent is answered right after, from the same
 * socket, which therefore gets its usual TTL back first. */
void punch_note_rx (struct n3n_runtime_data *eee, SOCKET sock,
                    const struct sockaddr *sender, time_t now) {

    for(int i = 0; i < NAT_PUNCH_BOUND; i++) {
        if(eee->client.punch_bound[i].dest.family && (eee->client.punch_bound[i].fd == sock)) {
            eee->client.punch_bound[i].last_rx = now;
            return;
        }
    }
    if(!eee->client.punch_pool_fds) {
        return;
    }

    for(int i = 0; i < NAT_PUNCH_POOLS; i++) {
        struct punch_pool *p = &eee->client.punch_pool[i];
        for(int j = 0; p->used && (j < p->count); j++) {
            if(p->fd[j] != sock) {
                continue;
            }

            n3n_sock_t from;
            if(fill_n3nsock(&from, sender) || punch_bound_find(eee, &from)) {
                // another socket of the pool got there first
                return;
            }
            struct punch_bound *b = &eee->client.punch_bound[0];
            for(int k = 0; k < NAT_PUNCH_BOUND; k++) {
                if(!eee->client.punch_bound[k].dest.family) {
                    b = &eee->client.punch_bound[k];
                    break;
                }
                if(eee->client.punch_bound[k].last_rx < b->last_rx) {
                    b = &eee->client.punch_bound[k];
                }
            }
            if(b->dest.family) {
                punch_bound_close(eee, b);
            }
            if(eee->conf.client.punch_ttl) {
                int level, name;
                ttl_option(p->dest.family, &level, &name);
                setsockopt(sock, level, name, (char *)&p->ttl0, sizeof(p->ttl0));
            }
            b->dest = from;
            b->fd = sock;
            b->last_rx = now;
            eee->client.punch_bound_count++;
            p->fd[j] = -1;
            eee->client.punch_pool_fds--;
            // the rest of the pool is closed by punch_sweep(), outside the
            // mainloop's walk through the fds
            p->won = true;

            struct sockaddr_storage local;
            socklen_t len = sizeof(local);
            uint16_t port = 0;
            if(getsockname(sock, (struct sockaddr *)&local, &len) == 0) {
                port = ntohs((local.ss_family == AF_INET6) ? ((struct sockaddr_in6 *)&local)->sin6_port
                                                           : ((struct sockaddr_in *)&local)->sin_port);
            }
            macstr_t mac_buf;
            n3n_sock_str_t sockbuf;
            traceEvent(TRACE_NORMAL, "%s [%s] got through the NAT to socket %d of %d (local port %u)",
                       macaddr_str(mac_buf, p->mac), sock_to_cstr(sockbuf, &from),
                       j + 1, p->count, port);
            return;
        }
    }
}


/* Once a second: close what is no longer needed - the rest of a pool once
 * one of its sockets got through, a pool no round used for two intervals,
 * and a bound socket the peer has not sent to for a while. */
void punch_sweep (struct n3n_runtime_data *eee, time_t now) {

    if(now == eee->client.punch_swept) {
        return;
    }
    eee->client.punch_swept = now;

    for(int i = 0; i < NAT_PUNCH_POOLS; i++) {
        struct punch_pool *p = &eee->client.punch_pool[i];
        if(p->used && (p->won || (now - p->used > 2 * (time_t)eee->conf.client.register_interval + 1))) {
            punch_pool_close(eee, p);
        }
    }
    for(int i = 0; i < NAT_PUNCH_BOUND; i++) {
        struct punch_bound *b = &eee->client.punch_bound[i];
        if(b->dest.family && (now - b->last_rx > NAT_PUNCH_BOUND_IDLE)) {
            n3n_sock_str_t sockbuf;
            traceEvent(TRACE_INFO, "closing the socket bound to [%s], idle", sock_to_cstr(sockbuf, &b->dest));
            punch_bound_close(eee, b);
        }
    }
}


/* A peer behind a hard NAT (see natclass.h) cannot be reached on the port the
 * supernode saw, and its REGISTERs straight to us get as far as our NAT only:
 * its NAT gave them a public port of their own, one we have not sent to. Its
 * hint tells the range of its ports, so each round we send REGISTERs to a few
 * more of them. Once one meets that port, its NAT lets ours in, the peer
 * answers, and our NAT lets the answer in, as we just sent to where it comes
 * from. Slowly, once per register_interval, so that it adds little to the
 * REGISTERs sent anyway.
 *
 * Where the peer answered is kept: when its entry expires, which happens
 * whenever the traffic goes one way only for a while, the next REGISTER
 * there finds the port again as long as the peer keeps it.
 */
static void punch_hard_peer (struct n3n_runtime_data *eee, struct peer_info *peer,
                             struct nat_peer *np, time_t now) {

    unsigned int lo, size, span, sent = 0;
    n3n_sock_t sock = peer->sock;
    n3n_sock_str_t sockbuf;
    macstr_t mac_buf;

    // with a hard NAT of our own, the peer's port would be for another port
    // of ours than the one we send from now
    enum nat_class own = eee->client.nat[sock.family == AF_INET6].nat_class;
    if((own == NAT_HARD) || (own == NAT_SEVERAL_ADDRESSES)) {
        return;
    }
    if(np->found.family) {
        send_register(eee, &np->found, peer->mac_addr, N2N_PORT_REG_COOKIE);
    }
    if(!nat_hint_range(np->hint, &lo, &size) || (size > NAT_PUNCH_MAX_RANGE) ||
       ((sock.family != AF_INET) && (sock.family != AF_INET6)) || is_empty_ip_address(&sock) ||
       (now - np->punched < eee->conf.client.register_interval)) {
        return;
    }
    // A stride through the range rounded up to a power of two meets every
    // port once, in an order hard to tell from random. Once through, it
    // starts over: the peer's port may have changed meanwhile.
    for(span = 1; span < size; span <<= 1);
    if(np->tried % span == 0) {
        np->start = n3n_rand();
        np->stride = n3n_rand() | 1;
    }
    while(sent < eee->conf.client.punch_ports) {
        unsigned int i = (np->start + np->tried * np->stride) & (span - 1);
        np->tried++;
        if((i < size) && (lo + i >= 1024)) {
            sock.port = lo + i;
            send_register(eee, &sock, peer->mac_addr, N2N_PORT_REG_COOKIE);
            sent++;
        }
        if(np->tried % span == 0) {
            break;
        }
    }
    np->punched = now;
    traceEvent(TRACE_INFO, "sent REGISTERs to %u more ports of %s [%s], %u tried",
               sent, macaddr_str(mac_buf, peer->mac_addr), sock_to_cstr(sockbuf, &sock),
               np->tried);
}


/* A UDP socket for a pool: on the address the edge's own socket of that
 * family is bound to, on a port the system picks, with the TTL of
 * connection.punch_ttl if set - then *ttl0 is the one it had. */
static int punch_open_sock (struct n3n_runtime_data *eee, int family, int *ttl0) {

    struct sockaddr_storage sa;
    socklen_t len = sizeof(sa);
    int i = bind_entry_for_family(eee, family);

    int sock = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if(sock < 0) {
        return -1;
    }
    memset(&sa, 0, sizeof(sa));
    if((i < 0) || (eee->bind_family[i] != family) ||
       getsockname(eee->bind_sock[i], (struct sockaddr *)&sa, &len)) {
        memset(&sa, 0, sizeof(sa));
        sa.ss_family = family;
    }
    if(family == AF_INET6) {
        int on = 1;
        setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&on, sizeof(on));
        ((struct sockaddr_in6 *)&sa)->sin6_port = 0;
        len = sizeof(struct sockaddr_in6);
    } else {
        ((struct sockaddr_in *)&sa)->sin_port = 0;
        len = sizeof(struct sockaddr_in);
    }
    if(bind(sock, (struct sockaddr *)&sa, len) != 0) {
        traceEvent(TRACE_WARNING, "could not bind a socket for punching: %s", strerror(errno));
        closesocket(sock);
        return -1;
    }
    set_sock_options(eee, sock, family, true);

    if(eee->conf.client.punch_ttl) {
        int level, name;
        int ttl = eee->conf.client.punch_ttl;
        socklen_t ttl_len = sizeof(*ttl0);
        ttl_option(family, &level, &name);
        getsockopt(sock, level, name, (char *)ttl0, &ttl_len);
        setsockopt(sock, level, name, (char *)&ttl, sizeof(ttl));
    }
    return sock;
}


/* Behind a hard NAT, the round towards a peer that guesses our port. One
 * REGISTER straight to its public socket makes one public port of ours that
 * its NAT will let in; the peer has to meet just that one. So we open
 * connection.punch_sockets more sockets for it and send a REGISTER from each
 * every round: the NAT gives each a public port of its own, and any of them
 * will do. The pool stays the same from round to round, so the peer's walk
 * through the range meets each of its ports once. All the pools together
 * hold at most NAT_PUNCH_POOL_MAX sockets: a NAT that gives every customer a
 * block of ports is not to be emptied by one edge.
 *
 * With connection.punch_ttl, these REGISTERs leave with a TTL that takes them
 * through our own NATs, but not to the peer's: they are only there to make
 * the ports, and the peer's network never sees them. */
static void punch_pool_round (struct n3n_runtime_data *eee, struct peer_info *peer, time_t now) {

    const n3n_sock_t *dest = &peer->sock;
    struct punch_pool *p = NULL;
    struct sockaddr_storage sa;
    socklen_t sa_len;
    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx;
    macstr_t mac_buf;
    n3n_sock_str_t sockbuf;

    if(!eee->conf.client.punch_sockets || (eee->client.punch_bound_count && punch_bound_find(eee, dest))) {
        // the REGISTER straight to the peer already leaves from the socket
        // it got through to before
        return;
    }

    for(int i = 0; i < NAT_PUNCH_POOLS; i++) {
        if(eee->client.punch_pool[i].used && !memcmp(eee->client.punch_pool[i].mac, peer->mac_addr, sizeof(n2n_mac_t))) {
            p = &eee->client.punch_pool[i];
            break;
        }
    }
    if(p && (p->won || !sock_equal(&p->dest, dest))) {
        // the peer moved, or the rest of a pool not swept yet
        punch_pool_close(eee, p);
        p = NULL;
    }

    if(!p) {
        int want = MIN((int)eee->conf.client.punch_sockets, NAT_PUNCH_POOL_MAX - eee->client.punch_pool_fds);

        for(int i = 0; i < NAT_PUNCH_POOLS; i++) {
            if(!eee->client.punch_pool[i].used) {
                p = &eee->client.punch_pool[i];
                break;
            }
        }
        if(!p || (want <= 0)) {
            traceEvent(TRACE_INFO, "no sockets left to punch towards %s", macaddr_str(mac_buf, peer->mac_addr));
            return;
        }
        memset(p, 0, sizeof(*p));
        memcpy(p->mac, peer->mac_addr, sizeof(n2n_mac_t));
        p->dest = *dest;
        while(p->count < want) {
            int sock = punch_open_sock(eee, dest->family, &p->ttl0);
            if(sock < 0) {
                break;
            }
            if(mainloop_register_fd(sock, fd_info_proto_v3udp) < 0) {
                closesocket(sock);
                break;
            }
            p->fd[p->count++] = sock;
            eee->client.punch_pool_fds++;
        }
        if(!p->count) {
            return;
        }
        traceEvent(TRACE_INFO, "opened %d sockets to punch towards %s [%s]",
                   p->count, macaddr_str(mac_buf, peer->mac_addr), sock_to_cstr(sockbuf, dest));
    }
    p->used = now;

    sa_len = fill_sockaddr((struct sockaddr *)&sa, sizeof(sa), dest);
    if(sa_len == 0) {
        return;
    }
    idx = encode_register_pkt(eee, pktbuf, peer->mac_addr, N2N_REGULAR_REG_COOKIE);
    for(int i = 0; i < p->count; i++) {
        if(p->fd[i] >= 0) {
            sendto_logged(p->fd[i], pktbuf, idx, (struct sockaddr *)&sa, sa_len);
        }
    }
    traceEvent(TRACE_INFO, "sent REGISTERs from %d sockets to %s [%s]",
               p->count, macaddr_str(mac_buf, peer->mac_addr), sock_to_cstr(sockbuf, dest));
}


/* A round towards a peer that cannot reach us directly yet: with it behind a
 * hard NAT, guess its port; with us behind one, send a REGISTER straight to
 * its public socket, which makes the port it guesses for, and keeps it for
 * the next rounds. */
void punch_round (struct n3n_runtime_data *eee, struct peer_info *peer, time_t now) {

    struct nat_peer *np = nat_peer_find(eee->client.nat_peers, peer->mac_addr, false);
    int f = peer->sock.family;

    if(!np || !eee->conf.client.punch_ports || eee->client.tcp || !eee->conf.client.allow_p2p) {
        return;
    }

    enum nat_class theirs = nat_hint_class(np->hint);
    if(theirs == NAT_HARD) {
        punch_hard_peer(eee, peer, np, now);
    } else if((theirs != NAT_SEVERAL_ADDRESSES) && ((f == AF_INET) || (f == AF_INET6)) &&
              !is_empty_ip_address(&peer->sock) && (eee->client.nat[f == AF_INET6].nat_class == NAT_HARD) &&
              (now - np->punched >= eee->conf.client.register_interval)) {
        send_register(eee, &peer->sock, peer->mac_addr, N2N_REGULAR_REG_COOKIE);
        punch_pool_round(eee, peer, now);
        np->punched = now;
    }
}
