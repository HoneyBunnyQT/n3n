/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-25 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The client role: registering with the supernodes and with the peers
 */

#ifdef _WIN32
#include "win32/defs.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <n3n/edge.h>
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
#include "header_encryption.h"
#include "management.h"
#include "n2n_wire.h"
#include "natclass.h"
#include "pearson.h"
#include "punch.h"
#include "role_client.h"
#include "role_tap.h"
#include "resolve.h"
#include "sn_selection.h"
#include "sock.h"
#include "edge_threads.h"
#include "stats.h"
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
#define closesocket(a) close(a)
#endif

#ifndef IPV6_ADD_MEMBERSHIP
#define IPV6_ADD_MEMBERSHIP 12       // the standard value for this option
#endif


// reset number of supernode connection attempts: try only once for already more realiable tcp connections
void reset_sup_attempts (struct n3n_runtime_data *eee) {
    if(eee->client.tcp) {
        eee->client.sup_attempts = 1;
    } else {
        eee->client.sup_attempts = N2N_EDGE_SUP_ATTEMPTS;
    }
}


// What a supernode saw of the socket the edge sent to it from. Over TCP it
// sees a connection, which a NAT maps apart from the UDP socket.
static void note_nat (struct n3n_runtime_data *eee, const n3n_sock_t *sn, const n3n_sock_t *seen, time_t now) {

    char buf[40];
    n3n_sock_str_t sockbuf;

    if(eee->client.tcp || (seen->family != sn->family) ||
       ((sn->family != AF_INET) && (sn->family != AF_INET6))) {
        return;
    }
    struct nat_view *view = &eee->client.nat[sn->family == AF_INET6];
    if(nat_view_add(view, sn, seen, now)) {
        traceEvent(TRACE_NORMAL, "%s NAT: %s, as of supernode [%s]",
                   (sn->family == AF_INET6) ? "IPv6" : "IPv4",
                   nat_view_str(buf, sizeof(buf), view),
                   sock_to_cstr(sockbuf, sn));
    }
}


// The cookie of a REGISTER through the supernode, with the hint for the peer
// how the NAT maps the socket that reaches the supernode, and so the peer
static n2n_cookie_t forwarded_reg_cookie (const struct n3n_runtime_data *eee) {

    return N2N_FORWARDED_REG_COOKIE | nat_view_hint(&eee->client.nat[eee->client.curr_sn->sock.family == AF_INET6]);
}


// The transport to the supernodes.  With connection.tcp_fallback, the edge
// uses UDP until no supernode answers over it, then TCP (eee->client.tcp),
// and goes back to UDP once a PING over UDP gets its answer: while on TCP,
// transport_probe() sends one from a socket of its own now and then.  With
// connect_tcp, it stays on TCP.  Packet threads need UDP, see edge_threads.h.
static size_t encode_query_peer (struct n3n_runtime_data *eee, uint8_t *pktbuf, const n2n_mac_t dst_mac);


// Whether a supernode can be reached over that transport: one given with
// "udp://" or "tcp://" only over that one
static bool sn_has_transport (const struct peer_info *sn, bool tcp) {

    return !sn->transports || (sn->transports & (tcp ? N3N_TRANSPORT_TCP : N3N_TRANSPORT_UDP));
}


// Where a supernode is reached over TCP: its "tcp://" address, if it has
// one of its own
static const n3n_sock_t *sn_tcp_sock (const struct peer_info *sn) {

    return sn->tcp_hostname ? &sn->tcp_sock : &sn->sock;
}


bool edge_is_registered (const struct n3n_runtime_data *eee, time_t now) {

    time_t last = SHARED_LOAD(eee->client.last_sup);

    // not just !sn_wait: that is also set while the answer to the periodic
    // re-registration is on its way
    return eee->client.curr_sn && last && (now - last <= 3 * (time_t)eee->conf.client.register_interval);
}


struct peer_info *supernode_first (struct n3n_runtime_data *eee) {

    return supernode_next(eee, NULL);
}


struct peer_info *supernode_next (struct n3n_runtime_data *eee, struct peer_info *sn) {

    struct peer_info *scan = sn ? sn->hh.next : eee->client.supernodes;

    for(int round = 0; round < 2; round++) {
        for(; scan; scan = scan->hh.next) {
            if(sn_has_transport(scan, eee->client.tcp)) {
                return scan;
            }
        }
        scan = eee->client.supernodes;
    }
    // none: the first one, which at least is one
    return eee->client.supernodes;
}


// how many supernodes can be reached over that transport
static int supernode_count (struct n3n_runtime_data *eee, bool tcp) {

    struct peer_info *scan, *tmp;
    int count = 0;

    HASH_ITER(hh, eee->client.supernodes, scan, tmp) {
        count += sn_has_transport(scan, tcp);
    }
    return count;
}

static bool transport_can_fall_back (const struct n3n_runtime_data *eee) {

    return eee->conf.client.tcp_fallback && !eee->conf.client.connect_tcp
           && !eee->conf.client.local_link && !eee->threads;
}


void transport_probe_close (struct n3n_runtime_data *eee) {

    if(eee->client.probe_sock >= 0) {
        mainloop_unregister_fd(eee->client.probe_sock);
        closesocket(eee->client.probe_sock);
        eee->client.probe_sock = -1;
    }
    eee->client.probe_ok = false;
}


// Close what reaches the supernode now, and open the other transport
static void transport_switch (struct n3n_runtime_data *eee, bool tcp, time_t now) {

    traceEvent(TRACE_NORMAL, tcp ? "no supernode answers over UDP, trying TCP"
                                 : "UDP gets through again, leaving TCP");
    supernode_disconnect(eee);
    transport_probe_close(eee);
    eee->client.tcp = tcp;
    eee->client.giveups = 0;
    eee->client.last_probe = now;
    if(!eee->client.curr_sn || !sn_has_transport(eee->client.curr_sn, tcp)) {
        eee->client.curr_sn = supernode_first(eee);
    }
    reset_sup_attempts(eee);
    supernode_connect(eee);
}


// A supernode did not answer, and the edge moves on to the next one.  After
// a round over all of them (twice with one) without an answer, it tries the
// other transport.  true if it did.
bool transport_note_giveup (struct n3n_runtime_data *eee, time_t now) {

    int round = supernode_count(eee, eee->client.tcp);

    if(eee->client.giveups < UINT8_MAX) {
        eee->client.giveups++;
    }
    if(!transport_can_fall_back(eee) || (eee->client.giveups < ((round < 2) ? 2 : round))
       || !supernode_count(eee, !eee->client.tcp)) {
        return false;
    }
    transport_switch(eee, !eee->client.tcp, now);
    return true;
}


// Over TCP by fallback: a PING to the current supernode over UDP, from a
// fresh socket, every three register intervals.  Its answer sets probe_ok,
// see edge_rx_peer_info().
static void transport_probe (struct n3n_runtime_data *eee, time_t now) {

    struct sockaddr_storage local = {0};
    struct sockaddr_storage dest;
    socklen_t dest_len;
    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t len;

    struct peer_info *sn = eee->client.curr_sn;

    if(!eee->client.tcp || !transport_can_fall_back(eee) || !sn
       || (now < eee->client.last_probe + 3 * (time_t)eee->conf.client.register_interval)) {
        return;
    }
    eee->client.last_probe = now;

    // the current one, if it can be reached over UDP, else the first that can
    if(!sn_has_transport(sn, false)) {
        struct peer_info *scan, *tmp;
        sn = NULL;
        HASH_ITER(hh, eee->client.supernodes, scan, tmp) {
            if(sn_has_transport(scan, false)) {
                sn = scan;
                break;
            }
        }
        if(!sn) {
            return;
        }
    }
    dest_len = fill_sockaddr((struct sockaddr *)&dest, sizeof(dest), &sn->sock);
    if(dest_len == 0) {
        return;
    }
    transport_probe_close(eee);
    local.ss_family = dest.ss_family;
    eee->client.probe_sock = open_socket((struct sockaddr *)&local,
                                         (local.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                                         0 /* UDP */);
    if(eee->client.probe_sock < 0) {
        return;
    }
    mainloop_register_fd(eee->client.probe_sock, fd_info_proto_v3udp);

    len = encode_query_peer(eee, pktbuf, null_mac);
    traceEvent(TRACE_DEBUG, "probing UDP to the supernode");
    eee->client.ping_sent_us = n3n_monotonic_us();
    sendto_logged(eee->client.probe_sock, pktbuf, len, (struct sockaddr *)&dest, dest_len);
}


// open socket, close it before if TCP
// in case of TCP, 'connect()' is required
void supernode_connect (struct n3n_runtime_data *eee) {

    struct sockaddr_storage sn_sock_storage;
    socklen_t sn_sock_len;
    n3n_sock_t local_sock;
    n3n_sock_str_t sockbuf;

    if(eee->conf.client.local_link) {
        // no sockets: the supernode is in this process, see local_link.h
        return;
    }

    if(eee->client.tcp) {
        // It might be already closed, but we can simply ignore errors and
        // carry on
        close_sockets(eee);
    }

    if(eee->sock >= 0) {
        return;
    }

    if(!eee->client.tcp) {
        if(open_udp_sockets(eee) != 0) {
            traceEvent(TRACE_ERROR, "failed to bind main UDP port");
            return;
        }
        // packet threads, if any, need a share of the new sockets' ports
        edge_threads_socket_changed(eee);
    } else {
        // One TCP socket, of the supernode's family - bound to the first
        // address of connection.bind of that family, or with IPv4 to the
        // port of a [::], which stands for IPv4 too
        sn_sock_len = fill_sockaddr((struct sockaddr*)&sn_sock_storage, sizeof(sn_sock_storage), sn_tcp_sock(eee->client.curr_sn));
        if(sn_sock_len == 0) {
            traceEvent(
                TRACE_WARNING,
                "failed to prepare sockaddr for family %d",
                sn_tcp_sock(eee->client.curr_sn)->family
            );
            return;
        }

        struct sockaddr_storage local = {0};
        local.ss_family = sn_sock_storage.ss_family;
        const struct n3n_bind *list = eee->conf.bind_address;
        for(int i = 0; list && (i < N3N_BIND_MAX) && list[i].sa.ss_family; i++) {
            const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6 *)&list[i].sa;

            if(!(list[i].transports & N3N_TRANSPORT_TCP)) {
                continue;
            }
            if(list[i].sa.ss_family == local.ss_family) {
                memcpy(&local, &list[i].sa, sizeof(local));
                break;
            }
            if((local.ss_family == AF_INET) && (sa6->sin6_family == AF_INET6)
               && IN6_IS_ADDR_UNSPECIFIED(&sa6->sin6_addr)) {
                ((struct sockaddr_in *)&local)->sin_port = sa6->sin6_port;
                break;
            }
        }
        eee->sock = open_socket((struct sockaddr *)&local,
                                (local.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                                1 /* TCP */);
        if(eee->sock < 0) {
            traceEvent(TRACE_ERROR, "failed to open the TCP socket");
            return;
        }
        mainloop_register_fd(eee->sock, fd_info_proto_v3tcp);

        // REVISIT: TODO:
        // - add a management event for "new supernode socket" to make it simpler
        //   to track subscriptions externally

        // set tcp socket to O_NONBLOCK so connect does not hang
        // requires checking the socket for readiness before sending and receving
#ifdef _WIN32
        u_long value = 1;
        ioctlsocket(eee->sock, FIONBIO, &value);
#else
        fcntl(eee->sock, F_SETFL, O_NONBLOCK);
#endif

        char buf[50];
        sockaddr_to_str(buf, sizeof(buf), (const struct sockaddr *)&sn_sock_storage);
        traceEvent(
            TRACE_DEBUG,
            "tcp_connect family=%d, sockaddr %s",
            sn_sock_storage.ss_family,
            buf
        );

        int result = connect(
            eee->sock,
            (struct sockaddr*)&(sn_sock_storage),
            sn_sock_len
        );

#ifndef _WIN32
        if((result == -1) && (errno != EINPROGRESS)) {
            traceEvent(TRACE_INFO, "Error connecting TCP: %i", errno);
            close_sockets(eee);
            return;
        }
#else
        // Oh Windows, this just seems needlessly incompatible
        int wsaerr = WSAGetLastError();

        if((result == -1) && (wsaerr != WSAEWOULDBLOCK)) {
            traceEvent(
                TRACE_INFO,
                "Error connecting TCP: WSAGetLastError %i",
                wsaerr
            );
            close_sockets(eee);
            return;
        }
#endif
        set_sock_options(eee, eee->sock, local.ss_family, false);
    }

    // What to tell the supernode about our local socket, from advertise_addr:
    // - auto: nothing, local peers find each other by multicast
    // - an address: that address, with the port of our socket
    // - detect: the address we send from towards the supernode, and our port
    eee->client.advertised_sock.family = AF_INVALID;

    if(eee->conf.client.preferred_sock.family == AF_INVALID) {
        return;
    }
    if(detect_local_ip_address(&local_sock, eee) != 0) {
        return;
    }

    if(is_empty_ip_address(&eee->conf.client.preferred_sock)) {
        eee->client.advertised_sock = local_sock;
    } else {
        eee->client.advertised_sock = eee->conf.client.preferred_sock;
        eee->client.advertised_sock.port = local_sock.port;
    }
    traceEvent(TRACE_INFO, "advertising local socket [%s]",
               sock_to_cstr(sockbuf, &eee->client.advertised_sock));
}


// always closes the socket
void supernode_disconnect (struct n3n_runtime_data *eee) {

    if(!eee || eee->conf.client.local_link) {
        return;
    }
    close_sockets(eee);
    traceEvent(TRACE_DEBUG, "closed");
}


static uint32_t localhost_v4 = 0x7f000001;


static uint8_t localhost_v6[IPV6_SIZE] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};


// An IPv6 link-local address is only good together with the interface it is
// on, and n3n_sock_t has no room for that: sent to without it, the system may
// pick any interface - n3n's own tap device included. Such an address comes
// only from local discovery on a host with no other IPv6 address, as the
// system prefers any other as the source; that host has IPv4 or the
// supernode to reach its peers.
bool is_link_local (const n3n_sock_t *sock) {

    return (sock->family == AF_INET6) && (sock->addr.v6[0] == 0xfe) && ((sock->addr.v6[1] & 0xc0) == 0x80);
}


/* How good a way to a peer its address is, the higher the better: its
 * LAN (a private IPv4 or a unique local IPv6 address), then public IPv6,
 * which needs no NAT, then public IPv4.  A peer heard from at a better one
 * moves there at once, see check_known_peer_sock_change(). */
int peer_way_rank (const n3n_sock_t *sock) {

    if(sock->family == AF_INET) {
        const uint8_t *a = sock->addr.v4;
        if((a[0] == 10)
           || ((a[0] == 172) && ((a[1] & 0xf0) == 16))
           || ((a[0] == 192) && (a[1] == 168))) {
            return 3;
        }
        return 1;
    }
    if(sock->family == AF_INET6) {
        if((sock->addr.v6[0] & 0xfe) == 0xfc) {
            return 3;
        }
        return 2;
    }
    return 0;
}


/* Exclude localhost as it may be received when an edge node runs
 * in the same supernode host.
 */
int is_valid_peer_sock (const n3n_sock_t *sock) {

    switch(sock->family) {
        case AF_INET: {
            uint32_t *a = (uint32_t*)sock->addr.v4;

            if(*a != htonl(localhost_v4))
                return(1);
        }
        break;

        case AF_INET6:
            if(memcmp(sock->addr.v6, localhost_v6, IPV6_SIZE))
                return(1);
            break;
    }

    return(0);
}


/***
 *
 * Register over multicast in case there is a peer on the same network listening
 */
static void register_with_local_peers (struct n3n_runtime_data * eee) {
#ifndef SKIP_MULTICAST_PEERS_DISCOVERY
    if(eee->conf.client.allow_p2p && eee->conf.client.local_discovery) {
        if(eee->client.multicast_joined_v4 && (eee->conf.client.preferred_sock.family == (uint8_t)AF_INVALID)) {
            /* send registration to the local multicast group */
            traceEvent(TRACE_DEBUG, "registering with IPv4 multicast group %s:%u",
                       N2N_MULTICAST_GROUP, N2N_MULTICAST_PORT);
            send_register(eee, &(eee->client.multicast_peer_v4), NULL, N2N_MCAST_REG_COOKIE);
        }
        if(eee->client.multicast_joined_v6) {
            traceEvent(TRACE_DEBUG, "registering with IPv6 multicast group %s:%u",
                       N3N_MULTICAST_GROUP_V6, N2N_MULTICAST_PORT);
            send_register(eee, &(eee->client.multicast_peer_v6), NULL, N2N_MCAST_REG_COOKIE);
        }
    }
#else
    traceEvent(TRACE_DEBUG, "multicast peers discovery is disabled, skipping");
#endif
}


/** Start the registration process.
 *
 *    If the peer is already in pending_peers, ignore the request.
 *    If not in pending_peers, add it and send a REGISTER.
 *
 *    If hdr is for a direct peer-to-peer packet, try to register back to sender
 *    even if the MAC is in pending_peers. This is because an incident direct
 *    packet indicates that peer-to-peer exchange should work so more aggressive
 *    registration can be permitted (once per incoming packet) as this should only
 *    last for a small number of packets..
 *
 *    Called from the main loop when Rx a packet for our device mac.
 */
static void register_with_new_peer (struct n3n_runtime_data *eee,
                                    uint8_t from_supernode,
                                    uint8_t via_multicast,
                                    const n2n_mac_t mac,
                                    const n2n_ip_subnet_t *dev_addr,
                                    const n2n_desc_t *dev_desc,
                                    const n3n_sock_t *peer) {

    /* REVISIT: purge of pending_peers not yet done. */
    struct peer_info *scan;
    macstr_t mac_buf;
    n3n_sock_str_t sockbuf;

    HASH_FIND_PEER(eee->client.pending_peers, mac, scan);

    /* NOTE: pending_peers are purged periodically with purge_expired_nodes */
    if(scan == NULL) {
        scan = peer_info_malloc(mac);

        scan->sock = *peer;
        scan->timeout = eee->conf.client.register_interval; /* TODO: should correspond to the peer supernode registration timeout */
        if(via_multicast)
            scan->local = 1;

        HASH_ADD_PEER(eee->client.pending_peers, scan);

        traceEvent(TRACE_DEBUG, "new pending peer %s [%s]",
                   macaddr_str(mac_buf, scan->mac_addr),
                   sock_to_cstr(sockbuf, &(scan->sock)));

        traceEvent(TRACE_DEBUG, "pending peers list size=%u",
                   HASH_COUNT(eee->client.pending_peers));
        /* trace Sending REGISTER */
        if(from_supernode) {
            /* UDP NAT hole punching through supernode. Send to peer first(punch local UDP hole)
             * and then ask supernode to forward. Supernode then ask peer to ack. Some nat device
             * drop and block ports with incoming UDP packet if out-come traffic does not exist.
             * So we can alternatively set TTL so that the packet sent to peer never really reaches
             * The register_ttl is basically nat level + 1. Set it to 1 means host like DMZ.
             */
            if(eee->conf.client.register_ttl == 1) {
                /* We are DMZ host or port is directly accessible. Just let peer to send back the ack */
#ifndef _WIN32
            } else if(eee->conf.client.register_ttl > 1) {
                /* Setting register_ttl usually implies that the edge knows the internal net topology
                 * clearly, we can apply aggressive port prediction to support incoming Symmetric NAT
                 */
                int curTTL = 0;
                socklen_t lenTTL = sizeof(int);
                n3n_sock_t sock = scan->sock;
                int alter = 16; /* TODO: set by command line or more reliable prediction method */
                // the socket these REGISTERs leave from, and its hop limit
                int i = bind_entry_for_family(eee, sock.family);
                SOCKET ttl_sock = (i >= 0) ? eee->bind_sock[i] : eee->sock;
                int level = IPPROTO_IP, name = IP_TTL;
#ifdef IPV6_UNICAST_HOPS
                if((i >= 0) && (eee->bind_family[i] == AF_INET6)) {
                    level = IPPROTO_IPV6;
                    name = IPV6_UNICAST_HOPS;
                }
#endif

                getsockopt(ttl_sock, level, name, (void *) (char *) &curTTL, &lenTTL);
                setsockopt(ttl_sock, level, name,
                           (void *) (char *) &eee->conf.client.register_ttl,
                           sizeof(eee->conf.client.register_ttl));
                for(; alter > 0; alter--, sock.port++) {
                    send_register(eee, &sock, mac, N2N_PORT_REG_COOKIE);
                }
                setsockopt(ttl_sock, level, name, (void *) (char *) &curTTL, sizeof(curTTL));
#endif
            } else { /* eee->conf.client.register_ttl == 0 */
                /* Normal STUN */
                send_register(eee, &(scan->sock), mac, N2N_REGULAR_REG_COOKIE);
            }
            send_register(eee, &(eee->client.curr_sn->sock), mac, forwarded_reg_cookie(eee));
        } else {
            /* P2P register, send directly */
            send_register(eee, &(scan->sock), mac, N2N_REGULAR_REG_COOKIE);
        }
        register_with_local_peers(eee);
    } else{
        scan->sock = *peer;
    }
    scan->last_seen = time(NULL);
    if(dev_addr != NULL) {
        memcpy(&(scan->dev_addr), dev_addr, sizeof(n2n_ip_subnet_t));
    }
    if(dev_desc) memcpy(scan->dev_desc, dev_desc, N2N_DESC_SIZE);
}


/** Update the last_seen time for this peer, or get registered. */
void check_peer_registration_needed (struct n3n_runtime_data *eee,
                                     uint8_t from_supernode,
                                     uint8_t via_multicast,
                                     const n2n_mac_t mac,
                                     const n2n_cookie_t cookie,
                                     const n2n_ip_subnet_t *dev_addr,
                                     const n2n_desc_t *dev_desc,
                                     const n3n_sock_t *peer) {

    struct peer_info *scan;

    HASH_FIND_PEER(eee->client.known_peers, mac, scan);

    /* If we were not able to find it by MAC, we try to find it by socket. */
    if(scan == NULL ) {
        scan = find_peer_by_sock(peer, eee->client.known_peers);

        // MAC change
        if(scan) {
            HASH_DEL(eee->client.known_peers, scan);
            memcpy(scan->mac_addr, mac, sizeof(n2n_mac_t));
            HASH_ADD_PEER(eee->client.known_peers, scan);
            // reset last_local_reg to allow re-registration
            scan->last_cookie = N2N_NO_REG_COOKIE;
        }
    }

    if(scan == NULL) {
        /* Not in known_peers - start the REGISTER process. */
        register_with_new_peer(eee, from_supernode, via_multicast, mac, dev_addr, dev_desc, peer);
    } else {
        /* Already in known_peers. */
        time_t now = time(NULL);

        if(!from_supernode)
            scan->last_p2p = now;

        if(via_multicast)
            scan->local = 1;

        if(((now - scan->last_seen) > 0 /* >= 1 sec */)
           ||(cookie > scan->last_cookie)) {
            /* Don't register too often */
            check_known_peer_sock_change(eee, from_supernode, via_multicast, mac, dev_addr, dev_desc, peer, now);
        }
    }
}


/* Confirm that a pending peer is reachable directly via P2P.
 *
 * peer must be a pointer to an element of the pending_peers list.
 */
static void peer_set_p2p_confirmed (struct n3n_runtime_data * eee,
                                    const n2n_mac_t mac,
                                    const n2n_cookie_t cookie,
                                    const n3n_sock_t * peer,
                                    time_t now) {

    struct peer_info *scan, *scan_tmp;
    macstr_t mac_buf;
    n3n_sock_str_t sockbuf;

    HASH_FIND_PEER(eee->client.pending_peers, mac, scan);
    if(scan == NULL) {
        scan = find_peer_by_sock(peer, eee->client.pending_peers);
        // in case of MAC change, reset last_local_reg to allow re-registration
        if(scan)
            scan->last_cookie = N2N_NO_REG_COOKIE;
    }

    if(scan) {
        HASH_DEL(eee->client.pending_peers, scan);

        scan_tmp = find_peer_by_sock(peer, eee->client.known_peers);
        if(scan_tmp != NULL) {
            HASH_DEL(eee->client.known_peers, scan_tmp);
            free(scan);
            scan = scan_tmp;
            memcpy(scan->mac_addr, mac, sizeof(n2n_mac_t));
            // in case of MAC change, reset cookie to allow immediate re-registration
            scan->last_cookie = N2N_NO_REG_COOKIE;
        } else {
            // update sock but ...
            // ... ignore ACKs's (and their socks) from lower ranked inbound
            // ways for a while: ranked by the address first (LAN, IPv6,
            // IPv4), then by the cookie (how the REGISTER found the peer)
            int rank_new = peer_way_rank(peer);
            int rank_cur = peer_way_rank(&scan->sock);
            if(((now - scan->last_seen) > REGISTRATION_TIMEOUT / 4)
               || (rank_new > rank_cur)
               || ((rank_new == rank_cur) && (cookie > scan->last_cookie))) {
                scan->sock = *peer;
                scan->last_cookie = cookie;
            }
        }

        HASH_ADD_PEER(eee->client.known_peers, scan);
        scan->last_p2p = now;
        mgmt_event_post(N3N_EVENT_PEER,N3N_EVENT_PEER_P2P_ADD,scan);

        traceEvent(TRACE_DEBUG, "p2p connection established: %s [%s]",
                   macaddr_str(mac_buf, mac),
                   sock_to_cstr(sockbuf, peer));

        traceEvent(TRACE_DEBUG, "new peer %s [%s]",
                   macaddr_str(mac_buf, scan->mac_addr),
                   sock_to_cstr(sockbuf, &(scan->sock)));

        traceEvent(TRACE_DEBUG, "pending peers list size=%u",
                   HASH_COUNT(eee->client.pending_peers));

        traceEvent(TRACE_DEBUG, "known peers list size=%u",
                   HASH_COUNT(eee->client.known_peers));

        scan->last_seen = now;
    } else
        traceEvent(TRACE_DEBUG, "failed to find sender in pending_peers");
}


// provides the current / a new local auth token
static int get_local_auth (struct n3n_runtime_data *eee, n2n_auth_t *auth) {

    switch(eee->conf.client.auth.scheme) {
        case n2n_auth_simple_id:
            memcpy(auth, &(eee->conf.client.auth), sizeof(n2n_auth_t));
            break;
        case n2n_auth_user_password:
            // start from the locally stored complete auth token (including type and size fields)
            memcpy(auth, &(eee->conf.client.auth), sizeof(n2n_auth_t));

            // the token data consists of
            //    32 bytes public key
            //    16 bytes random challenge

            // generate a new random auth challenge every time
            memrnd(auth->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, N2N_AUTH_CHALLENGE_SIZE);
            // store it in local auth token (for comparison later)
            memcpy(eee->conf.client.auth.token + N2N_PRIVATE_PUBLIC_KEY_SIZE, auth->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, N2N_AUTH_CHALLENGE_SIZE);
            // encrypt the challenge for transmission
            speck_128_encrypt(auth->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, (speck_context_t*)eee->conf.shared_secret_ctx);
            break;
        default:
            break;
    }

    return 0;
}


// handles a returning (remote) auth token, takes action as required by auth scheme
static int handle_remote_auth (struct n3n_runtime_data *eee, struct peer_info *peer, const n2n_auth_t *remote_auth) {

    uint8_t tmp_token[N2N_AUTH_MAX_TOKEN_SIZE];

    switch(eee->conf.client.auth.scheme) {
        case n2n_auth_simple_id:
            // no action required
            break;
        case n2n_auth_user_password:
            memcpy(tmp_token, remote_auth->token, N2N_AUTH_PW_TOKEN_SIZE);

            // the returning token data consists of
            //    16 bytes double-encrypted challenge
            //    16 bytes public key (second half)
            //    16 bytes encrypted (original random challenge XOR shared secret XOR dynamic key)

            // decrypt double-encrypted received challenge (first half of public key field)
            speck_128_decrypt(tmp_token, (speck_context_t*)eee->conf.shared_secret_ctx);
            speck_128_decrypt(tmp_token, (speck_context_t*)eee->conf.shared_secret_ctx);

            // compare to original challenge
            if(0 != memcmp(tmp_token, eee->conf.client.auth.token + N2N_PRIVATE_PUBLIC_KEY_SIZE, N2N_AUTH_CHALLENGE_SIZE))
                return -1;

            // decrypt the received challenge in which the dynamic key is wrapped
            speck_128_decrypt(tmp_token + N2N_PRIVATE_PUBLIC_KEY_SIZE, (speck_context_t*)eee->conf.shared_secret_ctx);
            // un-XOR the original challenge
            memxor(tmp_token + N2N_PRIVATE_PUBLIC_KEY_SIZE, eee->conf.client.auth.token + N2N_PRIVATE_PUBLIC_KEY_SIZE, N2N_AUTH_CHALLENGE_SIZE);
            // un-XOR the shared secret
            memxor(tmp_token + N2N_PRIVATE_PUBLIC_KEY_SIZE, *(eee->conf.shared_secret), N2N_AUTH_CHALLENGE_SIZE);
            // setup for use as dynamic key
            packet_header_change_dynamic_key(tmp_token + N2N_PRIVATE_PUBLIC_KEY_SIZE,
                                             &(eee->conf.header_encryption_ctx_dynamic),
                                             &(eee->conf.header_iv_ctx_dynamic));
            break;
        default:
            break;
    }

    return 0;
}


int is_empty_ip_address (const n3n_sock_t * sock) {

    const uint8_t * ptr = NULL;
    size_t len = 0;
    size_t i;

    if(AF_INET6 == sock->family) {
        ptr = sock->addr.v6;
        len = 16;
    } else {
        ptr = sock->addr.v4;
        len = 4;
    }

    for(i = 0; i < len; ++i) {
        if(0 != ptr[i]) {
            /* found a non-zero byte in address */
            return 0;
        }
    }

    return 1;
}


/** Check if a known peer socket has changed and possibly register again.
 */
void check_known_peer_sock_change (struct n3n_runtime_data *eee,
                                   uint8_t from_supernode,
                                   uint8_t via_multicast,
                                   const n2n_mac_t mac,
                                   const n2n_ip_subnet_t *dev_addr,
                                   const n2n_desc_t *dev_desc,
                                   const n3n_sock_t *peer,
                                   time_t when) {

    struct peer_info *scan;
    n3n_sock_str_t sockbuf1;
    n3n_sock_str_t sockbuf2; /* don't clobber sockbuf1 if writing two addresses to trace */
    macstr_t mac_buf;

    if(is_empty_ip_address(peer))
        return;

    if(is_multi_broadcast(mac))
        return;

    /* Search the peer in known_peers */
    HASH_FIND_PEER(eee->client.known_peers, mac, scan);

    if(!scan)
        /* Not in known_peers */
        return;

    if(!sock_equal(&(scan->sock), peer)) {
        if(!from_supernode
           && ((when - scan->last_seen) < REGISTRATION_TIMEOUT / 4)
           && (peer_way_rank(peer) <= peer_way_rank(&scan->sock))) {
            /* The peer still answers at its address: a packet from another
             * one of its addresses that is no better a way - see
             * peer_way_rank() - is taken, but does not move the peer, else
             * it moves back and forth with whichever comes first.  A better
             * one (its LAN, IPv6 rather than IPv4) moves it at once.  When
             * the address goes quiet, as when the peer roams or its NAT
             * rebinds, the next packet from any other one moves it, as do
             * the ACKs in peer_set_p2p_confirmed(). */
        } else if(!from_supernode) {
            /* This is a P2P packet */
            traceEvent(TRACE_NORMAL, "peer %s changed [%s] -> [%s]",
                       macaddr_str(mac_buf, scan->mac_addr),
                       sock_to_cstr(sockbuf1, &(scan->sock)),
                       sock_to_cstr(sockbuf2, peer));
            /* The peer has changed public socket. It can no longer be assumed to be reachable. */
            HASH_DEL(eee->client.known_peers, scan);
            mgmt_event_post(N3N_EVENT_PEER,N3N_EVENT_PEER_P2P_CHANGED,scan);
            peer_info_free(scan);

            register_with_new_peer(eee, from_supernode, via_multicast, mac, dev_addr, dev_desc, peer);
        } else {
            /* Don't worry about what the supernode reports, it could be seeing a different socket. */
        }
    } else
        scan->last_seen = when;
}


/* Bind eee->udp_multicast_sock to multicast group */
static void check_join_multicast_group (struct n3n_runtime_data *eee) {

#ifndef SKIP_MULTICAST_PEERS_DISCOVERY
    if((eee->conf.client.allow_p2p) && (eee->conf.client.local_discovery)
       && (eee->conf.client.preferred_sock.family == (uint8_t)AF_INVALID)) {
        if(!eee->client.multicast_joined_v4) {
            struct ip_mreq mreq;
            mreq.imr_multiaddr.s_addr = inet_addr(N2N_MULTICAST_GROUP);
#ifdef _WIN32
            uint32_t raw_addr = *(uint32_t *)&eee->client.curr_sn->sock.addr.v4;
            dec_ip_str_t ip_addr;
            get_best_interface_ip(raw_addr, &ip_addr);
            mreq.imr_interface.s_addr = inet_addr(ip_addr);
#else
            mreq.imr_interface.s_addr = htonl(INADDR_ANY);
#endif
            if(setsockopt(eee->client.udp_multicast_sock_v4, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) < 0) {
                traceEvent(TRACE_WARNING, "failed to bind to local multicast group %s:%u [errno %u]",
                           N2N_MULTICAST_GROUP, N2N_MULTICAST_PORT, errno);
#ifdef _WIN32
                traceEvent(TRACE_WARNING, "WSAGetLastError(): %u", WSAGetLastError());
#endif
            } else {
                traceEvent(TRACE_NORMAL, "successfully joined multicast group %s:%u",
                           N2N_MULTICAST_GROUP, N2N_MULTICAST_PORT);
                eee->client.multicast_joined_v4 = true;
            }
        }

        // IPv6
        if(eee->client.udp_multicast_sock_v6 >= 0 && !eee->client.multicast_joined_v6) {
            struct ipv6_mreq mreq6;
            inet_pton(AF_INET6, N3N_MULTICAST_GROUP_V6, &mreq6.ipv6mr_multiaddr);
            mreq6.ipv6mr_interface = 0; /* 'best' interface */
            if(setsockopt(eee->client.udp_multicast_sock_v6, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&mreq6, sizeof(mreq6)) < 0) {
                traceEvent(TRACE_WARNING, "failed to join IPv6 multicast group %s [errno %u]",
                           N3N_MULTICAST_GROUP_V6, errno);
#ifdef _WIN32
                traceEvent(TRACE_WARNING, "WSAGetLastError(): %u", WSAGetLastError());
#endif
            } else {
                traceEvent(TRACE_NORMAL, "successfully joined IPv6 multicast group %s",
                           N3N_MULTICAST_GROUP_V6);
                eee->client.multicast_joined_v6 = true;
            }
        }
    }
#endif
}


/** Send a QUERY_PEER packet to the current supernode. */
// A QUERY_PEER for dst_mac, or with the null MAC a PING, into pktbuf
static size_t encode_query_peer (struct n3n_runtime_data *eee, uint8_t *pktbuf, const n2n_mac_t dst_mac) {

    size_t idx = 0;
    n2n_common_t cmn = {0};
    n2n_QUERY_PEER_t query = {0};

    cmn.ttl = N2N_DEFAULT_TTL;
    cmn.pc = MSG_TYPE_QUERY_PEER;
    cmn.flags = 0;
    memcpy(cmn.community, eee->conf.community.community_name, N2N_COMMUNITY_SIZE);

    memcpy(query.srcMac, eee->tap.device.mac_addr, sizeof(n2n_mac_t));
    memcpy(query.targetMac, dst_mac, sizeof(n2n_mac_t));

    encode_QUERY_PEER(pktbuf, &idx, &cmn, &query);

    if(eee->conf.community.header_encryption == HEADER_ENCRYPTION_ENABLED) {
        packet_header_encrypt(pktbuf, idx, idx,
                              eee->conf.header_encryption_ctx_dynamic, eee->conf.header_iv_ctx_dynamic,
                              time_stamp());
    }
    return idx;
}


void send_query_peer (struct n3n_runtime_data * eee,
                      const n2n_mac_t dst_mac) {

    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx;
    struct peer_info *peer, *tmp;
    int n_o_pings = 0;
    int n_o_top_sn = 0;
    int n_o_rest_sn = 0;
    int n_o_skip_sn = 0;

    idx = encode_query_peer(eee, pktbuf, dst_mac);

    if(!is_null_mac(dst_mac)) {

        traceEvent(TRACE_DEBUG, "send QUERY_PEER to supernode");

        edge_sendto_sock(eee, pktbuf, idx, &(eee->client.curr_sn->sock));

    } else {
        traceEvent(TRACE_DEBUG, "send PING to supernodes");
        eee->client.ping_sent_us = n3n_monotonic_us();

        n_o_pings = eee->conf.client.number_max_sn_pings;
        eee->conf.client.number_max_sn_pings = NUMBER_SN_PINGS_REGULAR;

        // ping the 'floor(n/2)' top supernodes and 'ceiling(n/2)' of the remaining
        n_o_top_sn  = n_o_pings >> 1;
        n_o_rest_sn = (n_o_pings + 1) >> 1;

        // skip a random number of supernodes between top and remaining
        n_o_skip_sn = HASH_COUNT(eee->client.supernodes) - n_o_pings;
        n_o_skip_sn = (n_o_skip_sn < 0) ? 0 : n3n_rand_sqr(n_o_skip_sn);
        traceEvent(TRACE_DEBUG, "n_o_skip_sn=%i", n_o_skip_sn);
        HASH_ITER(hh, eee->client.supernodes, peer, tmp) {
            traceEvent(TRACE_DEBUG, "consider peer %p", peer);
            if(!sn_has_transport(peer, false)) {
                // given with tcp:// only
                continue;
            }
            if(n_o_top_sn) {
                n_o_top_sn--;
                // fall through (send to top supernode)
            } else if(n_o_skip_sn) {
                n_o_skip_sn--;
                // skip (do not send)
                continue;
            } else if(n_o_rest_sn) {
                n_o_rest_sn--;
                // fall through (send to remaining supernode)
            } else {
                // done with the remaining (do not send anymore)
                break;
            }
            traceEvent(TRACE_DEBUG, "send PING to this peer");
            edge_sendto_sock(eee, pktbuf, idx, &(peer->sock));
        }
    }
}


/** Send a REGISTER_SUPER packet to the current supernode. */
void send_register_super (struct n3n_runtime_data *eee) {

    uint8_t pktbuf[N2N_PKT_BUF_SIZE] = {0};
    uint8_t hash_buf[16] = {0};
    size_t idx;
    /* ssize_t sent; */
    n2n_common_t cmn;
    n2n_REGISTER_SUPER_t reg;
    n3n_sock_str_t sockbuf;

    /* reg.key_time is not set by this caller; zero it so encode_REGISTER_SUPER
     * does not emit garbage for that field */
    // TODO: refactor code to avoid needing memet
    memset(&reg, 0, sizeof(reg));

    cmn.ttl = N2N_DEFAULT_TTL;
    cmn.pc = MSG_TYPE_REGISTER_SUPER;
    if(eee->client.advertised_sock.family == (uint8_t)AF_INVALID) {
        cmn.flags = 0;
    } else {
        cmn.flags = N2N_FLAGS_SOCKET;
        memcpy(&(reg.sock), &(eee->client.advertised_sock), sizeof(n3n_sock_t));
    }
    memcpy(cmn.community, eee->conf.community.community_name, N2N_COMMUNITY_SIZE);

    eee->client.curr_sn->last_cookie = n3n_rand();

    reg.cookie = eee->client.curr_sn->last_cookie;
    reg.dev_addr.net_addr = ntohl(eee->tap.device.ip_addr);
    reg.dev_addr.net_bitlen = eee->conf.tap.tuntap_v4.net_bitlen;
    memcpy(reg.dev_desc, eee->conf.dev_desc, N2N_DESC_SIZE);
    get_local_auth(eee, &(reg.auth));

    memcpy(reg.edgeMac, eee->tap.device.mac_addr, sizeof(n2n_mac_t));

    idx = 0;
    encode_REGISTER_SUPER(pktbuf, &idx, &cmn, &reg);

    traceEvent(TRACE_DEBUG, "send REGISTER_SUPER to [%s]",
               sock_to_cstr(sockbuf, &(eee->client.curr_sn->sock)));

    if(eee->conf.community.header_encryption == HEADER_ENCRYPTION_ENABLED) {
        packet_header_encrypt(pktbuf, idx, idx,
                              eee->conf.header_encryption_ctx_static, eee->conf.header_iv_ctx_static,
                              time_stamp());

        if(eee->conf.shared_secret) {
            pearson_hash_128(hash_buf, pktbuf, idx);
            speck_128_encrypt(hash_buf, (speck_context_t*)eee->conf.shared_secret_ctx);
            encode_buf(pktbuf, &idx, hash_buf, N2N_REG_SUP_HASH_CHECK_LEN);
        }
    }

    edge_sendto_sock(eee, pktbuf, idx, &(eee->client.curr_sn->sock));
}


void send_unregister_super (struct n3n_runtime_data *eee) {

    uint8_t pktbuf[N2N_PKT_BUF_SIZE] = {0};
    size_t idx;
    /* ssize_t sent; */
    n2n_common_t cmn;
    n2n_UNREGISTER_SUPER_t unreg;
    n3n_sock_str_t sockbuf;

    if(!eee->client.curr_sn) {
        return;
    }

    cmn.ttl = N2N_DEFAULT_TTL;
    cmn.pc = MSG_TYPE_UNREGISTER_SUPER;
    cmn.flags = 0;
    memcpy(cmn.community, eee->conf.community.community_name, N2N_COMMUNITY_SIZE);
    get_local_auth(eee, &(unreg.auth));

    memcpy(unreg.srcMac, eee->tap.device.mac_addr, sizeof(n2n_mac_t));

    idx = 0;
    encode_UNREGISTER_SUPER(pktbuf, &idx, &cmn, &unreg);

    traceEvent(TRACE_DEBUG, "send UNREGISTER_SUPER to [%s]",
               sock_to_cstr(sockbuf, &(eee->client.curr_sn->sock)));

    if(eee->conf.community.header_encryption == HEADER_ENCRYPTION_ENABLED)
        packet_header_encrypt(pktbuf, idx, idx,
                              eee->conf.header_encryption_ctx_dynamic, eee->conf.header_iv_ctx_dynamic,
                              time_stamp());

    edge_sendto_sock(eee, pktbuf, idx, &(eee->client.curr_sn->sock));

}


void sort_supernodes (struct n3n_runtime_data *eee, time_t now) {

    struct peer_info *scan, *tmp;

    if(now - eee->client.last_sweep <= SWEEP_TIME) {
        return;
    }

    // this routine gets periodically called

    if(!eee->client.sn_wait) {
        // sort supernodes in ascending order of their selection_criterion fields
        sn_selection_sort(&(eee->client.supernodes));
    }

    if(eee->client.curr_sn != supernode_first(eee)) {
        // we have not been connected to the best/top one
        send_unregister_super(eee);
        eee->client.curr_sn = supernode_first(eee);
        reset_sup_attempts(eee);
        supernode_connect(eee);

        traceEvent(
            TRACE_INFO,
            "registering with supernode [%s][number of supernodes %d][attempts left %u]",
            peer_info_get_hostname(eee->client.curr_sn),
            HASH_COUNT(eee->client.supernodes),
            (unsigned int)eee->client.sup_attempts
        );

        send_register_super(eee);
        eee->client.last_register_req = now;
        eee->client.sn_wait = 1;
    }

    HASH_ITER(hh, eee->client.supernodes, scan, tmp) {
        if(scan == eee->client.curr_sn)
            scan->selection_criterion = sn_selection_criterion_good();
        else
            scan->selection_criterion = sn_selection_criterion_default();
    }
    sn_selection_criterion_common_data_default(eee);

    // send PING to all the supernodes
    if(!eee->client.tcp)
        send_query_peer(eee, null_mac);
    eee->client.last_sweep = now;

    // no answer yet (so far, unused in regular edge code; mainly used during bootstrap loading)
    eee->client.sn_pong = 0;
}


/** Encode a REGISTER packet to another edge into pktbuf, returns its size. */
size_t encode_register_pkt (struct n3n_runtime_data * eee,
                            uint8_t *pktbuf,
                            const n2n_mac_t peer_mac,
                            const n2n_cookie_t cookie) {

    size_t idx;
    n2n_common_t cmn;
    n2n_REGISTER_t reg;

    /* reg.auth is not set by this caller; zero it so encode_REGISTER does not
     * emit garbage for that field */
    // TODO: refactor code to avoid needing memet
    memset(&reg, 0, sizeof(reg));
    cmn.ttl = N2N_DEFAULT_TTL;
    cmn.pc = MSG_TYPE_REGISTER;
    cmn.flags = 0;
    memcpy(cmn.community, eee->conf.community.community_name, N2N_COMMUNITY_SIZE);

    reg.cookie = cookie;
    memcpy(reg.srcMac, eee->tap.device.mac_addr, sizeof(n2n_mac_t));

    if(peer_mac) {
        // can be NULL for multicast registrations
        memcpy(reg.dstMac, peer_mac, sizeof(n2n_mac_t));
    }
    reg.dev_addr.net_addr = ntohl(eee->tap.device.ip_addr);
    reg.dev_addr.net_bitlen = eee->conf.tap.tuntap_v4.net_bitlen;
    memcpy(reg.dev_desc, eee->conf.dev_desc, N2N_DESC_SIZE);

    idx = 0;
    encode_REGISTER(pktbuf, &idx, &cmn, &reg);

    if(eee->conf.community.header_encryption == HEADER_ENCRYPTION_ENABLED)
        packet_header_encrypt(pktbuf, idx, idx,
                              eee->conf.header_encryption_ctx_dynamic, eee->conf.header_iv_ctx_dynamic,
                              time_stamp());
    return idx;
}


/** Send a REGISTER packet to another edge. */
void send_register (struct n3n_runtime_data * eee,
                    const n3n_sock_t * remote_peer,
                    const n2n_mac_t peer_mac,
                    const n2n_cookie_t cookie) {

    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx;
    n3n_sock_str_t sockbuf;

    if(!eee->conf.client.allow_p2p) {
        traceEvent(TRACE_DEBUG, "skipping register as P2P is disabled");
        return;
    }

    idx = encode_register_pkt(eee, pktbuf, peer_mac, cookie);

    traceEvent(TRACE_INFO, "send REGISTER to [%s]",
               sock_to_cstr(sockbuf, remote_peer));

    edge_sendto_sock(eee, pktbuf, idx, remote_peer);
}


/** Send a REGISTER_ACK packet to a peer edge. */
static void send_register_ack (struct n3n_runtime_data * eee,
                               const n3n_sock_t * remote_peer,
                               const n2n_REGISTER_t * reg) {

    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx;
    /* ssize_t sent; */
    n2n_common_t cmn;
    n2n_REGISTER_ACK_t ack;
    n3n_sock_str_t sockbuf;

    if(!eee->conf.client.allow_p2p) {
        traceEvent(TRACE_DEBUG, "skipping register ACK as P2P is disabled");
        return;
    }

    cmn.ttl = N2N_DEFAULT_TTL;
    cmn.pc = MSG_TYPE_REGISTER_ACK;
    cmn.flags = 0;
    memcpy(cmn.community, eee->conf.community.community_name, N2N_COMMUNITY_SIZE);
    ack.cookie = reg->cookie;
    memcpy(ack.srcMac, eee->tap.device.mac_addr, N2N_MAC_SIZE);
    memcpy(ack.dstMac, reg->srcMac, N2N_MAC_SIZE);

    idx = 0;
    encode_REGISTER_ACK(pktbuf, &idx, &cmn, &ack);

    traceEvent(TRACE_INFO, "send REGISTER_ACK to [%s]",
               sock_to_cstr(sockbuf, remote_peer));

    if(eee->conf.community.header_encryption == HEADER_ENCRYPTION_ENABLED)
        packet_header_encrypt(pktbuf, idx, idx,
                              eee->conf.header_encryption_ctx_dynamic, eee->conf.header_iv_ctx_dynamic,
                              time_stamp());

    edge_sendto_sock(eee, pktbuf, idx, remote_peer);
}


/** @brief Check to see if we should re-register with the supernode.
 *
 *    This is frequently called by the main loop.
 */
void update_supernode_reg (struct n3n_runtime_data * eee, time_t now) {

    struct peer_info *peer, *tmp_peer;
    int cnt = 0;
    int off = 0;

    if(eee->client.probe_ok) {
        transport_switch(eee, false, now);
        eee->client.last_register_req = 0;   // register over UDP right away
    } else {
        transport_probe(eee, now);
    }

    if((eee->client.sn_wait && (now > (eee->client.last_register_req + (eee->conf.client.register_interval / 10))))
       ||(eee->client.sn_wait == 2)) { /* immediately re-register in case of RE_REGISTER_SUPER */
        /* fall through */
        traceEvent(TRACE_DEBUG, "update_supernode_reg: doing fast retry.");
    } else if(now < (eee->client.last_register_req + eee->conf.client.register_interval))
        return; /* Too early */

    // determine time offset to apply on last_register_req for
    // all edges's next re-registration does not happen all at once
    if(eee->client.sn_wait == 2) {
        // remaining 1/4 is greater than 1/10 fast retry allowance;
        // '%' might be expensive but does not happen all too often
        off = n3n_rand() % ((eee->conf.client.register_interval * 3) / 4);
    }

    check_join_multicast_group(eee);

    if(0 == eee->client.sup_attempts) {
        /* Give up on that supernode and try the next one. */
        if(eee->client.curr_sn) {
            eee->client.curr_sn->selection_criterion = sn_selection_criterion_bad();
        }
        sn_selection_sort(&(eee->client.supernodes));
        eee->client.curr_sn = supernode_first(eee);
        traceEvent(
            TRACE_WARNING,
            "supernode not responding, now trying [%s]",
            peer_info_get_hostname(eee->client.curr_sn)
        );
        reset_sup_attempts(eee);
        // trigger out-of-schedule DNS resolution
        eee->client.resolution_request = true;

        // in some multi-NATed scenarios communication gets stuck on losing connection to supernode
        // closing and re-opening the socket allows for re-establishing communication
        // this can only be done, if working on some unprivileged port and/or having sufficent
        // privileges. as we are not able to check for sufficent privileges here, we only do it
        // If bind_address is null then we definitely dont have a local port
        // set.  Since we have converted to using a sockaddr struct for the
        // bind details, it is not simple to check the local port.
        //
        // TODO:
        // - probably should re-add checking for unprivileged port
        // - count this condition in a metric so we can see how often it is
        //   triggered
        //

        if(eee->conf.bind_address) {
            // do not explicitly disconnect every time as the condition described is rare, so ...
            // ... check that there are no external peers (indicating a working socket) ...
            HASH_ITER(hh, eee->client.known_peers, peer, tmp_peer) {
                if(!peer->local) {
                    cnt++;
                    break;
                }
            }

            if(!cnt) {
                // ... and then count the connection retries
                (eee->client.close_socket_counter)++;
                if(eee->client.close_socket_counter >= N2N_CLOSE_SOCKET_COUNTER_MAX) {
                    eee->client.close_socket_counter = 0;
                    supernode_disconnect(eee);
                }
            }

            traceEvent(TRACE_DEBUG, "detected supernode disconnect");
        }
        supernode_connect(eee);
        transport_note_giveup(eee, now);
    } else {
        --(eee->client.sup_attempts);
    }

    // the supernode of this process has no name to resolve, see local_link.h
    if(eee->client.curr_sn->tcp_hostname) {
        maybe_supernode2sock(&(eee->client.curr_sn->tcp_sock), eee->client.curr_sn->tcp_hostname);
    }
    if(eee->conf.client.local_link
       || (maybe_supernode2sock(&(eee->client.curr_sn->sock), peer_info_get_hostname(eee->client.curr_sn)) == 0)) {
        traceEvent(
            TRACE_INFO,
            "registering with supernode [%s][number of supernodes %d][attempts left %u]",
            peer_info_get_hostname(eee->client.curr_sn),
            HASH_COUNT(eee->client.supernodes),
            (unsigned int)eee->client.sup_attempts
        );

        send_register_super(eee);
    }

    register_with_local_peers(eee);

    // if supernode repeatedly not responding (already waiting), safeguard the
    // current known connections to peers by re-registering
    if(eee->client.sn_wait == 1)
        HASH_ITER(hh, eee->client.known_peers, peer, tmp_peer)
        if((now - peer->last_seen) > REGISTER_SUPER_INTERVAL_DFL)
            send_register(eee, &(peer->sock), peer->mac_addr, peer->last_cookie);

    eee->client.sn_wait = 1;

    eee->client.last_register_req = now - off;
}


int check_query_peer_info (struct n3n_runtime_data *eee, time_t now, const n2n_mac_t mac) {

    struct peer_info *scan;

    HASH_FIND_PEER(eee->client.pending_peers, mac, scan);

    if(!scan) {
        scan = peer_info_malloc(mac);

        scan->timeout = eee->conf.client.register_interval; /* TODO: should correspond to the peer supernode registration timeout */
        scan->last_seen = now; /* Don't change this it marks the pending peer for removal. */

        HASH_ADD_PEER(eee->client.pending_peers, scan);
    }

    if(now - scan->last_sent_query > eee->conf.client.register_interval) {
        send_register(eee, &(eee->client.curr_sn->sock), mac, forwarded_reg_cookie(eee));
        send_query_peer(eee, scan->mac_addr);
        scan->last_sent_query = now;
        punch_round(eee, scan, now);
        return(0);
    }

    return(1);
}


/* The part of check_query_peer_info() that nearly every frame to a peer not
 * reached directly takes: the supernode was asked about the peer only a
 * moment ago, so there is nothing to do. Returns 0 if more is needed, which
 * then is an event. */
int query_peer_fast (struct n3n_runtime_data *eee, time_t now, const n2n_mac_t mac) {

    struct peer_info *scan;

    HASH_FIND_PEER(eee->client.pending_peers, mac, scan);

    return scan && !(now - scan->last_sent_query > eee->conf.client.register_interval);
}


// Whether the supernode appends a hash to its REGISTER_SUPER_ACK and _NAK:
// with user/password authentication and header encryption
static bool supernode_appends_hash (const struct n3n_runtime_data *eee) {

    return eee->conf.shared_secret && (eee->conf.community.header_encryption == HEADER_ENCRYPTION_ENABLED);
}


/* MSG_TYPE_REGISTER */
void edge_rx_register (struct n3n_runtime_data *eee, struct pdu_ctx *c) {

    n2n_common_t cmn = c->cmn;
    uint8_t *udp_buf = c->buf;
    size_t rem = c->rem;
    size_t idx = c->idx;
    n3n_sock_t sender = c->sender;
    n3n_sock_t *orig_sender = &sender;
    uint8_t from_supernode = c->from_supernode;
    uint8_t via_multicast = c->via_multicast;
    uint64_t stamp = c->stamp;
    time_t now = c->now;
    struct peer_info *sn = c->sn;
    n3n_sock_str_t sockbuf1;
    n3n_sock_str_t sockbuf2;        /* don't clobber sockbuf1 if writing two addresses to trace */
    macstr_t mac_buf1;
    macstr_t mac_buf2;

    /* Another edge is registering with us */
    n2n_REGISTER_t reg;

    if(decode_REGISTER(&reg, &cmn, udp_buf, &rem, &idx) < 0) {
        traceEvent(TRACE_INFO, "REGISTER section in N2N_UDP too short");
        return;
    }
    if(rem != 0) {
        traceEvent(TRACE_INFO, "REGISTER section in N2N_UDP too long");
        return;
    }

    // The hint about the peer's NAT is only meant for the way through
    // the supernode: an older peer can send the bits back directly,
    // as they were in a cookie of ours. Either way they are no part of
    // the cookie's rank.
    n2n_cookie_t nat_hint = reg.cookie & N2N_REG_COOKIE_HINT_MASK;
    reg.cookie &= ~N2N_REG_COOKIE_HINT_MASK;

    if(!from_supernode && is_link_local(&sender)) {
        traceEvent(TRACE_DEBUG, "ignored REGISTER from a link-local address");
        return;
    }

    via_multicast &= is_null_mac(reg.dstMac);

    if(eee->conf.community.header_encryption == HEADER_ENCRYPTION_ENABLED) {
        if(!find_peer_time_stamp_and_verify(
               eee->client.pending_peers,
               eee->client.known_peers,
               sn,
               reg.srcMac,
               stamp,
               via_multicast ? TIME_STAMP_ALLOW_JITTER : TIME_STAMP_NO_JITTER)) {
            traceEvent(TRACE_DEBUG, "dropped REGISTER due to time stamp error");
            return;
        }
    }

    if(is_valid_peer_sock(&reg.sock))
        orig_sender = &(reg.sock);

    if(via_multicast && !memcmp(reg.srcMac, eee->tap.device.mac_addr, N2N_MAC_SIZE)) {
        traceEvent(TRACE_DEBUG, "skipping REGISTER from self");
        return;
    }

    if(!via_multicast && memcmp(reg.dstMac, eee->tap.device.mac_addr, N2N_MAC_SIZE)) {
        traceEvent(TRACE_DEBUG, "skipping REGISTER for other peer");
        return;
    }

    if(!from_supernode) {
        /* This is a P2P registration from the peer. We purge a pending
         * registration towards the possibly nat-ted peer address as we now have
         * a valid channel. We still use check_peer_registration_needed below
         * to double check this.
         */
        traceEvent(TRACE_INFO, "[p2p] Rx REGISTER from %s [%s]%s",
                   macaddr_str(mac_buf1, reg.srcMac),
                   sock_to_cstr(sockbuf1, &sender),
                   (reg.cookie & N2N_LOCAL_REG_COOKIE) ? " (local)" : "");
        find_and_remove_peer(&eee->client.pending_peers, reg.srcMac);

        /* NOTE: only ACK to peers */
        send_register_ack(eee, orig_sender, &reg);
    } else {
        traceEvent(TRACE_INFO, "[pSp] Rx REGISTER from %s [%s] to %s via [%s]",
                   macaddr_str(mac_buf1, reg.srcMac), sock_to_cstr(sockbuf2, orig_sender),
                   macaddr_str(mac_buf2, reg.dstMac), sock_to_cstr(sockbuf1, &sender));
    }

    check_peer_registration_needed(eee, from_supernode, via_multicast,
                                   reg.srcMac, reg.cookie, &reg.dev_addr, (const n2n_desc_t*)&reg.dev_desc, orig_sender);

    if(from_supernode) {
        struct nat_peer *np = nat_peer_find(eee->client.nat_peers, reg.srcMac, true);
        if(np->hint != nat_hint) {
            char hintbuf[40];
            traceEvent(TRACE_INFO, "NAT of %s at [%s]: %s",
                       macaddr_str(mac_buf1, reg.srcMac),
                       sock_to_cstr(sockbuf1, orig_sender),
                       nat_hint_str(hintbuf, sizeof(hintbuf), nat_hint));
            // another range, or no guessing at all
            np->tried = 0;
            memset(&np->found, 0, sizeof(np->found));
        }
        np->hint = nat_hint;
        np->seen = now;

        // the peer is trying to reach us, so this is a round as well
        struct peer_info *peer;
        HASH_FIND_PEER(eee->client.pending_peers, reg.srcMac, peer);
        if(peer) {
            punch_round(eee, peer, now);
        }
    }
}


/* MSG_TYPE_REGISTER_ACK */
void edge_rx_register_ack (struct n3n_runtime_data *eee, struct pdu_ctx *c) {

    n2n_common_t cmn = c->cmn;
    uint8_t *udp_buf = c->buf;
    size_t rem = c->rem;
    size_t idx = c->idx;
    n3n_sock_t sender = c->sender;
    n3n_sock_t *orig_sender = &sender;
    uint64_t stamp = c->stamp;
    time_t now = c->now;
    struct peer_info *sn = c->sn;
    n3n_sock_str_t sockbuf1;
    n3n_sock_str_t sockbuf2;        /* don't clobber sockbuf1 if writing two addresses to trace */
    macstr_t mac_buf1;
    macstr_t mac_buf2;

    /* Peer edge is acknowledging our register request */
    n2n_REGISTER_ACK_t ra;

    if(decode_REGISTER_ACK(&ra, &cmn, udp_buf, &rem, &idx) < 0) {
        traceEvent(TRACE_INFO, "REGISTER_ACK section in N2N_UDP too short");
        return;
    }
    if(rem != 0) {
        traceEvent(TRACE_INFO, "REGISTER_ACK section in N2N_UDP too long");
        return;
    }

    if(eee->conf.community.header_encryption == HEADER_ENCRYPTION_ENABLED) {
        if(!find_peer_time_stamp_and_verify(
               eee->client.pending_peers,
               eee->client.known_peers,
               sn,
               ra.srcMac,
               stamp,
               TIME_STAMP_NO_JITTER)) {
            traceEvent(TRACE_DEBUG, "dropped REGISTER_ACK due to time stamp error");
            return;
        }
    }

    if(is_link_local(&sender)) {
        traceEvent(TRACE_DEBUG, "ignored REGISTER_ACK from a link-local address");
        return;
    }

    if(is_valid_peer_sock(&ra.sock))
        orig_sender = &(ra.sock);

    traceEvent(TRACE_INFO, "Rx REGISTER_ACK from %s [%s] to %s via [%s]%s",
               macaddr_str(mac_buf1, ra.srcMac),
               sock_to_cstr(sockbuf2, orig_sender),
               macaddr_str(mac_buf2, ra.dstMac),
               sock_to_cstr(sockbuf1, &sender),
               (ra.cookie & N2N_LOCAL_REG_COOKIE) ? " (local)" : "");

    peer_set_p2p_confirmed(eee, ra.srcMac,
                           ra.cookie,
                           &sender, now);

    // behind a hard NAT, the port it answered from is worth keeping
    struct nat_peer *np = nat_peer_find(eee->client.nat_peers, ra.srcMac, false);
    if(np && (nat_hint_class(np->hint) == NAT_HARD)) {
        np->found = sender;
    }
}


/* MSG_TYPE_REGISTER_SUPER_ACK */
void edge_rx_register_super_ack (struct n3n_runtime_data *eee, struct pdu_ctx *c) {

    n2n_common_t cmn = c->cmn;
    uint8_t *udp_buf = c->buf;
    size_t udp_size = c->size;
    size_t rem = c->rem;
    size_t idx = c->idx;
    n3n_sock_t sender = c->sender;
    n3n_sock_t *orig_sender = &sender;
    uint64_t stamp = c->stamp;
    uint8_t *hash_buf = c->hash_buf;
    time_t now = c->now;
    struct peer_info *sn = c->sn;
    n3n_sock_str_t sockbuf1;
    n3n_sock_str_t sockbuf2;        /* don't clobber sockbuf1 if writing two addresses to trace */
    macstr_t mac_buf1;

    n2n_REGISTER_SUPER_ACK_t ra;
    uint8_t tmpbuf[REG_SUPER_ACK_PAYLOAD_SPACE];
    int i;
    int skip_add;

    if(!(eee->client.sn_wait)) {
        traceEvent(TRACE_DEBUG, "Rx REGISTER_SUPER_ACK with no outstanding REGISTER_SUPER");
        return;
    }

    if(decode_REGISTER_SUPER_ACK(&ra, &cmn, udp_buf, &rem, &idx, tmpbuf) < 0) {
        traceEvent(TRACE_INFO, "REGISTER_SUPER_ACK section in N2N_UDP too short");
        return;
    }
    // with user/password and header encryption, the supernode
    // appends a hash, which the decoder leaves unread
    if(rem != (supernode_appends_hash(eee) ? N2N_REG_SUP_HASH_CHECK_LEN : 0)) {
        traceEvent(TRACE_INFO, "REGISTER_SUPER_ACK section in N2N_UDP of wrong size");
        return;
    }

    if(eee->conf.community.header_encryption == HEADER_ENCRYPTION_ENABLED) {
        if(!find_peer_time_stamp_and_verify(
               eee->client.pending_peers,
               eee->client.known_peers,
               sn,
               ra.srcMac,
               stamp,
               TIME_STAMP_NO_JITTER)) {
            traceEvent(TRACE_DEBUG, "dropped REGISTER_SUPER_ACK due to time stamp error");
            return;
        }
    }

    // hash check (user/pw auth only)
    if(eee->conf.shared_secret) {
        speck_128_encrypt(hash_buf, (speck_context_t*)eee->conf.shared_secret_ctx);
        if(memcmp(hash_buf, udp_buf + udp_size - N2N_REG_SUP_HASH_CHECK_LEN /* length is has already been checked */, N2N_REG_SUP_HASH_CHECK_LEN)) {
            traceEvent(TRACE_INFO, "Rx REGISTER_SUPER_ACK with wrong hash");
            return;
        }
    }

    if(ra.cookie != eee->client.curr_sn->last_cookie) {
        traceEvent(TRACE_INFO, "Rx REGISTER_SUPER_ACK with wrong or old cookie");
        return;
    }

    if(handle_remote_auth(eee, sn, &(ra.auth))) {
        traceEvent(TRACE_INFO, "Rx REGISTER_SUPER_ACK with wrong or old response to challenge");
        if(eee->conf.shared_secret) {
            traceEvent(TRACE_NORMAL, "Rx REGISTER_SUPER_ACK with wrong or old response to challenge, maybe indicating wrong federation public key (-P)");
        }
        return;
    }

    if(is_valid_peer_sock(&ra.sock)) {
        orig_sender = &(ra.sock);
        note_nat(eee, &sender, &ra.sock, now);
    }

    traceEvent(TRACE_INFO, "Rx REGISTER_SUPER_ACK from %s [%s] (external %s) with %u attempts left",
               macaddr_str(mac_buf1, ra.srcMac),
               sock_to_cstr(sockbuf1, &sender),
               sock_to_cstr(sockbuf2, orig_sender),
               (unsigned int)eee->client.sup_attempts);

    if(is_null_mac(eee->client.curr_sn->mac_addr)) {
        HASH_DEL(eee->client.supernodes, eee->client.curr_sn);
        memcpy(&eee->client.curr_sn->mac_addr, ra.srcMac, N2N_MAC_SIZE);
        HASH_ADD_PEER(eee->client.supernodes, eee->client.curr_sn);
    }

    n2n_REGISTER_SUPER_ACK_payload_t *payload;
    payload = (n2n_REGISTER_SUPER_ACK_payload_t*)tmpbuf;

    // from here on, 'sn' gets used differently
    for(i = 0; i < ra.num_sn; i++) {
        n3n_sock_t payload_sock;

        skip_add = SN_ADD;

        // bugfix for https://github.com/ntop/n2n/issues/1029
        // REVISIT: best to be removed with 4.0
        idx = 0;
        rem = sizeof(payload->sock);
        decode_sock_payload(&payload_sock, payload->sock, &rem, &idx);

        sn = add_sn_to_list_by_mac_or_sock(&(eee->client.supernodes), &payload_sock, payload->mac, &skip_add);

        if(skip_add == SN_ADD_ADDED) {
            sn->last_seen = 0; /* as opposed to payload handling in supernode */
            sock_to_cstr(sockbuf1, &(sn->sock));
            sn->hostname = strdup(sockbuf1);
            traceEvent(
                TRACE_NORMAL,
                "supernode '%s' added to the list of supernodes.",
                sockbuf1
            );
        }
        // shift to next payload entry
        payload++;
    }

    if(eee->conf.tap.tuntap_ip_mode == TUNTAP_IP_MODE_SN_ASSIGN) {
        if((ra.dev_addr.net_addr != 0) && (ra.dev_addr.net_bitlen != 0)) {
            eee->conf.tap.tuntap_v4.net_addr = htonl(ra.dev_addr.net_addr);
            eee->conf.tap.tuntap_v4.net_bitlen = ra.dev_addr.net_bitlen;
        }
    }

    eee->client.sn_wait = 0;
    eee->client.giveups = 0;
    reset_sup_attempts(eee); /* refresh because we got a response */

    // update last_sup only on 'real' REGISTER_SUPER_ACKs, not on bootstrap ones (own MAC address
    // still null_mac) this allows reliable in/out PACKET drop if not really registered with a supernode yet
    if(!is_null_mac(eee->tap.device.mac_addr)) {
        if(!SHARED_LOAD(eee->client.last_sup)) {
            // indicates first successful connection between the edge and a supernode
            traceEvent(TRACE_NORMAL, "[OK] edge <<< ================ >>> supernode");
            // send gratuitous ARP only upon first registration with supernode
            send_grat_arps(eee);
        }
        SHARED_STORE(eee->client.last_sup, now);
    }

    // NOTE: the register_interval should be chosen by the edge node based on its NAT configuration.
    // eee->conf.client.register_interval = ra.lifetime;

}


/* MSG_TYPE_REGISTER_SUPER_NAK */
void edge_rx_register_super_nak (struct n3n_runtime_data *eee, struct pdu_ctx *c) {

    n2n_common_t cmn = c->cmn;
    uint8_t *udp_buf = c->buf;
    size_t rem = c->rem;
    size_t idx = c->idx;
    uint64_t stamp = c->stamp;
    struct peer_info *sn = c->sn;


    n2n_REGISTER_SUPER_NAK_t nak;

    if(!(eee->client.sn_wait)) {
        traceEvent(TRACE_DEBUG, "Rx REGISTER_SUPER_NAK with no outstanding REGISTER_SUPER");
        return;
    }

    if(decode_REGISTER_SUPER_NAK(&nak, &cmn, udp_buf, &rem, &idx) < 0) {
        traceEvent(TRACE_INFO, "REGISTER_SUPER_NAK section in N2N_UDP too short");
        return;
    }
    // with user/password and header encryption, the supernode
    // appends a hash, which the decoder leaves unread
    if(rem != (supernode_appends_hash(eee) ? N2N_REG_SUP_HASH_CHECK_LEN : 0)) {
        traceEvent(TRACE_INFO, "REGISTER_SUPER_NAK section in N2N_UDP of wrong size");
        return;
    }

    if(eee->conf.community.header_encryption == HEADER_ENCRYPTION_ENABLED) {
        if(!find_peer_time_stamp_and_verify(
               eee->client.pending_peers,
               eee->client.known_peers,
               sn,
               nak.srcMac,
               stamp,
               TIME_STAMP_NO_JITTER)) {
            traceEvent(TRACE_DEBUG, "dropped REGISTER_SUPER_NAK due to time stamp error");
            return;
        }
    }

    if(nak.cookie != eee->client.curr_sn->last_cookie) {
        traceEvent(TRACE_DEBUG, "Rx REGISTER_SUPER_NAK with wrong or old cookie");
        return;
    }

    // REVISIT: authenticate the NAK packet really originating from the supernode along the auth token.
    //          this must follow a different scheme because it needs to prove authenticity although the
    //          edge-provided credentials are wrong

    traceEvent(TRACE_INFO, "Rx REGISTER_SUPER_NAK");

    if((memcmp(nak.srcMac, eee->tap.device.mac_addr, sizeof(n2n_mac_t))) == 0) {
        macstr_t buf_src;
        traceEvent(
            TRACE_ERROR,
            "auth error: mac %s",
            macaddr_str(buf_src, nak.srcMac)
        );
        if(eee->conf.shared_secret) {
            traceEvent(TRACE_ERROR, "authentication error, username or password not recognized by supernode");
        } else {
            traceEvent(TRACE_ERROR, "authentication error, MAC or IP address already in use or not released yet by supernode");
        }
        // REVISIT: the following portion is too harsh, repeated error warning should be sufficient until it eventually is resolved,
        //           preventing de-auth attacks
        /* exit(1); this is too harsh, repeated error warning should be sufficient until it eventually is resolved, preventing de-auth attacks
           } else {
           HASH_FIND_PEER(eee->client.known_peers, nak.srcMac, peer);
           if(peer != NULL) {
            HASH_DEL(eee->client.known_peers, peer);
           }
           HASH_FIND_PEER(eee->client.pending_peers, nak.srcMac, scan);
           if(scan != NULL) {
            HASH_DEL(eee->client.pending_peers, scan);
           } */
    }
}


/* MSG_TYPE_PEER_INFO */
void edge_rx_peer_info (struct n3n_runtime_data *eee, struct pdu_ctx *c) {

    n2n_common_t cmn = c->cmn;
    uint8_t *udp_buf = c->buf;
    size_t rem = c->rem;
    size_t idx = c->idx;
    n3n_sock_t sender = c->sender;
    uint64_t stamp = c->stamp;
    time_t now = c->now;
    struct peer_info *sn = c->sn;
    n3n_sock_str_t sockbuf1;
    macstr_t mac_buf1;


    n2n_PEER_INFO_t pi;
    struct peer_info * scan;
    int skip_add;

    if(decode_PEER_INFO(&pi, &cmn, udp_buf, &rem, &idx) < 0) {
        traceEvent(TRACE_INFO, "PEER_INFO section in N2N_UDP too short");
        return;
    }
    if(rem != 0) {
        traceEvent(TRACE_INFO, "PEER_INFO section in N2N_UDP too long");
        return;
    }

    if(eee->conf.community.header_encryption == HEADER_ENCRYPTION_ENABLED) {
        if(!find_peer_time_stamp_and_verify(
               eee->client.pending_peers,
               eee->client.known_peers,
               sn,
               null_mac,
               stamp,
               TIME_STAMP_ALLOW_JITTER)) {
            traceEvent(TRACE_DEBUG, "dropped PEER_INFO due to time stamp error");
            return;
        }
    }

    if((cmn.flags & N2N_FLAGS_SOCKET) && !is_valid_peer_sock(&pi.sock)) {
        traceEvent(TRACE_DEBUG, "skip invalid PEER_INFO from %s [%s]",
                   macaddr_str(mac_buf1, pi.mac),
                   sock_to_cstr(sockbuf1, &pi.sock));
        return;
    }

    if(is_null_mac(pi.mac)) {
        // PONG - answer to PING (QUERY_PEER_INFO with null mac)
        skip_add = SN_ADD_SKIP;
        scan = add_sn_to_list_by_mac_or_sock(&(eee->client.supernodes), &sender, pi.srcMac, &skip_add);
        if(scan != NULL) {
            eee->client.sn_pong = 1;
            if((eee->client.probe_sock >= 0) && (c->socket_fd == eee->client.probe_sock)) {
                // UDP gets through again, see transport_probe()
                eee->client.probe_ok = true;
            }
            scan->last_seen = now;
            scan->uptime = pi.uptime;
            memcpy(scan->version, pi.version, sizeof(n2n_version_t));
            // what the page and get_supernodes show, whatever the strategy
            scan->sn_load = pi.load;
            if(eee->client.ping_sent_us) {
                uint64_t rtt = n3n_monotonic_us() - eee->client.ping_sent_us;
                scan->sn_rtt_us = (rtt > UINT32_MAX) ? UINT32_MAX : (rtt ? rtt : 1);
            }
            /* The data type depends on the actual selection strategy that has been chosen. */
            uint64_t sn_sel_tmp = pi.load;
            sn_selection_criterion_calculate(eee, scan, sn_sel_tmp);

            traceEvent(TRACE_INFO, "Rx PONG from supernode %s version '%s'",
                       macaddr_str(mac_buf1, pi.srcMac),
                       pi.version);

            // by the sender, not scan->sock: that is one entry for
            // all the addresses of a supernode
            if(is_valid_peer_sock(&pi.sock)) {
                note_nat(eee, &sender, &pi.sock, now);
            }

            return;
        }
    } else {
        // regular PEER_INFO
        bool known = false;
        HASH_FIND_PEER(eee->client.pending_peers, pi.mac, scan);
        if(!scan) {
            // just in case the remote edge has been upgraded by the REG/ACK mechanism in the meantime
            HASH_FIND_PEER(eee->client.known_peers, pi.mac, scan);
            known = (scan != NULL);
        }

        if(scan) {
            // A peer that got known meanwhile keeps the address it
            // answered from: the supernode may see it at another one,
            // as behind a hard NAT, where the one that answered was
            // guessed (see punch_hard_peer())
            if(!known) {
                scan->sock = pi.sock;
            }

            traceEvent(TRACE_INFO, "Rx PEER_INFO %s can be found at [%s]",
                       macaddr_str(mac_buf1, pi.mac),
                       sock_to_cstr(sockbuf1, &pi.sock));

            if(cmn.flags & N2N_FLAGS_SOCKET) {
                scan->preferred_sock = pi.preferred_sock;
                send_register(eee, &scan->preferred_sock, scan->mac_addr, N2N_LOCAL_REG_COOKIE);

                traceEvent(TRACE_INFO, "%s has preferred local socket at [%s]",
                           macaddr_str(mac_buf1, pi.mac),
                           sock_to_cstr(sockbuf1, &pi.preferred_sock));
            }

            send_register(eee, &pi.sock, scan->mac_addr, N2N_REGULAR_REG_COOKIE);

        } else {
            traceEvent(TRACE_INFO, "Rx PEER_INFO unknown peer %s",
                       macaddr_str(mac_buf1, pi.mac));
        }
    }
}


/* MSG_TYPE_RE_REGISTER_SUPER */
void edge_rx_re_register_super (struct n3n_runtime_data *eee, struct pdu_ctx *c) {

    size_t rem = c->rem;
    uint64_t stamp = c->stamp;
    struct peer_info *sn = c->sn;


    // the common header is all there is
    if(rem != 0) {
        traceEvent(TRACE_INFO, "RE_REGISTER_SUPER in N2N_UDP too long");
        return;
    }

    if(eee->conf.community.header_encryption == HEADER_ENCRYPTION_ENABLED) {
        if(!find_peer_time_stamp_and_verify(
               eee->client.pending_peers,
               eee->client.known_peers,
               sn,
               null_mac,
               stamp,
               TIME_STAMP_NO_JITTER)) {
            traceEvent(TRACE_DEBUG, "dropped RE_REGISTER due to time stamp error");
            return;
        }
    }

    // only accept in user/pw mode for immediate re-registration because the new
    // key is required for continous traffic flow, in other modes edge will realize
    // changes with regular recurring REGISTER_SUPER
    if(!eee->conf.shared_secret) {
        traceEvent(TRACE_DEBUG, "dropped RE_REGISTER_SUPER as not in user/pw auth mode");
        return;
    }

    traceEvent(TRACE_INFO, "Rx RE_REGISTER_SUPER");

    eee->client.sn_wait = 2; /* immediately */

}
