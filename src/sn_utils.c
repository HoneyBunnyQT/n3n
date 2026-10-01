/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-25 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */


#include <errno.h>              // for errno, EAFNOSUPPORT
#include <n3n/conffile.h>       // for n3n_config_free_communities
#include <n3n/initfuncs.h>      // for n3n_deinitfuncs
#include <n3n/edge.h>           // for edge_conf_role_defaults, edge_stop_local
#include <n3n/logging.h>        // for traceEvent
#include <n3n/mainloop.h>       // for mainloop_register_fd, mainloop_close_fd, ...
#include <n3n/random.h>         // for n3n_rand, n3n_rand_sqr, memrnd
#include <n3n/strings.h>        // for ip_subnet_to_str, sock_to_cstr
#include <n3n/supernode.h>      // for load_allowed_sn_community, calculate_...
#include <stdbool.h>
#include <stdint.h>             // for uint8_t, uint32_t, uint16_t, uint64_t
#include <stdio.h>              // for sscanf, snprintf, fclose, fgets, fopen
#include <stdlib.h>             // for free, calloc, getenv
#include <string.h>             // for memcpy, NULL, memset, size_t, strerror
#include <sys/param.h>          // for MAX
#include <time.h>               // for time_t, time
#include <unistd.h>

#include "edge_threads.h"       // for edge_threads_post_pdu, edge_threads_sock, ...
#include "management.h"         // for process_mgmt
#include "n2n_define.h"
#include "n2n_wire.h"           // for encode_buf, encode_PEER_INFO, encode_...
#include "resolve.h"            // for resolve_create_thread, resolve_cancel...
#include "role_federate.h"
#include "role_relay.h"
#include "sn_communities.h"
#include "sn_utils.h"
#include "local_link.h"         // for LOCAL_LINK_FD, local_link_to_edge
#include "sock.h"               // for bind_entry_of_sock, sendto_logged, ...
#include "stats.h"              // for STATS_INC

#ifdef _WIN32
#include "win32/defs.h"

#include <direct.h>             // for _rmdir
#else
#include <arpa/inet.h>          // for inet_addr, inet_ntoa
#include <netinet/in.h>         // for ntohl, in_addr_t, sockaddr_in, INADDR...
#include <pwd.h>
#include <sys/socket.h>         // for recvfrom, shutdown, sockaddr_storage
#endif

#ifndef _WIN32
// Another wonderful gift from the world of POSIX compliance is not worth much
#define closesocket(a) close(a)
#endif

#ifdef _WIN32
#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0
#endif
#endif


/* ************************************** */


// Forget a TCP connection whose socket is closed already, and the edge that
// was connected over it
static void forget_tcp_connection (struct n3n_runtime_data *sss, n2n_tcp_connection_t *conn) {

    struct sn_community *comm, *tmp_comm;
    struct peer_info *edge, *tmp_edge;

    // find peer by file descriptor
    HASH_ITER(hh, sss->relay.communities, comm, tmp_comm) {
        HASH_ITER(hh, comm->edges, edge, tmp_edge) {
            if(edge->socket_fd == conn->socket_fd) {
                // remove peer
                HASH_DEL(comm->edges, edge);
                peer_info_free(edge);
                goto forget_conn; /* break - level 2 */
            }
        }
    }

forget_conn:
    HASH_DEL(sss->relay.tcp_connections, conn);
    free(conn);
}


// Close a TCP connection, and forget it and the edge that was connected over it
static void close_tcp_connection (struct n3n_runtime_data *sss, n2n_tcp_connection_t *conn) {

    if(!conn)
        return;

    shutdown(conn->socket_fd, SHUT_RDWR);
    mainloop_close_fd(conn->socket_fd);
    forget_tcp_connection(sss, conn);
}


// Forget an edge. One connected over TCP loses its connection too, which
// close_tcp_connection() takes care of, the edge included; what tells TCP
// from UDP is whether its descriptor is among the TCP connections.
void remove_edge (struct n3n_runtime_data *sss, struct sn_community *comm, struct peer_info *edge) {

    n2n_tcp_connection_t *conn = NULL;

    if(edge->socket_fd >= 0) {
        HASH_FIND_INT(sss->relay.tcp_connections, &(edge->socket_fd), conn);
    }
    if(conn) {
        close_tcp_connection(sss, conn);
        return;
    }
    HASH_DEL(comm->edges, edge);
    peer_info_free(edge);
}

/* ************************************** */

/* The UDP socket the calling thread sends from: a packet thread has its own,
 * bound to the same address and port as the main one. */
static SOCKET udp_sock (struct n3n_runtime_data *sss) {

    return n3n_thread_slot ? edge_threads_sock(sss) : sss->sock;
}


// is this one of the TCP connections, rather than a UDP socket?
static bool is_tcp (struct n3n_runtime_data *sss, SOCKET socket_fd) {

    return (socket_fd >= 0) && (bind_entry_of_sock(sss, socket_fd) < 0);
}


// The family a UDP socket was opened with: an IPv6 one takes IPv4
// destinations as mapped addresses, an IPv4 one only plain ones.
static int sock_family (struct n3n_runtime_data *sss, SOCKET socket_fd) {

    int i = bind_entry_of_sock(sss, socket_fd);

    return sss->bind_family[(i < 0) ? 0 : i];
}


// For a destination that did not come in on any of our sockets: the first
// address of connection.bind that can send to its family - an IPv4 one for
// IPv4, or an IPv6 one that takes mapped IPv4 addresses.
SOCKET family_sock (struct n3n_runtime_data *sss, int family) {

    int i = bind_entry_for_family(sss, family);

    return (i >= 0) ? bind_thread_sock(sss, i) : udp_sock(sss);
}


// The socket to reach a peer on is the one it came in on: its TCP
// connection, or its address of connection.bind, as its NAT may take answers
// only from the port it sent to - from the calling thread's own socket there.
// A peer that never came in, like a supernode of the federation known from
// the configuration, is reached from the first address fit for its family.
static SOCKET peer_sock (struct n3n_runtime_data *sss, const struct peer_info *peer) {

    int i;

    if(is_tcp(sss, peer->socket_fd) || (peer->socket_fd == LOCAL_LINK_FD)) {
        return peer->socket_fd;
    }
    i = bind_entry_of_sock(sss, peer->socket_fd);
    if(i >= 0) {
        return bind_thread_sock(sss, i);
    }
    return family_sock(sss, peer->sock.family);
}


/** Send a datagram to a network order socket of type struct sockaddr, or
 *  over the TCP connection socket_fd.
 *
 *    @return -1 on error otherwise number of bytes sent
 */
ssize_t sn_sendto_sock (struct n3n_runtime_data *sss,
                        SOCKET socket_fd,
                        const struct sockaddr *socket,
                        const uint8_t *pktbuf,
                        size_t pktsize) {

    // the edge in this process
    if(socket_fd == LOCAL_LINK_FD) {
        return local_link_to_edge(pktbuf, pktsize) ? pktsize : -1;
    }

    // if the connection is tcp, i.e. not the regular sock...
    if(is_tcp(sss, socket_fd)) {
        // ...the mainloop sends it, with the length in front; it drops it if
        // the connection is still busy with the one before
        if(!mainloop_send_v3tcp(socket_fd, pktbuf, pktsize)) {
            traceEvent(TRACE_DEBUG, "dropped a PDU for busy TCP connection %d", socket_fd);
            return -1;
        }
        return pktsize;
    }

    // TODO: do we really have to check this every time?
    //       maye try a struct containing the socket and its length
    //       would require broader changes
    struct sockaddr_storage dest_addr = {0};
    socklen_t socket_len = prepare_sockaddr_for_send(&dest_addr, sock_family(sss, socket_fd), socket);
    if(socket_len == 0) {
        // unknown or unsupported family we cannot send
        traceEvent(TRACE_ERROR, "found unknown address family %d", socket->sa_family);
        return -1;
    }

    return sendto_logged(socket_fd, pktbuf, pktsize, (const struct sockaddr *)&dest_addr, socket_len);
}


/** Send a datagram to a peer whose destination socket is embodied in its sock field of type n3n_sock_t.
 *  It calls sn_sendto_sock to do the final send.
 *
 *    @return -1 on error otherwise number of bytes sent
 */
ssize_t sn_sendto_peer (struct n3n_runtime_data *sss,
                        const struct peer_info *peer,
                        const uint8_t *pktbuf,
                        size_t pktsize) {

    struct sockaddr_storage socket_storage;
    socklen_t socket_len;
    n3n_sock_str_t sockbuf;

    // TODO: we do not work on the return value, do not even pass it on
    //       and even worse, do another length check further down the chain in sn_sendto_sock/fd
    //       the n3n_sock_t definitely needs a makeover (to hold the original sockaddr
    //       for immediate use and its length in memory) or, if we want to keep n3n_sock_t
    //       for compatibility reasons as it is used in network protocol, an internal sister.
    //       can't pull the length check up here easily because of other callers of sn_sendto_sock
    socket_len = fill_sockaddr((struct sockaddr *)&socket_storage,
                               sizeof(socket_storage), &(peer->sock));

    if(socket_len == 0) {
        // fill_sockaddr failed, e.g., unsupported family
        errno = EAFNOSUPPORT;
        return -1;
    }

    traceEvent(TRACE_DEBUG, "sent %lu bytes to [%s]",
               pktsize,
               sock_to_cstr(sockbuf, &(peer->sock)));

    return sn_sendto_sock(sss, peer_sock(sss, peer),
                          (const struct sockaddr*)&socket_storage, pktbuf, pktsize);
}


/** Initialise the supernode structure */
void sn_init_conf_defaults (struct n3n_runtime_data *sss, char *sessionname) {
    // TODO: this should accept a conf parameter, not a sss
    n2n_edge_conf_t *conf = &sss->conf;

    memset(sss, 0, sizeof(struct n3n_runtime_data));

    // Record the session name we used
    if(sessionname) {
        conf->sessionname = sessionname;
    } else {
        conf->sessionname = "NULL";
    }

    conf->is_supernode = true;
    conf->relay.spoofing_protection = true;

    // for an edge of its own, see supernode.tap
    edge_conf_role_defaults(conf);

    strncpy(conf->relay.version, VERSION, sizeof(n2n_version_t));
    conf->relay.version[sizeof(n2n_version_t) - 1] = '\0';

    // room for a full list and its end, as n3n_conf_sockaddr makes it:
    // open_bind_sockets() may add to it
    conf->bind_address = calloc(N3N_BIND_MAX + 1, sizeof(*conf->sas));

#ifdef _WIN32
    // Cannot rely on having unix domain sockets on windows
    conf->mgmt_port = N2N_SN_MGMT_PORT;
#endif
    conf->mgmt_password = strdup(N3N_MGMT_PASSWORD);

    /* Random auth token */
    conf->client.auth.scheme = n2n_auth_simple_id;
    memrnd(conf->client.auth.token, N2N_AUTH_ID_TOKEN_SIZE);
    conf->client.auth.token_size = N2N_AUTH_ID_TOKEN_SIZE;

    /* Initialize the federation name */
    // TODO: the edge has a separate function for getenv() defaults
    char *federation = getenv("N3N_FEDERATION");
    if(!federation) {
        federation = FEDERATION_NAME_DEFAULT;
    }
    strncpy(conf->relay.sn_federation, federation, sizeof(conf->relay.sn_federation));

#ifndef _WIN32
    struct passwd *pw = NULL;

    // The supernod can run with no additional privs, so the default is
    // just to run as the user who starts it.
    // It should not be running as root, so detect that and change the
    // defaults

    conf->userid = getuid();
    conf->groupid = getgid();
    if((conf->userid == 0) || (conf->groupid == 0)) {
        // Search a couple of usernames for one to use
        pw = getpwnam("n3n");
        if(pw == NULL) {
            pw = getpwnam("nobody");
        }
        if(pw != NULL) {
            // If we find one, use that as our default
            conf->userid = pw->pw_uid;
            conf->groupid = pw->pw_gid;
        }
    }

#endif


    /* Random MAC address */
    sss->conf.threads = 1;

    memrnd(sss->conf.relay.sn_mac_addr, N2N_MAC_SIZE);
    sss->conf.relay.sn_mac_addr[0] &= ~0x01; /* Clear multicast bit */
    sss->conf.relay.sn_mac_addr[0] |= 0x02;    /* Set locally-assigned bit */

    // [::] stands for IPv4 too, see open_bind_sockets()
    struct sockaddr_in6 *sa = (struct sockaddr_in6 *)conf->bind_address;
    sa->sin6_family = AF_INET6;
    sa->sin6_port = htons(N2N_SN_LPORT_DEFAULT);
    sa->sin6_addr = in6addr_any;

    sss->sock = -1;
    conf->relay.sn_min_auto_ip_net.net_addr = inet_addr(N2N_SN_MIN_AUTO_IP_NET_DEFAULT);
    conf->relay.sn_min_auto_ip_net.net_bitlen = N2N_SN_AUTO_IP_NET_BIT_DEFAULT;
    conf->relay.sn_max_auto_ip_net.net_addr = inet_addr(N2N_SN_MAX_AUTO_IP_NET_DEFAULT);
    conf->relay.sn_max_auto_ip_net.net_bitlen = N2N_SN_AUTO_IP_NET_BIT_DEFAULT;

    sss->relay.federation = (struct sn_community *)calloc(1, sizeof(struct sn_community));
    if(!sss->relay.federation) {
        abort();
    }

    // Setup the fields of the federation record
    // Note that this is not really conf, so it probably should move
    //
    /* enable the flag for federation */
    sss->relay.federation->is_federation = true;
    sss->relay.federation->purgeable = false;
    /* header encryption enabled by default */
    sss->relay.federation->header_encryption = HEADER_ENCRYPTION_ENABLED;
    sss->relay.federation->edges = NULL;
}


/** Initialise the supernode */
void sn_init (struct n3n_runtime_data *sss) {
    // The packet threads, if there are any, each read into a buffer of their
    // own pool of this shape
    n3n_pktbuf_initialise(N2N_SN_PKTBUF_SIZE, 4);

    // Show the user what has been configured
    resolve_log_hostnames(RESOLVE_LIST_SUPERNODE);
    resolve_log_hostnames(RESOLVE_LIST_PEER);

    // TODO:
    // - is sss->client.supernodes even used in supernode?
    // - should sss->relay.federation->edges be used instead?
    // - which works better in a merged edge/supernode environment?
    if(resolve_hostnames_str_to_peer_info(
           RESOLVE_LIST_SUPERNODE,
           &sss->client.supernodes)) {
        traceEvent(
            TRACE_ERROR,
            "resolve_hostnames_str_to_peer_info returned errors"
        );
    }

    // TODO: thread should probably be created before the above resolve!
    if(resolve_create_thread(&(sss->resolve_parameter), sss->relay.federation->edges) == 0) {
        traceEvent(TRACE_INFO, "successfully created resolver thread");
    }
}


/** Deinitialise the supernode structure and deallocate any memory owned by
 *    it. */
void sn_term (struct n3n_runtime_data *sss) {

    struct sn_community *community, *tmp;
    struct sn_community_regular_expression *re, *tmp_re;
    n2n_tcp_connection_t *conn, *tmp_conn;
    node_supernode_association_t *assoc, *tmp_assoc;

    resolve_cancel_thread(sss->resolve_parameter);

    // sock and tcp_sock are the first of these
    for(int i = 1; i < sss->bind_count; i++) {
        closesocket(sss->bind_sock[i]);
#ifdef N2N_HAVE_TCP
        shutdown(sss->bind_tcp[i], SHUT_RDWR);
        closesocket(sss->bind_tcp[i]);
#endif
    }
    sss->bind_count = 0;

    if(sss->sock >= 0) {
        closesocket(sss->sock);
    }
    sss->sock = -1;

    HASH_ITER(hh, sss->relay.tcp_connections, conn, tmp_conn) {
        shutdown(conn->socket_fd, SHUT_RDWR);
        mainloop_close_fd(conn->socket_fd);
        HASH_DEL(sss->relay.tcp_connections, conn);
        free(conn);
    }

    if(sss->relay.tcp_sock >= 0) {
        shutdown(sss->relay.tcp_sock, SHUT_RDWR);
        closesocket(sss->relay.tcp_sock);
    }
    sss->relay.tcp_sock = -1;

    HASH_ITER(hh, sss->relay.communities, community, tmp) {
        clear_peer_list(&community->edges);
        free(community->header_encryption_ctx_static);
        free(community->header_encryption_ctx_dynamic);
        free(community->header_iv_ctx_static);
        free(community->header_iv_ctx_dynamic);

        // remove all associations
        HASH_ITER(hh, community->assoc, assoc, tmp_assoc) {
            HASH_DEL(community->assoc, assoc);
            free(assoc);
        }

        // remove allowed users from community
        sn_user_t *user, *tmp_user;
        HASH_ITER(hh, community->allowed_users, user, tmp_user) {
            speck_deinit((speck_context_t*)user->shared_secret_ctx);
            HASH_DEL(community->allowed_users, user);
            free(user);
        }

        HASH_DEL(sss->relay.communities, community);
        free(community);
    }

    HASH_ITER(hh, sss->relay.rules, re, tmp_re) {
        HASH_DEL(sss->relay.rules, re);
        if(NULL != re->rule) {
            free(re->rule);
        }
        free(re);
    }

    free(sss->conf.bind_address);

    free(sss->conf.relay.community_file);
    n3n_conf_strlist_free(&sss->conf.relay.community_regex);
    n3n_config_free_communities(&sss->conf);

    free(sss->conf.mgmt_password);

#ifndef _WIN32
    char unixsock[1024];
    snprintf(unixsock, sizeof(unixsock), "%s/mgmt", sss->conf.sessiondir);
    unlink(unixsock);
    rmdir(sss->conf.sessiondir);
#else
    _rmdir(sss->conf.sessiondir);
#endif
    // Ignore errors in the unlink/rmdir as they could simply be that the
    // paths were chown/chmod by the administrator

    free(sss->conf.sessiondir);
    free(sss->conf.sessionname);

    if(sss->mgmt_slots) {
        slots_free(sss->mgmt_slots);
    }

    n3n_deinitfuncs();

#ifdef _WIN32
    destroyWin32();
#endif
}

/** Examine a datagram and determine what to do with it.
 *
 */
/* What the header of a PDU says, once it is decrypted. Finding it changes
 * nothing, so a packet thread can do that too, and it is all by value, so it
 * can travel to the main thread together with the decrypted PDU. */
/* Find the community a PDU belongs to and decrypt its header, if encrypted.
 * Returns -1 if the PDU is to be dropped. */
static int pdu_head_find (struct n3n_runtime_data *sss,
                          struct pdu_ctx *h,
                          struct sn_community **found) {

    uint8_t *udp_buf = h->buf;
    size_t udp_size = h->size;
    struct sn_community *comm, *tmp;

    h->header_enc = 0;
    h->stamp = 0;
    memset(h->hash_buf, 0, sizeof(h->hash_buf));
    h->in_community = false;
    *found = NULL;

    if(udp_size < 24) {
        traceEvent(TRACE_DEBUG, "dropped a packet too short to be valid");
        return -1;
    }
    if(pdu_header_plain(udp_buf, udp_size)) {
        /* most probably unencrypted */
        /* make sure, no downgrading happens here and no unencrypted packets can be
         * injected in a community which definitely deals with encrypted headers */
        HASH_FIND_COMMUNITY(sss->relay.communities, (char *)&udp_buf[04], comm);
        if(comm) {
            if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                traceEvent(TRACE_DEBUG, "dropped a packet with unencrypted header "
                           "addressed to community '%s' which uses encrypted headers",
                           comm->community);
                return -1;
            }
        }
    } else {
        /* most probably encrypted */
        /* cycle through the known communities (as keys) to eventually decrypt */
        HASH_ITER(hh, sss->relay.communities, comm, tmp) {
            /* skip the definitely unencrypted communities */
            if(comm->header_encryption == HEADER_ENCRYPTION_NONE) {
                continue;
            }

            // with the dynamic (2) or the static (1) keys?
            h->header_enc = pdu_header_decrypt(udp_buf, udp_size, comm->community,
                                               comm->header_encryption_ctx_dynamic, comm->header_iv_ctx_dynamic,
                                               comm->header_encryption_ctx_static, comm->header_iv_ctx_static,
                                               h->hash_buf, &h->stamp);

            if(h->header_enc) {
                // time stamp verification follows in the packet specific section as it requires to determine the
                // sender from the hash list by its MAC, this all depends on packet type and packet structure
                // (MAC is not always in the same place)

                // count the number of encrypted packets for sorting the communities from time to time
                // for the HASH_ITER a few lines above gets faster for the more busy communities
                COUNTER_INC(comm->number_enc_packets[n3n_thread_slot]);
                // no need to test further communities
                break;
            }
        }
        if(!h->header_enc) {
            // no matching key/community
            traceEvent(TRACE_DEBUG, "dropped a packet with seemingly encrypted header "
                       "for which no matching community which uses encrypted headers was found");
            return -1;
        }
    }

    h->in_community = (comm != NULL);
    *found = comm;
    return 0;
}


/* The first PDU of a community decides whether its headers are encrypted:
 * from then on, only PDUs that match are accepted. */
static void lock_header_encryption (struct sn_community *comm, uint32_t header_enc) {

    if(!comm || (comm->header_encryption != HEADER_ENCRYPTION_UNKNOWN)) {
        return;
    }

    if(header_enc) {
        traceEvent(TRACE_INFO, "locked community '%s' to "
                   "encrypted headers", comm->community);
        /* set 'encrypted' in case it is not set yet */
        comm->header_encryption = HEADER_ENCRYPTION_ENABLED;
    } else {
        traceEvent(TRACE_INFO, "locked community '%s' to "
                   "unencrypted headers", comm->community);
        /* set 'no encryption' in case it is not set yet */
        comm->header_encryption = HEADER_ENCRYPTION_NONE;
        free(comm->header_encryption_ctx_static);
        comm->header_encryption_ctx_static = NULL;
        free(comm->header_encryption_ctx_dynamic);
        comm->header_encryption_ctx_dynamic = NULL;
    }
}


/* Whether a packet thread can handle this PDU itself: a unicast PACKET to an
 * edge it reaches over UDP, or to the supernode that edge is registered at.
 * Everything else may change the tables, or goes out on a TCP connection,
 * which only the main thread writes to. */
static bool relay_here (struct n3n_runtime_data *sss,
                        struct sn_community *comm,
                        n2n_common_t *cmn,
                        bool from_supernode,
                        const uint8_t *udp_buf,
                        size_t rem,
                        size_t idx) {

    n2n_PACKET_t pkt;
    struct peer_info *scan;
    node_supernode_association_t *assoc;

    if((cmn->pc != MSG_TYPE_PACKET) || !comm
       || (comm->header_encryption == HEADER_ENCRYPTION_UNKNOWN)) {
        return false;
    }
    if(decode_PACKET(&pkt, cmn, udp_buf, &rem, &idx) < 0) {
        return false;
    }
    if(is_multi_broadcast(pkt.dstMac)) {
        return false;
    }

    HASH_FIND_PEER(comm->edges, pkt.dstMac, scan);
    if(scan) {
        // not to the edge in this process, see local_link.h
        return !is_tcp(sss, scan->socket_fd) && (scan->socket_fd != LOCAL_LINK_FD);
    }
    if(from_supernode) {
        // dropped
        return true;
    }
    HASH_FIND(hh, comm->assoc, pkt.dstMac, sizeof(n2n_mac_t), assoc);

    return assoc != NULL;
}


/* The handlers of the PDUs a supernode takes, by message type - see
 * sn_pdu_handlers below.  Each takes the locals it needs from the
 * struct pdu_ctx first.  Only a PACKET that relay_here() lets through runs
 * on a packet thread, everything else on the main thread. */

// The PDUs a supernode takes
static const pdu_handlers_t sn_pdu_handlers = {
    [MSG_TYPE_REGISTER] = sn_rx_register,
    [MSG_TYPE_PACKET] = sn_rx_packet,
    [MSG_TYPE_REGISTER_ACK] = sn_rx_register_ack,
    [MSG_TYPE_REGISTER_SUPER] = sn_rx_register_super,
    [MSG_TYPE_UNREGISTER_SUPER] = sn_rx_unregister_super,
    [MSG_TYPE_REGISTER_SUPER_ACK] = sn_rx_register_super_ack,
    [MSG_TYPE_REGISTER_SUPER_NAK] = sn_rx_register_super_nak,
    [MSG_TYPE_PEER_INFO] = sn_rx_peer_info,
    [MSG_TYPE_QUERY_PEER] = sn_rx_query_peer,
};


static int process_pdu_body (struct n3n_runtime_data * sss,
                             struct pdu_ctx *h,
                             struct sn_community *comm) {

    const struct sockaddr *sender_sock = h->sender_sock;
    uint8_t *udp_buf = h->buf;
    size_t udp_size = h->size;

    n2n_common_t cmn;        /* common fields in the packet header */
    size_t rem;
    size_t idx;
    size_t msg_type;
    bool from_supernode;
    struct peer_info *sn = NULL;
    n3n_sock_t sender;
    n3n_sock_str_t sockbuf;
    uint32_t header_enc = h->header_enc;
    int skip_add;

    fill_n3nsock(&sender, sender_sock);

    traceEvent(TRACE_DEBUG, "processing incoming UDP packet [len: %lu][sender: %s]",
               udp_size, sock_to_cstr(sockbuf, &sender));

    if(!n3n_thread_slot) {
        lock_header_encryption(comm, header_enc);
    }

    /* Use decode_common() to determine the kind of packet then process it:
     *
     * REGISTER_SUPER adds an edge and generate a return REGISTER_SUPER_ACK
     *
     * REGISTER, REGISTER_ACK and PACKET messages are forwarded to their
     * destination edge. If the destination is not known then PACKETs are
     * broadcast.
     */

    rem = udp_size; /* Counts down bytes of packet to protect against buffer overruns. */
    idx = 0; /* marches through packet header as parts are decoded. */

    if(decode_common(&cmn, udp_buf, &rem, &idx) < 0) {
        traceEvent(TRACE_ERROR, "failed to decode common section");
        return -1; /* failed to decode packet */
    }

    msg_type = cmn.pc; /* packet code */

    // special case for user/pw auth
    // community's auth scheme and message type need to match the used key (dynamic)
    if(comm) {
        if((comm->allowed_users)
           && (msg_type != MSG_TYPE_REGISTER_SUPER)
           && (msg_type != MSG_TYPE_REGISTER_SUPER_ACK)
           && (msg_type != MSG_TYPE_REGISTER_SUPER_NAK)) {
            if(header_enc != 2) {
                traceEvent(TRACE_WARNING, "dropped packet encrypted with static key where expecting dynamic key");
                return -1;
            }
        }
    }

    from_supernode = cmn.flags & N2N_FLAGS_FROM_SUPERNODE;
    if(from_supernode) {
        skip_add = SN_ADD_SKIP;
        sn = add_sn_to_list_by_mac_or_sock(&(sss->relay.federation->edges), &sender, null_mac, &skip_add);
        // only REGISTER_SUPER allowed from unknown supernodes
        if((!sn) && (msg_type != MSG_TYPE_REGISTER_SUPER)) {
            traceEvent(TRACE_DEBUG, "dropped incoming data from unknown supernode");
            return -1;
        }
    }

    if(cmn.ttl < 1) {
        traceEvent(TRACE_WARNING, "expired TTL");
        return 0; /* Don't process further */
    }

    --(cmn.ttl); /* The value copied into all forwarded packets. */

    h->cmn = cmn;
    h->rem = rem;
    h->idx = idx;
    h->sender = sender;
    h->from_supernode = from_supernode;

    if(n3n_thread_slot && !relay_here(sss, comm, &cmn, from_supernode, udp_buf, rem, idx)) {
        edge_threads_post_pdu(sss, h);
        return 0;
    }

    h->sn = sn;
    h->comm = comm;
    pdu_dispatch(sss, sn_pdu_handlers, h);

    return 0;
}


/** Long lived processing entry point. Split out from main to simply
 *  daemonisation on some platforms. */
static int process_pdu (struct n3n_runtime_data * sss,
                        const struct sockaddr *sender_sock, socklen_t sock_size,
                        const SOCKET socket_fd,
                        uint8_t * udp_buf,
                        size_t udp_size,
                        time_t now) {

    struct pdu_ctx h = {
        .buf = udp_buf,
        .size = udp_size,
        .socket_fd = socket_fd,
        .now = now,
        .sender_sock = sender_sock,
        .sock_size = sock_size,
    };
    struct sn_community *comm;

    if(pdu_head_find(sss, &h, &comm) < 0) {
        return -1;
    }
    return process_pdu_body(sss, &h, comm);
}


/* A PDU from the edge in this process, see local_link.h */
void sn_process_local_pdu (struct n3n_runtime_data *sss,
                           const struct sockaddr *sender_sock, socklen_t sock_size,
                           uint8_t *buf, size_t size, time_t now) {

    process_pdu(sss, sender_sock, sock_size, LOCAL_LINK_FD, buf, size, now);
}


/* A PDU a packet thread handed over, with its header already decrypted. It
 * came in over UDP. */
static void process_pdu_handed_over (struct n3n_runtime_data *sss, struct pdu_ctx *h) {

    struct sn_community *comm = NULL;

    h->now = time(NULL);

    if(h->in_community) {
        // the community may have gone meanwhile
        HASH_FIND_COMMUNITY(sss->relay.communities, (char *)h->cmn.community, comm);
        if(!comm) {
            traceEvent(TRACE_DEBUG, "dropped a PDU for community '%s' which is gone", h->cmn.community);
            return;
        }
    } else {
        // The community may have come up meanwhile, from the REGISTER_SUPER
        // of another edge handed over just before this one: look again, or
        // this REGISTER_SUPER creates a second community of the same name,
        // and the edges in one never find those in the other. The thread
        // found no community, so it has not decrypted the header either.
        if(pdu_head_find(sss, h, &comm) < 0) {
            return;
        }
    }
    process_pdu_body(sss, h, comm);
}


// Take one PDU off sock - for the main thread from the mainloop, for a packet
// thread from edge_threads.c
int sn_read_proto3_udp (struct n3n_runtime_data *sss,
                        SOCKET sock,
                        struct n3n_pktbuf *pktbuf,
                        time_t now) {

    struct sockaddr_storage sas;
    socklen_t ss_size = sizeof(sas);
    ssize_t bread;

    // The caller hands us the same buffer several times while draining
    n3n_pktbuf_zero(pktbuf);

    bread = recvfrom(sock,
                     n3n_pktbuf_getbufptr(*pktbuf),
                     n3n_pktbuf_getbufavail(*pktbuf),
                     MSG_DONTWAIT,
                     (struct sockaddr *)&sas,
                     &ss_size);
    if(bread < 0) {
#ifdef _WIN32
        unsigned int wsaerr = WSAGetLastError();
        // WSAECONNRESET on a UDP socket: an earlier send got an ICMP port
        // unreachable back
        if((wsaerr == WSAEWOULDBLOCK) || (wsaerr == WSAECONNRESET)) {
            return 0;
        }
        traceEvent(TRACE_ERROR, "WSAGetLastError(): %u", wsaerr);
#else
        if((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
            // nothing (more) queued for us
            return 0;
        }
#endif
        if(!n3n_thread_slot) {
            // The fd is no good now. Maybe we lost our interface. A packet
            // thread leaves it to the main thread, which sees it as well.
            traceEvent(TRACE_ERROR, "recvfrom() failed %d errno %d (%s)", bread, errno, strerror(errno));
            *sss->keep_running = false;
        }
        return 0;
    }
    if(bread == 0) {
        // For UDP bread of zero just means no data (unlike TCP)
        return 0;
    }

    // what comes in on a thread's socket is handled as if it came in on the
    // main thread's for the same address, which is what gets remembered
    int i = bind_entry_of_sock(sss, sock);
    process_pdu(sss, (struct sockaddr *)&sas, ss_size, sss->bind_sock[(i < 0) ? 0 : i],
                n3n_pktbuf_getbufptr(*pktbuf), bread, now);
    return 1;
}


void sn_read_proto3_tcp (struct n3n_runtime_data *sss,
                         SOCKET sock,
                         uint8_t *pktbuf,
                         ssize_t pktbuf_len,
                         time_t now) {

    n2n_tcp_connection_t *conn;

    HASH_FIND_INT(sss->relay.tcp_connections, &sock, conn);
    if(!conn) {
        // a connection the supernode has forgotten already
        if(pktbuf) {
            mainloop_close_fd(sock);
        }
        return;
    }

    if(!pktbuf) {
        n3n_sock_str_t sockbuf;
        traceEvent(TRACE_INFO, "closing tcp connection to [%s]",
                   sockaddr_to_str(sockbuf, sizeof(sockbuf), &conn->sock));
        forget_tcp_connection(sss, conn);
        return;
    }

    process_pdu(sss, &conn->sock, conn->sock_len, sock, pktbuf, pktbuf_len, now);
}


void sn_accepted_proto3_tcp (struct n3n_runtime_data *sss,
                             SOCKET sock,
                             const struct sockaddr *addr,
                             socklen_t addr_len) {

    n2n_tcp_connection_t *conn = calloc(1, sizeof(n2n_tcp_connection_t));
    n3n_sock_str_t sockbuf;

    if(!conn || (addr_len > sizeof(conn->sas))) {
        free(conn);
        mainloop_close_fd(sock);
        return;
    }

    conn->socket_fd = sock;
    memcpy(&conn->sas, addr, addr_len);
    conn->sock_len = addr_len;
    HASH_ADD_INT(sss->relay.tcp_connections, socket_fd, conn);
    traceEvent(TRACE_INFO, "accepted incoming TCP connection from [%s]",
               sockaddr_to_str(sockbuf, sizeof(sockbuf), addr));
}


static const struct edge_thread_ops sn_thread_ops = {
    .read_udp = sn_read_proto3_udp,
    .process_pdu = process_pdu_handed_over,
};


// The regular work of the supernode, done by the mainloop after each round,
// see mainloop_register_tick().  Each of these keeps its own time; there is
// one supernode in a process, as there is one mainloop.
static void sn_tick (struct n3n_runtime_data *sss, time_t now) {

    static time_t last_purge_edges = 0;
    static time_t last_sort_communities = 0;
    static time_t last_re_reg_and_purge = 0;

    re_register_and_purge_supernodes(
        sss,
        sss->relay.federation,
        &last_re_reg_and_purge,
        now,
        0 /* not forced */
    );
    purge_expired_communities(
        sss,
        &last_purge_edges,
        now
    );
    sort_communities(
        sss,
        &last_sort_communities,
        now
    );
    resolve_check(
        sss->resolve_parameter,
        false /* presumably, no special resolution requirement */,
        now
    );
}


int run_sn_loop (struct n3n_runtime_data *sss) {

    sss->start_time = time(NULL);

    // the mainloop reads the sockets of connection.bind, and accepts TCP
    // connections on them
    for(int i = 0; i < sss->bind_count; i++) {
        mainloop_register_fd(sss->bind_sock[i], fd_info_proto_v3udp);
#ifdef N2N_HAVE_TCP
        mainloop_register_fd(sss->bind_tcp[i], fd_info_proto_listen_v3tcp);
#endif
    }

    // more threads for PACKETs, if asked for; from here on the main thread
    // holds their lock whenever it is awake
    edge_threads_start(sss, edge_threads_wanted(&sss->conf), &sn_thread_ops);

    mainloop_register_tick(sn_tick, 0);
    mainloop_run(sss);

    if(sss->relay.local_edge) {
        edge_stop_local(sss->relay.local_edge);
        sss->relay.local_edge = NULL;
    }

    edge_threads_stop(sss);

    sn_term(sss);

    return 0;
}
