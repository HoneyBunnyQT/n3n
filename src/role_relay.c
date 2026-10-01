/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-25 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The relay role: the PDUs of the edges, registering them and passing their packets on
 */

#include <errno.h>
#include <n3n/logging.h>
#include <n3n/random.h>
#include <n3n/strings.h>
#include <n3n/supernode.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <time.h>
#include <unistd.h>

#include "header_encryption.h"
#include "n2n_define.h"
#include "n2n_regex.h"
#include "n2n_wire.h"
#include "pearson.h"
#include "sn_selection.h"
#include "role_federate.h"
#include "role_relay.h"
#include "sn_communities.h"
#include "sn_utils.h"
#include "stats.h"

#ifdef _WIN32
#include "win32/defs.h"

#include <direct.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pwd.h>
#include <sys/socket.h>
#endif


void update_node_supernode_association (struct sn_community *comm,
                                        n2n_mac_t *edgeMac,
                                        const struct sockaddr *sender_sock,
                                        socklen_t sock_size,
                                        time_t now) {

    node_supernode_association_t *assoc;

    // Look for an existing assoc entry
    HASH_FIND(hh, comm->assoc, edgeMac, sizeof(n2n_mac_t), assoc);

    if(!assoc) {
        // none found, create a new association
        assoc = (node_supernode_association_t*)calloc(1, sizeof(node_supernode_association_t));
        if(!assoc) {
            // TODO: log/abort on alloc failure
            return;
        }

        // Initialise the required fields
        memcpy(&(assoc->mac), edgeMac, sizeof(n2n_mac_t));
        HASH_ADD(hh, comm->assoc, mac, sizeof(n2n_mac_t), assoc);
    }

    // update old entry or initialise new entry
    // TODO: check sock_size for overflow
    memcpy(&(assoc->sock), sender_sock, sock_size);
    assoc->sock_len = sock_size;
    assoc->last_seen = now;
    return;
}


/** Determine the appropriate lifetime for new registrations.
 *
 *    If the supernode has been put into a pre-shutdown phase then this lifetime
 *    should not allow registrations to continue beyond the shutdown point.
 */
uint16_t reg_lifetime (struct n3n_runtime_data *sss) {

    /* NOTE: UDP firewalls usually have a 30 seconds timeout */
    return 15;
}


/** Verifies authentication tokens from known edges.
 *
 *  It is called by update_edge and during UNREGISTER_SUPER handling
 *  to verify the stored auth token.
 */
static int auth_edge (const n2n_auth_t *present, const n2n_auth_t *presented, n2n_auth_t *answer, struct sn_community *community) {

    sn_user_t *user = NULL;
    traceEvent(
        TRACE_INFO,
        "token scheme present=%i, presented=%i",
        present->scheme,
        presented->scheme
    );

    if(present->scheme == n2n_auth_none) {
        // n2n_auth_none scheme (set at supernode if cli option '-M')
        // if required, zero_token answer (not for NAK)
        if(answer)
            memset(answer, 0, sizeof(n2n_auth_t));
        // 0 == (always) successful
        return 0;
    }

    if((present->scheme == n2n_auth_simple_id) && (presented->scheme == n2n_auth_simple_id)) {
        // n2n_auth_simple_id scheme: if required, zero_token answer (not for NAK)
        if(answer)
            memset(answer, 0, sizeof(n2n_auth_t));

        // 0 = success (tokens are equal)
        return (memcmp(present, presented, sizeof(n2n_auth_t)));
    }

    if((present->scheme == n2n_auth_user_password) && (presented->scheme == n2n_auth_user_password)) {
        // check if submitted public key is in list of allowed users
        HASH_FIND(hh, community->allowed_users, &presented->token, sizeof(n2n_private_public_key_t), user);
        if(user) {
            if(answer) {
                memcpy(answer, presented, sizeof(n2n_auth_t));

                // return a double-encrypted challenge (just encrypt again) in the (first half of) public key field so edge can verify
                memcpy(answer->token, answer->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, N2N_AUTH_CHALLENGE_SIZE);
                speck_128_encrypt(answer->token, (speck_context_t*)user->shared_secret_ctx);

                // decrypt the challenge using user's shared secret
                speck_128_decrypt(answer->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, (speck_context_t*)user->shared_secret_ctx);
                // xor-in the community dynamic key
                memxor(answer->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, community->dynamic_key, N2N_AUTH_CHALLENGE_SIZE);
                // xor-in the user's shared secret
                memxor(answer->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, user->shared_secret, N2N_AUTH_CHALLENGE_SIZE);
                // encrypt it using user's shared secret
                speck_128_encrypt(answer->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, (speck_context_t*)user->shared_secret_ctx);
                // user in list? success! (we will see if edge can handle the key for further com)
            }
            return 0;
        }
    }

    // if not successful earlier: failure
    traceEvent(TRACE_INFO, "auth default fail");
    return -1;
}


// provides the current / a new local auth token
// REVISIT: behavior should depend on some local auth scheme setting (to be implemented)
int get_local_auth (struct n3n_runtime_data *sss, n2n_auth_t *auth) {

    // n2n_auth_simple_id scheme
    memcpy(auth, &(sss->conf.client.auth), sizeof(n2n_auth_t));

    return 0;
}


// handles an incoming (remote) auth token from a so far unknown edge,
// takes action as required by auth scheme, and
// could provide an answer auth token for use in REGISTER_SUPER_ACK
static int handle_remote_auth (struct n3n_runtime_data *sss, const n2n_auth_t *remote_auth,
                               n2n_auth_t *answer_auth,
                               struct sn_community *community) {

    sn_user_t *user = NULL;
    traceEvent(TRACE_INFO, "token scheme %i", remote_auth->scheme);

    if((NULL == community->allowed_users) != (remote_auth->scheme != n2n_auth_user_password)) {
        // received token's scheme does not match expected scheme
        traceEvent(TRACE_INFO, "token scheme mismatch");
        return -1;
    }

    switch(remote_auth->scheme) {
        // we do not handle n2n_auth_none because the edge always uses either
        // id or user/password
        // auth_none is sn-internal only (skipping MAC/IP address spoofing
        // protection)
        case n2n_auth_none:
        case n2n_auth_simple_id:
            // zero_token answer
            memset(answer_auth, 0, sizeof(n2n_auth_t));
            return 0;
        case n2n_auth_user_password:
            // check if submitted public key is in list of allowed users
            HASH_FIND(hh, community->allowed_users, &remote_auth->token, sizeof(n2n_private_public_key_t), user);
            if(user) {
                memcpy(answer_auth, remote_auth, sizeof(n2n_auth_t));

                // return a double-encrypted challenge (just encrypt again) in the (first half of) public key field so edge can verify
                memcpy(answer_auth->token, answer_auth->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, N2N_AUTH_CHALLENGE_SIZE);
                speck_128_encrypt(answer_auth->token, (speck_context_t*)user->shared_secret_ctx);

                // wrap dynamic key for transmission
                // decrypt the challenge using user's shared secret
                speck_128_decrypt(answer_auth->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, (speck_context_t*)user->shared_secret_ctx);
                // xor-in the community dynamic key
                memxor(answer_auth->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, community->dynamic_key, N2N_AUTH_CHALLENGE_SIZE);
                // xor-in the user's shared secret
                memxor(answer_auth->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, user->shared_secret, N2N_AUTH_CHALLENGE_SIZE);
                // encrypt it using user's shared secret
                speck_128_encrypt(answer_auth->token + N2N_PRIVATE_PUBLIC_KEY_SIZE, (speck_context_t*)user->shared_secret_ctx);
                return 0;
            }
            break;
        default:
            break;
    }

    // if not successful earlier: failure
    traceEvent(TRACE_INFO, "auth default fail");
    return -1;
}


/** Update the edge table with the details of the edge which contacted the
 *    supernode. */
int update_edge (struct n3n_runtime_data *sss,
                 const n2n_common_t* cmn,
                 const n2n_REGISTER_SUPER_t* reg,
                 struct sn_community *comm,
                 const n3n_sock_t *sender_sock,
                 const SOCKET socket_fd,
                 n2n_auth_t *answer_auth,
                 int skip_add,
                 time_t now) {

    macstr_t mac_buf;
    n3n_sock_str_t sockbuf;
    struct peer_info *scan, *iter, *tmp;

    traceEvent(TRACE_DEBUG, "update_edge for %s [%s]",
               macaddr_str(mac_buf, reg->edgeMac),
               sock_to_cstr(sockbuf, sender_sock));

    HASH_FIND_PEER(comm->edges, reg->edgeMac, scan);

    // if unknown, make sure it is also not known by IP address
    if(NULL == scan) {
        HASH_ITER(hh,comm->edges,iter,tmp) {
            // TODO:
            // - needs ipv6 support
            // - I suspect that this can leak TCP connections
            // - convert to using a peer_info_*() call for manipulating the
            //   peer info lists
            if(iter->dev_addr.net_addr == reg->dev_addr.net_addr) {
                scan = iter;
                HASH_DEL(comm->edges, scan);
                memcpy(scan->mac_addr, reg->edgeMac, sizeof(n2n_mac_t));
                HASH_ADD_PEER(comm->edges, scan);
                break;
            }
        }
    }

    scan = peer_info_validate(&comm->edges, scan);

    if(NULL == scan) {
        /* Not known */
        if(handle_remote_auth(sss, &(reg->auth), answer_auth, comm) == 0) {
            if(skip_add == SN_ADD) {
                scan = peer_info_malloc(reg->edgeMac); /* deallocated in purge_expired_nodes */
                scan->dev_addr.net_addr = reg->dev_addr.net_addr;
                scan->dev_addr.net_bitlen = reg->dev_addr.net_bitlen;
                memcpy((char*)scan->dev_desc, reg->dev_desc, N2N_DESC_SIZE);
                memcpy(&(scan->sock), sender_sock, sizeof(n3n_sock_t));
                scan->socket_fd = socket_fd;
                scan->last_cookie = reg->cookie;
                // eventually, store edge's preferred local socket from REGISTER_SUPER
                if(cmn->flags & N2N_FLAGS_SOCKET)
                    memcpy(&scan->preferred_sock, &reg->sock, sizeof(n3n_sock_t));
                else
                    scan->preferred_sock.family = AF_INVALID;

                // store the submitted auth token
                memcpy(&(scan->auth), &(reg->auth), sizeof(n2n_auth_t));
                // manually set to type 'auth_none' if cli option disables
                // MAC/IP address spoofing protection for id based auth
                // communities. This will be obsolete when handling public
                // keys only (v4.0?)
                if((reg->auth.scheme == n2n_auth_simple_id) && (!sss->conf.relay.spoofing_protection))
                    scan->auth.scheme = n2n_auth_none;

                HASH_ADD_PEER(comm->edges, scan);

                traceEvent(TRACE_INFO, "created edge  %s ==> %s",
                           macaddr_str(mac_buf, reg->edgeMac),
                           sock_to_cstr(sockbuf, sender_sock));

                scan->last_seen = now;
                return update_edge_new_sn;
            }
            return update_edge_new_sn;
        } else {
            traceEvent(TRACE_INFO, "authentication failed");
            return update_edge_auth_fail;
        }
    } else {
        /* Known */
        if(auth_edge(&(scan->auth), &(reg->auth), answer_auth, comm) == 0) {
            if(!sock_equal(sender_sock, &(scan->sock))) {
                scan->dev_addr.net_addr = reg->dev_addr.net_addr;
                scan->dev_addr.net_bitlen = reg->dev_addr.net_bitlen;
                memcpy((char*)scan->dev_desc, reg->dev_desc, N2N_DESC_SIZE);
                memcpy(&(scan->sock), sender_sock, sizeof(n3n_sock_t));
                scan->socket_fd = socket_fd;
                scan->last_cookie = reg->cookie;
                // eventually, update edge's preferred local socket from REGISTER_SUPER
                if(cmn->flags & N2N_FLAGS_SOCKET)
                    memcpy(&scan->preferred_sock, &reg->sock, sizeof(n3n_sock_t));
                else
                    scan->preferred_sock.family = AF_INVALID;

                traceEvent(TRACE_INFO, "updated edge  %s ==> %s",
                           macaddr_str(mac_buf, reg->edgeMac),
                           sock_to_cstr(sockbuf, sender_sock));
                scan->last_seen = now;
                return update_edge_sock_change;
            } else {
                scan->last_cookie = reg->cookie;
                // the same public address can come in on another of our
                // sockets, e.g. another port of this supernode
                scan->socket_fd = socket_fd;

                traceEvent(TRACE_DEBUG, "edge unchanged %s ==> %s",
                           macaddr_str(mac_buf, reg->edgeMac),
                           sock_to_cstr(sockbuf, sender_sock));

                scan->last_seen = now;
                return update_edge_no_change;
            }
        } else {
            traceEvent(TRACE_INFO, "authentication failed");
            return update_edge_auth_fail;
        }
    }

    return 0;
}


/** Try and broadcast a message to all edges in the community.
 *
 *    This will send the exact same datagram to zero or more edges registered to
 *    the supernode.
 */
static void try_broadcast (struct n3n_runtime_data * sss,
                           const struct sn_community *comm,
                           const n2n_common_t * cmn,
                           const n2n_mac_t srcMac,
                           bool from_supernode,
                           const uint8_t * pktbuf,
                           size_t pktsize,
                           time_t now) {

    struct peer_info        *scan, *tmp;
    macstr_t mac_buf;
    n3n_sock_str_t sockbuf;

    traceEvent(TRACE_DEBUG, "try_broadcast");

    /* We have to make sure that a broadcast reaches the other supernodes and edges
     * connected to them. try_broadcast needs a from_supernode parameter: if set,
     * do forward to edges of community only. If unset, forward to all locally known
     * nodes of community AND all supernodes associated with the community */

    if(!from_supernode) {
        // If the broadcast is not from a supernode, send it to all supernodes

        HASH_ITER(hh, sss->relay.federation->edges, scan, tmp) {
            int data_sent_len;

            // only forward to active supernodes
            if(scan->last_seen + LAST_SEEN_SN_INACTIVE > now) {

                data_sent_len = sn_sendto_peer(sss, scan, pktbuf, pktsize);

                if(data_sent_len != pktsize) {
                    STATS_INC(sss, sn_errors);
                    traceEvent(TRACE_WARNING, "multicast %lu to supernode [%s] %s failed %s",
                               pktsize,
                               sock_to_cstr(sockbuf, &(scan->sock)),
                               macaddr_str(mac_buf, scan->mac_addr),
                               strerror(errno));
                } else {
                    STATS_INC(sss, sn_broadcast);
                    traceEvent(TRACE_DEBUG, "multicast %lu to supernode [%s] %s",
                               pktsize,
                               sock_to_cstr(sockbuf, &(scan->sock)),
                               macaddr_str(mac_buf, scan->mac_addr));
                }
            }
        }
    }

    if(comm) {
        // If we know this community, send the broadcast to all known edges

        HASH_ITER(hh, comm->edges, scan, tmp) {
            if(memcmp(srcMac, scan->mac_addr, sizeof(n2n_mac_t)) != 0) {
                /* REVISIT: exclude if the destination socket is where the packet came from. */
                int data_sent_len;

                data_sent_len = sn_sendto_peer(sss, scan, pktbuf, pktsize);

                if(data_sent_len != pktsize) {
                    STATS_INC(sss, sn_errors);
                    traceEvent(TRACE_WARNING, "multicast %lu to [%s] %s failed %s",
                               pktsize,
                               sock_to_cstr(sockbuf, &(scan->sock)),
                               macaddr_str(mac_buf, scan->mac_addr),
                               strerror(errno));
                } else {
                    STATS_INC(sss, sn_broadcast);
                    traceEvent(TRACE_DEBUG, "multicast %lu to [%s] %s",
                               pktsize,
                               sock_to_cstr(sockbuf, &(scan->sock)),
                               macaddr_str(mac_buf, scan->mac_addr));
                }
            }
        }
    }

    return;
}


static void try_forward (struct n3n_runtime_data * sss,
                         const struct sn_community *comm,
                         const n2n_common_t * cmn,
                         const n2n_mac_t dstMac,
                         bool from_supernode,
                         const uint8_t * pktbuf,
                         size_t pktsize,
                         time_t now) {

    struct peer_info *             scan;
    node_supernode_association_t   *assoc;
    macstr_t mac_buf;
    n3n_sock_str_t sockbuf;

    HASH_FIND_PEER(comm->edges, dstMac, scan);

    if(scan) {
        // We found an edge matching the dest mac

        int data_sent_len;
        data_sent_len = sn_sendto_peer(sss, scan, pktbuf, pktsize);

        if(data_sent_len == pktsize) {
            STATS_INC(sss, sn_fwd);
            traceEvent(TRACE_DEBUG, "unicast %lu to [%s] %s",
                       pktsize,
                       sock_to_cstr(sockbuf, &(scan->sock)),
                       macaddr_str(mac_buf, scan->mac_addr));
            return;
        } else {
            STATS_INC(sss, sn_errors);
            traceEvent(TRACE_ERROR, "unicast %lu to [%s] %s FAILED (%d: %s)",
                       pktsize,
                       sock_to_cstr(sockbuf, &(scan->sock)),
                       macaddr_str(mac_buf, scan->mac_addr),
                       errno, strerror(errno));
            return;
        }

    }

    if(!from_supernode) {
        HASH_FIND(hh, comm->assoc, dstMac, sizeof(n2n_mac_t), assoc);
        if(assoc) {
            // if target edge is associated with a certain supernode
            traceEvent(
                TRACE_DEBUG,
                "found mac address associated with a known supernode, forwarding packet to that supernode"
            );
            sn_sendto_sock(sss, family_sock(sss, assoc->sock.sa_family),
                           &(assoc->sock),
                           pktbuf, pktsize);
            return;
        } else {
            // otherwise, forwarding packet to all federated supernodes
            traceEvent(
                TRACE_DEBUG,
                "unknown mac address, broadcasting packet to all federated supernodes"
            );
            try_broadcast(
                sss,
                NULL,
                cmn,
                sss->conf.relay.sn_mac_addr,
                from_supernode,
                pktbuf,
                pktsize,
                now
            );
            return;
        }
    }

    // Must be from a supernode then
    STATS_INC(sss, sn_drop);
    traceEvent(
        TRACE_DEBUG,
        "unknown mac address in packet from a supernode, dropping the packet"
    );
    /* Not a known MAC so drop. */
    return;
}


// Whether a REGISTER_SUPER and its _ACK and _NAK carry a hash after their
// fields: with user/password authentication and header encryption
bool community_appends_hash (const struct sn_community *comm) {

    return comm->allowed_users && (comm->header_encryption == HEADER_ENCRYPTION_ENABLED);
}


/* MSG_TYPE_PACKET */
void sn_rx_packet (struct n3n_runtime_data *sss, struct pdu_ctx *c) {

    uint8_t *udp_buf = c->buf;
    size_t udp_size = c->size;
    time_t now = c->now;
    n2n_common_t cmn = c->cmn;
    size_t rem = c->rem;
    size_t idx = c->idx;
    bool from_supernode = c->from_supernode;
    struct peer_info *sn = c->sn;
    struct sn_community *comm = c->comm;
    n3n_sock_t sender = c->sender;
    macstr_t mac_buf;
    macstr_t mac_buf2;
    uint64_t stamp = c->stamp;

    /* PACKET from one edge to another edge via supernode. */

    /* pkt will be modified in place and recoded to an output of potentially
     * different size due to addition of the socket.*/
    n2n_PACKET_t pkt;
    n2n_common_t cmn2;
    uint8_t encbuf[N2N_SN_PKTBUF_SIZE];
    size_t encx = 0;
    int unicast;           /* non-zero if unicast */
    uint8_t *     rec_buf; /* either udp_buf or encbuf */

    if(!comm) {
        traceEvent(TRACE_DEBUG, "PACKET with unknown community %s", cmn.community);
        return;
    }

    // every packet thread stores this, so only if it changed
    if(SHARED_LOAD(sss->relay.last_sn_fwd) != now) {
        SHARED_STORE(sss->relay.last_sn_fwd, now);
    }
    // whatever follows the header is the payload
    if(decode_PACKET(&pkt, &cmn, udp_buf, &rem, &idx) < 0) {
        traceEvent(TRACE_INFO, "PACKET section too short");
        return;
    }

    // already checked for valid comm
    if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
        if(!find_peer_time_stamp_and_verify(
               comm->edges,
               NULL,
               sn,
               pkt.srcMac,
               stamp,
               TIME_STAMP_ALLOW_JITTER)) {
            traceEvent(TRACE_DEBUG, "dropped PACKET due to time stamp error");
            return;
        }
    }

    unicast = (0 == is_multi_broadcast(pkt.dstMac));

    traceEvent(TRACE_DEBUG, "RX PACKET (%s) %s -> %s %s",
               (unicast ? "unicast" : "multicast"),
               macaddr_str(mac_buf, pkt.srcMac),
               macaddr_str(mac_buf2, pkt.dstMac),
               (from_supernode ? "from sn" : "local"));

    if(!from_supernode) {
        memcpy(&cmn2, &cmn, sizeof(n2n_common_t));

        /* We are going to add socket even if it was not there before */
        cmn2.flags |= N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;

        memcpy(&pkt.sock, &sender, sizeof(sender));

        rec_buf = encbuf;
        /* Re-encode the header. */
        encode_PACKET(encbuf, &encx, &cmn2, &pkt);

        uint16_t oldEncx = encx;

        /* Copy the original payload unchanged */
        encode_buf(encbuf, &encx, (udp_buf + idx), (udp_size - idx));

        if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
            // in case of user-password auth, also encrypt the iv of payload assuming ChaCha20 and SPECK having the same iv size
            packet_header_encrypt(rec_buf, oldEncx + (NULL != comm->allowed_users) * MIN(encx - oldEncx, N2N_SPECK_IVEC_SIZE), encx,
                                  comm->header_encryption_ctx_dynamic, comm->header_iv_ctx_dynamic,
                                  time_stamp());
        }
    } else {
        /* Already from a supernode. Nothing to modify, just pass to
         * destination. */

        traceEvent(TRACE_DEBUG, "Rx PACKET fwd unmodified");

        rec_buf = udp_buf;
        encx = udp_size;

        if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
            // in case of user-password auth, also encrypt the iv of payload assuming ChaCha20 and SPECK having the same iv size
            packet_header_encrypt(rec_buf, idx + (NULL != comm->allowed_users) * MIN(encx - idx, N2N_SPECK_IVEC_SIZE), encx,
                                  comm->header_encryption_ctx_dynamic, comm->header_iv_ctx_dynamic,
                                  time_stamp());
        }
    }

    /* Common section to forward the final product. */
    if(unicast) {
        try_forward(sss, comm, &cmn, pkt.dstMac, from_supernode, rec_buf, encx, now);
    } else {
        try_broadcast(sss, comm, &cmn, pkt.srcMac, from_supernode, rec_buf, encx, now);
    }
}


/* MSG_TYPE_REGISTER */
void sn_rx_register (struct n3n_runtime_data *sss, struct pdu_ctx *c) {

    uint8_t *udp_buf = c->buf;
    size_t udp_size = c->size;
    time_t now = c->now;
    n2n_common_t cmn = c->cmn;
    size_t rem = c->rem;
    size_t idx = c->idx;
    bool from_supernode = c->from_supernode;
    struct peer_info *sn = c->sn;
    struct sn_community *comm = c->comm;
    n3n_sock_t sender = c->sender;
    macstr_t mac_buf;
    macstr_t mac_buf2;
    uint64_t stamp = c->stamp;

    /* Forwarding a REGISTER from one edge to the next */

    n2n_REGISTER_t reg;
    n2n_common_t cmn2;
    uint8_t encbuf[N2N_SN_PKTBUF_SIZE];
    size_t encx = 0;
    int unicast;             /* non-zero if unicast */
    uint8_t *       rec_buf; /* either udp_buf or encbuf */

    if(!comm) {
        traceEvent(TRACE_DEBUG, "REGISTER from unknown community %s", cmn.community);
        return;
    }

    sss->relay.last_sn_fwd = now;
    if(decode_REGISTER(&reg, &cmn, udp_buf, &rem, &idx) < 0) {
        traceEvent(TRACE_INFO, "REGISTER section too short");
        return;
    }
    if(rem != 0) {
        traceEvent(TRACE_INFO, "REGISTER section too long");
        return;
    }

    // already checked for valid comm
    if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
        if(!find_peer_time_stamp_and_verify(
               comm->edges,
               NULL,
               sn,
               reg.srcMac,
               stamp,
               TIME_STAMP_NO_JITTER)) {
            traceEvent(TRACE_DEBUG, "dropped REGISTER due to time stamp error");
            return;
        }
    }

    unicast = (0 == is_multi_broadcast(reg.dstMac));

    if(unicast) {
        traceEvent(TRACE_DEBUG, "Rx REGISTER %s -> %s %s",
                   macaddr_str(mac_buf, reg.srcMac),
                   macaddr_str(mac_buf2, reg.dstMac),
                   ((cmn.flags & N2N_FLAGS_FROM_SUPERNODE) ? "from sn" : "local"));

        if(0 == (cmn.flags & N2N_FLAGS_FROM_SUPERNODE)) {
            memcpy(&cmn2, &cmn, sizeof(n2n_common_t));

            /* We are going to add socket even if it was not there before */
            cmn2.flags |= N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;

            memcpy(&reg.sock, &sender, sizeof(sender));

            /* Re-encode the header. */
            encode_REGISTER(encbuf, &encx, &cmn2, &reg);

            rec_buf = encbuf;
        } else {
            /* Already from a supernode. Nothing to modify, just pass to
             * destination. */

            rec_buf = udp_buf;
            encx = udp_size;
        }

        if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
            packet_header_encrypt(rec_buf, encx, encx,
                                  comm->header_encryption_ctx_dynamic, comm->header_iv_ctx_dynamic,
                                  time_stamp());
        }
        try_forward(sss, comm, &cmn, reg.dstMac, from_supernode, rec_buf, encx, now); /* unicast only */
    } else {
        traceEvent(TRACE_ERROR, "Rx REGISTER with multicast destination");
    }
}


/* MSG_TYPE_REGISTER_ACK */
void sn_rx_register_ack (struct n3n_runtime_data *sss, struct pdu_ctx *c) {

    traceEvent(TRACE_DEBUG, "Rx REGISTER_ACK (not implemented) should not be via supernode");
}


/* MSG_TYPE_REGISTER_SUPER */
void sn_rx_register_super (struct n3n_runtime_data *sss, struct pdu_ctx *c) {

    const struct sockaddr *sender_sock = c->sender_sock;
    socklen_t sock_size = c->sock_size;
    const SOCKET socket_fd = c->socket_fd;
    uint8_t *udp_buf = c->buf;
    size_t udp_size = c->size;
    time_t now = c->now;
    n2n_common_t cmn = c->cmn;
    size_t rem = c->rem;
    size_t idx = c->idx;
    bool from_supernode = c->from_supernode;
    struct peer_info *sn = c->sn;
    struct sn_community *comm = c->comm;
    n3n_sock_t sender = c->sender;
    macstr_t mac_buf;
    n3n_sock_str_t sockbuf;
    uint8_t *hash_buf = c->hash_buf;
    uint64_t stamp = c->stamp;
    int skip_add;
    time_t any_time = 0;

    n2n_REGISTER_SUPER_t reg;
    n2n_REGISTER_SUPER_ACK_t ack;
    n2n_REGISTER_SUPER_NAK_t nak;
    n2n_common_t cmn2;
    uint8_t ackbuf[N2N_SN_PKTBUF_SIZE];
    uint8_t payload_buf[REG_SUPER_ACK_PAYLOAD_SPACE];
    n2n_REGISTER_SUPER_ACK_payload_t       *payload;
    size_t encx = 0;
    struct sn_community_regular_expression *re, *tmp_re;
    struct peer_info                       *peer, *tmp_peer, *p;
    int8_t allowed_match = -1;
    uint8_t match = 0;
    int match_length = 0;
    n2n_ip_subnet_t ipaddr;
    int num = 0;
    int skip;
    int ret_value;
    sn_user_t                              *user = NULL;

    /*
     * ack.dev_addr is only set when the edge needs an IP assigned
     * (lines below); zero the whole struct so the encoded dev_addr
     * is zero rather than garbage when that branch is not taken
     */
    // TODO: refactor code to avoid needing memset
    memset(&ack, 0, sizeof(n2n_REGISTER_SUPER_ACK_t));

    /* Edge/supernode requesting registration with us.    */
    sss->relay.last_sn_reg=now;
    STATS_INC(sss, sn_reg);
    if(decode_REGISTER_SUPER(&reg, &cmn, udp_buf, &rem, &idx) < 0) {
        traceEvent(TRACE_INFO, "REGISTER_SUPER section too short");
        return;
    }
    // the length of the rest is checked once the community is known

    if(comm) {
        if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
            if(!find_peer_time_stamp_and_verify(
                   comm->edges,
                   NULL,
                   sn,
                   reg.edgeMac,
                   stamp,
                   TIME_STAMP_NO_JITTER)) {
                traceEvent(TRACE_DEBUG, "dropped REGISTER_SUPER due to time stamp error");
                return;
            }
        }
    }

    /*
        Before we move any further, we need to check if the requested
        community is allowed by the supernode. In case it is not we do
        not report any message back to the edge to hide the supernode
        existance (better from the security standpoint)
     */

    if(!comm && sss->relay.lock_communities) {
        HASH_ITER(hh, sss->relay.rules, re, tmp_re) {
            allowed_match = re_matchp(re->rule, (const char *)cmn.community, &match_length);

            if((allowed_match != -1)
               && (match_length == strlen((const char *)cmn.community)) // --- only full matches allowed (remove, if also partial matches wanted)
               && (allowed_match == 0)) { // --- only full matches allowed (remove, if also partial matches wanted)
                match = 1;
                break;
            }
        }
        if(match != 1) {
            traceEvent(TRACE_INFO, "discarded registration with unallowed community '%s'",
                       (char*)cmn.community);
            return;
        }
    }

    if(!comm && (!sss->relay.lock_communities || (match == 1))) {
        comm = (struct sn_community*)calloc(1, sizeof(struct sn_community));

        if(comm) {
            comm_init(comm, (char *)cmn.community);
            /* new communities introduced by REGISTERs could not have had encrypted header... */
            comm->header_encryption = HEADER_ENCRYPTION_NONE;
            free(comm->header_encryption_ctx_static);
            comm->header_encryption_ctx_static = NULL;
            free(comm->header_encryption_ctx_dynamic);
            comm->header_encryption_ctx_dynamic = NULL;
            /* ... and also are purgeable during periodic purge */
            comm->purgeable = true;
            memset(comm->number_enc_packets, 0, sizeof(comm->number_enc_packets));
            HASH_ADD_STR(sss->relay.communities, community, comm);

            traceEvent(TRACE_INFO, "new community: %s", comm->community);
            assign_one_ip_subnet(sss, comm);
        }
    }

    if(!comm) {
        traceEvent(TRACE_INFO, "discarded registration with unallowed community '%s'",
                   (char*)cmn.community);
        return;
    }

    // with user/password and header encryption, a hash follows,
    // which the decoder leaves unread
    if(rem != (community_appends_hash(comm) ? N2N_REG_SUP_HASH_CHECK_LEN : 0)) {
        traceEvent(TRACE_INFO, "REGISTER_SUPER section of wrong size");
        return;
    }

    // hash check (user/pw auth only)
    if(comm->allowed_users) {
        // check if submitted public key is in list of allowed users
        HASH_FIND(hh, comm->allowed_users, &reg.auth.token, sizeof(n2n_private_public_key_t), user);
        if(user) {
            speck_128_encrypt(hash_buf, (speck_context_t*)user->shared_secret_ctx);
            if(memcmp(hash_buf, udp_buf + udp_size - N2N_REG_SUP_HASH_CHECK_LEN /* length has already been checked */, N2N_REG_SUP_HASH_CHECK_LEN)) {
                traceEvent(TRACE_INFO, "Rx REGISTER_SUPER with wrong hash");
                return;
            }
        } else {
            traceEvent(TRACE_INFO, "Rx REGISTER_SUPER from unknown user");
            // continue and let auth check do the rest (otherwise, no NAK is sent)
        }
    }

    if(!memcmp(reg.edgeMac, sss->conf.relay.sn_mac_addr, sizeof(n2n_mac_t))) {
        traceEvent(TRACE_DEBUG, "Rx REGISTER_SUPER from self, ignoring");
        return;
    }

    cmn2.ttl = N2N_DEFAULT_TTL;
    cmn2.pc = MSG_TYPE_REGISTER_SUPER_ACK;
    cmn2.flags = N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;
    memcpy(cmn2.community, cmn.community, sizeof(n2n_community_t));

    ack.cookie = reg.cookie;
    memcpy(ack.srcMac, sss->conf.relay.sn_mac_addr, sizeof(n2n_mac_t));

    if(!comm->is_federation) { /* alternatively, do not send zero tap ip address in federation REGISTER_SUPER */
        if((reg.dev_addr.net_addr == 0) || (reg.dev_addr.net_addr == 0xFFFFFFFF) || (reg.dev_addr.net_bitlen == 0) ||
           ((reg.dev_addr.net_addr & 0xFFFF0000) == 0xA9FE0000 /* 169.254.0.0 */)) {
            memset(&ipaddr, 0, sizeof(n2n_ip_subnet_t));
            assign_one_ip_addr(comm, reg.dev_desc, &ipaddr);
            ack.dev_addr.net_addr = ipaddr.net_addr;
            ack.dev_addr.net_bitlen = ipaddr.net_bitlen;
        }
    }

    ack.lifetime = reg_lifetime(sss);

    memcpy(&ack.sock, &sender, sizeof(sender));

    /* Add sender's data to federation (or update it) */
    if(comm->is_federation) {
        skip_add = SN_ADD;
        p = add_sn_to_list_by_mac_or_sock(&(sss->relay.federation->edges), &(ack.sock), reg.edgeMac, &skip_add);
        p->last_seen = now;
        // answered where it came in
        p->socket_fd = socket_fd;
        if(skip_add == SN_ADD_ADDED) {
            sock_to_cstr(sockbuf, &(p->sock));
            p->hostname = strdup(sockbuf);
        }
    }

    /* Skip random numbers of supernodes before payload assembling, calculating an appropriate random_number.
     * That way, all supernodes have a chance to be propagated with REGISTER_SUPER_ACK. */
    skip = HASH_COUNT(sss->relay.federation->edges) - (int)(REG_SUPER_ACK_PAYLOAD_ENTRY_SIZE / REG_SUPER_ACK_PAYLOAD_ENTRY_SIZE);
    skip = (skip < 0) ? 0 : n3n_rand_sqr(skip);

    /* Assembling supernode list for REGISTER_SUPER_ACK payload */
    payload = (n2n_REGISTER_SUPER_ACK_payload_t*)payload_buf;
    HASH_ITER(hh, sss->relay.federation->edges, peer, tmp_peer) {
        if(skip) {
            skip--;
            continue;
        }
        if(peer->sock.family == (uint8_t)AF_INVALID)
            continue; /* do not add unresolved supernodes to payload */
        if(memcmp(&(peer->sock), &(ack.sock), sizeof(n3n_sock_t)) == 0) continue; /* a supernode doesn't add itself to the payload */
        if((now - peer->last_seen) >= LAST_SEEN_SN_NEW) continue;  /* skip long-time-not-seen supernodes.
                                                                    * We need to allow for a little extra time because supernodes sometimes exceed
                                                                    * their SN_ACTIVE time before they get re-registred to. */
        if(((++num)*REG_SUPER_ACK_PAYLOAD_ENTRY_SIZE) > REG_SUPER_ACK_PAYLOAD_SPACE) break; /* no more space available in REGISTER_SUPER_ACK payload */

        // bugfix for https://github.com/ntop/n2n/issues/1029
        // REVISIT: best to be removed with 4.0 (replace with encode_sock)
        idx = 0;
        encode_sock_payload(payload->sock, &idx, &(peer->sock));

        memcpy(payload->mac, peer->mac_addr, sizeof(n2n_mac_t));
        // shift to next payload entry
        payload++;
    }
    ack.num_sn = num;

    traceEvent(TRACE_DEBUG, "Rx REGISTER_SUPER for %s [%s]",
               macaddr_str(mac_buf, reg.edgeMac),
               sock_to_cstr(sockbuf, &(ack.sock)));

    // check authentication
    ret_value = update_edge_no_change;
    if(!comm->is_federation) { /* REVISIT: auth among supernodes is not implemented yet */
        if(cmn.flags & N2N_FLAGS_FROM_SUPERNODE) {
            ret_value = update_edge(sss, &cmn, &reg, comm, &(ack.sock), socket_fd, &(ack.auth), SN_ADD_SKIP, now);
        } else {
            // do not add in case of null mac (edge asking for ip address)
            ret_value = update_edge(sss, &cmn, &reg, comm, &(ack.sock), socket_fd, &(ack.auth), is_null_mac(reg.edgeMac) ? SN_ADD_SKIP : SN_ADD, now);
        }
    }

    if(ret_value == update_edge_auth_fail) {
        // send REGISTER_SUPER_NAK
        cmn2.pc = MSG_TYPE_REGISTER_SUPER_NAK;
        nak.cookie = reg.cookie;
        memcpy(nak.srcMac, reg.edgeMac, sizeof(n2n_mac_t));

        encode_REGISTER_SUPER_NAK(ackbuf, &encx, &cmn2, &nak);

        if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
            packet_header_encrypt(ackbuf, encx, encx,
                                  comm->header_encryption_ctx_static, comm->header_iv_ctx_static,
                                  time_stamp());
            // if user-password-auth
            if(comm->allowed_users) {
                encode_buf(ackbuf, &encx, hash_buf /* no matter what content */, N2N_REG_SUP_HASH_CHECK_LEN);
            }
        }
        sn_sendto_sock(sss, socket_fd, sender_sock, ackbuf, encx);

        traceEvent(TRACE_DEBUG, "Tx REGISTER_SUPER_NAK for %s",
                   macaddr_str(mac_buf, reg.edgeMac));

        return;
    }

    // if this is not already from a supernode ...
    // and not from federation, ...
    if((!(cmn.flags & N2N_FLAGS_FROM_SUPERNODE)) || (!(cmn.flags & N2N_FLAGS_SOCKET))) {
        // ... forward to all other supernodes (note try_broadcast()'s behavior with
        //     NULL comm and from_supernode parameter)
        // exception: do not forward auto ip draw
        if(!is_null_mac(reg.edgeMac)) {
            memcpy(&reg.sock, &sender, sizeof(sender));

            cmn2.pc = MSG_TYPE_REGISTER_SUPER;
            encode_REGISTER_SUPER(ackbuf, &encx, &cmn2, &reg);

            if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                packet_header_encrypt(ackbuf, encx, encx,
                                      comm->header_encryption_ctx_static, comm->header_iv_ctx_static,
                                      time_stamp());
                // if user-password-auth
                if(comm->allowed_users) {
                    // append an encrypted packet hash
                    pearson_hash_128(hash_buf, ackbuf, encx);
                    // same 'user' as above
                    speck_128_encrypt(hash_buf, (speck_context_t*)user->shared_secret_ctx);
                    encode_buf(ackbuf, &encx, hash_buf, N2N_REG_SUP_HASH_CHECK_LEN);
                }
            }

            try_broadcast(sss, NULL, &cmn, reg.edgeMac, from_supernode, ackbuf, encx, now);
        }

        // dynamic key time handling if appropriate
        ack.key_time = 0;
        if(comm->is_federation) {
            if(reg.key_time > sss->relay.dynamic_key_time) {
                traceEvent(TRACE_DEBUG, "setting new key time");
                // have all edges re_register (using old dynamic key)
                send_re_register_super(sss);
                // set new key time
                sss->relay.dynamic_key_time = reg.key_time;
                // calculate new dynamic keys for all communities
                calculate_dynamic_keys(sss);
                // force re-register with all supernodes
                re_register_and_purge_supernodes(sss, sss->relay.federation, &any_time, now, 1 /* forced */);
            }
            ack.key_time = sss->relay.dynamic_key_time;
        }

        // send REGISTER_SUPER_ACK
        encx = 0;
        cmn2.pc = MSG_TYPE_REGISTER_SUPER_ACK;

        encode_REGISTER_SUPER_ACK(ackbuf, &encx, &cmn2, &ack, payload_buf);

        if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
            packet_header_encrypt(ackbuf, encx, encx,
                                  comm->header_encryption_ctx_static, comm->header_iv_ctx_static,
                                  time_stamp());
            // if user-password-auth
            if(comm->allowed_users) {
                // append an encrypted packet hash
                pearson_hash_128(hash_buf, ackbuf, encx);
                // same 'user' as above
                speck_128_encrypt(hash_buf, (speck_context_t*)user->shared_secret_ctx);
                encode_buf(ackbuf, &encx, hash_buf, N2N_REG_SUP_HASH_CHECK_LEN);
            }
        }

        sn_sendto_sock(sss, socket_fd, sender_sock, ackbuf, encx);

        traceEvent(TRACE_DEBUG, "Tx REGISTER_SUPER_ACK for %s [%s]",
                   macaddr_str(mac_buf, reg.edgeMac),
                   sock_to_cstr(sockbuf, &(ack.sock)));
    } else {
        // this is an edge with valid authentication registering with another supernode, so ...
        // 1- ... associate it with that other supernode
        update_node_supernode_association(comm, &(reg.edgeMac), sender_sock, sock_size, now);
        // 2- ... we can delete it from regular list if present (can happen)
        HASH_FIND_PEER(comm->edges, reg.edgeMac, peer);
        if(peer != NULL) {
            remove_edge(sss, comm, peer);
        }
    }

}


/* MSG_TYPE_UNREGISTER_SUPER */
void sn_rx_unregister_super (struct n3n_runtime_data *sss, struct pdu_ctx *c) {

    uint8_t *udp_buf = c->buf;
    n2n_common_t cmn = c->cmn;
    size_t rem = c->rem;
    size_t idx = c->idx;
    bool from_supernode = c->from_supernode;
    struct peer_info *sn = c->sn;
    struct sn_community *comm = c->comm;
    macstr_t mac_buf;
    uint64_t stamp = c->stamp;

    n2n_UNREGISTER_SUPER_t unreg;
    struct peer_info       *peer;
    int auth;


    if(!comm) {
        traceEvent(TRACE_DEBUG, "dropped UNREGISTER_SUPER with unknown community %s", cmn.community);
        return;
    }

    if((from_supernode) || (comm->is_federation)) {
        traceEvent(TRACE_DEBUG, "dropped UNREGISTER_SUPER: should not come from a supernode or federation.");
        return;
    }

    if(decode_UNREGISTER_SUPER(&unreg, &cmn, udp_buf, &rem, &idx) < 0) {
        traceEvent(TRACE_INFO, "UNREGISTER_SUPER section too short");
        return;
    }
    if(rem != 0) {
        traceEvent(TRACE_INFO, "UNREGISTER_SUPER section too long");
        return;
    }

    if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
        if(!find_peer_time_stamp_and_verify(
               comm->edges,
               NULL,
               sn,
               unreg.srcMac,
               stamp,
               TIME_STAMP_NO_JITTER)) {
            traceEvent(TRACE_DEBUG, "dropped UNREGISTER_SUPER due to time stamp error");
            return;
        }
    }

    traceEvent(TRACE_DEBUG, "Rx UNREGISTER_SUPER from %s",
               macaddr_str(mac_buf, unreg.srcMac));

    HASH_FIND_PEER(comm->edges, unreg.srcMac, peer);
    if(peer != NULL) {
        if((auth = auth_edge(&(peer->auth), &unreg.auth, NULL, comm)) == 0) {
            remove_edge(sss, comm, peer);
        }
    }
}


/* MSG_TYPE_QUERY_PEER */
void sn_rx_query_peer (struct n3n_runtime_data *sss, struct pdu_ctx *c) {

    const struct sockaddr *sender_sock = c->sender_sock;
    const SOCKET socket_fd = c->socket_fd;
    uint8_t *udp_buf = c->buf;
    time_t now = c->now;
    n2n_common_t cmn = c->cmn;
    size_t rem = c->rem;
    size_t idx = c->idx;
    bool from_supernode = c->from_supernode;
    struct peer_info *sn = c->sn;
    struct sn_community *comm = c->comm;
    n3n_sock_t sender = c->sender;
    macstr_t mac_buf;
    macstr_t mac_buf2;
    uint64_t stamp = c->stamp;

    n2n_QUERY_PEER_t query;
    uint8_t encbuf[N2N_SN_PKTBUF_SIZE];
    size_t encx = 0;
    n2n_common_t cmn2 = {0};
    n2n_PEER_INFO_t pi = {0};
    struct sn_community_regular_expression *re, *tmp_re;
    int8_t allowed_match = -1;
    uint8_t match = 0;
    int match_length = 0;

    if(!comm && sss->relay.lock_communities) {
        HASH_ITER(hh, sss->relay.rules, re, tmp_re) {
            allowed_match = re_matchp(re->rule, (const char *)cmn.community, &match_length);

            if((allowed_match != -1)
               && (match_length == strlen((const char *)cmn.community)) // --- only full matches allowed (remove, if also partial matches wanted)
               && (allowed_match == 0)) {                               // --- only full matches allowed (remove, if also partial matches wanted)
                match = 1;
                break;
            }
        }
        if(match != 1) {
            traceEvent(TRACE_DEBUG, "QUERY_PEER from unknown community %s", cmn.community);
            return;
        }
    }

    if(!comm && sss->relay.lock_communities && (match == 0)) {
        traceEvent(TRACE_DEBUG, "QUERY_PEER from not allowed community %s", cmn.community);
        return;
    }

    if(decode_QUERY_PEER(&query, &cmn, udp_buf, &rem, &idx) < 0) {
        traceEvent(TRACE_INFO, "QUERY_PEER section too short");
        return;
    }
    if(rem != 0) {
        traceEvent(TRACE_INFO, "QUERY_PEER section too long");
        return;
    }

    // to answer a PING, it is sufficient if the provided communtiy would be a valid one, there does not
    // neccessarily need to be a comm entry present, e.g. because there locally are no edges of the
    // community connected (several supernodes in a federation setup)
    if(comm) {
        if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
            if(!find_peer_time_stamp_and_verify(
                   comm->edges,
                   NULL,
                   sn,
                   query.srcMac,
                   stamp,
                   TIME_STAMP_ALLOW_JITTER)) {
                traceEvent(TRACE_DEBUG, "dropped QUERY_PEER due to time stamp error");
                return;
            }
        }
    }

    if(is_null_mac(query.targetMac)) {
        traceEvent(TRACE_DEBUG, "Rx PING from %s",
                   macaddr_str(mac_buf, query.srcMac));

        cmn2.ttl = N2N_DEFAULT_TTL;
        cmn2.pc = MSG_TYPE_PEER_INFO;
        cmn2.flags = N2N_FLAGS_FROM_SUPERNODE;
        memcpy(cmn2.community, cmn.community, sizeof(n2n_community_t));

        pi.aflags = 0;
        memcpy(pi.mac, query.targetMac, sizeof(n2n_mac_t));
        memcpy(pi.srcMac, sss->conf.relay.sn_mac_addr, sizeof(n2n_mac_t));

        memcpy(&pi.sock, &sender, sizeof(sender));

        pi.load = sn_selection_criterion_gather_data(sss);

        snprintf(pi.version, sizeof(pi.version), "%s", sss->conf.relay.version);
        pi.uptime = now - sss->start_time;

        encode_PEER_INFO(encbuf, &encx, &cmn2, &pi);

        if(comm) {
            if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                packet_header_encrypt(encbuf, encx, encx, comm->header_encryption_ctx_dynamic,
                                      comm->header_iv_ctx_dynamic,
                                      time_stamp());
            }
        }

        sn_sendto_sock(sss, socket_fd, sender_sock, encbuf, encx);

        traceEvent(TRACE_DEBUG, "Tx PONG to %s",
                   macaddr_str(mac_buf, query.srcMac));

    } else {
        traceEvent(TRACE_DEBUG, "Rx QUERY_PEER from %s for %s",
                   macaddr_str(mac_buf, query.srcMac),
                   macaddr_str(mac_buf2, query.targetMac));

        struct peer_info *scan;

        // as opposed to the special case 'PING', proper QUERY_PEER processing requires a locally actually present community entry
        if(!comm) {
            traceEvent(TRACE_DEBUG, "QUERY_PEER with unknown community %s", cmn.community);
            return;
        }

        HASH_FIND_PEER(comm->edges, query.targetMac, scan);
        if(scan) {
            cmn2.ttl = N2N_DEFAULT_TTL;
            cmn2.pc = MSG_TYPE_PEER_INFO;
            cmn2.flags = N2N_FLAGS_FROM_SUPERNODE;
            memcpy(cmn2.community, cmn.community, sizeof(n2n_community_t));

            pi.aflags = 0;
            memcpy(pi.srcMac, query.srcMac, sizeof(n2n_mac_t));
            memcpy(pi.mac, query.targetMac, sizeof(n2n_mac_t));
            pi.sock = scan->sock;
            if(scan->preferred_sock.family != (uint8_t)AF_INVALID) {
                cmn2.flags |= N2N_FLAGS_SOCKET;
                pi.preferred_sock = scan->preferred_sock;
            }

            // FIXME:
            // If we get the request on TCP, the reply should indicate
            // our prefered sock is TCP ??

            encode_PEER_INFO(encbuf, &encx, &cmn2, &pi);

            if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                packet_header_encrypt(encbuf, encx, encx, comm->header_encryption_ctx_dynamic,
                                      comm->header_iv_ctx_dynamic,
                                      time_stamp());
            }
            // back to sender, be it edge or supernode (which will forward to edge)
            sn_sendto_sock(sss, socket_fd, sender_sock, encbuf, encx);

            traceEvent(TRACE_DEBUG, "Tx PEER_INFO to %s",
                       macaddr_str(mac_buf, query.srcMac));

        } else {

            if(from_supernode) {
                traceEvent(TRACE_DEBUG, "QUERY_PEER on unknown edge from supernode %s, dropping the packet",
                           macaddr_str(mac_buf, query.srcMac));
            } else {
                traceEvent(TRACE_DEBUG, "QUERY_PEER from unknown edge %s, forwarding to all other supernodes",
                           macaddr_str(mac_buf, query.srcMac));

                memcpy(&cmn2, &cmn, sizeof(n2n_common_t));
                cmn2.flags |= N2N_FLAGS_FROM_SUPERNODE;

                encode_QUERY_PEER(encbuf, &encx, &cmn2, &query);

                if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                    packet_header_encrypt(encbuf, encx, encx, comm->header_encryption_ctx_dynamic,
                                          comm->header_iv_ctx_dynamic,
                                          time_stamp());
                }

                try_broadcast(sss, NULL, &cmn, query.srcMac, from_supernode, encbuf, encx, now);
            }
        }
    }
}
