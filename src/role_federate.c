/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-25 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The federation of supernodes: registering with the other supernodes, and what they send
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
#include "n2n_wire.h"
#include "sn_selection.h"
#include "role_federate.h"
#include "role_relay.h"
#include "sn_communities.h"
#include "sn_utils.h"

#ifdef _WIN32
#include "win32/defs.h"

#include <direct.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pwd.h>
#include <sys/socket.h>
#endif


int re_register_and_purge_supernodes (struct n3n_runtime_data *sss, struct sn_community *comm, time_t *p_last_re_reg_and_purge, time_t now, uint8_t forced) {

    time_t time;
    struct peer_info *peer, *tmp;

    if(!forced) {
        if((now - (*p_last_re_reg_and_purge)) < RE_REG_AND_PURGE_FREQUENCY) {
            return 0;
        }

        // purge long-time-not-seen supernodes
        if(comm) {
            purge_expired_nodes(&(comm->edges), sss->sock, &sss->relay.tcp_connections, p_last_re_reg_and_purge,
                                RE_REG_AND_PURGE_FREQUENCY, LAST_SEEN_SN_INACTIVE);
        }
    }

    if(comm != NULL) {
        HASH_ITER(hh,comm->edges,peer,tmp) {

            time = now - peer->last_seen;

            if(!forced) {
                if(time <= LAST_SEEN_SN_ACTIVE) {
                    continue;
                }
            }

            /* re-register (send REGISTER_SUPER) */
            uint8_t pktbuf[N2N_PKT_BUF_SIZE] = {0};
            size_t idx;
            /* ssize_t sent; */
            n2n_common_t cmn = {0};
            n2n_REGISTER_SUPER_t reg = {0};
            n3n_sock_str_t sockbuf;

            cmn.ttl = N2N_DEFAULT_TTL;
            cmn.pc = MSG_TYPE_REGISTER_SUPER;
            cmn.flags = N2N_FLAGS_FROM_SUPERNODE;
            memcpy(cmn.community, comm->community, N2N_COMMUNITY_SIZE);

            reg.cookie = n3n_rand();
            peer->last_cookie = reg.cookie;

            reg.dev_addr.net_addr = ntohl(peer->dev_addr.net_addr);
            reg.dev_addr.net_bitlen = mask2bitlen(ntohl(peer->dev_addr.net_bitlen));
            get_local_auth(sss, &(reg.auth));

            reg.key_time = sss->relay.dynamic_key_time;

            memcpy(reg.edgeMac, sss->conf.relay.sn_mac_addr, sizeof(n2n_mac_t));

            idx = 0;
            encode_REGISTER_SUPER(pktbuf, &idx, &cmn, &reg);

            traceEvent(TRACE_DEBUG, "send REGISTER_SUPER to %s",
                       sock_to_cstr(sockbuf, &(peer->sock)));

            packet_header_encrypt(pktbuf, idx, idx,
                                  comm->header_encryption_ctx_static, comm->header_iv_ctx_static,
                                  time_stamp());

            /* sent = */ sn_sendto_peer(sss, peer, pktbuf, idx);
        }
    }

    return 0; /* OK */
}


/* MSG_TYPE_REGISTER_SUPER_ACK */
void sn_rx_register_super_ack (struct n3n_runtime_data *sss, struct pdu_ctx *c) {

    uint8_t *udp_buf = c->buf;
    time_t now = c->now;
    n2n_common_t cmn = c->cmn;
    size_t rem = c->rem;
    size_t idx = c->idx;
    bool from_supernode = c->from_supernode;
    struct peer_info *sn = c->sn;
    struct sn_community *comm = c->comm;
    n3n_sock_t sender = c->sender;
    n3n_sock_t *orig_sender = &sender;
    uint64_t stamp = c->stamp;
    int skip_add;
    time_t any_time = 0;

    n2n_REGISTER_SUPER_ACK_t ack;
    struct peer_info                 *scan, *tmp;
    n3n_sock_str_t sockbuf1;
    n3n_sock_str_t sockbuf2;
    macstr_t mac_buf1;
    int i;
    uint8_t dec_tmpbuf[REG_SUPER_ACK_PAYLOAD_SPACE];
    n2n_REGISTER_SUPER_ACK_payload_t *payload;
    n3n_sock_t payload_sock;

    if(!comm) {
        traceEvent(TRACE_DEBUG, "REGISTER_SUPER_ACK with unknown community %s", cmn.community);
        return;
    }

    if((!from_supernode) || (!comm->is_federation)) {
        traceEvent(TRACE_DEBUG, "dropped REGISTER_SUPER_ACK, should not come from an edge or regular community");
        return;
    }

    if(decode_REGISTER_SUPER_ACK(&ack, &cmn, udp_buf, &rem, &idx, dec_tmpbuf) < 0) {
        traceEvent(TRACE_INFO, "REGISTER_SUPER_ACK section too short");
        return;
    }
    // with user/password and header encryption, a hash follows,
    // which the decoder leaves unread
    if(rem != (community_appends_hash(comm) ? N2N_REG_SUP_HASH_CHECK_LEN : 0)) {
        traceEvent(TRACE_INFO, "REGISTER_SUPER_ACK section of wrong size");
        return;
    }
    orig_sender = &(ack.sock);

    if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
        if(!find_peer_time_stamp_and_verify(
               comm->edges,
               NULL,
               sn,
               ack.srcMac,
               stamp,
               TIME_STAMP_NO_JITTER)) {
            traceEvent(TRACE_DEBUG, "dropped REGISTER_SUPER_ACK due to time stamp error");
            return;
        }
    }

    traceEvent(TRACE_INFO, "Rx REGISTER_SUPER_ACK from MAC %s [%s] (external %s)",
               macaddr_str(mac_buf1, ack.srcMac),
               sock_to_cstr(sockbuf1, &sender),
               sock_to_cstr(sockbuf2, orig_sender));

    skip_add = SN_ADD_SKIP;
    scan = add_sn_to_list_by_mac_or_sock(&(sss->relay.federation->edges), &sender, ack.srcMac, &skip_add);
    if(scan != NULL) {
        scan->last_seen = now;
    } else {
        traceEvent(TRACE_DEBUG, "dropped REGISTER_SUPER_ACK due to an unknown supernode");
        return;
    }

    if(ack.cookie == scan->last_cookie) {

        payload = (n2n_REGISTER_SUPER_ACK_payload_t *)dec_tmpbuf;
        for(i = 0; i < ack.num_sn; i++) {
            skip_add = SN_ADD;

            // bugfix for https://github.com/ntop/n2n/issues/1029
            // REVISIT: best to be removed with 4.0
            idx = 0;
            rem = sizeof(payload->sock);
            decode_sock_payload(&payload_sock, payload->sock, &rem, &idx);

            // this very supernode, at another of its addresses: as a
            // member of its own federation, it would send itself what it
            // sends the others, and take its edges for the other's
            if(!memcmp(payload->mac, sss->conf.relay.sn_mac_addr, sizeof(n2n_mac_t))) {
                payload++;
                continue;
            }

            tmp = add_sn_to_list_by_mac_or_sock(&(sss->relay.federation->edges), &(payload_sock), payload->mac, &skip_add);
            // not come in yet: reached from an address fit for its family
            tmp->socket_fd = -1;

            if(skip_add == SN_ADD_ADDED) {
                tmp->last_seen = now - LAST_SEEN_SN_NEW;
                sock_to_cstr(sockbuf1, &(tmp->sock));
                tmp->hostname = strdup(sockbuf1);
            }

            // shift to next payload entry
            payload++;
        }

        if(ack.key_time > sss->relay.dynamic_key_time) {
            traceEvent(TRACE_DEBUG, "setting new key time");
            // have all edges re_register (using old dynamic key)
            send_re_register_super(sss);
            // set new key time
            sss->relay.dynamic_key_time = ack.key_time;
            // calculate new dynamic keys for all communities
            calculate_dynamic_keys(sss);
            // force re-register with all supernodes
            re_register_and_purge_supernodes(sss, sss->relay.federation, &any_time, now, 1 /* forced */);
        }

    } else {
        traceEvent(TRACE_INFO, "Rx REGISTER_SUPER_ACK with wrong or old cookie");
        traceEvent(
            TRACE_DEBUG,
            "got %u, expected %u",
            ack.cookie,
            scan->last_cookie
        );
    }
}


/* MSG_TYPE_REGISTER_SUPER_NAK */
void sn_rx_register_super_nak (struct n3n_runtime_data *sss, struct pdu_ctx *c) {

    uint8_t *udp_buf = c->buf;
    n2n_common_t cmn = c->cmn;
    size_t rem = c->rem;
    size_t idx = c->idx;
    bool from_supernode = c->from_supernode;
    struct peer_info *sn = c->sn;
    struct sn_community *comm = c->comm;
    n3n_sock_t sender = c->sender;
    uint8_t *hash_buf = c->hash_buf;
    uint64_t stamp = c->stamp;

    n2n_REGISTER_SUPER_NAK_t nak;
    uint8_t nakbuf[N2N_SN_PKTBUF_SIZE];
    size_t encx = 0;
    struct peer_info          *peer;
    n3n_sock_str_t sockbuf;
    macstr_t mac_buf;

    memset(&nak, 0, sizeof(n2n_REGISTER_SUPER_NAK_t));

    if(!comm) {
        traceEvent(TRACE_DEBUG, "REGISTER_SUPER_NAK with unknown community %s", cmn.community);
        return;
    }

    if(decode_REGISTER_SUPER_NAK(&nak, &cmn, udp_buf, &rem, &idx) < 0) {
        traceEvent(TRACE_INFO, "REGISTER_SUPER_NAK section too short");
        return;
    }
    // with user/password and header encryption, a hash follows,
    // which the decoder leaves unread
    if(rem != (community_appends_hash(comm) ? N2N_REG_SUP_HASH_CHECK_LEN : 0)) {
        traceEvent(TRACE_INFO, "REGISTER_SUPER_NAK section of wrong size");
        return;
    }

    if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
        if(!find_peer_time_stamp_and_verify(
               comm->edges,
               NULL,
               sn,
               nak.srcMac,
               stamp,
               TIME_STAMP_NO_JITTER)) {
            traceEvent(TRACE_DEBUG, "process_pdu dropped REGISTER_SUPER_NAK due to time stamp error");
            return;
        }
    }

    traceEvent(TRACE_INFO, "Rx REGISTER_SUPER_NAK from %s [%s]",
               macaddr_str(mac_buf, nak.srcMac),
               sock_to_cstr(sockbuf, &sender));

    // Only another supernode of the federation passes a NAK on, for
    // an edge in a regular community: from anyone else it could
    // throw out any edge
    HASH_FIND_PEER(comm->edges, nak.srcMac, peer);
    if(from_supernode && !comm->is_federation) {
        if(peer != NULL) {
            // this is a NAK for one of the edges conencted to this supernode, forward,
            // i.e. re-assemble (memcpy from udpbuf to nakbuf could be sufficient as well)

            // use incoming cmn (with already decreased TTL)
            // NAK (cookie, srcMac, auth) remains unchanged

            encode_REGISTER_SUPER_NAK(nakbuf, &encx, &cmn, &nak);

            if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                packet_header_encrypt(nakbuf, encx, encx,
                                      comm->header_encryption_ctx_static, comm->header_iv_ctx_static,
                                      time_stamp());
                // if user-password-auth
                if(comm->allowed_users) {
                    encode_buf(nakbuf, &encx, hash_buf /* no matter what content */, N2N_REG_SUP_HASH_CHECK_LEN);
                }
            }

            sn_sendto_peer(sss, peer, nakbuf, encx);

            remove_edge(sss, comm, peer);
        }
    }
}


/* MSG_TYPE_PEER_INFO */
void sn_rx_peer_info (struct n3n_runtime_data *sss, struct pdu_ctx *c) {

    const struct sockaddr *sender_sock = c->sender_sock;
    socklen_t sock_size = c->sock_size;
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
    n3n_sock_str_t sockbuf;
    uint64_t stamp = c->stamp;

    n2n_PEER_INFO_t pi;
    uint8_t encbuf[N2N_SN_PKTBUF_SIZE];
    size_t encx = 0;
    struct peer_info                       *peer;

    if(!comm) {
        traceEvent(TRACE_DEBUG, "PEER_INFO with unknown community %s", cmn.community);
        return;
    }

    if(decode_PEER_INFO(&pi, &cmn, udp_buf, &rem, &idx) < 0) {
        traceEvent(TRACE_INFO, "PEER_INFO section too short");
        return;
    }
    if(rem != 0) {
        traceEvent(TRACE_INFO, "PEER_INFO section too long");
        return;
    }

    if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
        if(!find_peer_time_stamp_and_verify(
               comm->edges,
               NULL,
               sn,
               pi.srcMac,
               stamp,
               TIME_STAMP_NO_JITTER)) {
            traceEvent(TRACE_DEBUG, "dropped PEER_INFO due to time stamp error");
            return;
        }
    }

    traceEvent(TRACE_INFO, "Rx PEER_INFO from %s [%s]",
               macaddr_str(mac_buf, pi.srcMac),
               sock_to_cstr(sockbuf, &sender));

    // The answer of another supernode of the federation to a
    // QUERY_PEER that one of our edges sent to all of them. From
    // anyone else it would tell the edge a wrong place for its peer,
    // and us a wrong supernode for it.
    HASH_FIND_PEER(comm->edges, pi.srcMac, peer);
    if(peer != NULL) {
        if(from_supernode && !comm->is_federation && !is_null_mac(pi.srcMac)) {
            // snoop on the information to use for supernode forwarding (do not wait until first remote REGISTER_SUPER)
            update_node_supernode_association(comm, &(pi.mac), sender_sock, sock_size, now);

            // this is a PEER_INFO for one of the edges conencted to this supernode, forward,
            // i.e. re-assemble (memcpy of udpbuf to encbuf could be sufficient as well)

            // use incoming cmn (with already decreased TTL)
            // PEER_INFO remains unchanged

            encode_PEER_INFO(encbuf, &encx, &cmn, &pi);

            if(comm->header_encryption == HEADER_ENCRYPTION_ENABLED) {
                packet_header_encrypt(encbuf, encx, encx,
                                      comm->header_encryption_ctx_dynamic, comm->header_iv_ctx_dynamic,
                                      time_stamp());
            }

            sn_sendto_peer(sss, peer, encbuf, encx);
        }
    }
}
