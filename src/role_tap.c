/**
 * (C) 2007-22 - ntop.org and contributors
 * Copyright (C) 2023-25 Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The tap role: the TAP device, and the PACKETs between it and the peers
 */

#ifdef _WIN32
#include "win32/defs.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <n3n/logging.h>
#include <n3n/strings.h>
#include <n3n/transform.h>
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
#include "minmax.h"
#include "n2n_wire.h"
#include "punch.h"
#include "role_client.h"
#include "tun.h"              // for tun_to_frame, tun_from_frame
#include "role_tap.h"
#include "sn_selection.h"
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


/** Destination 01:00:5E:00:00:00 - 01:00:5E:7F:FF:FF is multicast ethernet.
 */
static int is_ethMulticast (const void * buf, size_t bufsize) {

    int retval = 0;

    /* Match 01:00:5E:00:00:00 - 01:00:5E:7F:FF:FF */
    if(bufsize >= sizeof(ether_hdr_t)) {
        /* copy to aligned memory */
        ether_hdr_t eh;
        memcpy(&eh, buf, sizeof(ether_hdr_t));

        if((0x01 == eh.dhost[0]) &&
           (0x00 == eh.dhost[1]) &&
           (0x5E == eh.dhost[2]) &&
           (0 == (0x80 & eh.dhost[3])))
            retval = 1; /* This is an ethernet multicast packet [RFC1112]. */
    }

    return retval;
}


/** Destination MAC 33:33:0:00:00:00 - 33:33:FF:FF:FF:FF is reserved for IPv6
 *    neighbour discovery.
 */
static int is_ip6_discovery (const void * buf, size_t bufsize) {

    int retval = 0;

    if(bufsize >= sizeof(ether_hdr_t)) {
        /* copy to aligned memory */
        ether_hdr_t eh;

        memcpy(&eh, buf, sizeof(ether_hdr_t));

        if((0x33 == eh.dhost[0]) && (0x33 == eh.dhost[1]))
            retval = 1; /* This is an IPv6 multicast packet [RFC2464]. */
    }

    return retval;
}


static char gratuitous_arp[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* dest MAC */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* src MAC */
    0x08, 0x06, /* ARP */
    0x00, 0x01, /* ethernet */
    0x08, 0x00, /* IP */
    0x06, /* hw Size */
    0x04, /* protocol Size */
    0x00, 0x02, /* ARP reply */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* src MAC */
    0x00, 0x00, 0x00, 0x00, /* src IP */
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* target MAC */
    0x00, 0x00, 0x00, 0x00 /* target IP */
};


// build a gratuitous ARP packet */
static int build_gratuitous_arp (struct n3n_runtime_data * eee, char *buffer, uint16_t buffer_len) {

    if(buffer_len < sizeof(gratuitous_arp)) return(-1);

    memcpy(buffer, gratuitous_arp, sizeof(gratuitous_arp));
    memcpy(&buffer[6], eee->tap.device.mac_addr, 6);
    memcpy(&buffer[22], eee->tap.device.mac_addr, 6);
    memcpy(&buffer[28], &(eee->tap.device.ip_addr), 4);
    memcpy(&buffer[38], &(eee->tap.device.ip_addr), 4);

    return(sizeof(gratuitous_arp));
}


/** Called from update_supernode_reg to periodically send gratuitous ARP
 *    broadcasts. */
void send_grat_arps (struct n3n_runtime_data * eee) {

    uint8_t buffer[48];
    size_t len;

    traceEvent(TRACE_DEBUG, "sending gratuitous ARP...");
    len = build_gratuitous_arp(eee, (char*)buffer, sizeof(buffer));

    edge_send_packet2net(eee, buffer, len);
    edge_send_packet2net(eee, buffer, len); /* Two is better than one :-) */
}


/* The tap device, as the calling thread sees it: every packet thread reads and
 * writes a queue of its own, the main thread the first one. */
static int tap_read (struct n3n_runtime_data *eee, uint8_t *buf, int len) {

#ifdef __linux__
    if(n3n_thread_slot) {
        return tuntap_read_queue(&eee->tap.device, n3n_thread_slot, buf, len);
    }
#endif
    return tuntap_read(&eee->tap.device, buf, len);
}


static int tap_write_device (struct n3n_runtime_data *eee, uint8_t *buf, int len) {

#ifdef __linux__
    if(n3n_thread_slot) {
        return tuntap_write_queue(&eee->tap.device, n3n_thread_slot, buf, len);
    }
#endif
    return tuntap_write(&eee->tap.device, buf, len);
}


// A frame for the device: as it is to a TAP device, its IP packet to a TUN
// device, see tun.c
static int tap_write (struct n3n_runtime_data *eee, uint8_t *buf, int len) {

    if(eee->tap.device.tun) {
        return tun_from_frame(eee, buf, len, tap_write_device);
    }
    return tap_write_device(eee, buf, len);
}


static int handle_PACKET (struct n3n_runtime_data * eee,
                          const uint8_t from_supernode,
                          const n2n_PACKET_t * pkt,
                          const n3n_sock_t * orig_sender,
                          uint8_t * payload,
                          size_t psize) {

    ssize_t data_sent_len;
    uint8_t *                 eth_payload = NULL;
    time_t now;
    ether_hdr_t *             eh;
    ipstr_t ip_buf;
    macstr_t mac_buf;
    n3n_sock_str_t sockbuf;

    now = time(NULL);

    traceEvent(TRACE_DEBUG, "handle_PACKET size %u transform %u",
               (unsigned int)psize, (unsigned int)pkt->transform);

    if(from_supernode) {
        if(is_multi_broadcast(pkt->dstMac))
            STATS_INC(eee, rx_sup_broadcast);

        STATS_INC(eee, rx_sup);
        SHARED_STORE(eee->client.last_sup, now);
    } else {
        STATS_INC(eee, rx_p2p);
        SHARED_STORE(eee->client.last_p2p, now);
    }

    /* Handle transform. */
    uint8_t decode_buf[N2N_PKT_BUF_SIZE];
    uint8_t deflate_buf[N2N_PKT_BUF_SIZE];
    size_t eth_size;

    n2n_transform_t rx_transop_id = (n2n_transform_t)pkt->transform;
    uint8_t rx_compression_id = pkt->compression;

    if(rx_transop_id != eee->conf.community.transop_id) {
        traceEvent(
            TRACE_WARNING,
            "invalid transop ID: expected %s (%u), got %s (%u) from %s [%s]",
            n3n_transform_id2str(eee->conf.community.transop_id),
            eee->conf.community.transop_id,
            n3n_transform_id2str(rx_transop_id),
            rx_transop_id,
            macaddr_str(mac_buf, pkt->srcMac),
            sock_to_cstr(sockbuf, orig_sender)
        );
        return -1;
    }

    uint8_t is_multicast;
    // decrypt
    eth_payload = decode_buf;
    eth_size = eee->client.transop.rev(&eee->client.transop,
                                       eth_payload, N2N_PKT_BUF_SIZE,
                                       payload, psize, pkt->srcMac);
    STATS_INC(eee, transop_rx);

    /* decompress if necessary */
    size_t deflate_len;

    switch(rx_compression_id) {
        case N2N_COMPRESSION_ID_NONE:
            break; // continue afterwards

        case N2N_COMPRESSION_ID_LZO:
            deflate_len = eee->client.transop_lzo.rev(&eee->client.transop_lzo,
                                                      deflate_buf, N2N_PKT_BUF_SIZE,
                                                      decode_buf, eth_size, pkt->srcMac);
            break;

#ifdef HAVE_LIBZSTD
        case N2N_COMPRESSION_ID_ZSTD:
            deflate_len = eee->client.transop_zstd.rev(&eee->client.transop_zstd,
                                                       deflate_buf, N2N_PKT_BUF_SIZE,
                                                       decode_buf, eth_size, pkt->srcMac);
            break;
#endif
        default:
            traceEvent(
                TRACE_WARNING,
                "decompression: failed: unsupported %i",
                rx_compression_id
            );
            return(-1); // cannot handle it
    }

    if(rx_compression_id != N2N_COMPRESSION_ID_NONE) {
        traceEvent(
            TRACE_DEBUG,
            "decompression: %i: deflated %u bytes to %u bytes",
            rx_compression_id,
            eth_size,
            deflate_len
        );
        eth_payload = deflate_buf;
        eth_size = deflate_len;
    }

    eh = (ether_hdr_t*)eth_payload;

    is_multicast = (is_ip6_discovery(eth_payload, eth_size) || is_ethMulticast(eth_payload, eth_size));

    if(!eee->conf.tap.allow_multicast && is_multicast) {
        traceEvent(TRACE_INFO, "dropping RX multicast");
        STATS_INC(eee, rx_multicast_drop);
        return(-1);
    }

    if((!eee->conf.tap.allow_routing) && (!is_multicast)) {
        /* Check if it is a routed packet */

        if((ntohs(eh->type) == 0x0800) && (eth_size >= ETH_FRAMESIZE + IP4_MIN_SIZE)) {

            // the address is not aligned within the frame
            uint32_t dst;
            memcpy(&dst, &eth_payload[ETH_FRAMESIZE + IP4_DSTOFFSET], sizeof(dst));
            uint8_t *dst_mac = (uint8_t*)eth_payload;

            /* Note: all elements of the_ip are in network order */
            if(!memcmp(dst_mac, broadcast_mac, N2N_MAC_SIZE))
                traceEvent(TRACE_DEBUG, "RX broadcast packet destined to [%s]",
                           intoa(ntohl(dst), ip_buf, sizeof(ip_buf)));
            else if((dst != eee->tap.device.ip_addr)) {
                /* This is a packet that needs to be routed */
                traceEvent(TRACE_INFO, "discarding routed packet destined to [%s]",
                           intoa(ntohl(dst), ip_buf, sizeof(ip_buf)));
                return(-1);
            }

            /* This packet is directed to us */
            /* traceEvent(TRACE_INFO, "Sending non-routed packet"); */
        }
    }

#ifdef HAVE_BRIDGING_SUPPORT
    if((eee->conf.tap.allow_routing) && (!is_multi_broadcast(eh->shost))) {
        struct host_info *host = NULL;

        HASH_FIND(hh, eee->tap.known_hosts, eh->shost, sizeof(n2n_mac_t), host);
        if(host && !memcmp(host->edge_addr, pkt->srcMac, sizeof(n2n_mac_t))) {
            // known, and still behind the same edge
            SHARED_STORE(host->last_seen, now);
        } else {
            struct edge_event ev = { .type = EDGE_EVENT_HOST_SEEN, .now = now };

            memcpy(ev.host, eh->shost, sizeof(n2n_mac_t));
            memcpy(ev.mac, pkt->srcMac, sizeof(n2n_mac_t));
            edge_event_post(eee, &ev);
        }
    }
#endif

    if(eee->tap.network_traffic_filter) {
        if(eee->tap.network_traffic_filter->filter_packet_from_peer(
               eee->tap.network_traffic_filter,
               eee,
               orig_sender,
               eth_payload,
               eth_size) == N2N_DROP) {
            traceEvent(
                TRACE_DEBUG,
                "filtered packet of size %u",
                (unsigned int)eth_size
            );
            return(0);
        }
    }

    /* Write ethernet packet to tap device. */
    traceEvent(TRACE_DEBUG, "sending data of size %u to TAP", (unsigned int)eth_size);
    data_sent_len = tap_write(eee, eth_payload, eth_size);

    if(data_sent_len == eth_size) {
        return 0;
    }

    return -1;
}


#if 0
#ifndef _WIN32

static char *get_ip_from_arp (dec_ip_str_t buf, const n2n_mac_t req_mac) {

    FILE *fd;
    dec_ip_str_t ip_str = {'\0'};
    devstr_t dev_str = {'\0'};
    macstr_t mac_str = {'\0'};
    n2n_mac_t mac = {'\0'};

    strncpy(buf, "0.0.0.0", N2N_NETMASK_STR_SIZE - 1);

    if(is_null_mac(req_mac)) {
        traceEvent(TRACE_DEBUG, "MAC address is null.");
        return buf;
    }

    if(!(fd = fopen("/proc/net/arp", "r"))) {
        traceEvent(TRACE_WARNING, "could not open arp table: %d - %s", errno, strerror(errno));
        return buf;
    }

    while(!feof(fd) && fgetc(fd) != '\n');
    while(!feof(fd) && (fscanf(fd, " %15[0-9.] %*s %*s %17[A-Fa-f0-9:] %*s %15s", ip_str, mac_str, dev_str) == 3)) {
        str2mac(mac, mac_str);
        if(0 == memcmp(mac, req_mac, sizeof(n2n_mac_t))) {
            strncpy(buf, ip_str, N2N_NETMASK_STR_SIZE - 1);
            break;
        }
    }
    fclose(fd);

    return buf;
}

#endif
#endif


// Whether the supernode answers: the last re-registration got its answer
static bool supernode_answers (struct n3n_runtime_data *eee, time_t now) {

    time_t last = SHARED_LOAD(eee->client.last_sup);

    return last && (now - last <= (time_t)eee->conf.client.register_interval * 3 / 2);
}


/* @return 1 if destination is a peer, 0 if destination is supernode */
static int find_peer_destination (struct n3n_runtime_data * eee,
                                  n2n_mac_t mac_address,
                                  n3n_sock_t * destination) {

    struct peer_info *scan;
    macstr_t mac_buf;
    n3n_sock_str_t sockbuf;
    int retval = 0;
    time_t now = time(NULL);

    if(is_multi_broadcast(mac_address)) {
        traceEvent(TRACE_DEBUG, "multicast or broadcast destination peer, using supernode");
        memcpy(destination, &(eee->client.curr_sn->sock), sizeof(n3n_sock_t));
        return(0);
    }

    traceEvent(TRACE_DEBUG, "searching destination socket for %s",
               macaddr_str(mac_buf, mac_address));

    HASH_FIND_PEER(eee->client.known_peers, mac_address, scan);

    if(scan && (scan->last_seen > 0)) {
        if(((now - SHARED_LOAD(scan->last_p2p)) >= (scan->timeout / 2))
           && supernode_answers(eee, now)) {
            /* Too much time passed since we saw the peer, need to register again
             * since the peer address may have changed. */
            struct edge_event ev = { .type = EDGE_EVENT_PEER_EXPIRE, .now = now };

            traceEvent(TRACE_DEBUG, "refreshing idle known peer");
            memcpy(ev.mac, mac_address, sizeof(n2n_mac_t));
            edge_event_post(eee, &ev);
            /* NOTE: registration will be performed upon the receival of the next response packet */
        } else {
            /* Valid known peer found - or one not heard of late, while no
             * supernode answers: it would not find the peer again, so on
             * at its last address (update_supernode_reg() sends it
             * REGISTERs meanwhile) */
            memcpy(destination, &scan->sock, sizeof(n3n_sock_t));
            retval = 1;
        }
    }

    if(retval == 0) {
        memcpy(destination, &(eee->client.curr_sn->sock), sizeof(n3n_sock_t));
        traceEvent(TRACE_DEBUG, "p2p peer %s not found, using supernode",
                   macaddr_str(mac_buf, mac_address));

        if(!query_peer_fast(eee, now, mac_address)) {
            struct edge_event ev = { .type = EDGE_EVENT_QUERY_PEER, .now = now };

            memcpy(ev.mac, mac_address, sizeof(n2n_mac_t));
            edge_event_post(eee, &ev);
        }
    }

    traceEvent(TRACE_DEBUG, "found peer's socket %s [%s]",
               macaddr_str(mac_buf, mac_address),
               sock_to_cstr(sockbuf, destination));

    return retval;
}


/** Send an ecapsulated ethernet PACKET to a destination edge or broadcast MAC
 *    address. */
static int send_packet (struct n3n_runtime_data * eee,
                        n2n_mac_t dstMac,
                        const uint8_t * pktbuf,
                        size_t pktlen) {

    int is_p2p;
    /*ssize_t s; */
    n3n_sock_str_t sockbuf;
    n3n_sock_t destination;
    macstr_t mac_buf;
    struct peer_info *peer, *tmp_peer;

    is_p2p = find_peer_destination(eee, dstMac, &destination);

    traceEvent(TRACE_INFO, "Tx PACKET of %u bytes to %s [%s]",
               pktlen, macaddr_str(mac_buf, dstMac),
               sock_to_cstr(sockbuf, &destination));

    if(is_p2p)
        STATS_INC(eee, tx_p2p);
    else
        STATS_INC(eee, tx_sup);

    if(is_multi_broadcast(dstMac)) {
        STATS_INC(eee, tx_sup_broadcast);

        // if no supernode around, foward the broadcast to all known peers
        if(eee->client.sn_wait) {
            HASH_ITER(hh, eee->client.known_peers, peer, tmp_peer) {
                edge_sendto_sock(eee, pktbuf, pktlen, &peer->sock);
            }
            return 0;
        }
        // fall through otherwise
    }

    edge_sendto_sock(eee, pktbuf, pktlen, &destination);

    return 0;
}


/** A layer-2 packet was received at the tunnel and needs to be sent via UDP. */
/** Encode an ethernet frame into an n3n PDU.
 *
 * Returns the number of bytes written to pktbuf, or 0 if the packet was
 * discarded by policy (e.g. routing rules).  out_destMac receives the n3n
 * destination MAC that should be used to route the PDU.
 */
/* The part of encoding a PACKET that comes before the payload transform: the
 * routing check, working out the destination, compression, and the PACKET
 * header, which is written to the start of pktbuf.
 *
 * Returns the length of that header, or 0 if the frame is not to be sent. On
 * success, *enc_src and *enc_len say what the transform has to encode: the
 * frame itself, or compression_buf if it was worth compressing.
 */
static inline __attribute__((always_inline))
size_t edge_encode_packet_head (struct n3n_runtime_data *eee,
                                uint8_t *tap_pkt, size_t len,
                                uint8_t *pktbuf,
                                n2n_mac_t out_destMac,
                                uint8_t *compression_buf,
                                size_t compression_buf_size,
                                const uint8_t **enc_src,
                                size_t *enc_len) {

    ipstr_t ip_buf;
    n2n_common_t cmn;
    n2n_PACKET_t pkt;
    size_t idx = 0;
    n2n_transform_t tx_transop_idx = eee->client.transop.transform_id;
    ether_hdr_t eh;

    /* unless compression pays off below, the frame itself is what gets
     * encoded */
    *enc_src = tap_pkt;
    *enc_len = len;

    /* tap_pkt is not aligned so we have to copy to aligned memory */
    memcpy(&eh, tap_pkt, sizeof(ether_hdr_t));

    /* Discard IP packets that are not originated by this host */
    if(!(eee->conf.tap.allow_routing)) {
        if(ntohs(eh.type) == 0x0800) {
            /* This is an IP packet from the local source address - not forwarded. */
            // the address is not aligned within the frame
            uint32_t src;
            memcpy(&src, &tap_pkt[ETH_FRAMESIZE + IP4_SRCOFFSET], sizeof(src));

            /* Note: all elements of the_ip are in network order */
            if(src != eee->tap.device.ip_addr) {
                /* This is a packet that needs to be routed */
                traceEvent(TRACE_INFO, "discarding routed packet destined to [%s]",
                           intoa(ntohl(src), ip_buf, sizeof(ip_buf)));
                return 0;
            } else {
                /* This packet is originated by us */
                /* traceEvent(TRACE_INFO, "Sending non-routed packet"); */
            }
        }
    }

    /* Optionally compress then apply transforms, eg encryption. */

    /* Once processed, send to destination in PACKET */

    memcpy(out_destMac, eh.dhost, N2N_MAC_SIZE);
#ifdef HAVE_BRIDGING_SUPPORT
    /* find the destMac behind which edge, and change dest to this edge */
    if((eee->conf.tap.allow_routing) && (!is_multi_broadcast(out_destMac))) {
        struct host_info *host = NULL;
        HASH_FIND(hh, eee->tap.known_hosts, out_destMac, sizeof(n2n_mac_t), host);
        if(host) {
            memcpy(out_destMac, host->edge_addr, N2N_MAC_SIZE);
        }
    }
#endif

    cmn.ttl = N2N_DEFAULT_TTL;
    cmn.pc = MSG_TYPE_PACKET;
    cmn.flags = 0; /* no options, not from supernode, no socket */
    memcpy(cmn.community, eee->conf.community.community_name, N2N_COMMUNITY_SIZE);

    memcpy(pkt.srcMac, eee->tap.device.mac_addr, N2N_MAC_SIZE);
    memcpy(pkt.dstMac, out_destMac, N2N_MAC_SIZE);

    pkt.transform = tx_transop_idx;

    // compression needs to be tried before encode_PACKET is called for compression indication gets encoded there
    pkt.compression = N2N_COMPRESSION_ID_NONE;

    if(eee->conf.community.compression) {
        int32_t compression_len;

        switch(eee->conf.community.compression) {
            case N2N_COMPRESSION_ID_LZO:
                compression_len = eee->client.transop_lzo.fwd(&eee->client.transop_lzo,
                                                              compression_buf, compression_buf_size,
                                                              tap_pkt, len,
                                                              pkt.dstMac);

                if((compression_len > 0) && (compression_len < len)) {
                    pkt.compression = N2N_COMPRESSION_ID_LZO;
                }
                break;

#ifdef HAVE_LIBZSTD
            case N2N_COMPRESSION_ID_ZSTD:
                compression_len = eee->client.transop_zstd.fwd(&eee->client.transop_zstd,
                                                               compression_buf, compression_buf_size,
                                                               tap_pkt, len,
                                                               pkt.dstMac);

                if((compression_len > 0) && (compression_len < len)) {
                    pkt.compression = N2N_COMPRESSION_ID_ZSTD;
                }
                break;
#endif

            default:
                break;
        }

        if(pkt.compression != N2N_COMPRESSION_ID_NONE) {
            traceEvent(TRACE_DEBUG, "payload compression [%s]: compressed %u bytes to %u bytes\n",
                       n3n_compression_id2str(pkt.compression),
                       len, compression_len);
            *enc_src = compression_buf;
            *enc_len = compression_len;
        }
    }

    idx = 0;
    encode_PACKET(pktbuf, &idx, &cmn, &pkt);

    return idx;
}


/* The part of encoding a PACKET that comes after the payload transform: header
 * encryption - which with user-password auth reaches into the transformed
 * payload, so it has to come after it - and the statistics.
 *
 * idx is the length of the header plus the transformed payload, len the
 * length of the original frame. Returns the length of the finished PDU.
 */
static inline __attribute__((always_inline))
size_t edge_encode_packet_tail (struct n3n_runtime_data *eee,
                                uint8_t *pktbuf,
                                size_t headerIdx,
                                size_t idx,
                                size_t len) {

    traceEvent(TRACE_DEBUG, "encode PACKET of %u bytes, %u bytes data, %u bytes overhead, transform %u",
               (u_int)idx, (u_int)len, (u_int)(idx - len), eee->client.transop.transform_id);

    if(eee->conf.community.header_encryption == HEADER_ENCRYPTION_ENABLED)
        // in case of user-password auth, also encrypt the iv of payload assuming ChaCha20 and SPECK having the same iv size
        packet_header_encrypt(pktbuf, headerIdx + (NULL != eee->conf.shared_secret) * MIN(idx - headerIdx, N2N_SPECK_IVEC_SIZE), idx,
                              eee->conf.header_encryption_ctx_dynamic, eee->conf.header_iv_ctx_dynamic,
                              time_stamp());

#ifdef MTU_ASSERT_VALUE
    {
        const u_int eth_udp_overhead = ETH_FRAMESIZE + IP4_MIN_SIZE + UDP_SIZE;

        // MTU assertion which avoids fragmentation by N2N
        assert(idx + eth_udp_overhead <= MTU_ASSERT_VALUE);
    }
#endif

    STATS_INC(eee, transop_tx);

    return idx;
}


size_t edge_encode_packet (struct n3n_runtime_data *eee,
                           uint8_t *tap_pkt, size_t len,
                           uint8_t *pktbuf, size_t pktbuf_size,
                           n2n_mac_t out_destMac) {

    uint8_t compression_buf[N2N_PKT_BUF_SIZE];
    const uint8_t *enc_src;
    size_t enc_len;
    size_t headerIdx;
    size_t idx;

    headerIdx = edge_encode_packet_head(eee, tap_pkt, len, pktbuf, out_destMac,
                                        compression_buf, sizeof(compression_buf),
                                        &enc_src, &enc_len);
    if(!headerIdx) {
        return 0;
    }

    idx = headerIdx;
    idx += eee->client.transop.fwd(&eee->client.transop,
                                   pktbuf + idx, pktbuf_size - idx,
                                   enc_src, enc_len, out_destMac);

    return edge_encode_packet_tail(eee, pktbuf, headerIdx, idx, len);
}


void edge_send_packet2net (struct n3n_runtime_data * eee,
                           uint8_t *tap_pkt, size_t len) {

    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    n2n_mac_t destMac;

    size_t idx = edge_encode_packet(eee, tap_pkt, len, pktbuf, sizeof(pktbuf), destMac);
    if(idx) {
        send_packet(eee, destMac, pktbuf, idx); /* to peer or supernode */
    }
}


/* Open the tap device - with a queue for each thread that is going to handle
 * packets, now that there still are the privileges for that.
 */
int edge_tap_open (struct n3n_runtime_data *eee) {

    eee->tap.device.tun = eee->conf.tap.type == N3N_TUNTAP_TUN;
#ifdef __linux__
    if(eee->conf.tap.fd) {
        return tuntap_take_fd(&eee->tap.device, eee->conf.tap.fd, eee->conf.tap.tuntap_v4, eee->conf.tap.device_mac);
    }
    return tuntap_open_queues(&eee->tap.device, edge_threads_possible(&eee->conf),
                              eee->conf.tap.tuntap_dev_name,
                              eee->conf.tap.tuntap_ip_mode,
                              eee->conf.tap.tuntap_v4,
                              eee->conf.tap.device_mac,
                              eee->conf.tap.mtu,
                              eee->conf.tap.metric);
#else
    return tuntap_open(&eee->tap.device,
                       eee->conf.tap.tuntap_dev_name,
                       eee->conf.tap.tuntap_ip_mode,
                       eee->conf.tap.tuntap_v4,
                       eee->conf.tap.device_mac,
                       eee->conf.tap.mtu,
                       eee->conf.tap.metric);
#endif
}


/* Take one frame off the TAP interface into eth_pkt and decide whether it is
 * to be sent at all (multicast, not yet registered, traffic filter).
 *
 * Returns 1 if a frame was taken off the queue - *out_len is then its length,
 * or 0 if it was dropped here - 0 if the queue was empty and -1 if the device
 * needed to be reopened.
 */
static int edge_tap_take (struct n3n_runtime_data * eee,
                          uint8_t *eth_pkt,
                          size_t *out_len) {

    macstr_t mac_buf;
    ssize_t len;

    /* stays 0 unless a frame is taken that is to be sent */
    *out_len = 0;

    /* tuntap_read() is not a syscall on every platform, so make sure that we
     * do not test a stale errno below */
    errno = 0;

    // a TUN device gives the IP packet, which gets its Ethernet header in
    // front, see tun.c
    if(eee->tap.device.tun) {
        len = tap_read(eee, eth_pkt + 14, N2N_PKT_BUF_SIZE - 14);
    } else {
        len = tap_read(eee, eth_pkt, N2N_PKT_BUF_SIZE);
    }

    if((len < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK))) {
        /* The tap device is opened non blocking, so this just means that
         * there is nothing (more) queued for us */
        return 0;
    }

    if((len <= 0) || (len > N2N_PKT_BUF_SIZE)) {
        // TODO:
        // - how often does this actually happen
        // - why does it happen
        // - can we just remove this special case?
        traceEvent(
            TRACE_WARNING,
            "read()=%d [%d/%s]",
            len,
            errno,
            strerror(errno)
        );
        traceEvent(TRACE_WARNING, "TAP I/O operation aborted, restart later.");
        STATS_INC(eee, tx_tuntap_error);

        if(n3n_thread_slot) {
            edge_threads_tap_error(eee);
        } else {
            edge_tap_reopen(eee);
        }
        return -1;

    }

    if(eee->tap.device.tun) {
        len = tun_to_frame(eee, eth_pkt, len);
        if(!len) {
            // taken, but nothing to send
            return 1;
        }
    }

    const uint8_t * mac = eth_pkt;
    traceEvent(TRACE_DEBUG, "Rx TAP packet (%4d) for %s",
               (signed int)len, macaddr_str(mac_buf, mac));

    if(!eee->conf.tap.allow_multicast &&
       (is_ip6_discovery(eth_pkt, len) ||
        is_ethMulticast(eth_pkt, len))) {
        traceEvent(TRACE_INFO, "dropping Tx multicast");
        STATS_INC(eee, tx_multicast_drop);
        return 1;
    }

    if(!SHARED_LOAD(eee->client.last_sup)) {
        // drop packets before first registration with supernode
        traceEvent(TRACE_DEBUG, "DROP packet before first registration with supernode");
        return 1;
    }

    if(eee->tap.network_traffic_filter) {
        if(eee->tap.network_traffic_filter->filter_packet_from_tap(eee->tap.network_traffic_filter, eee, eth_pkt,
                                                                   len) == N2N_DROP) {
            traceEvent(TRACE_DEBUG, "filtered packet of size %u", (unsigned int)len);
            return 1;
        }
    }

    *out_len = len;
    return 1;
}


/** Read a single packet from the TAP interface, process it and write out the
 *    corresponding packet to the cooked socket.
 *
 * Returns 1 if a frame was taken off the tap queue, 0 if the queue was empty
 * and -1 if the device needed to be reopened.  The caller can use this to
 * drain several frames from one readiness event.
 */
int edge_read_from_tap (struct n3n_runtime_data * eee) {

    /* tun -> remote */
    uint8_t eth_pkt[N2N_PKT_BUF_SIZE];
    size_t len;
    int rc;

    rc = edge_tap_take(eee, eth_pkt, &len);
    if((rc > 0) && len) {
        edge_send_packet2net(eee, eth_pkt, len);
    }

    return rc;
}


/* How many frames edge_read_from_tap_batch() encodes together at most. A
 * multiple of 4, because that is how many packets the AES-NI code encrypts
 * side by side. */
#define EDGE_TX_BATCH 16


/* Scratch space for one batch of outgoing frames. It is always empty again by
 * the time edge_read_from_tap_batch() returns, so it carries no state from one
 * call to the next. Every thread that reads the tap gets its own on first
 * use. */
struct edge_tx_batch {
    int count;
    struct edge_tx_slot {
        uint8_t frame[N2N_PKT_BUF_SIZE];     /* as read from the tap device */
        uint8_t comp[N2N_PKT_BUF_SIZE];      /* the frame compressed, if that paid off */
        uint8_t pdu[N2N_PKT_BUF_SIZE];       /* header and transformed payload */
        size_t len;                          /* of the frame */
        size_t head;                         /* of the header at the start of pdu */
        n2n_mac_t dest;
    } slot[EDGE_TX_BATCH];
    n2n_transform_job_t job[EDGE_TX_BATCH];
};


static N3N_THREAD_LOCAL struct edge_tx_batch *tx_batch;


static void tx_batch_free (void) {

    free(tx_batch);
    tx_batch = NULL;
}


/* Transform every payload in the batch - all at once if the transform has a
 * batched form, one by one if not - then finish and send the packets, in the
 * order their frames were read. */
static void edge_tx_flush (struct n3n_runtime_data *eee, struct edge_tx_batch *b) {

    int i;

    if(b->count == 0) {
        return;
    }

    if(eee->client.transop.fwd_multi && (b->count > 1)) {
        eee->client.transop.fwd_multi(&eee->client.transop, b->job, b->count);
    } else {
        for(i = 0; i < b->count; i++) {
            n2n_transform_job_t *j = &b->job[i];

            j->result = eee->client.transop.fwd(&eee->client.transop,
                                                j->out, j->out_len,
                                                j->in, j->in_len, j->peer_mac);
        }
    }

    for(i = 0; i < b->count; i++) {
        struct edge_tx_slot *s = &b->slot[i];
        size_t idx = s->head;

        idx += b->job[i].result;
        idx = edge_encode_packet_tail(eee, s->pdu, s->head, idx, s->len);
        if(idx) {
            send_packet(eee, s->dest, s->pdu, idx); /* to peer or supernode */
        }
    }

    b->count = 0;
}


/** Read up to max frames from the TAP interface and send them, transforming
 *    them in batches where the transform supports that.
 *
 * This is what the mainloop uses. edge_read_from_tap() is still there, one
 * frame at a time, for the reader thread on Windows.
 *
 * Returns how many frames were taken off the tap queue.
 */
int edge_read_from_tap_batch (struct n3n_runtime_data * eee, int max) {

    struct edge_tx_batch *b = tx_batch;
    int taken = 0;

    if(!b) {
        b = calloc(1, sizeof(struct edge_tx_batch));
        if(!b) {
            return 0;
        }
        tx_batch = b;
        n3n_thread_on_cleanup(tx_batch_free);
    }

    while(taken < max) {
        struct edge_tx_slot *s = &b->slot[b->count];
        n2n_transform_job_t *j = &b->job[b->count];
        const uint8_t *enc_src;
        size_t enc_len;

        if(edge_tap_take(eee, s->frame, &s->len) <= 0) {
            break;
        }
        taken++;

        if(!s->len) {
            /* taken off the queue, but not to be sent */
            continue;
        }

        s->head = edge_encode_packet_head(eee, s->frame, s->len, s->pdu, s->dest,
                                          s->comp, sizeof(s->comp),
                                          &enc_src, &enc_len);
        if(!s->head) {
            continue;
        }

        j->out = s->pdu + s->head;
        j->out_len = sizeof(s->pdu) - s->head;
        j->in = enc_src;
        j->in_len = enc_len;
        j->peer_mac = s->dest;
        j->result = 0;

        if(++b->count == EDGE_TX_BATCH) {
            edge_tx_flush(eee, b);
        }
    }

    edge_tx_flush(eee, b);

    return taken;
}


/* MSG_TYPE_PACKET */
void edge_rx_packet (struct n3n_runtime_data *eee, struct pdu_ctx *c) {

    n2n_common_t cmn = c->cmn;
    uint8_t *udp_buf = c->buf;
    size_t udp_size = c->size;
    size_t rem = c->rem;
    size_t idx = c->idx;
    n3n_sock_t sender = c->sender;
    n3n_sock_t *orig_sender = &sender;
    uint8_t from_supernode = c->from_supernode;
    uint8_t via_multicast = c->via_multicast;
    uint64_t stamp = c->stamp;
    struct peer_info *sn = c->sn;
    n3n_sock_str_t sockbuf1;
    macstr_t mac_buf1;

    /* process PACKET - most frequent so first in list. */
    n2n_PACKET_t pkt;

    // whatever follows the header is the payload, its length is
    // not checked here
    if(decode_PACKET(&pkt, &cmn, udp_buf, &rem, &idx) < 0) {
        traceEvent(TRACE_INFO, "PACKET section in N2N_UDP too short");
        return;
    }

    if(eee->conf.community.header_encryption == HEADER_ENCRYPTION_ENABLED) {
        if(!find_peer_time_stamp_and_verify(
               eee->client.pending_peers,
               eee->client.known_peers,
               sn,
               pkt.srcMac,
               stamp,
               TIME_STAMP_ALLOW_JITTER)) {
            traceEvent(TRACE_DEBUG, "dropped PACKET due to time stamp error");
            return;
        }
    }

    if(!SHARED_LOAD(eee->client.last_sup)) {
        // drop packets received before first registration with supernode
        traceEvent(TRACE_DEBUG, "dropped PACKET recevied before first registration with supernode");
        return;
    }

    if(!from_supernode) {
        /* This is a P2P packet from the peer. We purge a pending
         * registration towards the possibly nat-ted peer address as we now have
         * a valid channel. We still use check_peer_registration_needed in
         * handle_PACKET to double check this.
         */
        traceEvent(TRACE_DEBUG, "[p2p] from %s",
                   macaddr_str(mac_buf1, pkt.srcMac));
        if(peer_is_pending(eee, pkt.srcMac)) {
            struct edge_event ev = { .type = EDGE_EVENT_PENDING_REMOVE };

            memcpy(ev.mac, pkt.srcMac, sizeof(n2n_mac_t));
            edge_event_post(eee, &ev);
        }
    } else {
        /* [PsP] : edge Peer->Supernode->edge Peer */

        if(is_valid_peer_sock(&pkt.sock))
            orig_sender = &(pkt.sock);

        traceEvent(TRACE_DEBUG, "[pSp] from %s via [%s]",
                   macaddr_str(mac_buf1, pkt.srcMac),
                   sock_to_cstr(sockbuf1, &sender));
    }

    /* Update the sender in peer table entry */
    {
        // REVISIT: also consider PORT_REG_COOKIEs when implemented
        n2n_cookie_t cookie = from_supernode ? N2N_FORWARDED_REG_COOKIE : N2N_REGULAR_REG_COOKIE;

        if(!peer_seen_fast(eee, from_supernode, via_multicast, pkt.srcMac, cookie)) {
            struct edge_event ev = {
                .type = EDGE_EVENT_PEER_SEEN,
                .sock = *orig_sender,
                .cookie = cookie,
                .from_supernode = from_supernode,
                .via_multicast = via_multicast,
            };

            memcpy(ev.mac, pkt.srcMac, sizeof(n2n_mac_t));
            edge_event_post(eee, &ev);
        }
    }

    handle_PACKET(eee, from_supernode, &pkt, orig_sender, udp_buf + idx, udp_size - idx);
}
