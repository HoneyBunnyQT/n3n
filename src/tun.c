/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The edge with a TUN device (tuntap.type = tun): the device carries IP
 * packets, the community Ethernet frames, as with a TAP device.  So the edge
 * does what the kernel does for a TAP device:
 *
 * - an IP packet from the device gets an Ethernet header: the edge's own MAC
 *   as source, as destination the MAC of the address - broadcast and
 *   multicast ones by rule, the others from what the peers announce of
 *   themselves (their address in REGISTER and REGISTER_SUPER), or from ARP:
 *   unknown, the edge sends an ARP request instead, and the packet is lost,
 *   as the kernel would drop it after a while
 * - a frame for the edge loses its Ethernet header and goes to the device;
 *   an ARP request for the edge's address is answered by the edge itself
 *
 * and for IPv6, with an address of the edge's own (tuntap.address6), the
 * same with neighbour discovery (RFC 4861), IPv6's ARP:
 *
 * - the MAC of an IPv6 address from what was learned, from the IPv4 table
 *   for an address of the edge's prefix with an IPv4 address in its lowest
 *   32 bits, from the address itself for an interface ID made of a MAC
 *   (modified EUI-64, as link-local addresses are), or else by asking: a
 *   neighbour solicitation goes out instead of the packet
 * - a neighbour solicitation for the edge's address is answered with an
 *   advertisement by the edge itself
 *
 * See docs/develop/MobileAndTun.md and docs/develop/IPv6.md.
 */

#include <n3n/ethernet.h>       // for is_null_mac
#include <n3n/logging.h>        // for traceEvent
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "n2n.h"
#include "n2n_typedefs.h"
#include "peer_info.h"
#include "role_tap.h"           // for edge_send_packet2net
#include "tun.h"
#include "uthash.h"

#define ETH_HLEN        14
#define ETH_P_IPV4      0x0800
#define ETH_P_ARP       0x0806
#define ETH_P_IPV6      0x86dd
#define ARP_LEN         28      // the ARP message for IPv4 over Ethernet
#define IP6_HLEN        40
#define IPPROTO_ICMP6   58
#define ND_SOLICIT      135
#define ND_ADVERT       136
#define ND_LEN          32      // a solicitation or advertisement with a link-layer address



static struct n3n_tun_arp *arp_slot (struct n3n_runtime_data *eee, uint32_t ip) {

    uint32_t h = ip;

    h ^= h >> 16;
    h *= 0x45d9f3b;
    h ^= h >> 16;
    return &eee->tap.tun_arp[h % N3N_TUN_ARP_SLOTS];
}


static void arp_learn (struct n3n_runtime_data *eee, uint32_t ip, const uint8_t *mac) {

    struct n3n_tun_arp *e;

    if(!ip || (ip == 0xffffffff) || (mac[0] & 0x01) || is_null_mac(mac)) {
        return;
    }
    e = arp_slot(eee, ip);
    e->ip = ip;
    memcpy(e->mac, mac, sizeof(n2n_mac_t));
    e->known = true;
}


// The MAC of ip, from the table or from what the peers announced
static bool arp_find (struct n3n_runtime_data *eee, uint32_t ip, n2n_mac_t mac) {

    struct n3n_tun_arp *e = arp_slot(eee, ip);
    struct peer_info *peer, *tmp;
    struct peer_info *tables[2] = {eee->client.known_peers, eee->client.pending_peers};

    if(e->known && (e->ip == ip)) {
        memcpy(mac, e->mac, sizeof(n2n_mac_t));
        return true;
    }
    for(int t = 0; t < 2; t++) {
        HASH_ITER(hh, tables[t], peer, tmp) {
            if(peer->dev_addr.net_addr && (htonl(peer->dev_addr.net_addr) == ip)) {
                memcpy(mac, peer->mac_addr, sizeof(n2n_mac_t));
                arp_learn(eee, ip, mac);
                return true;
            }
        }
    }
    return false;
}


static void eth_header (uint8_t *frame, const uint8_t *dst, const uint8_t *src, uint16_t type) {

    memcpy(frame, dst, 6);
    memcpy(frame + 6, src, 6);
    frame[12] = type >> 8;
    frame[13] = type & 0xff;
}


// An ARP message (op 1 request, 2 reply) after an Ethernet header to dst
static size_t arp_frame (uint8_t *frame, const uint8_t *dst, uint16_t op,
                         const uint8_t *sha, uint32_t spa, const uint8_t *tha, uint32_t tpa) {

    uint8_t *a = frame + ETH_HLEN;

    eth_header(frame, dst, sha, ETH_P_ARP);
    a[0] = 0; a[1] = 1;                 // Ethernet
    a[2] = 0x08; a[3] = 0x00;           // IPv4
    a[4] = 6; a[5] = 4;
    a[6] = 0; a[7] = op;
    memcpy(a + 8, sha, 6);
    memcpy(a + 14, &spa, 4);
    memcpy(a + 18, tha, 6);
    memcpy(a + 24, &tpa, 4);
    return ETH_HLEN + ARP_LEN;
}


static struct n3n_tun_nd *nd_slot (struct n3n_runtime_data *eee, const uint8_t *ip6) {

    uint32_t h;

    memcpy(&h, ip6 + 12, 4);
    h ^= h >> 16;
    h *= 0x45d9f3b;
    h ^= h >> 16;
    return &eee->tap.tun_nd[h % N3N_TUN_ND_SLOTS];
}


static void nd_learn (struct n3n_runtime_data *eee, const uint8_t *ip6, const uint8_t *mac) {

    static const uint8_t unspecified[16] = {0};
    struct n3n_tun_nd *e;

    if((ip6[0] == 0xff) || !memcmp(ip6, unspecified, 16) || (mac[0] & 0x01) || is_null_mac(mac)) {
        return;
    }
    e = nd_slot(eee, ip6);
    memcpy(e->ip6, ip6, 16);
    memcpy(e->mac, mac, sizeof(n2n_mac_t));
    e->known = true;
}


// Whether ip6 is in the edge's prefix
static bool in_prefix (const struct n3n_runtime_data *eee, const uint8_t *ip6) {

    int bits = eee->tap.ip6_len;

    if(!eee->tap.has_ip6 || memcmp(ip6, eee->tap.ip6, bits / 8)) {
        return false;
    }
    return !(bits % 8) || !((ip6[bits / 8] ^ eee->tap.ip6[bits / 8]) & (0xff00 >> (bits % 8)));
}


// The MAC of ip6, from what was learned or from the address itself
static bool nd_find (struct n3n_runtime_data *eee, const uint8_t *ip6, n2n_mac_t mac) {

    static const uint8_t zero[4] = {0};
    struct n3n_tun_nd *e = nd_slot(eee, ip6);

    if(e->known && !memcmp(e->ip6, ip6, 16)) {
        memcpy(mac, e->mac, sizeof(n2n_mac_t));
        return true;
    }
    // an address of the prefix with an IPv4 address in its lowest 32 bits,
    // as tuntap.address6 = auto makes them
    if(in_prefix(eee, ip6) && !memcmp(ip6 + 8, zero, 4)) {
        uint32_t v4;
        memcpy(&v4, ip6 + 12, 4);
        if(arp_find(eee, v4, mac)) {
            nd_learn(eee, ip6, mac);
            return true;
        }
    }
    // an interface ID made of a MAC: ff:fe in its middle
    if((ip6[11] == 0xff) && (ip6[12] == 0xfe) && !((ip6[8] ^ 0x02) & 0x01)) {
        mac[0] = ip6[8] ^ 0x02;
        mac[1] = ip6[9];
        mac[2] = ip6[10];
        mac[3] = ip6[13];
        mac[4] = ip6[14];
        mac[5] = ip6[15];
        return true;
    }
    return false;
}


// The checksum of an ICMPv6 message, with the pseudo header (RFC 8200)
static uint16_t icmp6_checksum (const uint8_t *src, const uint8_t *dst, const uint8_t *msg, size_t len) {

    uint32_t sum = len + IPPROTO_ICMP6;

    for(int i = 0; i < 16; i += 2) {
        sum += (src[i] << 8) | src[i + 1];
        sum += (dst[i] << 8) | dst[i + 1];
    }
    for(size_t i = 0; i < len; i += 2) {
        sum += (msg[i] << 8) | ((i + 1 < len) ? msg[i + 1] : 0);
    }
    while(sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~sum;
}


// A neighbour solicitation (to the address's solicited-node multicast
// address) or advertisement (to dst) about target, after an Ethernet header,
// with the edge's MAC as link-layer address
static size_t nd_frame (struct n3n_runtime_data *eee, uint8_t *frame, uint8_t type,
                        const uint8_t *eth_dst, const uint8_t *dst, const uint8_t *target, uint32_t flags) {

    uint8_t *ip = frame + ETH_HLEN;
    uint8_t *icmp = ip + IP6_HLEN;
    uint8_t mcast[16] = {0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xff};
    uint8_t mcast_mac[6] = {0x33, 0x33, 0xff};
    uint8_t to[16], about[16];
    uint8_t eth_to[6];

    // copies: they may point into frame, at the packet that the
    // solicitation takes the place of
    memcpy(about, target, 16);
    target = about;
    if(dst) {
        memcpy(to, dst, 16);
        dst = to;
    }
    if(eth_dst) {
        memcpy(eth_to, eth_dst, 6);
        eth_dst = eth_to;
    }

    if(type == ND_SOLICIT) {
        memcpy(mcast + 13, target + 13, 3);
        memcpy(mcast_mac + 3, target + 13, 3);
        dst = mcast;
        eth_dst = mcast_mac;
    }
    eth_header(frame, eth_dst, eee->tap.device.mac_addr, ETH_P_IPV6);

    memset(ip, 0, IP6_HLEN);
    ip[0] = 0x60;
    ip[4] = 0;
    ip[5] = ND_LEN;
    ip[6] = IPPROTO_ICMP6;
    ip[7] = 255;                        // the hop limit neighbour discovery wants
    memcpy(ip + 8, eee->tap.ip6, 16);
    memcpy(ip + 24, dst, 16);

    memset(icmp, 0, ND_LEN);
    icmp[0] = type;
    icmp[4] = flags >> 24;
    memcpy(icmp + 8, target, 16);
    icmp[24] = (type == ND_SOLICIT) ? 1 : 2;   // source / target link-layer address
    icmp[25] = 1;                               // in units of 8 bytes
    memcpy(icmp + 26, eee->tap.device.mac_addr, 6);
    uint16_t sum = icmp6_checksum(ip + 8, ip + 24, icmp, ND_LEN);
    icmp[2] = sum >> 8;
    icmp[3] = sum & 0xff;
    return ETH_HLEN + IP6_HLEN + ND_LEN;
}


// A neighbour solicitation or advertisement that came in: answered if it
// asks for the edge's address, learned from
static void nd_in (struct n3n_runtime_data *eee, const uint8_t *frame, int len) {

    static const uint8_t unspecified[16] = {0};
    static const uint8_t all_nodes[16] = {0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
    static const uint8_t all_nodes_mac[6] = {0x33, 0x33, 0, 0, 0, 0x01};
    const uint8_t *ip = frame + ETH_HLEN;
    const uint8_t *icmp = ip + IP6_HLEN;
    const uint8_t *src = ip + 8;
    const uint8_t *target = icmp + 8;
    const uint8_t *lladdr = frame + 6;

    // the link-layer address option, if there is one
    for(int at = 24; at + 8 <= len - ETH_HLEN - IP6_HLEN; at += icmp[at + 1] * 8) {
        if(!icmp[at + 1]) {
            break;
        }
        if(((icmp[0] == ND_SOLICIT) && (icmp[at] == 1)) || ((icmp[0] == ND_ADVERT) && (icmp[at] == 2))) {
            lladdr = icmp + at + 2;
        }
    }

    if(icmp[0] == ND_ADVERT) {
        nd_learn(eee, target, lladdr);
        return;
    }
    if(memcmp(src, unspecified, 16)) {
        nd_learn(eee, src, lladdr);
    }
    if(!eee->tap.has_ip6 || memcmp(target, eee->tap.ip6, 16)) {
        return;
    }

    uint8_t reply[ETH_HLEN + IP6_HLEN + ND_LEN];
    size_t n;
    if(memcmp(src, unspecified, 16)) {
        // solicited, and the address is the edge's to override
        n = nd_frame(eee, reply, ND_ADVERT, lladdr, src, eee->tap.ip6, 0x60000000);
    } else {
        // a duplicate address check: to all, not solicited
        n = nd_frame(eee, reply, ND_ADVERT, all_nodes_mac, all_nodes, eee->tap.ip6, 0x20000000);
    }
    edge_send_packet2net(eee, reply, n);
}


size_t tun_to_frame (struct n3n_runtime_data *eee, uint8_t *buf, size_t len) {

    const uint8_t *pkt = buf + ETH_HLEN;
    const uint8_t *own = eee->tap.device.mac_addr;
    uint32_t own_ip = eee->tap.device.ip_addr;
    n2n_mac_t dst;

    if(len < 1) {
        return 0;
    }

    if((pkt[0] >> 4) == 4) {
        uint32_t ip;
        uint32_t mask = eee->conf.tap.tuntap_v4.net_bitlen ?
                        htonl(~((1u << (32 - eee->conf.tap.tuntap_v4.net_bitlen)) - 1)) : 0;

        if(len < 20) {
            return 0;
        }
        memcpy(&ip, pkt + 16, 4);

        if((ip == 0xffffffff) || (mask && ((ip & ~mask) == ~mask) && ((ip & mask) == (own_ip & mask)))) {
            memcpy(dst, broadcast_mac, 6);
        } else if((pkt[16] & 0xf0) == 0xe0) {
            // 224.0.0.0/4: 01:00:5e and the low 23 bits
            dst[0] = 0x01; dst[1] = 0x00; dst[2] = 0x5e;
            dst[3] = pkt[17] & 0x7f; dst[4] = pkt[18]; dst[5] = pkt[19];
        } else {
            // the next hop: the address itself within the subnet, the
            // gateway (tuntap.gateway) for anything outside it
            uint32_t hop = ip;

            if(mask && ((ip & mask) != (own_ip & mask))) {
                if(!eee->conf.tap.gateway.net_addr) {
                    traceEvent(TRACE_DEBUG, "tun: no route for a packet outside the community's subnet");
                    return 0;
                }
                hop = eee->conf.tap.gateway.net_addr;
            }
            if(!arp_find(eee, hop, dst)) {
                struct n3n_tun_arp *e = arp_slot(eee, hop);
                time_t now = time(NULL);

                // ask, at most once a second for an address
                if((e->ip == hop) && (now - e->asked < 1)) {
                    return 0;
                }
                e->ip = hop;
                e->known = false;
                e->asked = now;
                return arp_frame(buf, broadcast_mac, 1, own, own_ip, (const uint8_t *)"\0\0\0\0\0\0", hop);
            }
        }
        eth_header(buf, dst, own, ETH_P_IPV4);
        return ETH_HLEN + len;
    }

    if((pkt[0] >> 4) == 6) {
        if(len < 40) {
            return 0;
        }
        const uint8_t *ip6 = pkt + 24;

        if(ip6[0] == 0xff) {
            // ff00::/8: 33:33 and the last 32 bits
            dst[0] = 0x33; dst[1] = 0x33;
            memcpy(dst + 2, pkt + 36, 4);
            eth_header(buf, dst, own, ETH_P_IPV6);
            return ETH_HLEN + len;
        }
        if(!eee->tap.has_ip6) {
            traceEvent(TRACE_DEBUG, "tun: IPv6 unicast needs tuntap.address6");
            return 0;
        }
        bool link_local = (ip6[0] == 0xfe) && ((ip6[1] & 0xc0) == 0x80);
        if(!link_local && !in_prefix(eee, ip6)) {
            // the next hop for anything outside the prefix: the gateway,
            // whose MAC its IPv4 address gives
            if(!eee->conf.tap.gateway.net_addr) {
                traceEvent(TRACE_DEBUG, "tun: no route for a packet outside the edge's IPv6 prefix");
                return 0;
            }
            if(!arp_find(eee, eee->conf.tap.gateway.net_addr, dst)) {
                return 0;
            }
        } else if(!nd_find(eee, ip6, dst)) {
            struct n3n_tun_nd *e = nd_slot(eee, ip6);
            time_t now = time(NULL);

            // ask, at most once a second for an address
            if(!memcmp(e->ip6, ip6, 16) && (now - e->asked < 1)) {
                return 0;
            }
            memcpy(e->ip6, ip6, 16);
            e->known = false;
            e->asked = now;
            return nd_frame(eee, buf, ND_SOLICIT, NULL, NULL, ip6, 0);
        }
        eth_header(buf, dst, own, ETH_P_IPV6);
        return ETH_HLEN + len;
    }

    return 0;
}


int tun_from_frame (struct n3n_runtime_data *eee, const uint8_t *frame, int len,
                    int (*write_fn)(struct n3n_runtime_data *eee, uint8_t *buf, int len)) {

    const uint8_t *own = eee->tap.device.mac_addr;
    uint32_t own_ip = eee->tap.device.ip_addr;
    uint16_t type;

    if(len < ETH_HLEN) {
        return len;
    }
    type = (frame[12] << 8) | frame[13];

    if(type == ETH_P_ARP) {
        const uint8_t *a = frame + ETH_HLEN;
        uint32_t spa, tpa;

        if((len < ETH_HLEN + ARP_LEN) || (a[1] != 1) || (a[2] != 0x08) || (a[3] != 0x00) || (a[4] != 6) || (a[5] != 4)) {
            return len;
        }
        memcpy(&spa, a + 14, 4);
        memcpy(&tpa, a + 24, 4);
        arp_learn(eee, spa, a + 8);
        if((a[7] == 1) && own_ip && (tpa == own_ip)) {
            uint8_t reply[ETH_HLEN + ARP_LEN];
            size_t n = arp_frame(reply, a + 8, 2, own, own_ip, a + 8, spa);
            edge_send_packet2net(eee, reply, n);
        }
        return len;
    }

    // for the edge, or for all
    if(memcmp(frame, own, 6) && !(frame[0] & 0x01)) {
        return len;
    }

    if(type == ETH_P_IPV4) {
        uint32_t src;

        if(len >= ETH_HLEN + 20) {
            memcpy(&src, frame + ETH_HLEN + 12, 4);
            arp_learn(eee, src, frame + 6);
        }
    } else if(type == ETH_P_IPV6) {
        const uint8_t *ip = frame + ETH_HLEN;

        if(len < ETH_HLEN + IP6_HLEN) {
            return len;
        }
        // neighbour discovery, as ARP above: the edge's, not the device's
        if((ip[6] == IPPROTO_ICMP6) && (ip[7] == 255) && (len >= ETH_HLEN + IP6_HLEN + 24)
           && ((ip[IP6_HLEN] == ND_SOLICIT) || (ip[IP6_HLEN] == ND_ADVERT))) {
            nd_in(eee, frame, len);
            return len;
        }
        nd_learn(eee, ip + 8, frame + 6);
    } else {
        return len;
    }

    int n = write_fn(eee, (uint8_t *)frame + ETH_HLEN, len - ETH_HLEN);
    return (n == len - ETH_HLEN) ? len : n;
}
