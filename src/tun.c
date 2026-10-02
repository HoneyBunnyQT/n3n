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
 * IPv4 only for now: IPv6 multicast goes out, IPv6 coming in reaches the
 * device, but IPv6 unicast out needs neighbour discovery, which is not
 * here yet.  See docs/develop/MobileAndTun.md.
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
        } else if(!arp_find(eee, ip, dst)) {
            struct n3n_tun_arp *e = arp_slot(eee, ip);
            time_t now = time(NULL);

            if(mask && ((ip & mask) != (own_ip & mask))) {
                traceEvent(TRACE_DEBUG, "tun: no route for a packet outside the community's subnet");
                return 0;
            }
            // ask, at most once a second for an address
            if((e->ip == ip) && (now - e->asked < 1)) {
                return 0;
            }
            e->ip = ip;
            e->known = false;
            e->asked = now;
            return arp_frame(buf, broadcast_mac, 1, own, own_ip, (const uint8_t *)"\0\0\0\0\0\0", ip);
        }
        eth_header(buf, dst, own, ETH_P_IPV4);
        return ETH_HLEN + len;
    }

    if((pkt[0] >> 4) == 6) {
        if(len < 40) {
            return 0;
        }
        if(pkt[24] == 0xff) {
            // ff00::/8: 33:33 and the last 32 bits
            dst[0] = 0x33; dst[1] = 0x33;
            memcpy(dst + 2, pkt + 36, 4);
            eth_header(buf, dst, own, ETH_P_IPV6);
            return ETH_HLEN + len;
        }
        traceEvent(TRACE_DEBUG, "tun: IPv6 unicast is not supported yet");
        return 0;
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
    } else if(type != ETH_P_IPV6) {
        return len;
    }

    int n = write_fn(eee, (uint8_t *)frame + ETH_HLEN, len - ETH_HLEN);
    return (n == len - ETH_HLEN) ? len : n;
}
