/*
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The TUN edge's IPv6 neighbour discovery (src/tun.c), on frames made
 * here, for an edge with the address fd00:77::a63:1/64 (its IPv4 address
 * 10.99.0.1 in the lowest 32 bits):
 *
 *   - a packet to an address of the prefix whose MAC is unknown becomes a
 *     neighbour solicitation for it: to its solicited-node multicast
 *     address, with the edge's MAC, a valid checksum and the address asked
 *     for as target - not the multicast address that took its place in the
 *     buffer; another packet to it within the second asks no second time
 *   - what an advertisement tells is learned: the packet then goes to that
 *     MAC
 *   - the MAC of an address of the prefix with an IPv4 address in its
 *     lowest 32 bits comes from the IPv4 table, that of an EUI-64 one from
 *     the address itself; multicast goes to 33:33 and the last 32 bits
 *   - outside the prefix without a gateway, and without an IPv6 address of
 *     the edge's own, nothing goes out
 *   - a solicitation for the edge's address is answered by the edge, not
 *     handed to the device
 *
 * The output is the same on every system and byte order.
 */

#include <n3n/edge.h>           // for edge_init_conf_defaults
#include <n3n/initfuncs.h>      // for n3n_initfuncs
#include <n3n/logging.h>        // for setTraceLevel
#include <stdio.h>              // for printf
#include <string.h>             // for memcpy, memcmp, memset
#include "n2n.h"                // for struct n3n_runtime_data
#include "../src/peer_info.h"   // for struct peer_info
#include "../src/tun.h"         // for tun_from_frame, tun_to_frame

#ifdef _WIN32
#include "../src/win32/defs.h"
#else
#include <arpa/inet.h>          // for htonl, inet_pton
#include <sys/socket.h>         // for AF_INET, AF_INET6
#endif

static struct n3n_runtime_data eee;
static struct peer_info supernode;
static int failed;
static int written;             // what reached the (stubbed) device

static const uint8_t own_mac[6] = {0x02, 0x00, 0x00, 0x99, 0x00, 0x01};
static const uint8_t peer_mac[6] = {0x02, 0x00, 0x00, 0x99, 0x00, 0x02};

static int write_sink (struct n3n_runtime_data *rt, uint8_t *buf, int len) {

    written++;
    return len;
}

static void check (const char *what, int ok) {
    printf("%s: %s\n", what, ok ? "ok" : "FAIL");
    failed |= !ok;
}

static void addr6 (uint8_t *to, const char *text) {

    inet_pton(AF_INET6, text, to);
}

// An echo request from the edge to dst, as from the device, at buf + 14;
// its length
static size_t echo (uint8_t *buf, const char *dst) {

    uint8_t *p = buf + 14;

    memset(p, 0, 48);
    p[0] = 0x60;
    p[5] = 8;                   // payload length
    p[6] = 58;                  // ICMPv6
    p[7] = 64;
    addr6(p + 8, "fd00:77::a63:1");
    addr6(p + 24, dst);
    p[40] = 128;                // echo request
    return 48;
}

// The ICMPv6 checksum of a frame checks out
static int checksum_ok (const uint8_t *frame, size_t len) {

    const uint8_t *ip = frame + 14;
    size_t plen = len - 14 - 40;
    uint32_t sum = plen + 58;

    for(int i = 0; i < 32; i += 2) {
        sum += (ip[8 + i] << 8) | ip[8 + i + 1];
    }
    for(size_t i = 0; i < plen; i += 2) {
        sum += (ip[40 + i] << 8) | ((i + 1 < plen) ? ip[40 + i + 1] : 0);
    }
    while(sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return sum == 0xffff;
}

// A neighbour solicitation (135) or advertisement (136) from a peer about
// target, with its link-layer address option, as it comes from the network
static size_t nd_from_peer (uint8_t *frame, uint8_t type, const char *src,
                            const char *dst, const uint8_t *eth_dst, const char *target) {

    uint8_t *ip = frame + 14;
    uint8_t *icmp = ip + 40;

    memcpy(frame, eth_dst, 6);
    memcpy(frame + 6, peer_mac, 6);
    frame[12] = 0x86;
    frame[13] = 0xdd;
    memset(ip, 0, 40 + 32);
    ip[0] = 0x60;
    ip[5] = 32;
    ip[6] = 58;
    ip[7] = 255;
    addr6(ip + 8, src);
    addr6(ip + 24, dst);
    icmp[0] = type;
    addr6(icmp + 8, target);
    icmp[24] = (type == 135) ? 1 : 2;
    icmp[25] = 1;
    memcpy(icmp + 26, peer_mac, 6);
    return 14 + 40 + 32;
}

int main (int argc, char *argv[]) {

    static uint8_t buf[2048];
    static const uint8_t solicited_mac[6] = {0x33, 0x33, 0xff, 0x00, 0x0b, 0x0b};
    uint8_t want[16];
    size_t n;

    setTraceLevel(-1);
    n3n_initfuncs();
    edge_init_conf_defaults(&eee.conf, "_TEST");
    eee.conf.is_edge = true;
    eee.conf.tap.type = N3N_TUNTAP_TUN;
    eee.sock = -1;               // what the edge sends goes nowhere
    eee.tap.device.tun = true;
    eee.tap.device.ip_addr = htonl(0x0a630001);
    memcpy(eee.tap.device.mac_addr, own_mac, 6);
    eee.conf.tap.tuntap_v4.net_bitlen = 24;
    supernode.sock.family = AF_INET;
    eee.client.curr_sn = &supernode;
    n2n_transop_null_init(&eee.conf, &eee.client.transop);

    // without an IPv6 address of its own
    n = tun_to_frame(&eee, buf, echo(buf, "fd00:77::b0b"));
    check("without an address of its own: nothing out", n == 0);

    addr6(eee.tap.ip6, "fd00:77::a63:1");
    eee.tap.ip6_len = 64;
    eee.tap.has_ip6 = true;

    // a solicitation instead of the packet
    n = tun_to_frame(&eee, buf, echo(buf, "fd00:77::b0b"));
    addr6(want, "fd00:77::b0b");
    check("unknown: a solicitation", (n == 14 + 40 + 32) && (buf[14 + 40] == 135));
    check("solicitation: to the solicited-node MAC, from the edge's",
          !memcmp(buf, solicited_mac, 6) && !memcmp(buf + 6, own_mac, 6));
    addr6(want, "ff02::1:ff00:b0b");
    check("solicitation: to the solicited-node address, hop limit 255",
          !memcmp(buf + 14 + 24, want, 16) && (buf[14 + 7] == 255));
    addr6(want, "fd00:77::b0b");
    check("solicitation: the address asked for as target", !memcmp(buf + 14 + 40 + 8, want, 16));
    check("solicitation: the edge's MAC as source link-layer address",
          (buf[14 + 40 + 24] == 1) && !memcmp(buf + 14 + 40 + 26, own_mac, 6));
    check("solicitation: the checksum", checksum_ok(buf, n));
    n = tun_to_frame(&eee, buf, echo(buf, "fd00:77::b0b"));
    check("asked within the second: not again", n == 0);

    // the advertisement: learned
    n = nd_from_peer(buf, 136, "fd00:77::b0b", "fd00:77::a63:1", own_mac, "fd00:77::b0b");
    written = 0;
    tun_from_frame(&eee, buf, n, write_sink);
    check("an advertisement: not for the device", written == 0);
    n = tun_to_frame(&eee, buf, echo(buf, "fd00:77::b0b"));
    check("advertised: the packet to its MAC",
          (n == 14 + 48) && !memcmp(buf, peer_mac, 6) && (buf[12] == 0x86) && (buf[13] == 0xdd));

    // the IPv4 table, from an ARP reply of 10.99.0.3
    {
        uint8_t arp[14 + 28];
        static const uint8_t mac3[6] = {0x02, 0x00, 0x00, 0x99, 0x00, 0x03};
        memcpy(arp, own_mac, 6);
        memcpy(arp + 6, mac3, 6);
        arp[12] = 0x08; arp[13] = 0x06;
        uint8_t *a = arp + 14;
        a[0] = 0; a[1] = 1; a[2] = 0x08; a[3] = 0x00; a[4] = 6; a[5] = 4; a[6] = 0; a[7] = 2;
        memcpy(a + 8, mac3, 6);
        a[14] = 10; a[15] = 99; a[16] = 0; a[17] = 3;
        memcpy(a + 18, own_mac, 6);
        a[24] = 10; a[25] = 99; a[26] = 0; a[27] = 1;
        tun_from_frame(&eee, arp, sizeof(arp), write_sink);
        n = tun_to_frame(&eee, buf, echo(buf, "fd00:77::a63:3"));
        check("the IPv4 address in it: its MAC from the IPv4 table",
              (n == 14 + 48) && !memcmp(buf, mac3, 6));
    }

    // an EUI-64 interface ID: the MAC from the address
    {
        static const uint8_t mac4[6] = {0x02, 0x00, 0x00, 0x99, 0x00, 0x04};
        n = tun_to_frame(&eee, buf, echo(buf, "fe80::ff:fe99:4"));
        check("an EUI-64 interface ID: the MAC from the address", (n == 14 + 48) && !memcmp(buf, mac4, 6));
    }

    // multicast, and outside the prefix
    {
        static const uint8_t all_nodes[6] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x01};
        n = tun_to_frame(&eee, buf, echo(buf, "ff02::1"));
        check("multicast: 33:33 and the last 32 bits", (n == 14 + 48) && !memcmp(buf, all_nodes, 6));
        n = tun_to_frame(&eee, buf, echo(buf, "2001:db8::1"));
        check("outside the prefix, no gateway: nothing out", n == 0);
    }

    // a solicitation for the edge's address: the edge's to answer
    n = nd_from_peer(buf, 135, "fd00:77::b0b", "ff02::1:ff63:1",
                     (const uint8_t *)"\x33\x33\xff\x63\x00\x01", "fd00:77::a63:1");
    written = 0;
    tun_from_frame(&eee, buf, n, write_sink);
    check("a solicitation for the edge: not for the device", written == 0);

    // and an IPv6 packet for the edge does reach the device
    n = nd_from_peer(buf, 135, "fd00:77::b0b", "fd00:77::a63:1", own_mac, "fd00:77::a63:1");
    buf[14 + 7] = 64;           // not neighbour discovery: hop limit not 255
    written = 0;
    tun_from_frame(&eee, buf, n, write_sink);
    check("an IPv6 packet for the edge: to the device", written == 1);

    // the kinds of destination MAC (n2n.c), for the frames a TUN edge
    // builds and those of TAP edges alike: to every edge of the community
    // (broadcast and multicast), or to none (IEEE 802.1 link-local)
    {
        static const struct {
            const char *what;
            uint8_t mac[6];
            int to_all;
            int link_local;
        } kinds[] = {
            {"broadcast", {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 1, 0},
            {"IPv4 multicast (SSDP)", {0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa}, 1, 0},
            {"IPv6 multicast", {0x33, 0x33, 0x00, 0x00, 0x00, 0x0c}, 1, 0},
            {"NetBEUI's NetBIOS", {0x03, 0x00, 0x00, 0x00, 0x00, 0x01}, 1, 0},
            {"PROFINET DCP", {0x01, 0x0e, 0xcf, 0x00, 0x00, 0x00}, 1, 0},
            {"AppleTalk", {0x09, 0x00, 0x07, 0xff, 0xff, 0xff}, 1, 0},
            {"spanning tree", {0x01, 0x80, 0xc2, 0x00, 0x00, 0x00}, 0, 1},
            {"pause frames", {0x01, 0x80, 0xc2, 0x00, 0x00, 0x01}, 0, 1},
            {"LLDP", {0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}, 0, 1},
            {"the last link-local one", {0x01, 0x80, 0xc2, 0x00, 0x00, 0x0f}, 0, 1},
            {"the first after them", {0x01, 0x80, 0xc2, 0x00, 0x00, 0x10}, 1, 0},
            {"a peer's", {0x02, 0x00, 0x00, 0x99, 0x00, 0x02}, 0, 0},
        };
        char what[80];

        for(size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
            snprintf(what, sizeof(what), "destination MAC: %s, %s", kinds[i].what,
                     kinds[i].to_all ? "to all" : kinds[i].link_local ? "never" : "unicast");
            check(what, (!!is_multi_broadcast(kinds[i].mac) == kinds[i].to_all)
                  && (!!is_link_local_mac(kinds[i].mac) == kinds[i].link_local));
        }
    }

    return failed;
}
