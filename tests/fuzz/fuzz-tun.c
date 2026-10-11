/*
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Fuzz target: the TUN edge (src/tun.c), which plays the part of the
 * kernel's Ethernet and ARP for an edge whose device carries IP packets.
 * Two directions, the first byte of the input picks which:
 *
 * - tun_from_frame(): a frame from the network (a peer), as role_tap
 *   hands it over - the untrusted side.  ARP is parsed and answered or
 *   learned from, an IP packet for this edge loses its header and goes to
 *   the (stubbed) device.
 * - tun_to_frame(): an IP packet from the device gets an Ethernet header,
 *   or becomes an ARP request.  The device is local, but a malformed
 *   packet should not crash the edge either.
 *
 * The edge is set up as its defaults make it, in TUN mode, with a fixed
 * MAC and address and no socket (eee->sock = -1): the ARP reply that
 * tun_from_frame() may send is built and encoded, but edge_sendto_sock()
 * drops it rather than touch a socket.  See README.md.
 */

#include <arpa/inet.h>          // for htonl
#include <sys/socket.h>         // for AF_INET
#include <n3n/edge.h>           // for edge_init_conf_defaults
#include <n3n/initfuncs.h>      // for n3n_initfuncs
#include <n3n/logging.h>        // for setTraceLevel
#include <string.h>             // for memcpy
#include "fuzz.h"
#include "n2n.h"                // for struct n3n_runtime_data, transop null
#include "peer_info.h"          // for struct peer_info
#include "tun.h"                // for tun_from_frame, tun_to_frame

#define OWN_IP   0x0a000001     // 10.0.0.1, network order set below

static struct n3n_runtime_data eee;
static struct peer_info supernode;

// where a frame for the device would go: a copy, so a read past the end
// of what tun_from_frame() hands over shows under AddressSanitizer
static int write_sink (struct n3n_runtime_data *rt, uint8_t *buf, int len) {

    static uint8_t sink[N2N_PKT_BUF_SIZE];

    (void)rt;
    if(len < 0) {
        __builtin_trap();
    }
    if(len > (int)sizeof(sink)) {
        len = sizeof(sink);
    }
    memcpy(sink, buf, len);
    return len;
}

int LLVMFuzzerInitialize (int *argc, char ***argv) {

    // what the code logs about bad input: not the point here, and slow
    setTraceLevel(-1);
    n3n_initfuncs();

    edge_init_conf_defaults(&eee.conf, "_FUZZ");
    eee.conf.is_edge = true;
    eee.conf.tap.type = N3N_TUNTAP_TUN;
    eee.sock = -1;               // edge_sendto_sock() then drops, no syscall
    eee.tap.device.tun = true;
    eee.tap.device.ip_addr = htonl(OWN_IP);
    memcpy(eee.tap.device.mac_addr,
           "\x02\x00\x00\x00\x00\x01", 6);
    // a /24, so the broadcast and "outside the subnet" paths are reachable
    eee.conf.tap.tuntap_v4.net_bitlen = 24;

    // a running edge has a current supernode on its data path: the ARP
    // reply that tun_from_frame() sends is routed to it when the peer is
    // not a known one.  Its socket's family is set so edge_sendto_sock()
    // gets as far as the eee->sock == -1 check and drops there
    supernode.sock.family = AF_INET;
    eee.client.curr_sn = &supernode;

    // the ARP reply's encode path needs a transop; null needs no key
    n2n_transop_null_init(&eee.conf, &eee.client.transop);
    return 0;
}

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size) {

    static uint8_t buf[N2N_PKT_BUF_SIZE];

    if(size < 1) {
        return 0;
    }
    bool to = data[0] & 1;
    data++;
    size--;

    // leave the ARP table and the asked-times as they were learned: a run
    // builds on the last, as a daemon would

    if(to) {
        // an IP packet from the device, at buf + ETH_HLEN (14); the frame
        // is built in place, so leave room for the header and the body
        size_t max = sizeof(buf) - 14;
        if(size > max) {
            size = max;
        }
        memcpy(buf + 14, data, size);
        tun_to_frame(&eee, buf, size);
    } else {
        // a frame from the network, as it came
        if(size > sizeof(buf)) {
            size = sizeof(buf);
        }
        memcpy(buf, data, size);
        tun_from_frame(&eee, buf, size, write_sink);
    }
    return 0;
}
