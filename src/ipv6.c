/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The edge's IPv6 address inside the tunnel - see ipv6.h
 */

#include <n3n/logging.h>     // for traceEvent
#include <stdlib.h>          // for strtoul
#include <string.h>          // for memcpy, memset, strchr, strcmp, strncpy
#include "n2n_define.h"      // for N2N_COMMUNITY_SIZE
#include "ipv6.h"
#include "pearson.h"         // for pearson_hash_64

#ifdef _WIN32
#include "win32/defs.h"
#else
#include <arpa/inet.h>       // for inet_pton
#endif


void n3n_ipv6_prefix_default (const char *community, uint8_t prefix[16]) {

    uint8_t name[N2N_COMMUNITY_SIZE];

    // as the community is kept: its name, padded with zeros
    memset(name, 0, sizeof(name));
    strncpy((char *)name, community, sizeof(name) - 1);
    uint64_t h = pearson_hash_64(name, sizeof(name));

    // fd, the 40 highest bits of the hash as global ID, subnet 0 (RFC 4193)
    memset(prefix, 0, 16);
    prefix[0] = 0xfd;
    for(int i = 0; i < 5; i++) {
        prefix[1 + i] = (uint8_t)(h >> (56 - 8 * i));
    }
}


// "address/len" into addr and len; -1 if it is none
static int parse (const char *s, uint8_t addr[16], uint8_t *len) {

    char buf[64];
    const char *slash = strchr(s, '/');
    size_t n = slash ? (size_t)(slash - s) : strlen(s);

    if(!slash || (n >= sizeof(buf))) {
        return -1;
    }
    memcpy(buf, s, n);
    buf[n] = 0;

    char *end;
    unsigned long l = strtoul(slash + 1, &end, 10);
    if(!slash[1] || *end || (l < 1) || (l > 128) || (inet_pton(AF_INET6, buf, addr) != 1)) {
        return -1;
    }
    *len = (uint8_t)l;
    return 0;
}


int n3n_ipv6_address (const char *address6, const char *prefix6, const char *community,
                      uint32_t ipv4, const uint8_t mac[6], uint8_t addr[16], uint8_t *len) {

    if(!address6 || !*address6) {
        return 1;
    }
    if(strcmp(address6, "auto")) {
        if(parse(address6, addr, len)) {
            traceEvent(TRACE_ERROR, "tuntap.address6 = %s: neither auto nor an address with its prefix length",
                       address6);
            return -1;
        }
        return 0;
    }

    // the prefix
    if(prefix6 && *prefix6) {
        if(parse(prefix6, addr, len) || (*len > 64)) {
            traceEvent(TRACE_ERROR, "tuntap.prefix6 = %s: no prefix of 64 bits or less", prefix6);
            return -1;
        }
        // what the prefix length leaves out is not the prefix's
        for(int bit = *len; bit < 128; bit++) {
            addr[bit / 8] &= ~(0x80 >> (bit % 8));
        }
    } else {
        n3n_ipv6_prefix_default(community, addr);
        *len = 64;
    }

    // the interface ID, the lowest 64 bits: the IPv4 address, or the MAC
    if(ipv4) {
        memcpy(&addr[12], &ipv4, 4);
    } else {
        // modified EUI-64: ff:fe between the halves, the universal/local
        // bit turned
        addr[8] = mac[0] ^ 0x02;
        addr[9] = mac[1];
        addr[10] = mac[2];
        addr[11] = 0xff;
        addr[12] = 0xfe;
        addr[13] = mac[3];
        addr[14] = mac[4];
        addr[15] = mac[5];
    }
    return 0;
}
