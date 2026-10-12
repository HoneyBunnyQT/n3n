/*
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The edge's IPv6 address inside the tunnel (src/ipv6.c):
 *
 *   - the default prefix of a community: fd, 40 bits of a hash of its
 *     name, subnet 0, the same for the same name, another for another
 *   - auto: that prefix or tuntap.prefix6, with the IPv4 address in the
 *     lowest 32 bits, or without one the modified EUI-64 of the MAC
 *   - an address with its prefix length, taken as it is
 *   - none without tuntap.address6, and errors for what is no address or
 *     prefix
 *
 * The output is the same on every system and byte order.
 */

#include <n3n/logging.h>      // for setTraceLevel
#include <stdio.h>            // for printf
#include <string.h>           // for memcmp
#include "../src/ipv6.h"      // for n3n_ipv6_address, n3n_ipv6_prefix_default

#ifdef _WIN32
#include "win32/defs.h"
#else
#include <arpa/inet.h>        // for inet_ntop, inet_pton
#endif

static const uint8_t mac[6] = {0x02, 0x00, 0x00, 0x5e, 0x00, 0x01};

static void show (const char *what, const char *address6, const char *prefix6, const char *ipv4) {

    uint8_t addr[16];
    uint8_t len = 0;
    uint32_t v4 = 0;
    char buf[INET6_ADDRSTRLEN];

    if(ipv4) {
        inet_pton(AF_INET, ipv4, &v4);
    }
    int ret = n3n_ipv6_address(address6, prefix6, "nettest", v4, mac, addr, &len);
    if(ret) {
        printf("%-40s %s\n", what, (ret > 0) ? "none" : "error");
        return;
    }
    printf("%-40s %s/%u\n", what, inet_ntop(AF_INET6, addr, buf, sizeof(buf)), len);
}

int main (int argc, char *argv[]) {

    uint8_t a[16], b[16], c[16];
    char buf[INET6_ADDRSTRLEN];

    setTraceLevel(-1);

    n3n_ipv6_prefix_default("nettest", a);
    n3n_ipv6_prefix_default("nettest", b);
    n3n_ipv6_prefix_default("other", c);
    printf("%-40s %s/64\n", "prefix of nettest", inet_ntop(AF_INET6, a, buf, sizeof(buf)));
    printf("%-40s %s/64\n", "prefix of other", inet_ntop(AF_INET6, c, buf, sizeof(buf)));
    printf("%-40s %s\n", "the same for the same name", memcmp(a, b, 16) ? "FAIL" : "ok");

    show("auto, IPv4 10.77.0.5", "auto", NULL, "10.77.0.5");
    show("auto, no IPv4: from the MAC", "auto", NULL, NULL);
    show("auto, prefix6 given", "auto", "fd12:3456:789a:1::/64", "10.77.0.5");
    show("auto, prefix6 /48, bits beyond cleared", "auto", "fd12:3456:789a:ffff::/48", NULL);
    show("an address", "fd00:77::5/64", NULL, "10.77.0.5");
    show("not set", NULL, NULL, "10.77.0.5");
    show("empty", "", NULL, "10.77.0.5");
    show("no prefix length", "fd00:77::5", NULL, NULL);
    show("no address", "something/64", NULL, NULL);
    show("prefix length 129", "fd00::5/129", NULL, NULL);
    show("auto, prefix6 longer than 64", "auto", "fd12::/96", NULL);
    show("auto, prefix6 no prefix", "auto", "nonsense", NULL);
    return 0;
}
