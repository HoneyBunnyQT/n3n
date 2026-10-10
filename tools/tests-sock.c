/*
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The send layer's batches and udp_drain() (src/sock.c), over two UDP
 * sockets on the loopback address:
 *
 *   - datagrams sent while a batch is open arrive whole and in order, also
 *     when the caller's buffer is used again for the next one at once (the
 *     batch keeps copies), and more of them than one sendmmsg() takes
 *   - a batch inside a batch sends nothing of its own
 *   - udp_drain() hands each datagram to the role once, in order: with
 *     recvmmsg() where there is one, one by one elsewhere
 *
 * The output is the same on every system: where there is no sendmmsg(),
 * each datagram simply goes at once.
 */

#include <n3n/initfuncs.h>     // for n3n_initfuncs
#include <n3n/logging.h>       // for setTraceLevel
#include <stdio.h>             // for printf, snprintf
#include <string.h>            // for memcmp, strlen
#include "n2n.h"               // for n3n_runtime_data, SOCKET
#include "../src/sock.h"       // for sock_batch_begin, sendto_logged, udp_drain

#ifdef _WIN32
#include "win32/defs.h"
#else
#include <arpa/inet.h>         // for htonl
#include <netinet/in.h>        // for sockaddr_in, INADDR_LOOPBACK
#include <sys/select.h>        // for select
#include <sys/socket.h>        // for socket, bind, recvfrom
#include <unistd.h>            // for close
#define closesocket(s) close(s)
#endif

#define COUNT 40               // more than one sendmmsg() of a batch takes

static int next_expected;
static int out_of_order;

static void check (const uint8_t *buf, size_t len) {
    char want[32];

    snprintf(want, sizeof(want), "dgram %d", next_expected);
    if((len != strlen(want)) || memcmp(buf, want, len)) {
        out_of_order++;
    }
    next_expected++;
}

static void rx_one (struct n3n_runtime_data *rt, SOCKET sock,
                    struct sockaddr *from, socklen_t from_len,
                    uint8_t *buf, size_t len, time_t now) {
    check(buf, len);
}

// the role's read of one datagram, as udp_drain() falls back to
static int read_one (struct n3n_runtime_data *rt, SOCKET sock,
                     struct n3n_pktbuf *pkt, time_t now) {
    uint8_t buf[64];
    fd_set rd;
    struct timeval tv = { 0, 0 };

    FD_ZERO(&rd);
    FD_SET(sock, &rd);
    if(select((int)sock + 1, &rd, NULL, NULL, &tv) < 1) {
        return 0;
    }
    int len = recvfrom(sock, (char *)buf, sizeof(buf), 0, NULL, NULL);
    if(len <= 0) {
        return 0;
    }
    check(buf, len);
    return 1;
}

// wait up to a second for sock to have something to read
static int readable (SOCKET sock) {
    fd_set rd;
    struct timeval tv = { 1, 0 };

    FD_ZERO(&rd);
    FD_SET(sock, &rd);
    return select((int)sock + 1, &rd, NULL, NULL, &tv) > 0;
}

int main (int argc, char *argv[]) {
    struct n3n_runtime_data rt;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    char buf[32];
    int failed = 0;

    setTraceLevel(TRACE_ERROR);
    n3n_initfuncs();

    SOCKET rx = socket(AF_INET, SOCK_DGRAM, 0);
    SOCKET tx = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if((rx < 0) || (tx < 0) || bind(rx, (struct sockaddr *)&addr, sizeof(addr))
       || getsockname(rx, (struct sockaddr *)&addr, &addr_len)) {
        printf("sock: no sockets on the loopback address\n");
        return 1;
    }

    // one buffer for all of them, written anew for each: what was sent
    // before must not change with it
    sock_batch_begin();
    for(int i = 0; i < COUNT; i++) {
        if(i == COUNT / 2) {
            // a batch inside the batch: its end sends nothing yet
            sock_batch_begin();
        }
        snprintf(buf, sizeof(buf), "dgram %d", i);
        sendto_logged(tx, buf, strlen(buf), (struct sockaddr *)&addr, sizeof(addr));
        memset(buf, 'x', sizeof(buf));
        if(i == COUNT / 2) {
            sock_batch_end();
        }
    }
    sock_batch_end();
    // and one without a batch
    snprintf(buf, sizeof(buf), "dgram %d", COUNT);
    sendto_logged(tx, buf, strlen(buf), (struct sockaddr *)&addr, sizeof(addr));

    // the receiving socket as an address of connection.bind, which
    // udp_drain() takes several at a time from
    memset(&rt, 0, sizeof(rt));
    rt.bind_count = 1;
    rt.bind_sock[0] = rx;
    rt.bind_family[0] = AF_INET;

    while((next_expected <= COUNT) && readable(rx)) {
        if(!udp_drain(&rt, rx, NULL, 64, 0, read_one, rx_one)) {
            break;
        }
    }

    int ok = (next_expected == COUNT + 1) && !out_of_order;
    failed |= !ok;
    printf("sock: %d datagrams through a batch, nested and overflowing, and one "
           "without: %s\n", COUNT, ok ? "ok" : "FAIL");
    if(!ok) {
        printf("sock: %d arrived, %d not as sent\n", next_expected, out_of_order);
    }

    closesocket(rx);
    closesocket(tx);
    return failed;
}
