/*
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Mutated PDUs at running daemons, for the netns scenarios tagged "spray"
 * (tests/netns, see docs/develop/netns_testing.md): the fuzz targets take
 * the decoders apart one PDU at a time, this reaches the handlers behind
 * them, with all their state.
 *
 *   fuzz-spray [-c COMMUNITY] [-e] [-m MAC]... [-t SECONDS] [-r RATE]
 *              [-s SEED] SEEDDIR udp:HOST:PORT|tcp:HOST:PORT...
 *
 * It takes the PDUs fuzz-seeds wrote into SEEDDIR/wire, puts COMMUNITY
 * into their header, changes a few bytes of each - or the length, or puts
 * one of the MACs in - and with -e encrypts the header with the
 * community's keys (header encryption), so that what was changed gets
 * past the decryption.  To each target in turn, RATE PDUs a second for
 * SECONDS: over UDP as they are, over TCP each with the length in front
 * as a v3tcp connection takes it - the length changed too now and then -
 * on a connection that is closed and opened again every few PDUs.  The
 * same SEED (for n3n's own generator, 0 by default) gives the same PDUs.
 * At the end, how many went out.
 */

#include <arpa/inet.h>           // for inet_pton, htons
#include <dirent.h>              // for opendir, readdir
#include <errno.h>               // for errno
#include <fcntl.h>               // for fcntl, O_NONBLOCK
#include <n3n/logging.h>         // for setTraceLevel
#include <n3n/random.h>          // for n3n_rand, n3n_srand
#include <netinet/in.h>          // for sockaddr_in
#include <stdio.h>               // for fprintf, fopen
#include <stdlib.h>              // for strtoul, exit
#include <string.h>              // for memcpy, memset, strncpy
#include <sys/socket.h>          // for socket, sendto, connect
#include <time.h>                // for clock_gettime, nanosleep
#include <unistd.h>              // for close, getopt
#include "header_encryption.h"   // for packet_header_encrypt, packet_header_setup_key
#include "n2n.h"                 // for N2N_PKT_BUF_SIZE, time_stamp
#include "n2n_wire.h"            // for decode_common, decode_PACKET

#define MAX_SEEDS   256
#define MAX_TARGETS 16
#define MAX_MACS    8

struct seed {
    uint8_t data[N2N_PKT_BUF_SIZE];
    size_t len;
};

struct target {
    int tcp;
    struct sockaddr_in addr;
    int fd;                      // the TCP connection, -1 while there is none
    int left;                    // PDUs until it is closed and opened again
    unsigned long sent;
};

static struct seed seeds[MAX_SEEDS];
static int nseeds;
static struct target targets[MAX_TARGETS];
static int ntargets;
static uint8_t macs[MAX_MACS][N2N_MAC_SIZE];
static int nmacs;
static n2n_community_t community = "fuzzcomm";
static int encrypt;
static struct speck_context_t *ctx_static, *ctx_dynamic, *iv_static, *iv_dynamic;
static uint32_t rnd (void) {

    // n3n's own generator, seeded with -s: the same seed, the same PDUs
    return (uint32_t)(n3n_rand() >> 32);
}

static void usage (const char *prog) {

    fprintf(stderr, "usage: %s [-c COMMUNITY] [-e] [-m MAC]... [-t SECONDS] [-r RATE] "
            "[-s SEED] SEEDDIR udp:HOST:PORT|tcp:HOST:PORT...\n", prog);
    exit(2);
}

static void read_seeds (const char *dir) {

    char path[4096];
    struct dirent *e;
    DIR *d;

    snprintf(path, sizeof(path), "%s/wire", dir);
    d = opendir(path);
    if(!d) {
        perror(path);
        exit(1);
    }
    while((e = readdir(d)) && (nseeds < MAX_SEEDS)) {
        FILE *f;

        if(e->d_name[0] == '.') {
            continue;
        }
        snprintf(path, sizeof(path), "%s/wire/%s", dir, e->d_name);
        f = fopen(path, "rb");
        if(!f) {
            continue;
        }
        seeds[nseeds].len = fread(seeds[nseeds].data, 1, sizeof(seeds[nseeds].data), f);
        fclose(f);
        if(seeds[nseeds].len >= 24) {
            nseeds++;
        }
    }
    closedir(d);
    if(!nseeds) {
        fprintf(stderr, "no seeds in %s/wire: run fuzz-seeds %s first\n", dir, dir);
        exit(1);
    }
}

static void add_target (const char *arg) {

    char host[64];
    const char *p;
    struct target *t;

    if(ntargets == MAX_TARGETS) {
        fprintf(stderr, "too many targets\n");
        exit(2);
    }
    t = &targets[ntargets];
    memset(t, 0, sizeof(*t));
    t->fd = -1;
    if(!strncmp(arg, "udp:", 4)) {
        t->tcp = 0;
    } else if(!strncmp(arg, "tcp:", 4)) {
        t->tcp = 1;
    } else {
        usage("fuzz-spray");
    }
    arg += 4;
    p = strrchr(arg, ':');
    if(!p || ((size_t)(p - arg) >= sizeof(host))) {
        usage("fuzz-spray");
    }
    memcpy(host, arg, p - arg);
    host[p - arg] = '\0';
    t->addr.sin_family = AF_INET;
    t->addr.sin_port = htons((uint16_t)strtoul(p + 1, NULL, 10));
    if(inet_pton(AF_INET, host, &t->addr.sin_addr) != 1) {
        fprintf(stderr, "not an IPv4 address: %s\n", host);
        exit(2);
    }
    ntargets++;
}

static void add_mac (const char *arg) {

    unsigned int m[N2N_MAC_SIZE];
    int i;

    if((nmacs == MAX_MACS) || (sscanf(arg, "%x:%x:%x:%x:%x:%x",
                                      &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6)) {
        usage("fuzz-spray");
    }
    for(i = 0; i < N2N_MAC_SIZE; i++) {
        macs[nmacs][i] = (uint8_t)m[i];
    }
    nmacs++;
}

// One PDU to send: a seed with the community, changed a little
static size_t mutate (uint8_t *buf) {

    static const uint8_t bytes[] = {0x00, 0x01, 0x02, 0x7f, 0x80, 0xfe, 0xff};
    static const uint16_t words[] = {0x0000, 0x0001, 0x00ff, 0x7fff, 0x8000, 0xfffe, 0xffff};
    struct seed *s = &seeds[rnd() % nseeds];
    size_t len = s->len;
    int n, i;

    memcpy(buf, s->data, len);
    // the community, in the common header behind version, ttl and flags
    if(rnd() % 16) {
        memcpy(buf + 4, community, N2N_COMMUNITY_SIZE);
    }
    n = 1 + rnd() % 4;
    for(i = 0; i < n; i++) {
        size_t at = rnd() % len;

        switch(rnd() % 10) {
            case 0:
                buf[at] ^= (uint8_t)(1 << (rnd() % 8));
                break;
            case 1:
                buf[at] = (uint8_t)rnd();
                break;
            case 2:
                buf[at] = bytes[rnd() % sizeof(bytes)];
                break;
            case 3:
                if(at + 2 <= len) {
                    uint16_t w = words[rnd() % (sizeof(words) / sizeof(words[0]))];
                    buf[at] = (uint8_t)(w >> 8);
                    buf[at + 1] = (uint8_t)w;
                }
                break;
            case 4:
                // one of the daemons' own MACs, as destination or as anything
                if(nmacs && (at + N2N_MAC_SIZE <= len)) {
                    memcpy(buf + at, macs[rnd() % nmacs], N2N_MAC_SIZE);
                }
                break;
            case 5:
                // shorter
                len = 1 + rnd() % len;
                break;
            case 6:
                // longer, by some random bytes
                {
                    size_t more = 1 + rnd() % 64;
                    if(len + more <= N2N_PKT_BUF_SIZE) {
                        while(more--) {
                            buf[len++] = (uint8_t)rnd();
                        }
                    }
                }
                break;
            case 7:
                // a piece of it once more, further on
                {
                    uint8_t tmp[N2N_PKT_BUF_SIZE];
                    size_t from = rnd() % len;
                    size_t piece = 1 + rnd() % (len - from);
                    if(len + piece <= N2N_PKT_BUF_SIZE) {
                        memcpy(tmp, buf + from, piece);
                        memmove(buf + at + piece, buf + at, len - at);
                        memcpy(buf + at, tmp, piece);
                        len += piece;
                    }
                }
                break;
            default:
                // the message type and flags, which pick the handler
                buf[2 + rnd() % 2] = (uint8_t)rnd();
                break;
        }
    }
    if(encrypt && (len >= 24)) {
        // the header as its type has it: a PACKET's ends before the payload
        n2n_common_t cmn;
        n2n_PACKET_t pkt;
        size_t rem = len, idx = 0;
        size_t header_len = len;

        if((decode_common(&cmn, buf, &rem, &idx) >= 0) && (cmn.pc == MSG_TYPE_PACKET)
           && (decode_PACKET(&pkt, &cmn, buf, &rem, &idx) >= 0) && (idx >= 24)) {
            header_len = idx;
        }
        packet_header_encrypt(buf, header_len, len, ctx_static, iv_static, time_stamp());
    }
    return len;
}

static void send_udp (int fd, struct target *t, const uint8_t *buf, size_t len) {

    if(sendto(fd, buf, len, 0, (struct sockaddr *)&t->addr, sizeof(t->addr)) >= 0) {
        t->sent++;
    }
}

static void send_tcp (struct target *t, const uint8_t *buf, size_t len) {

    uint8_t frame[2 + N2N_PKT_BUF_SIZE];
    uint16_t flen = (uint16_t)len;
    size_t out = 2 + len;

    if(t->fd < 0) {
        t->fd = socket(AF_INET, SOCK_STREAM, 0);
        if(t->fd < 0) {
            return;
        }
        if(connect(t->fd, (struct sockaddr *)&t->addr, sizeof(t->addr)) < 0) {
            close(t->fd);
            t->fd = -1;
            return;
        }
        fcntl(t->fd, F_SETFL, O_NONBLOCK);
        t->left = 1 + rnd() % 32;
    }
    switch(rnd() % 16) {
        case 0:
            // a length that is not the PDU's
            flen = (uint16_t)rnd();
            break;
        case 1:
            // half a frame, then the connection goes
            out = 1 + rnd() % out;
            t->left = 1;
            break;
    }
    frame[0] = (uint8_t)(flen >> 8);
    frame[1] = (uint8_t)flen;
    memcpy(frame + 2, buf, len);
    if(send(t->fd, frame, out, MSG_NOSIGNAL) >= 0) {
        t->sent++;
    } else if(errno != EAGAIN) {
        t->left = 1;
    }
    if(--t->left <= 0) {
        close(t->fd);
        t->fd = -1;
    }
}

int main (int argc, char *argv[]) {

    double seconds = 10, rate = 1000;
    uint64_t seed = 0;
    unsigned long total = 0, i, n;
    struct timespec t0, now;
    uint8_t buf[N2N_PKT_BUF_SIZE];
    int udp, opt, k;

    setTraceLevel(-1);
    while((opt = getopt(argc, argv, "c:em:t:r:s:")) != -1) {
        switch(opt) {
            case 'c':
                memset(community, 0, sizeof(community));
                strncpy((char *)community, optarg, sizeof(community) - 1);
                break;
            case 'e':
                encrypt = 1;
                break;
            case 'm':
                add_mac(optarg);
                break;
            case 't':
                seconds = atof(optarg);
                break;
            case 'r':
                rate = atof(optarg);
                break;
            case 's':
                seed = strtoull(optarg, NULL, 0);
                break;
            default:
                usage(argv[0]);
        }
    }
    if(argc - optind < 2) {
        usage(argv[0]);
    }
    n3n_srand(seed);
    read_seeds(argv[optind]);
    for(k = optind + 1; k < argc; k++) {
        add_target(argv[k]);
    }
    if(encrypt) {
        packet_header_setup_key((char *)community, &ctx_static, &ctx_dynamic, &iv_static, &iv_dynamic);
    }
    udp = socket(AF_INET, SOCK_DGRAM, 0);
    if(udp < 0) {
        perror("socket");
        return 1;
    }
    fcntl(udp, F_SETFL, O_NONBLOCK);

    n = (unsigned long)(seconds * rate);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for(i = 0; i < n; i++) {
        struct target *t = &targets[i % ntargets];
        size_t len = mutate(buf);
        double due = i / rate, elapsed;

        if(t->tcp) {
            send_tcp(t, buf, len);
        } else {
            send_udp(udp, t, buf, len);
        }
        clock_gettime(CLOCK_MONOTONIC, &now);
        elapsed = (now.tv_sec - t0.tv_sec) + (now.tv_nsec - t0.tv_nsec) / 1e9;
        if(due > elapsed) {
            struct timespec ts;
            double wait = due - elapsed;
            ts.tv_sec = (time_t)wait;
            ts.tv_nsec = (long)((wait - ts.tv_sec) * 1e9);
            nanosleep(&ts, NULL);
        }
    }
    for(k = 0; k < ntargets; k++) {
        char host[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &targets[k].addr.sin_addr, host, sizeof(host));
        printf("%s:%s:%u %lu\n", targets[k].tcp ? "tcp" : "udp", host,
               ntohs(targets[k].addr.sin_port), targets[k].sent);
        total += targets[k].sent;
        if(targets[k].fd >= 0) {
            close(targets[k].fd);
        }
    }
    printf("sent %lu of %lu\n", total, n);
    return 0;
}
