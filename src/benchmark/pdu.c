/*
 * SPDX-License-Identifier: GPL-2.0-only
 * SPDX-FileCopyrightText: Copyright Hamish Coleman
 *
 */

#include <n2n.h>            // for edge_init
#include <n2n_define.h>     // for N2N_PKT_BUF_SIZE
#include <n2n_typedefs.h>   // for n2n_edge_conf
#include <n2n_wire.h>       // for fill_n3nsock
#include <n3n/benchmark.h>  // for bench_item
#include <n3n/edge.h>       // for edge_init_conf_defaults, edge_verify_conf
#include <n3n/pktbuf.h>
#include <n3n/resolve.h>    // for resolve_supernode_str_add
#include <stddef.h>         // for NULL
#include <stdio.h>          // for perror
#include <stdlib.h>         // for calloc, free
#include <unistd.h>         // for read

#ifndef _WIN32
#include <sys/socket.h>     // for socketpair
#endif

#include "../peer_info.h"   // for peer_info_malloc

struct bench_ctx {
    struct n3n_runtime_data eee;
    struct sockaddr_in sender;
    int sv[2];
    uint8_t outbuf[N2N_PKT_BUF_SIZE];
    ssize_t outbuf_size;
};

// the source MAC in test_data_pdu_v3
static const n2n_mac_t bench_peer_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

static void *bench_setup (void *const _ctx) {
    struct bench_ctx *ctx = (struct bench_ctx *)_ctx;
    struct peer_info *peer;

    edge_init_conf_defaults(&ctx->eee.conf,"edge");
    strcpy(ctx->eee.conf.community.community_name, "test");
    ctx->eee.conf.community.transop_id = N2N_TRANSFORM_ID_NULL;
    ctx->eee.client.last_sup = 1;
    ctx->eee.client.curr_sn = peer_info_malloc(null_mac);
    ctx->eee.client.curr_sn->sock.family = AF_INVALID;
    ctx->eee.client.pending_peers = NULL;
    ctx->eee.client.known_peers = NULL;
    ctx->eee.tap.network_traffic_filter = NULL;

    ctx->sender.sin_family = AF_INET;
    ctx->sender.sin_port = 1;
    ctx->sender.sin_addr.s_addr = 0x0fee1bad;

    // Nearly every PDU an edge receives comes from a peer it already knows,
    // so the benchmark PDU does too
    peer = peer_info_malloc(bench_peer_mac);
    fill_n3nsock(&peer->sock, (struct sockaddr *)&ctx->sender);
    peer->timeout = ctx->eee.conf.client.register_interval;
    peer->last_seen = time(NULL);
    HASH_ADD_PEER(ctx->eee.client.known_peers, peer);

    n2n_transop_null_init(&ctx->eee.conf, &ctx->eee.client.transop);

    memset(ctx->eee.tap.device.mac_addr, 0, N2N_MAC_SIZE);
    ctx->eee.tap.device.mac_addr[0] = 0x02;

#ifndef _WIN32
    if(socketpair(AF_UNIX, SOCK_DGRAM, 0, ctx->sv) == -1) {
        perror("socketpair");
        exit(EXIT_FAILURE);
    }
    ctx->eee.tap.device.fd = ctx->sv[0];
#else
    ctx->sv[0] = -1;
    ctx->sv[1] = -1;
#endif
    return ctx;
}

static void bench_teardown (void *_ctx) {
    struct bench_ctx *ctx = (struct bench_ctx *)_ctx;

    clear_peer_list(&ctx->eee.client.pending_peers);
    clear_peer_list(&ctx->eee.client.known_peers);
    peer_info_free(ctx->eee.client.curr_sn);
    edge_term_conf(&ctx->eee.conf);
}

#ifndef _WIN32
static const void *const bench_get_output (void *const _ctx) {
    struct bench_ctx *ctx = (struct bench_ctx *)_ctx;
    return &ctx->outbuf;
}
#endif

#ifdef _WIN32
static int const bench_check_fake (void *const _ctx, const int level) {
    // Since we cannot create a socketpair and read the PDU, we cannot run
    // checks on windows.
    // TODO:
    // - this is a limitation of how tuntap devs are handled / selected
    fprintf(stderr, "pdu2tun: WARN: cannot check on Win32 platform");
    return 0;
}
#endif

// TODO: use headers to declare this
void process_pdu (struct n3n_runtime_data *eee,
                  const struct sockaddr *sender_sock,
                  const SOCKET in_sock,
                  uint8_t *udp_buf,
                  size_t udp_size,
                  time_t now
);

static const ssize_t bench_pdu2tun_run (
    void *_ctx,
    const struct n3n_pktbuf *inbuf,
    ssize_t *in
) {
    struct bench_ctx *ctx = (struct bench_ctx *)_ctx;
    const ssize_t data_in_size = n3n_pktbuf_getbufsize(*inbuf);

    time_t now = time(NULL);

    // Avoid attempt to send a reply to this PDU
    ctx->eee.sock = -1;

    process_pdu(
        &ctx->eee,
        (struct sockaddr *)&ctx->sender,
        -1,
        n3n_pktbuf_getbufptr(*inbuf),
        data_in_size,
        now
    );

    // If we could not create the socketpair, we cannot read the buffer
    if(ctx->sv[1] != -1) {
        ctx->outbuf_size = read(ctx->sv[1], &ctx->outbuf, sizeof(ctx->outbuf));
    } else {
        ctx->outbuf_size = 0;
        ctx->outbuf[0] = 0;
    }
    *in = data_in_size;
    return ctx->outbuf_size;
}

static struct bench_item bench_pdu2tun = {
    .name = "pdu2tun",
    .ctx_size = sizeof(struct bench_ctx),
    .setup = bench_setup,
    .run = bench_pdu2tun_run,
#ifndef _WIN32
    .get_output = bench_get_output,
#else
    .check = bench_check_fake,
#endif
    .teardown = bench_teardown,
    .data_in = test_data_pdu_v3,
    .data_out = test_data_pdu_eth,
};

static const ssize_t bench_tun2pdu_run (
    void *_ctx,
    const struct n3n_pktbuf *inbuf,
    ssize_t *in
) {
    struct bench_ctx *ctx = (struct bench_ctx *)_ctx;
    const ssize_t data_in_size = n3n_pktbuf_getbufsize(*inbuf);
    n2n_mac_t destMac;

    ctx->outbuf_size = edge_encode_packet(
        &ctx->eee,
        n3n_pktbuf_getbufptr(*inbuf),
        data_in_size,
        ctx->outbuf, sizeof(ctx->outbuf),
        destMac
    );

    *in = data_in_size;
    return ctx->outbuf_size;
}

static struct bench_item bench_tun2pdu = {
    .name = "tun2pdu",
    .ctx_size = sizeof(struct bench_ctx),
    .setup = bench_setup,
    .run = bench_tun2pdu_run,
#ifndef _WIN32
    .get_output = bench_get_output,
#else
    .check = bench_check_fake,
#endif
    .teardown = bench_teardown,
    .data_in = test_data_pdu_eth,
    .data_out = test_data_tun2pdu,
};

void n3n_initfuncs_benchmark_pdu () {
    n3n_benchmark_register(&bench_pdu2tun);
    n3n_benchmark_register(&bench_tun2pdu);
}
