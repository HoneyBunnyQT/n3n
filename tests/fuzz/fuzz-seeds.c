/*
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The seeds of the fuzz targets: "fuzz-seeds DIR" writes into DIR/wire,
 * DIR/header and DIR/transop valid inputs of each - PDUs of every type,
 * the same with encrypted headers, and payloads as each transform makes
 * them - for the fuzzer to start from.  See README.md.
 */

#include <n3n/edge.h>            // for edge_init_conf_defaults
#include <n3n/initfuncs.h>       // for n3n_initfuncs
#include <stdio.h>               // for fopen, snprintf
#include <stdlib.h>              // for strdup
#include <string.h>              // for memset, memcpy, strncpy
#include <sys/stat.h>            // for mkdir
#include "config.h"              // for HAVE_LIBZSTD
#include "fuzz.h"
#include "header_encryption.h"   // for packet_header_encrypt, packet_header_setup_key
#include "n2n.h"                 // for the message structs, transops
#include "n2n_wire.h"            // for encode_*

#define FUZZ_KEY "fuzz-secret"

static const char *top;
static struct speck_context_t *ctx_static, *ctx_dynamic, *iv_static, *iv_dynamic;

static void put (const char *target, const char *name, const uint8_t *data, size_t size) {

    char path[4096];
    FILE *f;

    snprintf(path, sizeof(path), "%s/%s", top, target);
    mkdir(path, 0777);
    snprintf(path, sizeof(path), "%s/%s/%s", top, target, name);
    f = fopen(path, "wb");
    if(!f || (fwrite(data, 1, size, f) != size)) {
        perror(path);
        exit(1);
    }
    fclose(f);
}

static void fill (void *p, size_t len, uint8_t seed) {

    uint8_t *b = p;
    size_t i;

    for(i = 0; i < len; i++) {
        b[i] = (uint8_t)(seed + i * 7);
    }
}

static void common (n2n_common_t *cmn, uint8_t pc, uint16_t flags) {

    memset(cmn, 0, sizeof(*cmn));
    cmn->ttl = 2;
    cmn->pc = pc;
    cmn->flags = flags;
    strncpy((char *)cmn->community, FUZZ_COMMUNITY, N2N_COMMUNITY_SIZE);
}

static void sock4 (n3n_sock_t *s, uint8_t seed) {

    s->family = AF_INET;
    s->port = 7654 + seed;
    fill(s->addr.v4, 4, seed);
}

static void sock6 (n3n_sock_t *s, uint8_t seed) {

    s->family = AF_INET6;
    s->port = 7654 + seed;
    fill(s->addr.v6, 16, seed);
}

// a PDU, plain for the decoders and the header target, and with an
// encrypted header for the header target
static void pdu (const char *name, uint8_t *buf, size_t len, size_t header_len) {

    uint8_t enc[N2N_PKT_BUF_SIZE];

    put("wire", name, buf, len);
    put("header", name, buf, len);
    memcpy(enc, buf, len);
    packet_header_encrypt(enc, header_len, len, ctx_static, iv_static, time_stamp());
    {
        char ename[256];
        snprintf(ename, sizeof(ename), "%s-enc", name);
        put("header", ename, enc, len);
    }
}

static void pdus (void) {

    uint8_t buf[N2N_PKT_BUF_SIZE];
    n2n_common_t cmn;
    size_t idx;
    int s;

    for(s = 0; s < 3; s++) {   // without a socket, with an IPv4 one, with an IPv6 one
        char name[64];
        uint16_t flags = s ? N2N_FLAGS_SOCKET : 0;

        {
            n2n_REGISTER_t m;
            memset(&m, 0, sizeof(m));
            fill(&m.cookie, sizeof(m.cookie), 1);
            fill(m.srcMac, 6, 2);
            fill(m.dstMac, 6, 3);
            (s == 2) ? sock6(&m.sock, 4) : sock4(&m.sock, 4);
            m.dev_addr.net_addr = 0x0a000002;
            m.dev_addr.net_bitlen = 24;
            strcpy((char *)m.dev_desc, "fuzz");
            common(&cmn, MSG_TYPE_REGISTER, flags);
            idx = 0;
            encode_REGISTER(buf, &idx, &cmn, &m);
            snprintf(name, sizeof(name), "register-%d", s);
            pdu(name, buf, idx, idx);
        }
        {
            n2n_REGISTER_ACK_t m;
            memset(&m, 0, sizeof(m));
            fill(&m.cookie, sizeof(m.cookie), 5);
            fill(m.srcMac, 6, 6);
            fill(m.dstMac, 6, 7);
            (s == 2) ? sock6(&m.sock, 8) : sock4(&m.sock, 8);
            common(&cmn, MSG_TYPE_REGISTER_ACK, flags);
            idx = 0;
            encode_REGISTER_ACK(buf, &idx, &cmn, &m);
            snprintf(name, sizeof(name), "register_ack-%d", s);
            pdu(name, buf, idx, idx);
        }
        {
            n2n_PACKET_t m;
            size_t header;
            memset(&m, 0, sizeof(m));
            fill(m.srcMac, 6, 9);
            fill(m.dstMac, 6, 10);
            (s == 2) ? sock6(&m.sock, 11) : sock4(&m.sock, 11);
            m.transform = N2N_TRANSFORM_ID_NULL;
            common(&cmn, MSG_TYPE_PACKET, flags);
            idx = 0;
            encode_PACKET(buf, &idx, &cmn, &m);
            header = idx;
            fill(buf + idx, 64, 12);   // a payload
            idx += 64;
            snprintf(name, sizeof(name), "packet-%d", s);
            pdu(name, buf, idx, header);
        }
        {
            n2n_PEER_INFO_t m;
            memset(&m, 0, sizeof(m));
            m.aflags = s ? 1 : 0;
            fill(m.srcMac, 6, 13);
            fill(m.mac, 6, 14);
            (s == 2) ? sock6(&m.sock, 15) : sock4(&m.sock, 15);
            sock4(&m.preferred_sock, 16);
            common(&cmn, MSG_TYPE_PEER_INFO, flags);
            idx = 0;
            encode_PEER_INFO(buf, &idx, &cmn, &m);
            snprintf(name, sizeof(name), "peer_info-%d", s);
            pdu(name, buf, idx, idx);
        }
        {
            n2n_REGISTER_SUPER_t m;
            memset(&m, 0, sizeof(m));
            fill(&m.cookie, sizeof(m.cookie), 17);
            fill(m.edgeMac, 6, 18);
            (s == 2) ? sock6(&m.sock, 19) : sock4(&m.sock, 19);
            m.dev_addr.net_addr = 0x0a000001;
            m.dev_addr.net_bitlen = 24;
            strcpy((char *)m.dev_desc, "fuzz");
            m.auth.scheme = n2n_auth_simple_id;
            m.auth.token_size = 16;
            fill(m.auth.token, 16, 20);
            common(&cmn, MSG_TYPE_REGISTER_SUPER, flags);
            idx = 0;
            encode_REGISTER_SUPER(buf, &idx, &cmn, &m);
            snprintf(name, sizeof(name), "register_super-%d", s);
            pdu(name, buf, idx, idx);
        }
        {
            n2n_REGISTER_SUPER_ACK_t m;
            uint8_t payload[REG_SUPER_ACK_PAYLOAD_SPACE];
            n2n_REGISTER_SUPER_ACK_payload_t *p = (n2n_REGISTER_SUPER_ACK_payload_t *)payload;
            int i;
            memset(&m, 0, sizeof(m));
            memset(payload, 0, sizeof(payload));
            fill(&m.cookie, sizeof(m.cookie), 21);
            fill(m.srcMac, 6, 22);
            m.dev_addr.net_addr = 0x0a000003;
            m.dev_addr.net_bitlen = 24;
            m.lifetime = 60;
            (s == 2) ? sock6(&m.sock, 23) : sock4(&m.sock, 23);
            m.auth.scheme = n2n_auth_simple_id;
            m.auth.token_size = 16;
            fill(m.auth.token, 16, 24);
            m.num_sn = s + 1;   // other supernodes it knows
            for(i = 0; i < m.num_sn; i++, p++) {
                n3n_sock_t other;
                size_t pidx = 0;
                (i == 1) ? sock6(&other, 25 + i) : sock4(&other, 25 + i);
                encode_sock_payload(p->sock, &pidx, &other);
                fill(p->mac, 6, 30 + i);
            }
            common(&cmn, MSG_TYPE_REGISTER_SUPER_ACK, flags);
            idx = 0;
            encode_REGISTER_SUPER_ACK(buf, &idx, &cmn, &m, payload);
            snprintf(name, sizeof(name), "register_super_ack-%d", s);
            pdu(name, buf, idx, idx);
        }
        if(s) {
            continue;
        }
        {
            n2n_REGISTER_SUPER_NAK_t m;
            memset(&m, 0, sizeof(m));
            fill(&m.cookie, sizeof(m.cookie), 33);
            fill(m.srcMac, 6, 34);
            m.auth.scheme = n2n_auth_simple_id;
            m.auth.token_size = 16;
            fill(m.auth.token, 16, 35);
            common(&cmn, MSG_TYPE_REGISTER_SUPER_NAK, 0);
            idx = 0;
            encode_REGISTER_SUPER_NAK(buf, &idx, &cmn, &m);
            pdu("register_super_nak", buf, idx, idx);
        }
        {
            n2n_UNREGISTER_SUPER_t m;
            memset(&m, 0, sizeof(m));
            m.auth.scheme = n2n_auth_simple_id;
            m.auth.token_size = 16;
            fill(m.auth.token, 16, 36);
            fill(m.srcMac, 6, 37);
            common(&cmn, MSG_TYPE_UNREGISTER_SUPER, 0);
            idx = 0;
            encode_UNREGISTER_SUPER(buf, &idx, &cmn, &m);
            pdu("unregister_super", buf, idx, idx);
        }
        {
            n2n_QUERY_PEER_t m;
            memset(&m, 0, sizeof(m));
            fill(m.srcMac, 6, 38);
            fill(m.targetMac, 6, 39);
            common(&cmn, MSG_TYPE_QUERY_PEER, 0);
            idx = 0;
            encode_QUERY_PEER(buf, &idx, &cmn, &m);
            pdu("query_peer", buf, idx, idx);
            // a PING: a QUERY_PEER for the null MAC
            memset(m.targetMac, 0, 6);
            idx = 0;
            encode_QUERY_PEER(buf, &idx, &cmn, &m);
            pdu("ping", buf, idx, idx);
        }
    }
}

static void transops (void) {

    static const char *names[] = {"null", "tf", "aes", "cc20", "speck", "lzo", "zstd"};
    static n2n_edge_conf_t conf;
    n2n_trans_op_t ops[7];
    n2n_mac_t mac = {0x02, 0, 0, 0, 0, 0x01};
    uint8_t in[1400];
    uint8_t out[N2N_PKT_BUF_SIZE + 1];
    int nops = 6;
    int i;

    n3n_initfuncs();
    edge_init_conf_defaults(&conf, "_FUZZ");
    strncpy((char *)conf.community.community_name, FUZZ_COMMUNITY, sizeof(conf.community.community_name));
    conf.community.encrypt_key = strdup(FUZZ_KEY);
    n2n_transop_null_init(&conf, &ops[0]);
    n2n_transop_tf_init(&conf, &ops[1]);
    n2n_transop_aes_init(&conf, &ops[2]);
    n2n_transop_cc20_init(&conf, &ops[3]);
    n2n_transop_speck_init(&conf, &ops[4]);
    n2n_transop_lzo_init(&conf, &ops[5]);
#ifdef HAVE_LIBZSTD
    n2n_transop_zstd_init(&conf, &ops[6]);
    nops = 7;
#endif

    // an ethernet frame of sorts: some repetition for the compressions
    for(i = 0; i < (int)sizeof(in); i++) {
        in[i] = (i < 64) ? (uint8_t)(i * 13) : (uint8_t)"n3n fuzz "[i % 9];
    }
    for(i = 0; i < nops; i++) {
        size_t sizes[] = {60, sizeof(in)};
        unsigned j;

        for(j = 0; j < 2; j++) {
            char name[64];
            int n;

            out[0] = (uint8_t)i;   // the transform, as fuzz-transop takes it
            n = ops[i].fwd(&ops[i], out + 1, sizeof(out) - 1, in, sizes[j], mac);
            if(n <= 0) {
                continue;
            }
            snprintf(name, sizeof(name), "%s-%zu", names[i], sizes[j]);
            put("transop", name, out, n + 1);
        }
        ops[i].deinit(&ops[i]);
    }
}

int main (int argc, char *argv[]) {

    if(argc != 2) {
        fprintf(stderr, "usage: %s DIR\n", argv[0]);
        return 2;
    }
    top = argv[1];
    mkdir(top, 0777);
    packet_header_setup_key((char *)fuzz_community, &ctx_static, &ctx_dynamic, &iv_static, &iv_dynamic);
    pdus();
    transops();
    return 0;
}
