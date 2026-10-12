/*
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The seeds of the fuzz targets: "fuzz-seeds DIR" writes into DIR/wire,
 * DIR/header, DIR/transop and DIR/tcp valid inputs of each - PDUs of every
 * type, the same with encrypted headers, payloads as each transform makes
 * them, and PDUs as a TCP connection brings them - for the fuzzer to start
 * from.  See README.md.
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

// A PDU on a v3tcp connection, for the tcp target: its length in front,
// in pieces of a byte with their length and then as many bytes - pieces of
// at most step bytes, and copies of the frame one after the other
static void tcp (const char *name, const char *how, const uint8_t *buf, size_t len,
                 size_t step, int copies) {

    static uint8_t out[4 * (N2N_PKT_BUF_SIZE + 2) * 2];
    uint8_t frame[N2N_PKT_BUF_SIZE + 2];
    size_t n = 0;
    char tname[256];
    int c;

    frame[0] = (uint8_t)(len >> 8);
    frame[1] = (uint8_t)len;
    memcpy(frame + 2, buf, len);
    for(c = 0; c < copies; c++) {
        size_t at = 0;
        while(at < len + 2) {
            size_t piece = (len + 2 - at < step) ? len + 2 - at : step;
            out[n++] = (uint8_t)piece;
            memcpy(out + n, frame + at, piece);
            n += piece;
            at += piece;
        }
    }
    snprintf(tname, sizeof(tname), "%s-%s", name, how);
    put("tcp", tname, out, n);
}

// a PDU, plain for the decoders and the header target, and with an
// encrypted header for the header target; framed for the tcp target
static void pdu (const char *name, uint8_t *buf, size_t len, size_t header_len) {

    uint8_t enc[N2N_PKT_BUF_SIZE];

    tcp(name, "whole", buf, len, 255, 1);
    tcp(name, "split", buf, len, 1, 1);    // a byte at a time
    tcp(name, "two", buf, len, 100, 2);    // two, cut across
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

// Requests to the management interface, for the mgmt target: a byte for
// the runtime (0 the supernode, 1 the edge), then the request
static void mgmt (void) {

    static const char *gets[] = {
        "/", "/unlock", "/debug/slots", "/events/peer", "/help", "/metrics",
        "/script.js", "/status"
    };
    static const char *methods[] = {
        "get_communities", "get_edges", "get_info", "get_mac", "get_packetstats",
        "get_supernodes", "get_timestamps", "get_verbose", "help", "help.events",
        "post.test", "reload", "reload_communities", "set_verbose", "stop"
    };
    static const char *paths[] = {"/v1", "/v1/edge", "/v1/supernode"};
    // "fuzz:n3n", the default password
    static const char *auth = "Authorization: Basic ZnV6ejpuM24=\r\n";
    char req[1024];
    char name[128];
    unsigned i, j;
    int role, a;

    for(role = 0; role < 2; role++) {
        for(i = 0; i < sizeof(gets) / sizeof(gets[0]); i++) {
            int n = snprintf(req, sizeof(req), "%cGET %s HTTP/1.1\r\nHost: localhost\r\n"
                             "Connection: keep-alive\r\n%s\r\n", role, gets[i], i == 1 ? auth : "");
            snprintf(name, sizeof(name), "%d-get-%u", role, i);
            put("mgmt", name, (uint8_t *)req, n);
        }
        for(i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
            for(a = 0; a < 2; a++) {
                char body[256];
                int blen = snprintf(body, sizeof(body),
                                    "{\"jsonrpc\":\"2.0\",\"method\":\"%s\",\"id\":%u,"
                                    "\"params\":%s}", methods[i], i,
                                    !strcmp(methods[i], "set_verbose") ? "3"
                                    : !strcmp(methods[i], "post.test") ? "\"hello\""
                                    : "{\"limit\":2,\"offset\":1}");
                j = i % (sizeof(paths) / sizeof(paths[0]));
                int n = snprintf(req, sizeof(req), "%cPOST %s HTTP/1.1\r\nHost: localhost\r\n"
                                 "Origin: http://localhost\r\n%sContent-Length: %d\r\n\r\n%s",
                                 role, paths[j], a ? auth : "", blen, body);
                snprintf(name, sizeof(name), "%d-rpc-%s-%d", role, methods[i], a);
                put("mgmt", name, (uint8_t *)req, n);
            }
        }
        {
            static const char *page = "do=more";
            int n = snprintf(req, sizeof(req), "%cPOST /page HTTP/1.0\r\n%s"
                             "Content-Length: %zu\r\n\r\n%s", role, auth, strlen(page), page);
            snprintf(name, sizeof(name), "%d-page", role);
            put("mgmt", name, (uint8_t *)req, n);
        }
    }
}

// Inputs for the tun target: a byte for the direction (0 a frame from the
// network for tun_from_frame, 1 an IP packet from the device for
// tun_to_frame), then the frame or packet
static void tun (void) {

    uint8_t b[256];
    uint8_t own[6] = {0x02, 0, 0, 0, 0, 0x01};
    uint8_t peer[6] = {0x02, 0, 0, 0, 0, 0x02};

    // --- frames from the network (direction 0) ---

    // an ARP request for the edge's address (10.0.0.1)
    {
        size_t n = 0;
        b[n++] = 0;                                 // direction
        memcpy(b + n, "\xff\xff\xff\xff\xff\xff", 6); n += 6;   // dst broadcast
        memcpy(b + n, peer, 6); n += 6;             // src
        b[n++] = 0x08; b[n++] = 0x06;               // ARP
        b[n++] = 0; b[n++] = 1; b[n++] = 0x08; b[n++] = 0x00;
        b[n++] = 6; b[n++] = 4; b[n++] = 0; b[n++] = 1;   // request
        memcpy(b + n, peer, 6); n += 6;             // sha
        b[n++] = 10; b[n++] = 0; b[n++] = 0; b[n++] = 2;  // spa 10.0.0.2
        memcpy(b + n, "\0\0\0\0\0\0", 6); n += 6;      // tha
        b[n++] = 10; b[n++] = 0; b[n++] = 0; b[n++] = 1;  // tpa 10.0.0.1
        put("tun", "arp-request", b, n);
        b[9] = 2;                                   // op reply
        put("tun", "arp-reply", b, n);
    }

    // an IPv4 packet to the edge
    {
        size_t n = 0;
        b[n++] = 0;
        memcpy(b + n, own, 6); n += 6;              // dst the edge
        memcpy(b + n, peer, 6); n += 6;             // src
        b[n++] = 0x08; b[n++] = 0x00;               // IPv4
        size_t ip = n;
        memset(b + n, 0, 20);
        b[ip] = 0x45;                               // v4, ihl 5
        b[ip + 9] = 17;                             // UDP
        b[ip + 12] = 10; b[ip + 13] = 0; b[ip + 14] = 0; b[ip + 15] = 2;  // src
        b[ip + 16] = 10; b[ip + 17] = 0; b[ip + 18] = 0; b[ip + 19] = 1;  // dst
        n += 20;
        n += 8;                                     // a little payload
        put("tun", "ipv4-in", b, n);
    }

    // --- IP packets from the device (direction 1) ---

    // IPv4 to a peer in the subnet
    {
        size_t n = 0;
        b[n++] = 1;
        size_t ip = n;
        memset(b + n, 0, 20);
        b[ip] = 0x45;
        b[ip + 16] = 10; b[ip + 17] = 0; b[ip + 18] = 0; b[ip + 19] = 2;  // dst in subnet
        n += 20 + 8;
        put("tun", "ipv4-out", b, n);
        b[1 + 16] = 0xff; b[1 + 17] = 0xff; b[1 + 18] = 0xff; b[1 + 19] = 0xff;
        put("tun", "ipv4-out-broadcast", b, n);
        b[1 + 16] = 0xe0; b[1 + 17] = 0; b[1 + 18] = 0; b[1 + 19] = 1;     // 224.0.0.1
        put("tun", "ipv4-out-multicast", b, n);
    }

    // IPv6 multicast from the device
    {
        size_t n = 0;
        b[n++] = 1;
        size_t ip = n;
        memset(b + n, 0, 40);
        b[ip] = 0x60;                               // v6
        b[ip + 24] = 0xff; b[ip + 25] = 0x02;       // ff02::...
        b[ip + 36] = 0; b[ip + 37] = 0; b[ip + 38] = 0; b[ip + 39] = 1;
        n += 40;
        put("tun", "ipv6-out-multicast", b, n);
        // to the IPv4 address of a peer in the prefix, to one asked for
        // with a neighbour solicitation, to a MAC's EUI-64, outside it
        memcpy(b + ip + 24, "\xfd\x00\x00\x77\0\0\0\0\0\0\0\0\x0a\x00\x00\x02", 16);
        put("tun", "ipv6-out-v4", b, n);
        memcpy(b + ip + 24, "\xfd\x00\x00\x77\0\0\0\0\0\0\0\0\0\0\x0b\x0b", 16);
        put("tun", "ipv6-out-solicit", b, n);
        memcpy(b + ip + 24, "\xfe\x80\0\0\0\0\0\0\0\0\0\xff\xfe\0\0\x02", 16);
        put("tun", "ipv6-out-eui64", b, n);
        memcpy(b + ip + 24, "\x20\x01\x0d\xb8\0\0\0\0\0\0\0\0\0\0\0\x01", 16);
        put("tun", "ipv6-out-elsewhere", b, n);
    }

    // a neighbour solicitation for the edge's IPv6 address, and an
    // advertisement of a peer's, each with its link-layer address option
    {
        size_t n = 0;
        b[n++] = 0;
        memcpy(b + n, "\x33\x33\xff\x00\x00\x01", 6); n += 6;   // solicited-node
        memcpy(b + n, peer, 6); n += 6;
        b[n++] = 0x86; b[n++] = 0xdd;               // IPv6
        size_t ip = n;
        memset(b + n, 0, 40 + 32);
        b[ip] = 0x60;
        b[ip + 5] = 32;                             // payload length
        b[ip + 6] = 58;                             // ICMPv6
        b[ip + 7] = 255;                            // hop limit
        memcpy(b + ip + 8, "\xfd\x00\x00\x77\0\0\0\0\0\0\0\0\x0a\x00\x00\x02", 16);
        memcpy(b + ip + 24, "\xff\x02\0\0\0\0\0\0\0\0\0\x01\xff\x00\x00\x01", 16);
        size_t icmp = ip + 40;
        b[icmp] = 135;                              // solicitation
        memcpy(b + icmp + 8, "\xfd\x00\x00\x77\0\0\0\0\0\0\0\0\x0a\x00\x00\x01", 16);
        b[icmp + 24] = 1; b[icmp + 25] = 1;         // source link-layer address
        memcpy(b + icmp + 26, peer, 6);
        n += 40 + 32;
        put("tun", "ipv6-solicit", b, n);
        b[icmp] = 136;                              // advertisement, of the peer
        memcpy(b + icmp + 8, b + ip + 8, 16);
        b[icmp + 24] = 2;                           // target link-layer address
        put("tun", "ipv6-advert", b, n);
        memset(b + ip + 8, 0, 16);                  // a duplicate address check
        b[icmp] = 135;
        memcpy(b + icmp + 8, "\xfd\x00\x00\x77\0\0\0\0\0\0\0\0\x0a\x00\x00\x01", 16);
        put("tun", "ipv6-solicit-dad", b, n);
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
    mgmt();
    tun();
    return 0;
}
