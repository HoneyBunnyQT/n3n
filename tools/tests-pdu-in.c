/*
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The first steps with a received PDU, the same for both roles
 * (src/pdu_in.c), on PDUs made here:
 *
 *   - pdu_header_plain(): a header as encode_common() makes it is plain,
 *     one with a wrong version, type, flags or community name, too short,
 *     or encrypted is not
 *   - pdu_header_decrypt(): with the community's keys, the dynamic ones
 *     first, else the static ones over all but the hash that follows a
 *     registration with user/password authentication; the PDU and its
 *     time stamp come back as they were sent, and the hash is that of the
 *     still encrypted PDU; another community's keys, or a short PDU, fit
 *     neither
 *   - pdu_in_common(): the common header decoded, or the PDU dropped; with
 *     user/password authentication (dynamic keys) the static keys or none
 *     only for the types let through; a PDU from a supernode with the
 *     supernode it came from, or dropped if it is not known - unless its
 *     type is let through - and no supernode added for it
 *   - pdu_dispatch(): the handler of the type, once, with the runtime and
 *     the PDU; none for a type without a handler, or beyond the last type
 *
 * The output is the same on every system and byte order: the random numbers
 * of the IVs come from a fixed seed.
 */

#include <n3n/initfuncs.h>      // for n3n_initfuncs
#include <n3n/logging.h>        // for setTraceLevel
#include <n3n/random.h>         // for n3n_srand
#include <stdio.h>              // for printf
#include <string.h>             // for memcpy, memcmp, memset, strncpy
#include "header_encryption.h"  // for packet_header_encrypt, packet_header_setup_key, ...
#include "n2n.h"                // for n3n_runtime_data
#include "n2n_wire.h"           // for encode_common
#include "pearson.h"            // for pearson_hash_128
#include "uthash.h"             // for HASH_COUNT
#include "../src/pdu_in.h"      // for pdu_in_common, pdu_header_decrypt, ...
#include "../src/peer_info.h"   // for peer_info_malloc, clear_peer_list

#define COMMUNITY "pdu-test"
#define BODY 16                // bytes after the common header

static int failed;

static void check (const char *what, int ok) {
    printf("%s: %s\n", what, ok ? "ok" : "FAIL");
    failed |= !ok;
}

// A PDU of a type with flags, the common header and BODY bytes after it,
// into buf; returns its size
static size_t make_pdu (uint8_t *buf, const char *community, unsigned int type, uint16_t flags) {
    n2n_common_t cmn;
    size_t idx = 0;

    memset(&cmn, 0, sizeof(cmn));
    cmn.ttl = 2;
    cmn.pc = type;
    cmn.flags = flags;
    strncpy(cmn.community, community, N2N_COMMUNITY_SIZE - 1);
    encode_common(buf, &idx, &cmn);
    for(int i = 0; i < BODY; i++) {
        buf[idx++] = (uint8_t)(0xa0 + i);
    }
    return idx;
}

static void test_plain (void) {
    uint8_t buf[128];
    size_t size;
    int ok = 1;

    for(unsigned int type = 0; type <= MSG_TYPE_MAX_TYPE; type++) {
        size = make_pdu(buf, COMMUNITY, type, N2N_FLAGS_FROM_SUPERNODE | N2N_FLAGS_SOCKET);
        ok &= pdu_header_plain(buf, size);
    }
    check("plain: an encoded header of each type", ok);

    size = make_pdu(buf, COMMUNITY, MSG_TYPE_PACKET, 0);
    check("plain: one byte short of a header", !pdu_header_plain(buf, 23));

    buf[0] = N2N_PKT_VERSION - 1;
    check("plain: another version", !pdu_header_plain(buf, size));

    make_pdu(buf, COMMUNITY, MSG_TYPE_MAX_TYPE + 1, 0);
    check("plain: a type beyond the last", !pdu_header_plain(buf, size));

    make_pdu(buf, COMMUNITY, MSG_TYPE_PACKET, 0);
    buf[3] |= N2N_FLAGS_OPTIONS_MAX;
    check("plain: flags beyond the known ones", !pdu_header_plain(buf, size));

    make_pdu(buf, COMMUNITY, MSG_TYPE_PACKET, 0);
    buf[23] = 'x';
    check("plain: a community name not ended", !pdu_header_plain(buf, size));
}

// The keys of a community, as edge and supernode set them up
struct keys {
    struct speck_context_t *ctx_static, *ctx_dynamic, *iv_static, *iv_dynamic;
};

static void keys_setup (struct keys *k, const char *community, int user_password) {
    n2n_community_t name;

    memset(name, 0, sizeof(name));
    strncpy(name, community, N2N_COMMUNITY_SIZE - 1);
    memset(k, 0, sizeof(*k));
    packet_header_setup_key(name, &k->ctx_static, &k->ctx_dynamic, &k->iv_static, &k->iv_dynamic);
    if(user_password) {
        uint8_t dynamic_key[N2N_AUTH_CHALLENGE_SIZE];
        for(int i = 0; i < N2N_AUTH_CHALLENGE_SIZE; i++) {
            dynamic_key[i] = (uint8_t)(7 * i + 1);
        }
        packet_header_change_dynamic_key(dynamic_key, &k->ctx_dynamic, &k->iv_dynamic);
    }
}

static void keys_free (struct keys *k) {
    speck_deinit((speck_context_t *)k->ctx_static);
    speck_deinit((speck_context_t *)k->ctx_dynamic);
    speck_deinit((speck_context_t *)k->iv_static);
    speck_deinit((speck_context_t *)k->iv_dynamic);
}

static int decrypt (uint8_t *buf, size_t size, struct keys *k, uint8_t *hash_buf, uint64_t *stamp) {
    n2n_community_t name;

    memset(name, 0, sizeof(name));
    strncpy(name, COMMUNITY, N2N_COMMUNITY_SIZE - 1);
    return pdu_header_decrypt(buf, size, name, k->ctx_dynamic, k->iv_dynamic,
                              k->ctx_static, k->iv_static, hash_buf, stamp);
}

static void test_decrypt (void) {
    const uint64_t sent_stamp = 0x0123456789abcdefULL;
    uint8_t plain[128], buf[128], encrypted[128], hash[16], want_hash[16];
    uint64_t stamp;
    struct keys k, uk, other;
    size_t size;
    int got;

    keys_setup(&k, COMMUNITY, 0);
    keys_setup(&uk, COMMUNITY, 1);
    keys_setup(&other, "another", 0);

    // without user/password authentication the dynamic keys are the
    // static ones: whatever the type, it fits them first
    size = make_pdu(plain, COMMUNITY, MSG_TYPE_REGISTER_SUPER, 0);
    memcpy(buf, plain, size);
    packet_header_encrypt(buf, size, size, k.ctx_static, k.iv_static, sent_stamp);
    check("decrypt: an encrypted header is not plain", !pdu_header_plain(buf, size));
    stamp = 0;
    got = decrypt(buf, size, &k, NULL, &stamp);
    check("decrypt: the static keys, as the dynamic ones", got == 2);
    check("decrypt: the PDU as it was sent", !memcmp(buf, plain, size));
    check("decrypt: its time stamp", stamp == sent_stamp);

    // with user/password authentication, a PDU under the dynamic keys
    size = make_pdu(plain, COMMUNITY, MSG_TYPE_PACKET, 0);
    memcpy(buf, plain, size);
    packet_header_encrypt(buf, size, size, uk.ctx_dynamic, uk.iv_dynamic, sent_stamp);
    got = decrypt(buf, size, &uk, hash, &stamp);
    check("decrypt: user/password, the dynamic keys", (got == 2) && !memcmp(buf, plain, size));

    // and a registration under the static ones, with the hash after it
    size = make_pdu(plain, COMMUNITY, MSG_TYPE_REGISTER_SUPER, 0);
    memcpy(buf, plain, size);
    packet_header_encrypt(buf, size, size, uk.ctx_static, uk.iv_static, sent_stamp);
    for(int i = 0; i < N2N_REG_SUP_HASH_CHECK_LEN; i++) {
        buf[size + i] = (uint8_t)(0x50 + i);
    }
    memcpy(encrypted, buf, size + N2N_REG_SUP_HASH_CHECK_LEN);
    pearson_hash_128(want_hash, encrypted, size);
    stamp = 0;
    got = decrypt(buf, size + N2N_REG_SUP_HASH_CHECK_LEN, &uk, hash, &stamp);
    check("decrypt: user/password, the static keys, but the hash",
          (got == 1) && !memcmp(buf, plain, size) && (stamp == sent_stamp));
    check("decrypt: the hash of the PDU still encrypted", !memcmp(hash, want_hash, sizeof(hash)));
    check("decrypt: the hash after it left alone",
          !memcmp(buf + size, encrypted + size, N2N_REG_SUP_HASH_CHECK_LEN));

    // another community's
    size = make_pdu(plain, "another", MSG_TYPE_PACKET, 0);
    memcpy(buf, plain, size);
    packet_header_encrypt(buf, size, size, other.ctx_static, other.iv_static, sent_stamp);
    check("decrypt: another community's keys fit neither", decrypt(buf, size, &k, NULL, &stamp) == 0);

    // too short to be encrypted
    size = make_pdu(plain, COMMUNITY, MSG_TYPE_PACKET, 0);
    memcpy(buf, plain, size);
    packet_header_encrypt(buf, size, size, k.ctx_static, k.iv_static, sent_stamp);
    check("decrypt: a PDU shorter than a header", decrypt(buf, 23, &k, NULL, &stamp) == 0);

    keys_free(&k);
    keys_free(&uk);
    keys_free(&other);
}

static void sock_of (n3n_sock_t *sock, uint8_t last, uint16_t port) {
    memset(sock, 0, sizeof(*sock));
    sock->family = AF_INET;
    sock->type = SOCK_DGRAM;
    sock->port = port;
    sock->addr.v4[0] = 192;
    sock->addr.v4[1] = 0;
    sock->addr.v4[2] = 2;
    sock->addr.v4[3] = last;
}

// A received PDU of a type, decrypted with keys (0 plain, 1 static, 2
// dynamic), from a supernode or not, from 192.0.2.<last>
static void ctx_of (struct pdu_ctx *c, uint8_t *buf, unsigned int type, uint32_t header_enc,
                    int from_supernode, uint8_t last) {
    memset(c, 0, sizeof(*c));
    c->buf = buf;
    c->size = make_pdu(buf, COMMUNITY, type, from_supernode ? N2N_FLAGS_FROM_SUPERNODE : 0);
    c->header_enc = header_enc;
    sock_of(&c->sender, last, 7654);
    // a supernode of a PDU before: it has to be set anew
    c->sn = (struct peer_info *)c;
}

static void test_common (void) {
    const uint32_t registration = PDU_TYPE_BIT(MSG_TYPE_REGISTER_SUPER)
                                  | PDU_TYPE_BIT(MSG_TYPE_REGISTER_SUPER_ACK)
                                  | PDU_TYPE_BIT(MSG_TYPE_REGISTER_SUPER_NAK);
    const n2n_mac_t sn_mac = {0x02, 0x00, 0x5e, 0x00, 0x00, 0x01};
    struct peer_info *supernodes = NULL;
    struct peer_info *sn = peer_info_malloc(sn_mac);
    struct pdu_ctx c;
    uint8_t buf[128];
    int ret;

    sock_of(&sn->sock, 1, 7654);
    HASH_ADD_PEER(supernodes, sn);

    ctx_of(&c, buf, MSG_TYPE_PACKET, 0, 0, 9);
    ret = pdu_in_common(&c, false, 0, &supernodes, 0);
    check("common: a plain PACKET from an edge",
          (ret == 0) && (c.cmn.pc == MSG_TYPE_PACKET) && (c.cmn.ttl == 2)
          && !strcmp(c.cmn.community, COMMUNITY) && !c.from_supernode && !c.sn);
    check("common: what is left after the common header",
          (c.idx == c.size - BODY) && (c.rem == BODY) && (buf[c.idx] == 0xa0));

    ctx_of(&c, buf, MSG_TYPE_PACKET, 0, 0, 9);
    c.size = 10;
    check("common: a PDU shorter than a common header", pdu_in_common(&c, false, 0, &supernodes, 0) < 0);

    ctx_of(&c, buf, MSG_TYPE_PACKET, 0, 0, 9);
    buf[0] = N2N_PKT_VERSION + 1;
    check("common: another version", pdu_in_common(&c, false, 0, &supernodes, 0) < 0);

    // with user/password authentication
    ctx_of(&c, buf, MSG_TYPE_PACKET, 2, 0, 9);
    check("common: user/password, a PACKET under the dynamic keys",
          pdu_in_common(&c, true, registration, &supernodes, 0) == 0);
    ctx_of(&c, buf, MSG_TYPE_PACKET, 1, 0, 9);
    check("common: user/password, a PACKET under the static keys",
          pdu_in_common(&c, true, registration, &supernodes, 0) < 0);
    ctx_of(&c, buf, MSG_TYPE_PACKET, 0, 0, 9);
    check("common: user/password, a PACKET with a plain header",
          pdu_in_common(&c, true, registration, &supernodes, 0) < 0);
    ctx_of(&c, buf, MSG_TYPE_REGISTER_SUPER, 1, 0, 9);
    check("common: user/password, a REGISTER_SUPER under the static keys",
          pdu_in_common(&c, true, registration, &supernodes, 0) == 0);
    ctx_of(&c, buf, MSG_TYPE_REGISTER_SUPER_ACK, 1, 1, 1);
    check("common: user/password, a REGISTER_SUPER_ACK under the static keys",
          pdu_in_common(&c, true, registration, &supernodes, 0) == 0);
    ctx_of(&c, buf, MSG_TYPE_PEER_INFO, 1, 1, 1);
    check("common: user/password, a PEER_INFO under the static keys",
          pdu_in_common(&c, true, registration, &supernodes, 0) < 0);

    // from a supernode
    ctx_of(&c, buf, MSG_TYPE_PEER_INFO, 0, 1, 1);
    ret = pdu_in_common(&c, false, 0, &supernodes, 0);
    check("common: from a supernode known", (ret == 0) && c.from_supernode && (c.sn == sn));

    ctx_of(&c, buf, MSG_TYPE_PEER_INFO, 0, 1, 2);
    ret = pdu_in_common(&c, false, 0, &supernodes, 0);
    check("common: from a supernode not known", ret < 0);

    ctx_of(&c, buf, MSG_TYPE_REGISTER_SUPER, 0, 1, 2);
    ret = pdu_in_common(&c, false, 0, &supernodes, PDU_TYPE_BIT(MSG_TYPE_REGISTER_SUPER));
    check("common: from a supernode not known, of a type let through",
          (ret == 0) && c.from_supernode && !c.sn);
    check("common: no supernode added for them", HASH_COUNT(supernodes) == 1);

    clear_peer_list(&supernodes);
}

static struct n3n_runtime_data *handled_rt;
static struct pdu_ctx *handled_c;
static int handled;

static void handle_packet (struct n3n_runtime_data *rt, struct pdu_ctx *c) {
    handled_rt = rt;
    handled_c = c;
    handled++;
}

static void test_dispatch (void) {
    struct n3n_runtime_data rt;
    pdu_handlers_t handlers;
    struct pdu_ctx c;
    uint8_t buf[128];
    int ret;

    memset(handlers, 0, sizeof(handlers));
    handlers[MSG_TYPE_PACKET] = handle_packet;

    ctx_of(&c, buf, MSG_TYPE_PACKET, 0, 0, 9);
    pdu_in_common(&c, false, 0, NULL, 0);
    ret = pdu_dispatch(&rt, handlers, &c);
    check("dispatch: the handler of its type, once",
          (ret == 0) && (handled == 1) && (handled_rt == &rt) && (handled_c == &c));

    ctx_of(&c, buf, MSG_TYPE_REGISTER, 0, 0, 9);
    pdu_in_common(&c, false, 0, NULL, 0);
    ret = pdu_dispatch(&rt, handlers, &c);
    check("dispatch: a type without a handler", (ret < 0) && (handled == 1));

    c.cmn.pc = MSG_TYPE_MAX_TYPE + 1;
    ret = pdu_dispatch(&rt, handlers, &c);
    check("dispatch: a type beyond the last", (ret < 0) && (handled == 1));
}

int main (int argc, char *argv[]) {

    setTraceLevel(TRACE_ERROR);
    n3n_initfuncs();
    n3n_srand(42);

    test_plain();
    test_decrypt();
    test_common();
    test_dispatch();

    return failed;
}
