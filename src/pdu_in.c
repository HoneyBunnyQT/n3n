/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The first steps with a received PDU - see pdu_in.h
 */

#include "header_encryption.h"  // for packet_header_decrypt
#include "n2n_define.h"         // for N2N_PKT_VERSION, N2N_REG_SUP_HASH_CHECK_LEN, ...
#include "n2n_typedefs.h"       // for MSG_TYPE_MAX_TYPE
#include "pdu_in.h"
#include "pearson.h"            // for pearson_hash_128


bool pdu_header_plain (const uint8_t *buf, size_t size) {

    // it heavily relies on the structure of the common part of the header:
    // changes to encode_common() and decode_common() go together with this
    if(size < 24) {
        return false;
    }

    uint16_t flags = ((uint16_t)buf[2] << 8) | buf[3];

    return (buf[23] == 0x00)                                         // null terminated community name
           && (buf[0] == N2N_PKT_VERSION)                            // correct packet version
           && ((flags & N2N_FLAGS_TYPE_MASK) <= MSG_TYPE_MAX_TYPE)   // message type
           && (flags < N2N_FLAGS_OPTIONS_MAX);                       // flags
}


int pdu_header_decrypt (uint8_t *buf, size_t size, const char *community,
                        struct speck_context_t *ctx_dynamic, struct speck_context_t *iv_dynamic,
                        struct speck_context_t *ctx_static, struct speck_context_t *iv_static,
                        uint8_t *hash_buf, uint64_t *stamp) {

    size_t size_no_hash = (size > N2N_REG_SUP_HASH_CHECK_LEN) ? size - N2N_REG_SUP_HASH_CHECK_LEN : 0;

    // the dynamic keys first: with plain header encryption they are the same
    // as the static ones
    if(packet_header_decrypt(buf, size, (char *)community, ctx_dynamic, iv_dynamic, stamp)) {
        return 2;
    }

    // the static ones: very likely a REGISTER_SUPER, _ACK, _NAK or invalid.
    // The hash of the still encrypted PDU is what user/password
    // authentication checks later
    if(hash_buf) {
        pearson_hash_128(hash_buf, buf, size_no_hash);
    }
    if(packet_header_decrypt(buf, size_no_hash, (char *)community, ctx_static, iv_static, stamp)) {
        return 1;
    }

    return 0;
}
