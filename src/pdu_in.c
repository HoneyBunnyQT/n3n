/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The first steps with a received PDU - see pdu_in.h
 */

#include <n3n/logging.h>        // for traceEvent
#include "header_encryption.h"  // for packet_header_decrypt
#include "n2n_define.h"         // for N2N_PKT_VERSION, N2N_REG_SUP_HASH_CHECK_LEN, ...
#include "n2n_typedefs.h"       // for MSG_TYPE_MAX_TYPE, null_mac
#include "n2n_wire.h"           // for decode_common
#include "pdu_in.h"
#include "peer_info.h"          // for add_sn_to_list_by_mac_or_sock, SN_ADD_SKIP
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


int pdu_in_common (struct pdu_ctx *c, bool dynamic_keys, uint32_t static_ok,
                   struct peer_info **supernodes, uint32_t unknown_sn_ok) {

    // counts down what is left, against reading past the PDU
    c->rem = c->size;
    c->idx = 0;
    if(decode_common(&c->cmn, c->buf, &c->rem, &c->idx) < 0) {
        // from the local network: maybe another community's, its header
        // encrypted
        traceEvent(c->via_multicast ? TRACE_DEBUG : TRACE_INFO, "dropped a PDU: its common header does not decode");
        return -1;
    }

    unsigned int type = c->cmn.pc;
    uint32_t bit = (type < 32) ? PDU_TYPE_BIT(type) : 0;

    // with user/password authentication only the registration with a
    // supernode may come with the static keys, see pdu_header_decrypt()
    if(dynamic_keys && (c->header_enc != 2) && !(static_ok & bit)) {
        traceEvent(TRACE_INFO, "dropped a PDU encrypted with the static keys where the dynamic ones are due");
        return -1;
    }

    c->from_supernode = c->cmn.flags & N2N_FLAGS_FROM_SUPERNODE;
    c->sn = NULL;
    if(c->from_supernode) {
        int skip_add = SN_ADD_SKIP;
        c->sn = add_sn_to_list_by_mac_or_sock(supernodes, &c->sender, null_mac, &skip_add);
        if(!c->sn && !(unknown_sn_ok & bit)) {
            traceEvent(TRACE_DEBUG, "dropped incoming data from unknown supernode");
            return -1;
        }
    }

    return 0;
}


int pdu_dispatch (struct n3n_runtime_data *rt, const pdu_handlers_t handlers, struct pdu_ctx *c) {

    unsigned int type = c->cmn.pc;

    if((type > MSG_TYPE_MAX_TYPE) || !handlers[type]) {
        traceEvent(TRACE_INFO, "unable to handle packet type %u: ignored", type);
        return -1;
    }
    handlers[type](rt, c);
    return 0;
}
