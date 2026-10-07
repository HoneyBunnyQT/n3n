/*
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Fuzz target: a received PDU's first steps (src/pdu_in.c) - whether its
 * header is plain, the header decryption with the dynamic and the static
 * keys of a community - and then the decoders, on what came out.  See
 * README.md.
 */

#include <string.h>              // for memcpy
#include <n3n/logging.h>  // for setTraceLevel
#include "fuzz.h"
#include "header_encryption.h"   // for packet_header_setup_key
#include "n2n.h"                 // for N2N_PKT_BUF_SIZE
#include "pdu_in.h"              // for pdu_header_plain, pdu_header_decrypt

static struct speck_context_t *ctx_static, *ctx_dynamic, *iv_static, *iv_dynamic;

int LLVMFuzzerInitialize (int *argc, char ***argv) {

    // what the code logs about bad input: not the point here, and slow
    setTraceLevel(-1);

    packet_header_setup_key((char *)fuzz_community, &ctx_static, &ctx_dynamic, &iv_static, &iv_dynamic);
    return 0;
}

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size) {

    static uint8_t buf[N2N_PKT_BUF_SIZE];
    uint8_t hash[16];
    uint64_t stamp = 0;

    if(size > sizeof(buf)) {
        return 0;
    }
    memcpy(buf, data, size);

    if(pdu_header_plain(buf, size)) {
        fuzz_decode_pdu(buf, size);
        return 0;
    }
    if(pdu_header_decrypt(buf, size, (char *)fuzz_community, ctx_dynamic, iv_dynamic,
                          ctx_static, iv_static, hash, &stamp) > 0) {
        fuzz_decode_pdu(buf, size);
    }
    return 0;
}
