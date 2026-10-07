/*
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Regression tests for the receive-path out-of-bounds fixes (3.4.7):
 *
 *   - packet_header_decrypt() must not act on a packet shorter than the
 *     common part, nor on a decrypted header length below it (a foreign
 *     or made up packet) - header_len - 16 would wrap and the decryption
 *     run far past the buffer.
 *   - a transform's rev() must never write past out_len, and the block
 *     ciphers must not take a cipher text their assembly buffer cannot
 *     hold: it is given a narrow outbuf, and a cipher text as long as a
 *     whole packet buffer, and must refuse rather than overrun.
 *
 * Built with the sanitizers in CI, so an overrun shows as an ASan report;
 * without them, the return value alone is checked (never more than the
 * output buffer).  These hand malformed input straight to the decoders,
 * the way the fuzz targets found the bugs (tests/fuzz).
 */

#include <n3n/edge.h>          // for edge_init_conf_defaults, edge_term_conf
#include <n3n/initfuncs.h>     // for n3n_initfuncs, n3n_deinitfuncs
#include <n3n/logging.h>       // for setTraceLevel
#include <stdint.h>            // for uint8_t
#include <stdio.h>             // for printf
#include <stdlib.h>            // for strdup
#include <string.h>            // for memset, strncpy
#include "config.h"            // for HAVE_LIBZSTD
#include "header_encryption.h" // for packet_header_setup_key, packet_header_decrypt
#include "n2n.h"               // for n2n_trans_op_t, N2N_PKT_BUF_SIZE, ...

#define COMMON_PART 24         // what packet_header_encrypt() always makes


static int test_header (void) {
    char community[N2N_COMMUNITY_SIZE];
    struct speck_context_t *ctx_static, *ctx_dynamic, *iv_static, *iv_dynamic;
    uint8_t buf[N2N_PKT_BUF_SIZE];
    uint64_t stamp = 0;
    int failed = 0;

    memset(community, 0, sizeof(community));
    strncpy(community, "boundstest", sizeof(community) - 1);
    packet_header_setup_key(community, &ctx_static, &ctx_dynamic, &iv_static, &iv_dynamic);

    // a packet shorter than the common part must be left alone (return 0),
    // never read or written past its end
    memset(buf, 0, sizeof(buf));
    failed |= (packet_header_decrypt(buf, COMMON_PART - 1, community,
                                     ctx_static, iv_static, &stamp) != 0);
    printf("decode-bounds: header short packet rejected: %s\n", failed ? "FAIL" : "ok");

    // minimum-length packets of every community but ours: the decrypted
    // header length is arbitrary, so this used to wrap and overrun.  The
    // result does not matter, only that it stays within the buffer (ASan).
    int wrapped = 0;
    for(int pattern = 0; pattern < 3; pattern++) {
        for(int len = COMMON_PART; len <= COMMON_PART + 8; len++) {
            memset(buf, (pattern == 0) ? 0x00 : (pattern == 1) ? 0xff : 0x5a, sizeof(buf));
            packet_header_decrypt(buf, (uint16_t)len, community,
                                  ctx_static, iv_static, &stamp);
            wrapped++;
        }
    }
    printf("decode-bounds: header sub-minimal length handled (%d): ok\n", wrapped);

    speck_deinit((speck_context_t *)ctx_static);
    speck_deinit((speck_context_t *)ctx_dynamic);
    speck_deinit((speck_context_t *)iv_static);
    speck_deinit((speck_context_t *)iv_dynamic);
    return failed;
}


// Hand rev() a cipher text as long as a whole packet buffer, with a narrow
// output buffer: it must refuse (return <= 0), or at least never report
// more than the output buffer it was given.
static int test_transop_narrow (const char *name, n2n_trans_op_t *op) {
    uint8_t in[N2N_PKT_BUF_SIZE];
    uint8_t out[64];
    n2n_mac_t mac = {0x02, 0, 0, 0, 0, 0x01};
    int failed = 0;

    for(size_t i = 0; i < sizeof(in); i++) {
        in[i] = (uint8_t)(i * 31 + 7);
    }

    // narrow outbuf, cipher text far longer than it
    int rc = op->rev(op, out, sizeof(out), in, sizeof(in), mac);
    failed |= (rc > (int)sizeof(out));

    // and a cipher text filling the whole packet buffer, wide outbuf: the
    // block ciphers' assembly must still hold it (plus the stolen block)
    uint8_t wide[N2N_PKT_BUF_SIZE];
    rc = op->rev(op, wide, sizeof(wide), in, sizeof(in), mac);
    failed |= (rc > (int)sizeof(wide));

    printf("decode-bounds: %s within buffers: %s\n", name, failed ? "FAIL" : "ok");
    return failed;
}


int main (int argc, char *argv[]) {
    n2n_edge_conf_t conf;
    n2n_trans_op_t tf, aes, cc20, speck, lzo;
    int failed = 0;

    setTraceLevel(-1); // what the code logs about bad input is not the point
    n3n_initfuncs();

    edge_init_conf_defaults(&conf, "_TEST");
    strncpy((char *)conf.community.community_name, "boundstest", sizeof(conf.community.community_name));
    conf.community.encrypt_key = strdup("SoMEVer!S$cUREPassWORD");

    failed |= test_header();

    n2n_transop_tf_init(&conf, &tf);
    n2n_transop_aes_init(&conf, &aes);
    n2n_transop_cc20_init(&conf, &cc20);
    n2n_transop_speck_init(&conf, &speck);
    n2n_transop_lzo_init(&conf, &lzo);

    failed |= test_transop_narrow("tf", &tf);
    failed |= test_transop_narrow("aes", &aes);
    failed |= test_transop_narrow("cc20", &cc20);
    failed |= test_transop_narrow("speck", &speck);
    failed |= test_transop_narrow("lzo", &lzo);

    tf.deinit(&tf);
    aes.deinit(&aes);
    cc20.deinit(&cc20);
    speck.deinit(&speck);
    lzo.deinit(&lzo);

    edge_term_conf(&conf);
    n3n_deinitfuncs();
    return failed;
}
