/*
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Fuzz target: the payload of a PACKET as the transforms take it apart -
 * the ciphers' and the compressions' rev().  The first byte picks the
 * transform, the rest is its input.  See README.md.
 */

#include <n3n/edge.h>        // for edge_init_conf_defaults
#include <n3n/initfuncs.h>   // for n3n_initfuncs
#include <n3n/logging.h>     // for setTraceLevel
#include <stdlib.h>          // for strdup
#include <string.h>          // for strncpy
#include "config.h"          // for HAVE_LIBZSTD
#include "fuzz.h"
#include "n2n.h"             // for n2n_transop_*_init, N2N_PKT_BUF_SIZE

#ifdef HAVE_LIBZSTD
#define NOPS 7
#else
#define NOPS 6
#endif

// the key the seeds use too
#define FUZZ_KEY "fuzz-secret"

static n2n_trans_op_t ops[NOPS];

int LLVMFuzzerInitialize (int *argc, char ***argv) {

    // what the code logs about bad input: not the point here, and slow
    setTraceLevel(-1);

    static n2n_edge_conf_t conf;

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
#endif
    return 0;
}

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size) {

    static uint8_t out[N2N_PKT_BUF_SIZE];
    n2n_mac_t mac = {0x02, 0, 0, 0, 0, 0x01};
    n2n_trans_op_t *op;

    if(size < 1) {
        return 0;
    }
    op = &ops[data[0] % NOPS];
    op->rev(op, out, sizeof(out), data + 1, size - 1, mac);
    return 0;
}
