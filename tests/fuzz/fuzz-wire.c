/*
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Fuzz target: the PDU decoders (src/wire.c), on PDUs as they are after
 * the header decryption - or as they come, with plain headers.  See
 * README.md.
 */

#include <n3n/logging.h>  // for setTraceLevel
#include "fuzz.h"

int LLVMFuzzerInitialize (int *argc, char ***argv) {

    // what the code logs about bad input: not the point here, and slow
    setTraceLevel(-1);

    return 0;
}

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size) {

    fuzz_decode_pdu(data, size);
    return 0;
}
