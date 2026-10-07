/*
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * What the fuzz targets share, see README.md: each is a libFuzzer target
 * (LLVMFuzzerTestOneInput), built either with libFuzzer, or with driver.c,
 * which feeds it the files it is given - the regression corpus in the
 * unit tests.
 */

#ifndef _FUZZ_H_
#define _FUZZ_H_

#include <stddef.h>  // for size_t
#include <stdint.h>  // for uint8_t

// The community the header targets and the seeds use: as a name is kept,
// in a buffer of N2N_COMMUNITY_SIZE, padded with zeros - which the header
// keys are made of
#define FUZZ_COMMUNITY "fuzzcomm"
extern const uint8_t fuzz_community[];

int LLVMFuzzerInitialize (int *argc, char ***argv);
int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size);

// Decode a whole PDU as an edge or a supernode would: the common header,
// then the message its type says.  The result of the type's decoder, or
// -1.  What decodes is encoded again, which runs the encoders on whatever
// values the decoders let through.
int fuzz_decode_pdu (const uint8_t *buf, size_t size);

#endif
