/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The first steps with a received PDU, the same for edge and supernode
 */

#ifndef N3N_PDU_IN_H
#define N3N_PDU_IN_H

#include <stdbool.h>         // for bool
#include <stddef.h>          // for size_t
#include <stdint.h>          // for uint8_t, uint64_t

struct speck_context_t;

// Whether the header of a PDU looks unencrypted: a version, a message type
// and flags that make sense, and a community name that ends where it has to.
// Around 99.99962 percent reliable.  false for a PDU too short for a header.
bool pdu_header_plain (const uint8_t *buf, size_t size);

// Decrypt the header of a PDU with the keys of a community: the dynamic
// ones first, over the whole PDU, else the static ones, over all but the
// hash that may follow a REGISTER_SUPER, _ACK or _NAK with user/password
// authentication - hash_buf, if not NULL, gets the hash of the PDU before
// that.  stamp gets the time stamp of the header.
// Returns 2 for the dynamic keys, 1 for the static ones, 0 if neither fits.
int pdu_header_decrypt (uint8_t *buf, size_t size, const char *community,
                        struct speck_context_t *ctx_dynamic, struct speck_context_t *iv_dynamic,
                        struct speck_context_t *ctx_static, struct speck_context_t *iv_static,
                        uint8_t *hash_buf, uint64_t *stamp);

#endif
