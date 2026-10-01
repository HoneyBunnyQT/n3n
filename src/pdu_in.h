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
#include <time.h>            // for time_t
#include "n2n_typedefs.h"    // for n2n_common_t, n3n_sock_t, SOCKET

struct speck_context_t;
struct sockaddr;
struct sn_community;
struct peer_info;

// A received PDU and what the first steps found out about it, for the
// handler of its message type.  It travels by value - from a packet thread
// to the main thread, with a copy of the PDU - so the pointers at its end are
// only good on the thread that set them.
struct pdu_ctx {
    uint8_t *buf;                   // the PDU, its header decrypted
    size_t size;
    n2n_common_t cmn;               // its common header, decoded
    size_t rem;                     // left to decode after the common header
    size_t idx;                     // decoding position after it
    n3n_sock_t sender;              // where it came from
    uint32_t header_enc;            // 0 plain, 1 static keys, 2 dynamic keys
    uint64_t stamp;                 // the time stamp of an encrypted header
    uint8_t hash_buf[16];           // of the still encrypted PDU, user/pw auth only
    bool from_supernode;
    bool via_multicast;
    bool in_community;              // relay: it belongs to a community known here
    SOCKET socket_fd;               // the socket it came in on; relay: the main thread's for that address
    time_t now;

    // only good on the thread that set them
    const struct sockaddr *sender_sock;
    socklen_t sock_size;
};

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
