/**
 * SPDX-License-Identifier: GPL-3.0-only
 * SPDX-FileCopyrightText: Copyright ntop.org and contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */


#ifdef HAVE_LIBCRYPTO // openSSL 1.1 ---------------------------------------------------------------------
#elif defined (__AVX512F__)  // AVX512 ------------------------------------------------------------------------------
#elif defined (__AVX2__)  // AVX2 -----------------------------------------------------------------------------------
#elif defined (__SSE2__)  // SSE2 ---------------------------------------------------------------------------------
#else // plain C --------------------------------------------------------------------------------------------------


#include <n3n/logging.h> // for traceEvent
#include <stdlib.h>     // for calloc, free, size_t
#include <string.h>     // for memcpy

#include "cc20.h"
#include "config.h"  // HAVE_LIBCRYPTO
#include "portable_endian.h"  // for htole32, le32toh


// taken (and modified) from https://github.com/Ginurx/chacha20-c (public domain)


// what one call works on - on its stack, not in the shared context
typedef struct cc20_block {
    uint32_t keystream32[16];
    uint32_t state[16];
} cc20_block_t;


static void cc20_init_block (const cc20_context_t *ctx, cc20_block_t *blk, const uint8_t nonce[]) {

    const uint8_t *magic_constant = (uint8_t*)"expand 32-byte k";

    memcpy(&(blk->state[ 0]), magic_constant, 16);
    memcpy(&(blk->state[ 4]), ctx->key, CC20_KEY_BYTES);
    memcpy(&(blk->state[12]), nonce, CC20_IV_SIZE);

    // the words of constant, key and nonce are little endian
    for(int i = 0; i < 16; i++) {
        blk->state[i] = le32toh(blk->state[i]);
    }
}


#define ROL32(x,r) (((x)<<(r))|((x)>>(32-(r))))

#define CC20_QUARTERROUND(x, a, b, c, d)         \
    x[a] += x[b]; x[d] = ROL32(x[d] ^ x[a], 16); \
    x[c] += x[d]; x[b] = ROL32(x[b] ^ x[c], 12); \
    x[a] += x[b]; x[d] = ROL32(x[d] ^ x[a],  8); \
    x[c] += x[d]; x[b] = ROL32(x[b] ^ x[c],  7)

#define CC20_DOUBLE_ROUND(s)            \
    /* odd round */                     \
    CC20_QUARTERROUND(s, 0, 4,  8, 12); \
    CC20_QUARTERROUND(s, 1, 5,  9, 13); \
    CC20_QUARTERROUND(s, 2, 6, 10, 14); \
    CC20_QUARTERROUND(s, 3, 7, 11, 15); \
    /* even round */                    \
    CC20_QUARTERROUND(s, 0, 5, 10, 15); \
    CC20_QUARTERROUND(s, 1, 6, 11, 12); \
    CC20_QUARTERROUND(s, 2, 7,  8, 13); \
    CC20_QUARTERROUND(s, 3, 4,  9, 14)


static void cc20_block_next (cc20_block_t *blk) {

    uint32_t *counter = blk->state + 12;

    blk->keystream32[ 0] = blk->state[ 0];
    blk->keystream32[ 1] = blk->state[ 1];
    blk->keystream32[ 2] = blk->state[ 2];
    blk->keystream32[ 3] = blk->state[ 3];
    blk->keystream32[ 4] = blk->state[ 4];
    blk->keystream32[ 5] = blk->state[ 5];
    blk->keystream32[ 6] = blk->state[ 6];
    blk->keystream32[ 7] = blk->state[ 7];
    blk->keystream32[ 8] = blk->state[ 8];
    blk->keystream32[ 9] = blk->state[ 9];
    blk->keystream32[10] = blk->state[10];
    blk->keystream32[11] = blk->state[11];
    blk->keystream32[12] = blk->state[12];
    blk->keystream32[13] = blk->state[13];
    blk->keystream32[14] = blk->state[14];
    blk->keystream32[15] = blk->state[15];

    // 10 double rounds
    CC20_DOUBLE_ROUND(blk->keystream32);
    CC20_DOUBLE_ROUND(blk->keystream32);
    CC20_DOUBLE_ROUND(blk->keystream32);
    CC20_DOUBLE_ROUND(blk->keystream32);
    CC20_DOUBLE_ROUND(blk->keystream32);
    CC20_DOUBLE_ROUND(blk->keystream32);
    CC20_DOUBLE_ROUND(blk->keystream32);
    CC20_DOUBLE_ROUND(blk->keystream32);
    CC20_DOUBLE_ROUND(blk->keystream32);
    CC20_DOUBLE_ROUND(blk->keystream32);

    blk->keystream32[ 0] += blk->state[ 0];
    blk->keystream32[ 1] += blk->state[ 1];
    blk->keystream32[ 2] += blk->state[ 2];
    blk->keystream32[ 3] += blk->state[ 3];
    blk->keystream32[ 4] += blk->state[ 4];
    blk->keystream32[ 5] += blk->state[ 5];
    blk->keystream32[ 6] += blk->state[ 6];
    blk->keystream32[ 7] += blk->state[ 7];
    blk->keystream32[ 8] += blk->state[ 8];
    blk->keystream32[ 9] += blk->state[ 9];
    blk->keystream32[10] += blk->state[10];
    blk->keystream32[11] += blk->state[11];
    blk->keystream32[12] += blk->state[12];
    blk->keystream32[13] += blk->state[13];
    blk->keystream32[14] += blk->state[14];
    blk->keystream32[15] += blk->state[15];

    // the keystream is the little endian bytes of its words
    for(int i = 0; i < 16; i++) {
        blk->keystream32[i] = htole32(blk->keystream32[i]);
    }

    (*counter)++;
}


static void cc20_init_context (const cc20_context_t *ctx, cc20_block_t *blk, const uint8_t *nonce) {

    cc20_init_block(ctx, blk, nonce);
}


int cc20_crypt (unsigned char *out, const unsigned char *in, size_t in_len,
                const unsigned char *iv, cc20_context_t *ctx) {

    cc20_block_t blk;
    uint8_t   *keystream8 = (uint8_t*)blk.keystream32;

    cc20_init_context(ctx, &blk, iv);

    // in and out may be unaligned, as they are within packets
    while(in_len >= 64) {
        uint32_t w[16];

        cc20_block_next(&blk);

        memcpy(w, in, 64);
        for(int i = 0; i < 16; i++) {
            w[i] ^= blk.keystream32[i];
        }
        memcpy(out, w, 64);

        in += 64;
        out += 64;
        in_len -= 64;
    }

    if(in_len > 0) {
        cc20_block_next(&blk);

        for(size_t i = 0; i < in_len; i++) {
            out[i] = in[i] ^ keystream8[i];
        }
    }

    return(0);
}


int cc20_init (const unsigned char *key, cc20_context_t **ctx) {

    // allocate context...
    *ctx = (cc20_context_t*)calloc(1, sizeof(cc20_context_t));
    if(!(*ctx))
        return -1;
    memcpy((*ctx)->key, key, CC20_KEY_BYTES);

    return 0;
}


int cc20_deinit (cc20_context_t *ctx) {

    free(ctx);
    return 0;
}


#endif // openSSL 1.1, plain C ------------------------------------------------------------------------------------
