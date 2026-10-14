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


#include <string.h>           // for memcpy

#include "portable_endian.h"  // for htole64, le64toh
#include "speck.h"


// The words of a block are little endian in memory, wherever they are: also
// unaligned, as they are within packets
static inline u64 load64_le (const unsigned char *p) {
    u64 v;
    memcpy(&v, p, sizeof(v));
    return le64toh(v);
}

static inline void store64_le (unsigned char *p, u64 v) {
    v = htole64(v);
    memcpy(p, &v, sizeof(v));
}

// cipher SPECK -- 128 bit block size -- 128 and 256 bit key size -- CTR mode
// taken from (and modified: removed pure crypto-stream generation and seperated key expansion)
// https://github.com/nsacyber/simon-speck-supercop/blob/master/crypto_stream/speck128256ctr/


#define ROR(x,r) (((x)>>(r))|((x)<<(64-(r))))
#define ROL(x,r) (((x)<<(r))|((x)>>(64-(r))))
#define R(x,y,k) (x=ROR(x,8), x+=y, x^=k, y=ROL(y,3), y^=x)


static int speck_encrypt (u64 *u, u64 *v, speck_context_t *ctx, int numrounds) {

    u64 i, x = *u, y = *v;

    for(i = 0; i < numrounds; i++)
        R(x, y, ctx->key[i]);
    *u = x; *v = y;

    return 0;
}


static int internal_speck_ctr (unsigned char *out, const unsigned char *in, unsigned long long inlen,
                               const unsigned char *n, speck_context_t *ctx) {

    u64 i, nonce[2], x, y, t;
    unsigned char block[16];
    int numrounds = (ctx->keysize == 256)?34:32;

    if(!inlen) {
        return 0;
    }
    nonce[0] = load64_le(&n[0]);
    nonce[1] = load64_le(&n[8]);

    // the keystream XORs the text as little endian words
    t=0;
    while(inlen >= 16) {
        x = nonce[1]; y = nonce[0]; nonce[0]++;
        speck_encrypt(&x, &y, ctx, numrounds);
        store64_le(&out[8 * (1+t)], x ^ load64_le(&in[8 * (1+t)]));
        store64_le(&out[8 * (0+t)], y ^ load64_le(&in[8 * (0+t)]));
        t += 2;
        inlen -= 16;
    }

    if(inlen > 0) {
        x = nonce[1]; y = nonce[0];
        speck_encrypt(&x, &y, ctx, numrounds);
        store64_le(&block[8], x); store64_le(&block[0], y);
        for(i = 0; i < inlen; i++)
            out[i + 8*t] = block[i] ^ in[i + 8*t];
    }

    return 0;
}


static void speck_expand_key (speck_context_t *ctx, const unsigned char *k, int keysize) {

    u64 K[4];
    u64 i;

    for(i = 0; i < (keysize >> 6); i++)
        K[i] = load64_le(&k[8 * i]);

    for(i = 0; i < 33; i += 3) {
        ctx->key[i  ] = K[0];
        R(K[1], K[0], i    );

        if(keysize == 256) {
            ctx->key[i+1] = K[0];
            R(K[2], K[0], i + 1);
            ctx->key[i+2] = K[0];
            R(K[3], K[0], i + 2);
        } else {
            // counter the i += 3 to make the loop go one by one in this case
            // we can afford the unused 31 and 32
            i -= 2;
        }
    }
    ctx->key[33] = K[0];

    ctx->keysize = keysize;
}


// every context's round keys once each (speck_init()), and the variant of
// every CPU
const struct speck_impl speck_impl_plainc = {
    .name = "plain C",
    .expand_key = speck_expand_key,
    .ctr = internal_speck_ctr,
};


// ----------------------------------------------------------------------------------------------------------------


// cipher SPECK -- 128 bit block size -- 128 bit key size -- ECB mode (decrypt only)
// follows endianess rules as used in official implementation guide and NOT as in original 2013 cipher presentation
// used for IV in header encryption (one block) and challenge encryption (user/password)
// for now: just plain C -- probably no need for AVX, SSE, NEON


#define ROTL64(x,r) (((x)<<(r))|((x)>>(64-(r))))
#define ROTR64(x,r) (((x)>>(r))|((x)<<(64-(r))))
#define DR128(x,y,k) (y^=x, y=ROTR64(y,3), x^=k, x-=y, x=ROTL64(x,8))
#define ER128(x,y,k) (x=(ROTR64(x,8)+y)^k, y=ROTL64(y,3)^x)

int speck_128_decrypt (unsigned char *inout, speck_context_t *ctx) {

    u64 x, y;
    int i;

    x = load64_le(&inout[8]);
    y = load64_le(&inout[0]);

    for(i = 31; i >= 0; i--)
        DR128(x, y, ctx->key[i]);

    store64_le(&inout[8], x);
    store64_le(&inout[0], y);

    return 0;
}


int speck_128_encrypt (unsigned char *inout, speck_context_t *ctx) {

    u64 x, y;
    int i;

    x = load64_le(&inout[8]);
    y = load64_le(&inout[0]);

    for(i = 0; i < 32; i++)
        ER128(x, y, ctx->key[i]);

    store64_le(&inout[8], x);
    store64_le(&inout[0], y);

    return 0;
}
