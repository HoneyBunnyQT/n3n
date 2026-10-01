/**
 * SPDX-License-Identifier: GPL-3.0-only
 * SPDX-FileCopyrightText: Copyright ntop.org and contributors
 * SPDX-FileCopyrightText: Copyright Honey Bunny QT
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


#include <n3n/logging.h> // for traceEvent
#include <stdlib.h>     // for calloc, free, size_t
#include <string.h>     // for memcpy

#include "cc20.h"
#include "config.h"  // HAVE_LIBCRYPTO
#include "portable_endian.h"  // for htole32


// same approach as the SSE2 code below, but with four blocks per register: each
// 128 bit lane of a __m512i holds one row of one block, so the same permutes and
// rounds work lane by lane and four blocks are computed at once


#include <immintrin.h>  // for _mm512_xor_si512, _mm512_add_epi32, _mm512_rol_epi32
#include <xmmintrin.h>  // for _MM_SHUFFLE


#define XOR _mm512_xor_si512
#define ADD _mm512_add_epi32
#define ROL(X,r) (_mm512_rol_epi32(X,r))  /* AVX512F rotates, no shift and or needed */

#define ROL8(X)  ROL(X,8)
#define ROL16(X) ROL(X,16)

#define ZERO_TO_THREE _mm512_setr_epi32(0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0)
#define FOUR          _mm512_setr_epi32(4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0)
#define EIGHT         _mm512_setr_epi32(8, 0, 0, 0, 8, 0, 0, 0, 8, 0, 0, 0, 8, 0, 0, 0)


#define CC20_PERMUTE_ROWS(A,B,C,D)                        \
    B = _mm512_shuffle_epi32(B, _MM_SHUFFLE(0, 3, 2, 1)); \
    C = _mm512_shuffle_epi32(C, _MM_SHUFFLE(1, 0, 3, 2)); \
    D = _mm512_shuffle_epi32(D, _MM_SHUFFLE(2, 1, 0, 3))

#define CC20_PERMUTE_ROWS_INV(A,B,C,D)                    \
    B = _mm512_shuffle_epi32(B, _MM_SHUFFLE(2, 1, 0, 3)); \
    C = _mm512_shuffle_epi32(C, _MM_SHUFFLE(1, 0, 3, 2)); \
    D = _mm512_shuffle_epi32(D, _MM_SHUFFLE(0, 3, 2, 1))

#define CC20_ODD_ROUND(A,B,C,D)            \
    /* odd round */                        \
    A = ADD(A, B); D = ROL16(XOR(D, A));   \
    C = ADD(C, D); B = ROL(XOR(B, C), 12); \
    A = ADD(A, B); D = ROL8(XOR(D, A));    \
    C = ADD(C, D); B = ROL(XOR(B, C),  7)

#define CC20_EVEN_ROUND(A,B,C,D)   \
    CC20_PERMUTE_ROWS(A, B, C, D); \
    CC20_ODD_ROUND(A, B, C, D);    \
    CC20_PERMUTE_ROWS_INV(A, B, C, D)

#define CC20_DOUBLE_ROUND(A,B,C,D) \
    CC20_ODD_ROUND(A, B, C, D);    \
    CC20_EVEN_ROUND(A, B, C, D)

// the four rows of a block sit in the same lane of four registers, gather them
// into one register per block (lane j of K0..K3 becomes block j)
#define CC20_LANES_TO_BLOCKS(K0,K1,K2,K3,B0,B1,B2,B3)    \
    B0 = _mm512_shuffle_i32x4(K0, K1, _MM_SHUFFLE(1, 0, 1, 0)); \
    B1 = _mm512_shuffle_i32x4(K2, K3, _MM_SHUFFLE(1, 0, 1, 0)); \
    B2 = _mm512_shuffle_i32x4(K0, K1, _MM_SHUFFLE(3, 2, 3, 2)); \
    B3 = _mm512_shuffle_i32x4(K2, K3, _MM_SHUFFLE(3, 2, 3, 2)); \
    K0 = _mm512_shuffle_i32x4(B0, B1, _MM_SHUFFLE(2, 0, 2, 0)); \
    K1 = _mm512_shuffle_i32x4(B0, B1, _MM_SHUFFLE(3, 1, 3, 1)); \
    K2 = _mm512_shuffle_i32x4(B2, B3, _MM_SHUFFLE(2, 0, 2, 0)); \
    K3 = _mm512_shuffle_i32x4(B2, B3, _MM_SHUFFLE(3, 1, 3, 1))

#define STOREXOR(O,I,X)                                              \
    _mm512_storeu_si512((__m512i*)O,                                 \
                        _mm512_xor_si512(_mm512_loadu_si512((__m512i*)I), X)); \
    I += 64; O += 64                                                 \

#define STORE(O,X)                          \
    _mm512_storeu_si512((__m512i*)O, X);    \
    O += 64                                 \


int cc20_crypt (unsigned char *out, const unsigned char *in, size_t in_len,
                const unsigned char *iv, cc20_context_t *ctx) {

    __m512i a, b, c, d, k0, k1, k2, k3, k4, k5, k6, k7, t0, t1, t2, t3;

    uint8_t keystream8[256];
    uint8_t *keystream_p;

    const uint8_t *magic_constant = (uint8_t*)"expand 32-byte k";

    a = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)magic_constant));
    b = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(ctx->key)));
    c = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)((ctx->key)+16)));
    d = ADD(_mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)iv)), ZERO_TO_THREE);

    while(in_len >= 512) {
        k0 = a; k1 = b; k2 = c; k3 = d;
        k4 = a; k5 = b; k6 = c; k7 = ADD(d, FOUR);

        // 10 double rounds -- two in parallel to make better use of all registers
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3); CC20_DOUBLE_ROUND(k4, k5, k6, k7);

        k0 = ADD(k0, a); k1 = ADD(k1, b); k2 = ADD(k2, c); k3 = ADD(k3, d);
        k4 = ADD(k4, a); k5 = ADD(k5, b); k6 = ADD(k6, c); k7 = ADD(k7, d); k7 = ADD(k7, FOUR);

        CC20_LANES_TO_BLOCKS(k0, k1, k2, k3, t0, t1, t2, t3);
        STOREXOR(out, in, k0); STOREXOR(out, in, k1); STOREXOR(out, in, k2); STOREXOR(out, in, k3);

        CC20_LANES_TO_BLOCKS(k4, k5, k6, k7, t0, t1, t2, t3);
        STOREXOR(out, in, k4); STOREXOR(out, in, k5); STOREXOR(out, in, k6); STOREXOR(out, in, k7);

        // increment counter, make sure it is and stays little endian in memory
        d = ADD(d, EIGHT);

        in_len -= 512;
    }

    while(in_len >= 256) {
        k0 = a; k1 = b; k2 = c; k3 = d;

        // 10 double rounds
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);

        k0 = ADD(k0, a); k1 = ADD(k1, b); k2 = ADD(k2, c); k3 = ADD(k3, d);

        CC20_LANES_TO_BLOCKS(k0, k1, k2, k3, t0, t1, t2, t3);
        STOREXOR(out, in, k0); STOREXOR(out, in, k1); STOREXOR(out, in, k2); STOREXOR(out, in, k3);

        // increment counter, make sure it is and stays little endian in memory
        d = ADD(d, FOUR);

        in_len -= 256;
    }

    if(in_len) {
        k0 = a; k1 = b; k2 = c; k3 = d;

        // 10 double rounds
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);
        CC20_DOUBLE_ROUND(k0, k1, k2, k3);

        k0 = ADD(k0, a); k1 = ADD(k1, b); k2 = ADD(k2, c); k3 = ADD(k3, d);

        CC20_LANES_TO_BLOCKS(k0, k1, k2, k3, t0, t1, t2, t3);

        keystream_p = keystream8;
        STORE(keystream_p, k0); STORE(keystream_p, k1); STORE(keystream_p, k2); STORE(keystream_p, k3);

        // keep in mind that out and in got increased inside the last loop
        // and point to current position now
        while(in_len > 0) {
            in_len--;
            out[in_len] = in[in_len] ^ keystream8[in_len];
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


#elif defined (__AVX2__)  // AVX2 -----------------------------------------------------------------------------------
#elif defined (__SSE2__)  // SSE2 ---------------------------------------------------------------------------------
#elif defined (__ARM_NEON) && !defined (__ARM_BIG_ENDIAN) // NEON ---------------------------------------------------
#else // plain C --------------------------------------------------------------------------------------------------
#endif // openSSL 1.1, plain C ------------------------------------------------------------------------------------
