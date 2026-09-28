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
#elif defined (__AVX2__)  // AVX2 -----------------------------------------------------------------------------------


#include <n3n/logging.h> // for traceEvent
#include <stdlib.h>     // for calloc, free, size_t
#include <string.h>     // for memcpy

#include "cc20.h"
#include "config.h"  // HAVE_LIBCRYPTO
#include "portable_endian.h"  // for htole32


// same approach as the SSE2 code below, but with two blocks per register: each
// 128 bit lane of a __m256i holds one row of one block, so the same permutes and
// rounds work lane by lane and two blocks are computed at once


#include <immintrin.h>  // for _mm256_xor_si256, _mm256_add_epi32, _mm256_shuffle_epi8
#include <xmmintrin.h>  // for _MM_SHUFFLE


#define SL  _mm256_slli_epi32
#define SR  _mm256_srli_epi32
#define XOR _mm256_xor_si256
#define ADD _mm256_add_epi32
#define ROL(X,r) (XOR(SL(X,r),SR(X,(32-r))))

// AVX2 always has the byte shuffle, so these two rotations are one instruction
#define L8  _mm256_set_epi32(0x0e0d0c0fL, 0x0a09080bL, 0x06050407L, 0x02010003L, \
                             0x0e0d0c0fL, 0x0a09080bL, 0x06050407L, 0x02010003L)
#define L16 _mm256_set_epi32(0x0d0c0f0eL, 0x09080b0aL, 0x05040706L, 0x01000302L, \
                             0x0d0c0f0eL, 0x09080b0aL, 0x05040706L, 0x01000302L)
#define ROL8(X)  (_mm256_shuffle_epi8(X, L8))
#define ROL16(X) (_mm256_shuffle_epi8(X, L16))

#define ZERO_ONE _mm256_setr_epi32(0, 0, 0, 0, 1, 0, 0, 0)
#define TWO      _mm256_setr_epi32(2, 0, 0, 0, 2, 0, 0, 0)
#define FOUR     _mm256_setr_epi32(4, 0, 0, 0, 4, 0, 0, 0)


#define CC20_PERMUTE_ROWS(A,B,C,D)                        \
    B = _mm256_shuffle_epi32(B, _MM_SHUFFLE(0, 3, 2, 1)); \
    C = _mm256_shuffle_epi32(C, _MM_SHUFFLE(1, 0, 3, 2)); \
    D = _mm256_shuffle_epi32(D, _MM_SHUFFLE(2, 1, 0, 3))

#define CC20_PERMUTE_ROWS_INV(A,B,C,D)                    \
    B = _mm256_shuffle_epi32(B, _MM_SHUFFLE(2, 1, 0, 3)); \
    C = _mm256_shuffle_epi32(C, _MM_SHUFFLE(1, 0, 3, 2)); \
    D = _mm256_shuffle_epi32(D, _MM_SHUFFLE(0, 3, 2, 1))

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
// into two registers per block (low lanes are the first block, high lanes the second)
#define CC20_LANES_TO_BLOCKS(K0,K1,K2,K3,B0,B1,B2,B3)  \
    B0 = _mm256_permute2x128_si256(K0, K1, 0x20);      \
    B1 = _mm256_permute2x128_si256(K2, K3, 0x20);      \
    B2 = _mm256_permute2x128_si256(K0, K1, 0x31);      \
    B3 = _mm256_permute2x128_si256(K2, K3, 0x31);      \
    K0 = B0; K1 = B1; K2 = B2; K3 = B3

#define STOREXOR(O,I,X)                                              \
    _mm256_storeu_si256((__m256i*)O,                                 \
                        _mm256_xor_si256(_mm256_loadu_si256((__m256i*)I), X)); \
    I += 32; O += 32                                                 \

#define STORE(O,X)                          \
    _mm256_storeu_si256((__m256i*)O, X);    \
    O += 32                                 \


int cc20_crypt (unsigned char *out, const unsigned char *in, size_t in_len,
                const unsigned char *iv, cc20_context_t *ctx) {

    __m256i a, b, c, d, k0, k1, k2, k3, k4, k5, k6, k7, t0, t1, t2, t3;

    uint8_t keystream8[128];
    uint8_t *keystream_p;

    const uint8_t *magic_constant = (uint8_t*)"expand 32-byte k";

    a = _mm256_broadcastsi128_si256(_mm_loadu_si128((__m128i*)magic_constant));
    b = _mm256_broadcastsi128_si256(_mm_loadu_si128((__m128i*)(ctx->key)));
    c = _mm256_broadcastsi128_si256(_mm_loadu_si128((__m128i*)((ctx->key)+16)));
    d = ADD(_mm256_broadcastsi128_si256(_mm_loadu_si128((__m128i*)iv)), ZERO_ONE);

    while(in_len >= 256) {
        k0 = a; k1 = b; k2 = c; k3 = d;
        k4 = a; k5 = b; k6 = c; k7 = ADD(d, TWO);

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
        k4 = ADD(k4, a); k5 = ADD(k5, b); k6 = ADD(k6, c); k7 = ADD(k7, d); k7 = ADD(k7, TWO);

        CC20_LANES_TO_BLOCKS(k0, k1, k2, k3, t0, t1, t2, t3);
        STOREXOR(out, in, k0); STOREXOR(out, in, k1); STOREXOR(out, in, k2); STOREXOR(out, in, k3);

        CC20_LANES_TO_BLOCKS(k4, k5, k6, k7, t0, t1, t2, t3);
        STOREXOR(out, in, k4); STOREXOR(out, in, k5); STOREXOR(out, in, k6); STOREXOR(out, in, k7);

        // increment counter, make sure it is and stays little endian in memory
        d = ADD(d, FOUR);

        in_len -= 256;
    }

    while(in_len >= 128) {
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
        d = ADD(d, TWO);

        in_len -= 128;
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


#elif defined (__SSE2__)  // SSE2 ---------------------------------------------------------------------------------
#else // plain C --------------------------------------------------------------------------------------------------
#endif // openSSL 1.1, plain C ------------------------------------------------------------------------------------
