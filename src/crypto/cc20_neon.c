/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * ChaCha20 with ARM NEON
 *
 * Built where the compiler may use NEON on a little endian host: always on
 * aarch64, on 32 bit ARM with e.g. -mfpu=neon.  The same row-wise layout as
 * cc20_sse2.c: a vector holds a row of the 4x4 state, and several blocks are
 * worked on at once to keep the NEON pipeline busy - four on aarch64, two on
 * 32 bit ARM with its fewer registers.
 */


#include "config.h"     // for HAVE_LIBCRYPTO


#ifdef HAVE_LIBCRYPTO // openSSL 1.1 ---------------------------------------------------------------------
#elif defined (__AVX512F__)  // AVX512 ------------------------------------------------------------------------------
#elif defined (__AVX2__)  // AVX2 -----------------------------------------------------------------------------------
#elif defined (__SSE2__)  // SSE2 ---------------------------------------------------------------------------------
#elif defined (__ARM_NEON) && !defined (__ARM_BIG_ENDIAN) // NEON ---------------------------------------------------


#include <arm_neon.h>       // for uint32x4_t, vaddq_u32, veorq_u32, ...
#include <stdlib.h>         // for calloc, free, size_t
#include <string.h>         // for memcpy

#include "cc20.h"


#define ADD vaddq_u32
#define XOR veorq_u32

// rotate each 32 bit lane left: shift left, and insert the bits shifted out
// on the right
#define ROL(X,r) vsriq_n_u32(vshlq_n_u32(X, r), X, 32 - (r))

// by 16: swap the halves of each lane
#define ROL16(X) vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(X)))

#if defined (__aarch64__)
// by 8: a byte shuffle
static const uint8_t rol8_idx[16] = { 3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14 };
#define ROL8(X) vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(X), rol8_tbl))
#else
#define ROL8(X) ROL(X, 8)
#endif

// rotate the lanes of the rows so that the diagonals line up as columns, and
// back
#define CC20_PERMUTE_ROWS(A,B,C,D) \
    B = vextq_u32(B, B, 1);        \
    C = vextq_u32(C, C, 2);        \
    D = vextq_u32(D, D, 3)

#define CC20_PERMUTE_ROWS_INV(A,B,C,D) \
    B = vextq_u32(B, B, 3);            \
    C = vextq_u32(C, C, 2);            \
    D = vextq_u32(D, D, 1)

#define CC20_ODD_ROUND(A,B,C,D)            \
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

// XOR 16 bytes of keystream into the text, which need not be aligned
#define STOREXOR(O,I,X)                                                        \
    vst1q_u8(O, veorq_u8(vld1q_u8(I), vreinterpretq_u8_u32(X))); \
    I += 16; O += 16


// the keystream of one block, worked out from the state a, b, c, d
#define CC20_BLOCK(K0,K1,K2,K3,A,B,C,D)                   \
    K0 = A; K1 = B; K2 = C; K3 = D;                         \
    for(int r_ = 0; r_ < 10; r_++) {                        \
        CC20_DOUBLE_ROUND(K0, K1, K2, K3);                  \
    }                                                       \
    K0 = ADD(K0, A); K1 = ADD(K1, B); K2 = ADD(K2, C); K3 = ADD(K3, D)


int cc20_crypt (unsigned char *out, const unsigned char *in, size_t in_len,
                const unsigned char *iv, cc20_context_t *ctx) {

    uint32x4_t a, b, c, d;
    uint32x4_t k0, k1, k2, k3, k4, k5, k6, k7;
    const uint32x4_t one = { 1, 0, 0, 0 };
    const uint32x4_t two = { 2, 0, 0, 0 };
#if defined (__aarch64__)
    const uint8x16_t rol8_tbl = vld1q_u8(rol8_idx);
    const uint32x4_t three = { 3, 0, 0, 0 };
    const uint32x4_t four = { 4, 0, 0, 0 };
    uint32x4_t k8, k9, k10, k11, k12, k13, k14, k15;
#endif

    // the state: constant, key and nonce (with the counter in its first
    // word), all little endian
    a = vreinterpretq_u32_u8(vld1q_u8((const uint8_t *)"expand 32-byte k"));
    b = vreinterpretq_u32_u8(vld1q_u8(ctx->key));
    c = vreinterpretq_u32_u8(vld1q_u8(ctx->key + 16));
    d = vreinterpretq_u32_u8(vld1q_u8(iv));

#if defined (__aarch64__)
    while(in_len >= 256) {
        uint32x4_t d1 = ADD(d, one);
        uint32x4_t d2 = ADD(d, two);
        uint32x4_t d3 = ADD(d, three);

        k0 = a; k1 = b; k2 = c; k3 = d;
        k4 = a; k5 = b; k6 = c; k7 = d1;
        k8 = a; k9 = b; k10 = c; k11 = d2;
        k12 = a; k13 = b; k14 = c; k15 = d3;

        // 10 double rounds, four blocks side by side
        for(int r = 0; r < 10; r++) {
            CC20_DOUBLE_ROUND(k0, k1, k2, k3);
            CC20_DOUBLE_ROUND(k4, k5, k6, k7);
            CC20_DOUBLE_ROUND(k8, k9, k10, k11);
            CC20_DOUBLE_ROUND(k12, k13, k14, k15);
        }

        k0 = ADD(k0, a); k1 = ADD(k1, b); k2 = ADD(k2, c); k3 = ADD(k3, d);
        k4 = ADD(k4, a); k5 = ADD(k5, b); k6 = ADD(k6, c); k7 = ADD(k7, d1);
        k8 = ADD(k8, a); k9 = ADD(k9, b); k10 = ADD(k10, c); k11 = ADD(k11, d2);
        k12 = ADD(k12, a); k13 = ADD(k13, b); k14 = ADD(k14, c); k15 = ADD(k15, d3);

        STOREXOR(out, in, k0); STOREXOR(out, in, k1); STOREXOR(out, in, k2); STOREXOR(out, in, k3);
        STOREXOR(out, in, k4); STOREXOR(out, in, k5); STOREXOR(out, in, k6); STOREXOR(out, in, k7);
        STOREXOR(out, in, k8); STOREXOR(out, in, k9); STOREXOR(out, in, k10); STOREXOR(out, in, k11);
        STOREXOR(out, in, k12); STOREXOR(out, in, k13); STOREXOR(out, in, k14); STOREXOR(out, in, k15);

        d = ADD(d, four);
        in_len -= 256;
    }
#endif

    while(in_len >= 128) {
        uint32x4_t d1 = ADD(d, one);

        k0 = a; k1 = b; k2 = c; k3 = d;
        k4 = a; k5 = b; k6 = c; k7 = d1;

        // 10 double rounds, two blocks side by side
        for(int r = 0; r < 10; r++) {
            CC20_DOUBLE_ROUND(k0, k1, k2, k3);
            CC20_DOUBLE_ROUND(k4, k5, k6, k7);
        }

        k0 = ADD(k0, a); k1 = ADD(k1, b); k2 = ADD(k2, c); k3 = ADD(k3, d);
        k4 = ADD(k4, a); k5 = ADD(k5, b); k6 = ADD(k6, c); k7 = ADD(k7, d1);

        STOREXOR(out, in, k0); STOREXOR(out, in, k1); STOREXOR(out, in, k2); STOREXOR(out, in, k3);
        STOREXOR(out, in, k4); STOREXOR(out, in, k5); STOREXOR(out, in, k6); STOREXOR(out, in, k7);

        d = ADD(d, two);
        in_len -= 128;
    }

    if(in_len >= 64) {
        CC20_BLOCK(k0, k1, k2, k3, a, b, c, d);

        STOREXOR(out, in, k0); STOREXOR(out, in, k1); STOREXOR(out, in, k2); STOREXOR(out, in, k3);

        d = ADD(d, one);
        in_len -= 64;
    }

    if(in_len) {
        uint8_t keystream8[64];

        CC20_BLOCK(k0, k1, k2, k3, a, b, c, d);

        vst1q_u8(&keystream8[ 0], vreinterpretq_u8_u32(k0));
        vst1q_u8(&keystream8[16], vreinterpretq_u8_u32(k1));
        vst1q_u8(&keystream8[32], vreinterpretq_u8_u32(k2));
        vst1q_u8(&keystream8[48], vreinterpretq_u8_u32(k3));

        for(size_t i = 0; i < in_len; i++) {
            out[i] = in[i] ^ keystream8[i];
        }
    }

    return 0;
}


int cc20_init (const unsigned char *key, cc20_context_t **ctx) {

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


#endif // openSSL 1.1, AVX512, AVX2, SSE2, NEON -----------------------------------------------------------------
