/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Twofish's AVX-512 variant: its CBC decryption of 16 blocks at a time,
 * with VBMI and GFNI - built with those for these functions only, and taken
 * where the CPU has them (see tf.c for how a variant is chosen).  The rest
 * of the cipher is plain C (tf.c).
 */


#include "crypto_impl.h"  // for CRYPTO_TARGET_BEGIN
#include "tf.h"

#if defined (TF_X86_AVX512)


#include <immintrin.h>
#include <string.h>     // for memcpy

CRYPTO_TARGET_BEGIN("avx512f,avx512bw,avx512vbmi,gfni")


// 16 blocks at a time: one __m512i holds the same state word of 16 independent blocks,
// one block per 32-bit lane. Unlike the scalar rails, the g function does not use the
// QF tables from memory. Instead, the four keyed byte S-boxes s0..s3 (256 bytes each)
// are kept in registers and looked up with VPERMI2B, and the MDS multiplication is done
// with GF2P8AFFINEQB. Multiplying by a constant in GF(2^8) is linear over GF(2) for any
// reduction polynomial, so this works for Twofish's 0x169 as well (not only AES' 0x11B).
// As a side effect, this path does not do secret-indexed memory lookups.

// 8x8 bit matrices for multiplication by 0xEF and 0x5B mod 0x169, in GF2P8AFFINEQB
// layout (row for output bit i in byte 7-i), checked against multEF[] / mult5B[]
#define TF_AFFINE_MUL_EF 0x070F1F3972E3C183ULL
#define TF_AFFINE_MUL_5B 0x050B162953A24182ULL


// in-lane 4x4 transpose of 32-bit words, maps 16 blocks in memory order to (a permutation
// of) one block per lane and back, it is its own inverse
#define TRANSPOSE_4X4_512(X0, X1, X2, X3) { \
        __m512i t0 = _mm512_unpacklo_epi32(X0, X1), t1 = _mm512_unpackhi_epi32(X0, X1); \
        __m512i t2 = _mm512_unpacklo_epi32(X2, X3), t3 = _mm512_unpackhi_epi32(X2, X3); \
        X0 = _mm512_unpacklo_epi64(t0, t2); X1 = _mm512_unpackhi_epi64(t0, t2); \
        X2 = _mm512_unpacklo_epi64(t1, t3); X3 = _mm512_unpackhi_epi64(t1, t3); }


typedef struct {
    __m512i sb[4][4];                     // sb[p][c] holds s_p[64*c .. 64*c+63]
    __m512i mul_ef, mul_5b;               // affine matrices
    __m512i shA, shB1, shB2, shC1, shC2;  // MDS byte shuffles
} tf_avx512_sbox_t;


// byte position p within each 32-bit lane
#define POS_MASK(p) (0x1111111111111111ULL << (p))

// load the four 64 byte chunks of one keyed byte S-box (computed per key in tf_init)
#define LOAD_SB(s, ctx, p) ((s)->sb[p][0] = _mm512_loadu_si512((const void*)&(ctx)->SB[p][0]), \
                            (s)->sb[p][1] = _mm512_loadu_si512((const void*)&(ctx)->SB[p][64]), \
                            (s)->sb[p][2] = _mm512_loadu_si512((const void*)&(ctx)->SB[p][128]), \
                            (s)->sb[p][3] = _mm512_loadu_si512((const void*)&(ctx)->SB[p][192]))

// with y = S-box outputs (bytes y0..y3 per lane), A = y, B = 0xEF*y, C = 0x5B*y,
// the MDS output bytes are (read off the QF construction in fullKey()):
//   z0 = A0 ^ B1 ^ C2 ^ C3      z1 = C0 ^ B1 ^ B2 ^ A3
//   z2 = B0 ^ C1 ^ A2 ^ B3      z3 = B0 ^ A1 ^ B2 ^ C3
// gathered with in-lane byte shuffles (Z = zero)
#define Z (-128) /* index with top bit set yields zero, stays negative after the +4/+8/+12 */
#define SH(a, b, c, d) _mm512_broadcast_i32x4(_mm_setr_epi8(a,  b,  c,  d,  4+(a), 4+(b), 4+(c), 4+(d), \
                                                            8+(a), 8+(b), 8+(c), 8+(d), 12+(a), 12+(b), 12+(c), 12+(d)))

static void tf_avx512_setup (tf_avx512_sbox_t *s, const tf_context_t *ctx) {

    LOAD_SB(s, ctx, 0);
    LOAD_SB(s, ctx, 1);
    LOAD_SB(s, ctx, 2);
    LOAD_SB(s, ctx, 3);

    s->mul_ef = _mm512_set1_epi64((long long)TF_AFFINE_MUL_EF);
    s->mul_5b = _mm512_set1_epi64((long long)TF_AFFINE_MUL_5B);

    s->shA  = SH(0, 3, 2, 1);
    s->shB1 = SH(1, 1, 0, 0);
    s->shB2 = SH(Z, 2, 3, 2);
    s->shC1 = SH(2, 0, 1, 3);
    s->shC2 = SH(3, Z, Z, Z);
}
#undef Z
#undef SH


// 16-lane keyed S-box step: the byte at position p of each lane goes through s_p,
// TBL-style, one masked VPERMI2B per position and table half. As with fkh() above,
// the arguments are used more than once, so pass variables and not expressions.
#define SBOX_512(dst, X, s) do { \
        __mmask64 hi_ = _mm512_movepi8_mask(X); \
        __m512i r0_, r1_, r2_, r3_, r4_, r5_, r6_, r7_; \
        r0_ = _mm512_maskz_permutex2var_epi8(POS_MASK(0) & ~hi_, (s)->sb[0][0], X, (s)->sb[0][1]); \
        r1_ = _mm512_maskz_permutex2var_epi8(POS_MASK(0) & (hi_), (s)->sb[0][2], X, (s)->sb[0][3]); \
        r2_ = _mm512_maskz_permutex2var_epi8(POS_MASK(1) & ~hi_, (s)->sb[1][0], X, (s)->sb[1][1]); \
        r3_ = _mm512_maskz_permutex2var_epi8(POS_MASK(1) & (hi_), (s)->sb[1][2], X, (s)->sb[1][3]); \
        r4_ = _mm512_maskz_permutex2var_epi8(POS_MASK(2) & ~hi_, (s)->sb[2][0], X, (s)->sb[2][1]); \
        r5_ = _mm512_maskz_permutex2var_epi8(POS_MASK(2) & (hi_), (s)->sb[2][2], X, (s)->sb[2][3]); \
        r6_ = _mm512_maskz_permutex2var_epi8(POS_MASK(3) & ~hi_, (s)->sb[3][0], X, (s)->sb[3][1]); \
        r7_ = _mm512_maskz_permutex2var_epi8(POS_MASK(3) & (hi_), (s)->sb[3][2], X, (s)->sb[3][3]); \
        r0_ = _mm512_ternarylogic_epi32(r0_, r1_, r2_, 0xFE); /* a | b | c */ \
        r3_ = _mm512_ternarylogic_epi32(r3_, r4_, r5_, 0xFE); \
        (dst) = _mm512_ternarylogic_epi32(r0_, r3_, _mm512_or_si512(r6_, r7_), 0xFE); } while(0)


// 16-lane fully keyed h (aka g) function
#define G_512(dst, X, s) do { \
        __m512i y_, b_, c_, z_; \
        SBOX_512(y_, X, s); \
        b_ = _mm512_gf2p8affine_epi64_epi8(y_, (s)->mul_ef, 0); \
        c_ = _mm512_gf2p8affine_epi64_epi8(y_, (s)->mul_5b, 0); \
        z_ = _mm512_ternarylogic_epi32(_mm512_shuffle_epi8(y_, (s)->shA), /* a ^ b ^ c */ \
                                       _mm512_shuffle_epi8(b_, (s)->shB1), \
                                       _mm512_shuffle_epi8(b_, (s)->shB2), 0x96); \
        (dst) = _mm512_ternarylogic_epi32(z_, _mm512_shuffle_epi8(c_, (s)->shC1), \
                                          _mm512_shuffle_epi8(c_, (s)->shC2), 0x96); } while(0)


// 16-lane version of DEC_ROUND, ROL(R1, 8) is a single VPROLD here so no fkh8 trick needed
#define DEC_ROUND_512(R0, R1, R2, R3, round) do { \
        __m512i rot_ = _mm512_rol_epi32(R1, 8); \
        G_512(T0, R0, &sbox); \
        G_512(T1, rot_, &sbox); \
        R2 = _mm512_xor_si512(_mm512_rol_epi32(R2, 1), \
                              _mm512_add_epi32(_mm512_add_epi32(T0, T1), \
                                               _mm512_set1_epi32(ctx->K[2*round+8]))); \
        R3 = _mm512_ror_epi32(_mm512_xor_si512(R3, \
                                               _mm512_add_epi32(_mm512_add_epi32(T0, _mm512_add_epi32(T1, T1)), \
                                                                _mm512_set1_epi32(ctx->K[2*round+9]))), 1); } while(0)


// CBC-decrypt n16 * 16 blocks, updates ivec to the last ciphertext block; in == out is fine
static void tf_avx512_cbc_decrypt_16way (unsigned char *out, const unsigned char *in, int n16,
                                         uint32_t ivec[TF_BLOCK_WORDS], tf_context_t *ctx) {

    tf_avx512_sbox_t sbox;
    __m512i R0, R1, R2, R3, T0, T1;
    __m512i P0, P1, P2, P3; // chaining values
    uint8_t first[64];      // ivec followed by the first three ciphertext blocks

    tf_avx512_setup(&sbox, ctx);

    for(; n16 > 0; n16--) {
        // x86 is little endian, so no byteswapping on loads and stores
        R0 = _mm512_loadu_si512((const void*)(in +   0));
        R1 = _mm512_loadu_si512((const void*)(in +  64));
        R2 = _mm512_loadu_si512((const void*)(in + 128));
        R3 = _mm512_loadu_si512((const void*)(in + 192));

        // chaining values are the preceding ciphertext blocks, read them now so
        // that in-place (in == out) operation does not clobber them
        memcpy(first, ivec, TF_BLOCK_SIZE);
        memcpy(first + TF_BLOCK_SIZE, in, 3 * TF_BLOCK_SIZE);
        P0 = _mm512_loadu_si512((const void*)first);
        P1 = _mm512_loadu_si512((const void*)(in +  48));
        P2 = _mm512_loadu_si512((const void*)(in + 112));
        P3 = _mm512_loadu_si512((const void*)(in + 176));
        memcpy(ivec, in + 15 * TF_BLOCK_SIZE, TF_BLOCK_SIZE);

        // transpose, whiten input
        TRANSPOSE_4X4_512(R0, R1, R2, R3);
        R0 = _mm512_xor_si512(R0, _mm512_set1_epi32(ctx->K[4]));
        R1 = _mm512_xor_si512(R1, _mm512_set1_epi32(ctx->K[5]));
        R2 = _mm512_xor_si512(R2, _mm512_set1_epi32(ctx->K[6]));
        R3 = _mm512_xor_si512(R3, _mm512_set1_epi32(ctx->K[7]));

        DEC_ROUND_512(R0, R1, R2, R3, 15);
        DEC_ROUND_512(R2, R3, R0, R1, 14);
        DEC_ROUND_512(R0, R1, R2, R3, 13);
        DEC_ROUND_512(R2, R3, R0, R1, 12);
        DEC_ROUND_512(R0, R1, R2, R3, 11);
        DEC_ROUND_512(R2, R3, R0, R1, 10);
        DEC_ROUND_512(R0, R1, R2, R3,  9);
        DEC_ROUND_512(R2, R3, R0, R1,  8);
        DEC_ROUND_512(R0, R1, R2, R3,  7);
        DEC_ROUND_512(R2, R3, R0, R1,  6);
        DEC_ROUND_512(R0, R1, R2, R3,  5);
        DEC_ROUND_512(R2, R3, R0, R1,  4);
        DEC_ROUND_512(R0, R1, R2, R3,  3);
        DEC_ROUND_512(R2, R3, R0, R1,  2);
        DEC_ROUND_512(R0, R1, R2, R3,  1);
        DEC_ROUND_512(R2, R3, R0, R1,  0);

        // whiten output (output word order is R2, R3, R0, R1), transpose back, chain, store
        T0 = _mm512_xor_si512(R2, _mm512_set1_epi32(ctx->K[0]));
        T1 = _mm512_xor_si512(R3, _mm512_set1_epi32(ctx->K[1]));
        R0 = _mm512_xor_si512(R0, _mm512_set1_epi32(ctx->K[2]));
        R1 = _mm512_xor_si512(R1, _mm512_set1_epi32(ctx->K[3]));
        TRANSPOSE_4X4_512(T0, T1, R0, R1);

        _mm512_storeu_si512((void*)(out +   0), _mm512_xor_si512(T0, P0));
        _mm512_storeu_si512((void*)(out +  64), _mm512_xor_si512(T1, P1));
        _mm512_storeu_si512((void*)(out + 128), _mm512_xor_si512(R0, P2));
        _mm512_storeu_si512((void*)(out + 192), _mm512_xor_si512(R1, P3));

        in += 16 * TF_BLOCK_SIZE; out += 16 * TF_BLOCK_SIZE;
    }
}


CRYPTO_TARGET_END


const struct tf_impl tf_impl_avx512 = {
    .name = "AVX-512",
    .cbc_decrypt_16way = tf_avx512_cbc_decrypt_16way,
};


#endif // TF_X86_AVX512
