/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * AES with the ARMv8 Cryptography Extension
 *
 * Built when the compiler may use the AES instructions of ARMv8, e.g. with
 * -march=armv8-a+crypto or -march=native on a CPU that has them (Raspberry
 * Pi 5, most phones and servers - not the Raspberry Pi 3 and 4), on a little
 * endian host.  The results are the same as those of the other
 * implementations.
 */


#include "config.h"     // for HAVE_LIBCRYPTO


#ifdef HAVE_LIBCRYPTO // openSSL 1.1 ---------------------------------------------------------------------
#elif defined (__AES__) && defined (__SSE2__) // Intel's AES-NI ---------------------------------------------------
#elif (defined (__ARM_FEATURE_AES) || defined (__ARM_FEATURE_CRYPTO)) && !defined (__ARM_BIG_ENDIAN) // ARMv8 CE -


#include <arm_neon.h>       // for vaeseq_u8, vaesmcq_u8, vaesdq_u8, vaesimcq_u8, ...
#include <n3n/logging.h>    // for traceEvent
#include <stdlib.h>         // for calloc, free
#include <string.h>         // for memcpy

#include "aes.h"


// The round keys are worked out as 32 bit words, each holding four bytes of
// the key schedule in memory order - which is what the AES instructions want
// on a little endian host.


// SubWord() of FIPS-197: AESE with a zero round key does SubBytes and
// ShiftRows; with the word in all four columns, ShiftRows changes nothing
static uint32_t sub_word (uint32_t w) {

    uint8x16_t s = vaeseq_u8(vreinterpretq_u8_u32(vdupq_n_u32(w)), vdupq_n_u8(0));

    return vgetq_lane_u32(vreinterpretq_u32_u8(s), 0);
}


// RotWord() of FIPS-197, the bytes in memory order on a little endian host
static uint32_t rot_word (uint32_t w) {

    return (w >> 8) | (w << 24);
}


static int aes_internal_key_setup (aes_context_t *ctx, const uint8_t *key, int key_bits) {

    static const uint8_t rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
    uint32_t w[4 * 15];
    int nk = key_bits / 32;
    int nr = nk + 6;

    memcpy(w, key, 4 * nk);

    for(int i = nk; i < 4 * (nr + 1); i++) {
        uint32_t t = w[i - 1];
        if((i % nk) == 0) {
            t = sub_word(rot_word(t)) ^ rcon[i / nk - 1];
        } else if((nk > 6) && ((i % nk) == 4)) {
            t = sub_word(t);
        }
        w[i] = w[i - nk] ^ t;
    }

    for(int r = 0; r <= nr; r++) {
        ctx->rk_enc[r] = vreinterpretq_u8_u32(vld1q_u32(&w[4 * r]));
    }

    // the equivalent inverse cipher: the round keys in reverse order, the
    // inner ones with InvMixColumns
    ctx->rk_dec[0] = ctx->rk_enc[nr];
    for(int r = 1; r < nr; r++) {
        ctx->rk_dec[r] = vaesimcq_u8(ctx->rk_enc[nr - r]);
    }
    ctx->rk_dec[nr] = ctx->rk_enc[0];

    ctx->Nr = nr;

    return nr;
}


static inline uint8x16_t encrypt_block (const aes_context_t *ctx, uint8x16_t s) {

    int r;

    // AESE is AddRoundKey, SubBytes and ShiftRows, AESMC is MixColumns
    for(r = 0; r < ctx->Nr - 1; r++) {
        s = vaesmcq_u8(vaeseq_u8(s, ctx->rk_enc[r]));
    }
    s = vaeseq_u8(s, ctx->rk_enc[r]);

    return veorq_u8(s, ctx->rk_enc[r + 1]);
}


static inline uint8x16_t decrypt_block (const aes_context_t *ctx, uint8x16_t s) {

    int r;

    for(r = 0; r < ctx->Nr - 1; r++) {
        s = vaesimcq_u8(vaesdq_u8(s, ctx->rk_dec[r]));
    }
    s = vaesdq_u8(s, ctx->rk_dec[r]);

    return veorq_u8(s, ctx->rk_dec[r + 1]);
}


// ------------------------------------------------------------------------------------------------------------------
// public API


int aes_ecb_decrypt (unsigned char *out, const unsigned char *in, aes_context_t *ctx) {

    vst1q_u8(out, decrypt_block(ctx, vld1q_u8(in)));

    return AES_BLOCK_SIZE;
}


int aes_cbc_encrypt (unsigned char *out, const unsigned char *in, size_t in_len,
                     const unsigned char *iv, aes_context_t *ctx) {

    int ret = (int)in_len & 15;  /* remainder */
    uint8x16_t ivec = vld1q_u8(iv);

    for(size_t n = in_len / 16; n != 0; n--) {
        ivec = encrypt_block(ctx, veorq_u8(vld1q_u8(in), ivec));
        vst1q_u8(out, ivec);
        in += 16;
        out += 16;
    }

    return ret;
}


// encrypts several packets, each with its own CBC chain, at once
//
// CBC feeds every cipher text block into the next one, so a single packet
// leaves the pipeline of the AES unit mostly idle while each AESE waits for
// the one before.  Packets are independent of each other: four of them in
// lockstep fill the pipeline, as aes_sse2.c does with AES-NI.
int aes_cbc_encrypt_multi (unsigned char *out[], const unsigned char *in[], const size_t in_len[],
                           const unsigned char *iv, aes_context_t *ctx, int count) {

    int i;

    for(i = 0; i + 4 <= count; i += 4) {
        const unsigned char *in4[4];
        unsigned char *out4[4];
        size_t n4[4];
        uint8x16_t ivec[4];
        size_t n;

        for(int k = 0; k < 4; k++) {
            in4[k] = in[i + k];
            out4[k] = out[i + k];
            n4[k] = in_len[i + k] / 16;
            ivec[k] = vld1q_u8(iv);
        }

        // the four rails run in lockstep for as long as all four packets have
        // blocks left
        n = n4[0];
        for(int k = 1; k < 4; k++) {
            if(n4[k] < n) {
                n = n4[k];
            }
        }

        for(size_t b = 0; b < n; b++) {
            uint8x16_t s0 = veorq_u8(vld1q_u8(in4[0]), ivec[0]);
            uint8x16_t s1 = veorq_u8(vld1q_u8(in4[1]), ivec[1]);
            uint8x16_t s2 = veorq_u8(vld1q_u8(in4[2]), ivec[2]);
            uint8x16_t s3 = veorq_u8(vld1q_u8(in4[3]), ivec[3]);
            int r;

            for(r = 0; r < ctx->Nr - 1; r++) {
                s0 = vaesmcq_u8(vaeseq_u8(s0, ctx->rk_enc[r]));
                s1 = vaesmcq_u8(vaeseq_u8(s1, ctx->rk_enc[r]));
                s2 = vaesmcq_u8(vaeseq_u8(s2, ctx->rk_enc[r]));
                s3 = vaesmcq_u8(vaeseq_u8(s3, ctx->rk_enc[r]));
            }
            ivec[0] = veorq_u8(vaeseq_u8(s0, ctx->rk_enc[r]), ctx->rk_enc[r + 1]);
            ivec[1] = veorq_u8(vaeseq_u8(s1, ctx->rk_enc[r]), ctx->rk_enc[r + 1]);
            ivec[2] = veorq_u8(vaeseq_u8(s2, ctx->rk_enc[r]), ctx->rk_enc[r + 1]);
            ivec[3] = veorq_u8(vaeseq_u8(s3, ctx->rk_enc[r]), ctx->rk_enc[r + 1]);

            for(int k = 0; k < 4; k++) {
                vst1q_u8(out4[k], ivec[k]);
                in4[k] += 16;
                out4[k] += 16;
            }
        }

        // whatever is longer than the shortest packet of the four finishes on
        // its own
        for(int k = 0; k < 4; k++) {
            if(n4[k] > n) {
                uint8_t ivec_bytes[AES_BLOCK_SIZE];
                vst1q_u8(ivec_bytes, ivec[k]);
                aes_cbc_encrypt(out4[k], in4[k], (n4[k] - n) * 16, ivec_bytes, ctx);
            }
        }
    }

    // fewer than four packets left over
    for(; i < count; i++) {
        aes_cbc_encrypt(out[i], in[i], in_len[i], iv, ctx);
    }

    return 0;
}


int aes_cbc_decrypt (unsigned char *out, const unsigned char *in, size_t in_len,
                     const unsigned char *iv, aes_context_t *ctx) {

    int ret = (int)in_len & 15;  /* remainder */
    size_t n = in_len / 16;
    uint8x16_t ivec = vld1q_u8(iv);

    // the blocks are independent: four at a time keep the pipeline busy.
    // in and out may be the same buffer, so all four are read first
    for(; n >= 4; n -= 4) {
        uint8x16_t c0 = vld1q_u8(in);
        uint8x16_t c1 = vld1q_u8(in + 16);
        uint8x16_t c2 = vld1q_u8(in + 32);
        uint8x16_t c3 = vld1q_u8(in + 48);
        uint8x16_t s0 = c0, s1 = c1, s2 = c2, s3 = c3;
        int r;

        for(r = 0; r < ctx->Nr - 1; r++) {
            s0 = vaesimcq_u8(vaesdq_u8(s0, ctx->rk_dec[r]));
            s1 = vaesimcq_u8(vaesdq_u8(s1, ctx->rk_dec[r]));
            s2 = vaesimcq_u8(vaesdq_u8(s2, ctx->rk_dec[r]));
            s3 = vaesimcq_u8(vaesdq_u8(s3, ctx->rk_dec[r]));
        }
        s0 = veorq_u8(vaesdq_u8(s0, ctx->rk_dec[r]), ctx->rk_dec[r + 1]);
        s1 = veorq_u8(vaesdq_u8(s1, ctx->rk_dec[r]), ctx->rk_dec[r + 1]);
        s2 = veorq_u8(vaesdq_u8(s2, ctx->rk_dec[r]), ctx->rk_dec[r + 1]);
        s3 = veorq_u8(vaesdq_u8(s3, ctx->rk_dec[r]), ctx->rk_dec[r + 1]);

        vst1q_u8(out, veorq_u8(s0, ivec));
        vst1q_u8(out + 16, veorq_u8(s1, c0));
        vst1q_u8(out + 32, veorq_u8(s2, c1));
        vst1q_u8(out + 48, veorq_u8(s3, c2));
        ivec = c3;

        in += 64;
        out += 64;
    }

    for(; n != 0; n--) {
        uint8x16_t c = vld1q_u8(in);
        vst1q_u8(out, veorq_u8(decrypt_block(ctx, c), ivec));
        ivec = c;
        in += 16;
        out += 16;
    }

    return ret;
}


int aes_init (const unsigned char *key, size_t key_size, aes_context_t **ctx) {

    switch(key_size) {
        case AES128_KEY_BYTES:
        case AES192_KEY_BYTES:
        case AES256_KEY_BYTES:
            break;
        default:
            traceEvent(TRACE_ERROR, "aes_init invalid key size %u\n", key_size);
            return -1;
    }

    *ctx = (aes_context_t*)calloc(1, sizeof(aes_context_t));
    if(!(*ctx)) {
        return -1;
    }

    aes_internal_key_setup(*ctx, key, 8 * key_size);

    return 0;
}


int aes_deinit (aes_context_t *ctx) {

    free(ctx);

    return 0;
}


#endif // openSSL 1.1, AES-NI, ARMv8 CE ---------------------------------------------------------------------------
