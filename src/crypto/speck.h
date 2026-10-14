/**
 * (C) 2007-22 - ntop.org and contributors
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


// cipher SPECK -- 128 bit block size -- 128 and 256 bit key size -- CTR mode
// taken from (and modified: removed pure crypto-stream generation and seperated key expansion)
// https://github.com/nsacyber/simon-speck-supercop/blob/master/crypto_stream/speck128256ctr/
//
// Every variant of the CPU's architecture is built - plain C, and SSE2,
// SSSE3, AVX2 and AVX-512 on x86, NEON on ARM - each with the extension it
// needs for its own functions only, and speck_init() takes the fastest one
// that the CPU at hand has (speck.c).  They all give the same bytes.


#ifndef SPECK_H
#define SPECK_H


#include <stdint.h>     // for uint64_t, uint32_t


#include <string.h>    /* memcpy() */

#define u32 uint32_t
#define u64 uint64_t

// A word of a block anywhere in memory, also unaligned (as within packets),
// in the CPU's order: the SIMD versions are for little endian CPUs only
static inline u64 speck_ld64 (const void *p) {
    u64 v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static inline void speck_st64 (void *p, u64 v) {
    memcpy(p, &v, sizeof(v));
}

#define N2N_SPECK_IVEC_SIZE     16
#define SPECK_KEY_BYTES       (256/8)


// The variants built besides plain C, by the architecture the compiler
// builds for; the SIMD ones are little endian only.  AVX2 and AVX-512 not
// on Windows: GCC does not align its stack there for 32 and 64 byte
// vectors (GCC bug 54412), and code that spills them would crash.
#if defined (__x86_64__) || defined (__i386__)
#define SPECK_X86       1
#if !defined (_WIN32)
#define SPECK_X86_AVX   1
#endif
#endif

#if defined (__ARM_NEON) && !defined (__ARM_BIG_ENDIAN)
#define SPECK_NEON      1
#endif

// A key, ready for use: its round keys once each, for plain C and the one
// block functions below, and as the context's variant has them, in priv -
// one per lane of its vectors, up to the eight of AVX-512, and aligned for
// them
#define SPECK_PRIV_BYTES        (40 * 64)

struct speck_impl;

typedef struct speck_context_t {
#if defined (_MSC_VER)
    __declspec(align(64)) unsigned char priv[SPECK_PRIV_BYTES];
#else
    unsigned char priv[SPECK_PRIV_BYTES] __attribute__((aligned(64)));
#endif
    u64 key[34];
    u32 keysize;
    const struct speck_impl *impl;
} speck_context_t;

// A variant: its name, and how it sets up priv and encrypts
struct speck_impl {
    const char *name;
    void (*expand_key)(speck_context_t *ctx, const unsigned char *k, int keysize);
    int (*ctr)(unsigned char *out, const unsigned char *in, unsigned long long inlen,
               const unsigned char *n, speck_context_t *ctx);
};


int speck_ctr (unsigned char *out, const unsigned char *in, unsigned long long inlen,
               const unsigned char *n,
               speck_context_t *ctx);

// create context loaded with round keys ready for use, key size either 128
// or 256 (bits), for the fastest variant this CPU has; 0, or -1 without
// memory
int speck_init (speck_context_t **ctx, const unsigned char *k, int keysize);

// the same for the variant given, one of speck_impls()
int speck_init_impl (speck_context_t **ctx, const unsigned char *k, int keysize,
                     const struct speck_impl *impl);

int speck_deinit (speck_context_t *ctx);

// The variants this CPU can run, slowest first - as many as fit in list,
// and how many there are - and the one speck_init() takes
int speck_impls (const struct speck_impl **list, int max);

const struct speck_impl *speck_impl_chosen (void);

// The variant of that name (see crypto_impl_named()), if this CPU has it;
// else NULL
const struct speck_impl *speck_impl_find (const char *name);


// ----------------------------------------------------------------------------------------------------------------
// ----------------------------------------------------------------------------------------------------------------


// cipher SPECK -- 128 bit block size -- 128 bit key size -- ECB mode
// follows endianess rules as used in official implementation guide and NOT as in original 2013 cipher presentation
// used for IV in header encryption (one block) and challenge encryption (user/password)
// for now: just plain C -- probably no need for AVX, SSE, NEON


int speck_128_decrypt (unsigned char *inout, speck_context_t *ctx);

int speck_128_encrypt (unsigned char *inout, speck_context_t *ctx);


#endif // SPECK_H
