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


#ifndef AES_H
#define AES_H


#include <stdint.h>
#include <stdlib.h>

#include "portable_endian.h"

#define AES_BLOCK_SIZE           16
#define AES_IV_SIZE             (AES_BLOCK_SIZE)

#define AES256_KEY_BYTES        (256/8)
#define AES192_KEY_BYTES        (192/8)
#define AES128_KEY_BYTES        (128/8)


// Every variant the build can have is built - plain C; AES-NI on x86, the
// ARMv8 Cryptography Extension on little endian ARM (on 32 bit ARM only
// where the build's baseline has it); OpenSSL's, with --with-openssl -
// each with the extension it needs for its own functions only, and
// aes_init() takes the fastest one the CPU at hand has (aes.c).  They all
// give the same bytes.
#if defined (__x86_64__) || defined (__i386__)
#define AES_X86         1
#endif

#if defined (__aarch64__) && !defined (__ARM_BIG_ENDIAN)
#define AES_ARMCE       1
#elif defined (__arm__) && (defined (__ARM_FEATURE_AES) || defined (__ARM_FEATURE_CRYPTO)) && !defined (__ARM_BIG_ENDIAN)
#define AES_ARMCE       1
#endif


// A key, ready for use: the round keys as its variant has them, in priv,
// aligned for 16 byte vectors
#define AES_PRIV_BYTES          512

struct aes_impl;

typedef struct aes_context_t {
#if defined (_MSC_VER)
    __declspec(align(16)) unsigned char priv[AES_PRIV_BYTES];
#else
    unsigned char priv[AES_PRIV_BYTES] __attribute__((aligned(16)));
#endif
    const struct aes_impl *impl;
} aes_context_t;

// A variant: its name, how it sets up priv for a key of 16, 24 or 32 bytes
// (0, or -1), and what it does with them
struct aes_impl {
    const char *name;
    int (*setup)(aes_context_t *ctx, const unsigned char *key, size_t key_size);
    int (*cbc_encrypt)(unsigned char *out, const unsigned char *in, size_t in_len,
                       const unsigned char *iv, aes_context_t *ctx);
    int (*cbc_encrypt_multi)(unsigned char *out[], const unsigned char *in[], const size_t in_len[],
                             const unsigned char *iv, aes_context_t *ctx, int count);
    int (*cbc_decrypt)(unsigned char *out, const unsigned char *in, size_t in_len,
                       const unsigned char *iv, aes_context_t *ctx);
    int (*ecb_decrypt)(unsigned char *out, const unsigned char *in, aes_context_t *ctx);
};


int aes_cbc_encrypt (unsigned char *out, const unsigned char *in, size_t in_len,
                     const unsigned char *iv, aes_context_t *ctx);

// encrypts count packets, each with its own CBC chain, all with the same iv;
// returns 0. Where AES-NI is available, the packets are encrypted in parallel
int aes_cbc_encrypt_multi (unsigned char *out[], const unsigned char *in[], const size_t in_len[],
                           const unsigned char *iv, aes_context_t *ctx, int count);

int aes_cbc_decrypt (unsigned char *out, const unsigned char *in, size_t in_len,
                     const unsigned char *iv, aes_context_t *ctx);

int aes_ecb_decrypt (unsigned char *out, const unsigned char *in, aes_context_t *ctx);

// a context for the key, of 16, 24 or 32 bytes, for the fastest variant
// this CPU has; 0, or -1 (a key of another size, or no memory)
int aes_init (const unsigned char *key, size_t key_size, aes_context_t **ctx);

// the same for the variant given, one of aes_impls()
int aes_init_impl (const unsigned char *key, size_t key_size, aes_context_t **ctx,
                   const struct aes_impl *impl);

int aes_deinit (aes_context_t *ctx);

// The variants this CPU can run, slowest first - as many as fit in list,
// and how many there are - the one aes_init() takes, and the one of a name
// (see crypto_impl_named()) if this CPU has it, else NULL
int aes_impls (const struct aes_impl **list, int max);

const struct aes_impl *aes_impl_chosen (void);

const struct aes_impl *aes_impl_find (const char *name);


#endif // AES_H
