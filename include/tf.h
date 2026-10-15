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


// taken (and modified) from github/fudanchii/twofish as of August 2020
// which itself is a modified copy of Andrew T. Csillag's implementation
// published on github/drewcsillag/twofish


/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Andrew T. Csillag
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */


#ifndef TF_H
#define TF_H


#include <stdint.h>  // for uint32_t
#include <stdlib.h>  // for size_t


#define TF_BLOCK_SIZE     16
#define TF_IV_SIZE       (TF_BLOCK_SIZE)
#define TF_BLOCK_WORDS   (TF_BLOCK_SIZE / 4)


// Besides plain C, a CBC decryption of 16 blocks at a time with AVX-512
// (VBMI and GFNI) on x86 - built with those for its own functions only, and
// taken where the CPU has them (tf.c).  Not on Windows, as for Speck
// (speck.h): GCC does not align its stack there for 64 byte vectors.
#if (defined (__x86_64__) || defined (__i386__)) && !defined (_WIN32)
#define TF_X86_AVX512   1
#endif

struct tf_impl;

typedef struct tf_context_t {
    int N;
    uint32_t K[40];
    uint32_t QF[4][256];
    uint8_t SB[4][256];   // keyed byte S-boxes (QF without the MDS part), used by SIMD code
    const struct tf_impl *impl;
} tf_context_t;

// A variant: its name, and how it CBC-decrypts n16 times 16 blocks, ivec
// the chaining value before and after (NULL: plain C does all, three blocks
// side by side)
struct tf_impl {
    const char *name;
    void (*cbc_decrypt_16way)(unsigned char *out, const unsigned char *in, int n16,
                              uint32_t ivec[TF_BLOCK_WORDS], tf_context_t *ctx);
};


int tf_ecb_decrypt (unsigned char *out, const unsigned char *in, tf_context_t *ctx);

int tf_ecb_encrypt (unsigned char *out, const unsigned char *in, tf_context_t *ctx);

int tf_cbc_encrypt (unsigned char *out, const unsigned char *in, size_t in_len,
                    const unsigned char *iv, tf_context_t *ctx);

// encrypts count packets, each with its own CBC chain, all starting from the
// same iv; returns 0. Three packets at a time run side by side
int tf_cbc_encrypt_multi (unsigned char *out[], const unsigned char *in[], const size_t in_len[],
                          const unsigned char *iv, tf_context_t *ctx, int count);

int tf_cbc_decrypt (unsigned char *out, const unsigned char *in, size_t in_len,
                    const unsigned char *iv, tf_context_t *ctx);

// a context for the key (key_size in bits), for the fastest variant this
// CPU has; 0, or -1 without memory
int tf_init (const unsigned char *key, size_t key_size, tf_context_t **ctx);

// the same for the variant given, one of tf_impls()
int tf_init_impl (const unsigned char *key, size_t key_size, tf_context_t **ctx,
                  const struct tf_impl *impl);

int tf_deinit (tf_context_t *ctx);

// The variants this CPU can run, slowest first - as many as fit in list,
// and how many there are - the one tf_init() takes, and the one of a name
// (see crypto_impl_named()) if this CPU has it, else NULL
int tf_impls (const struct tf_impl **list, int max);

const struct tf_impl *tf_impl_chosen (void);

const struct tf_impl *tf_impl_find (const char *name);


#endif // TF_H
