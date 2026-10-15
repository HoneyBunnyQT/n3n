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


#ifndef CC20_H
#define CC20_H


#include <stddef.h>  // for size_t
#include <stdint.h>  // for uint32_t, uint8_t


#define CC20_IV_SIZE           16
#define CC20_KEY_BYTES       (256/8)


// Every variant the build can have is built - plain C; SSE2, SSSE3, AVX2
// and AVX-512 on x86, NEON on ARM where the build's baseline has it;
// OpenSSL's, with --with-openssl - each with the extension it needs for
// its own functions only, and cc20_init() takes the fastest one the CPU at
// hand has (cc20.c).  They all give the same bytes.  AVX2 and AVX-512 not
// on Windows, as for Speck (speck.h): GCC does not align its stack there
// for 32 and 64 byte vectors.
#if defined (__x86_64__) || defined (__i386__)
#define CC20_X86        1
#if !defined (_WIN32)
#define CC20_X86_AVX    1
#endif
#endif

#if defined (__ARM_NEON) && !defined (__ARM_BIG_ENDIAN)
#define CC20_NEON       1
#endif


struct cc20_impl;

// only the key, and the variant: the keystream is worked out on the stack
// of every call (and OpenSSL's context is per thread), so that several
// threads can use one context at once
typedef struct cc20_context_t {
    uint8_t key[CC20_KEY_BYTES];                 /* the pure key data for payload encryption & decryption */
    const struct cc20_impl *impl;
} cc20_context_t;

// A variant: its name, and how it en- or decrypts
struct cc20_impl {
    const char *name;
    int (*crypt)(unsigned char *out, const unsigned char *in, size_t in_len,
                 const unsigned char *iv, cc20_context_t *ctx);
};


int cc20_crypt (unsigned char *out, const unsigned char *in, size_t in_len,
                const unsigned char *iv, cc20_context_t *ctx);

// a context for the key, for the fastest variant this CPU has; 0, or -1
// without memory
int cc20_init (const unsigned char *key, cc20_context_t **ctx);

// the same for the variant given, one of cc20_impls()
int cc20_init_impl (const unsigned char *key, cc20_context_t **ctx,
                    const struct cc20_impl *impl);

int cc20_deinit (cc20_context_t *ctx);

// The variants this CPU can run, slowest first - as many as fit in list,
// and how many there are - the one cc20_init() takes, and the one of a
// name (see crypto_impl_named()) if this CPU has it, else NULL
int cc20_impls (const struct cc20_impl **list, int max);

const struct cc20_impl *cc20_impl_chosen (void);

const struct cc20_impl *cc20_impl_find (const char *name);


#endif // CC20_H
