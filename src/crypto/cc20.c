/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * ChaCha20's variants, chosen at runtime as Speck's are (speck.c): every
 * one the build can have is built, each with the extension it needs for
 * its own functions only, and a context gets the fastest the CPU at hand
 * has - so that a build for the baseline of x86-64, as distributions make
 * them, still uses AVX2 where there is AVX2.
 *
 * The x86 extensions are asked of the CPU (__builtin_cpu_supports); NEON
 * is built where the build's baseline has it, and so is there on every CPU
 * the build runs on.
 */


#include <stdbool.h>    // for bool
#include <stddef.h>     // for NULL
#include <string.h>     // for memcpy

#include "config.h"     // for HAVE_LIBCRYPTO
#include "cc20.h"
#include "crypto_impl.h"  // for crypto_ctx_alloc, crypto_impl_named


extern const struct cc20_impl cc20_impl_plainc;
#if defined (HAVE_LIBCRYPTO)
extern const struct cc20_impl cc20_impl_openssl;
#endif
#if defined (CC20_X86)
extern const struct cc20_impl cc20_impl_sse2;
extern const struct cc20_impl cc20_impl_ssse3;
#endif
#if defined (CC20_X86_AVX)
extern const struct cc20_impl cc20_impl_avx2;
extern const struct cc20_impl cc20_impl_avx512;
#endif
#if defined (CC20_NEON)
extern const struct cc20_impl cc20_impl_neon;
#endif


#if defined (CC20_X86) && (defined (__GNUC__) || defined (__clang__))
#define has(feature) __builtin_cpu_supports(feature)
#else
#define has(feature) false
#endif

#if defined (CC20_X86)
static bool has_sse2 (void) {
#if defined (__x86_64__) || defined (__SSE2__)
    // part of x86-64, and of a 32 bit build for it
    return true;
#else
    return has("sse2");
#endif
}

static bool has_ssse3 (void) {
    return has("ssse3");
}
#endif

#if defined (CC20_X86_AVX)
static bool has_avx2 (void) {
    return has("avx2");
}

static bool has_avx512 (void) {
    return has("avx512f");
}
#endif


// Slowest first, and whether this CPU can run it (NULL: any)
static const struct {
    const struct cc20_impl *impl;
    bool (*usable)(void);
} variants[] = {
    { &cc20_impl_plainc, NULL },
#if defined (CC20_X86)
    { &cc20_impl_sse2, has_sse2 },
#endif
#if defined (CC20_NEON)
    { &cc20_impl_neon, NULL },
#endif
    // OpenSSL's, with the overhead of its EVP interface on every packet:
    // faster than SSE2 here, but slower than SSSE3 - and on ARM with
    // assembler of its own, above NEON as it was before the variants
#if defined (HAVE_LIBCRYPTO)
    { &cc20_impl_openssl, NULL },
#endif
#if defined (CC20_X86)
    { &cc20_impl_ssse3, has_ssse3 },
#endif
#if defined (CC20_X86_AVX)
    { &cc20_impl_avx2, has_avx2 },
    { &cc20_impl_avx512, has_avx512 },
#endif
};

#define VARIANTS ((int)(sizeof(variants) / sizeof(variants[0])))

static bool usable (int i) {

    return !variants[i].usable || variants[i].usable();
}


int cc20_impls (const struct cc20_impl **list, int max) {

    int n = 0;

    for(int i = 0; i < VARIANTS; i++) {
        if(usable(i)) {
            if(n < max) {
                list[n] = variants[i].impl;
            }
            n++;
        }
    }

    return n;
}


const struct cc20_impl *cc20_impl_chosen (void) {

    for(int i = VARIANTS - 1; i > 0; i--) {
        if(usable(i)) {
            return variants[i].impl;
        }
    }

    return &cc20_impl_plainc;
}


const struct cc20_impl *cc20_impl_find (const char *name) {

    for(int i = 0; i < VARIANTS; i++) {
        if(crypto_impl_named(variants[i].impl->name, name)) {
            return usable(i) ? variants[i].impl : NULL;
        }
    }

    return NULL;
}


int cc20_init_impl (const unsigned char *key, cc20_context_t **ctx,
                    const struct cc20_impl *impl) {

    *ctx = crypto_ctx_alloc(sizeof(cc20_context_t), 16);
    if(!*ctx) {
        return -1;
    }
    memcpy((*ctx)->key, key, CC20_KEY_BYTES);
    (*ctx)->impl = impl;

    return 0;
}


int cc20_init (const unsigned char *key, cc20_context_t **ctx) {

    return cc20_init_impl(key, ctx, cc20_impl_chosen());
}


int cc20_deinit (cc20_context_t *ctx) {

    if(ctx) {
        crypto_ctx_free(ctx);
    }

    return 0;
}


int cc20_crypt (unsigned char *out, const unsigned char *in, size_t in_len,
                const unsigned char *iv, cc20_context_t *ctx) {

    return ctx->impl->crypt(out, in, in_len, iv, ctx);
}
