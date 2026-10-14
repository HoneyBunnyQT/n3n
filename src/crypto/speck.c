/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Speck's variants, chosen at runtime: every one the architecture has is
 * built (each with the extension it needs, for its own functions only, see
 * SPECK_TARGET_BEGIN in speck.h), and a context gets the fastest one the
 * CPU at hand can run - so that a build for the baseline of x86-64, as
 * distributions make them, still uses AVX2 where there is AVX2.
 *
 * The x86 extensions are asked of the CPU (__builtin_cpu_supports, which
 * also checks that the system saves the wider registers); NEON is built
 * only where the build's baseline has it, and is no choice of its own: on
 * many ARM cores the plain C version is as fast, so it is taken only with
 * SPECK_ARM_NEON - and is measured by the benchmark either way.
 */


#include <stdbool.h>    // for bool
#include <stdlib.h>     // for posix_memalign, free
#include <string.h>     // for memset

#include "speck.h"

#if defined (_WIN32)
#include <malloc.h>     // for _aligned_malloc, _aligned_free
#endif


extern const struct speck_impl speck_impl_plainc;
#if defined (SPECK_X86)
extern const struct speck_impl speck_impl_sse2;
extern const struct speck_impl speck_impl_ssse3;
#endif
#if defined (SPECK_X86_AVX)
extern const struct speck_impl speck_impl_avx2;
extern const struct speck_impl speck_impl_avx512;
#endif
#if defined (SPECK_NEON)
extern const struct speck_impl speck_impl_neon;
#endif


#if defined (SPECK_X86) && (defined (__GNUC__) || defined (__clang__))
#define has(feature) __builtin_cpu_supports(feature)
#else
#define has(feature) false
#endif

#if defined (SPECK_X86)
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

#if defined (SPECK_X86_AVX)
static bool has_avx2 (void) {
    return has("avx2");
}

static bool has_avx512 (void) {
    return has("avx512f");
}
#endif


// Slowest first: whether this CPU can run it (NULL: any of the
// architecture), and whether speck_init() may take it
static const struct {
    const struct speck_impl *impl;
    bool (*usable)(void);
    bool choice;
} variants[] = {
    { &speck_impl_plainc, NULL, true },
#if defined (SPECK_X86)
    { &speck_impl_sse2, has_sse2, true },
    { &speck_impl_ssse3, has_ssse3, true },
#endif
#if defined (SPECK_X86_AVX)
    { &speck_impl_avx2, has_avx2, true },
    { &speck_impl_avx512, has_avx512, true },
#endif
#if defined (SPECK_NEON)
#if defined (SPECK_ARM_NEON)
    { &speck_impl_neon, NULL, true },
#else
    { &speck_impl_neon, NULL, false },
#endif
#endif
};

#define VARIANTS ((int)(sizeof(variants) / sizeof(variants[0])))

static bool usable (int i) {

    return !variants[i].usable || variants[i].usable();
}


int speck_impls (const struct speck_impl **list, int max) {

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


const struct speck_impl *speck_impl_chosen (void) {

    for(int i = VARIANTS - 1; i > 0; i--) {
        if(variants[i].choice && usable(i)) {
            return variants[i].impl;
        }
    }

    return &speck_impl_plainc;
}


int speck_init_impl (speck_context_t **ctx, const unsigned char *k, int keysize,
                     const struct speck_impl *impl) {

    // aligned for the vectors in priv
#if defined (_WIN32)
    *ctx = _aligned_malloc(sizeof(speck_context_t), 64);
#else
    void *p = NULL;
    *ctx = posix_memalign(&p, 64, sizeof(speck_context_t)) ? NULL : p;
#endif
    if(!(*ctx)) {
        return -1;
    }
    memset(*ctx, 0, sizeof(speck_context_t));

    // the round keys once each, for plain C and the one block functions,
    // then as the variant has them
    speck_impl_plainc.expand_key(*ctx, k, keysize);
    if(impl != &speck_impl_plainc) {
        impl->expand_key(*ctx, k, keysize);
    }
    (*ctx)->impl = impl;

    return 0;
}


int speck_init (speck_context_t **ctx, const unsigned char *k, int keysize) {

    return speck_init_impl(ctx, k, keysize, speck_impl_chosen());
}


int speck_ctr (unsigned char *out, const unsigned char *in, unsigned long long inlen,
               const unsigned char *n, speck_context_t *ctx) {

    return ctx->impl->ctr(out, in, inlen, n, ctx);
}


int speck_deinit (speck_context_t *ctx) {

    if(ctx) {
#if defined (_WIN32)
        _aligned_free(ctx);
#else
        free(ctx);
#endif
    }

    return 0;
}
