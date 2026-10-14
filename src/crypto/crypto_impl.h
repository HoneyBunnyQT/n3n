/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * What the ciphers with variants chosen at runtime (speck.c, aes.c) share:
 * the extension a variant's code may use, the memory of a context, and how
 * a variant is found by the name the configuration gives
 * ("cipher = AES/AES-NI").
 */


#ifndef CRYPTO_IMPL_H
#define CRYPTO_IMPL_H


#include <ctype.h>      // for isalnum, tolower
#include <stdbool.h>    // for bool
#include <stdlib.h>     // for posix_memalign, free
#include <string.h>     // for memset

#if defined (_WIN32)
#include <malloc.h>     // for _aligned_malloc, _aligned_free
#endif


// A function of a variant gets the extension the variant needs, whatever
// the rest of the build may use: between CRYPTO_TARGET_BEGIN("avx2") and
// CRYPTO_TARGET_END, after the headers
#define CRYPTO_PRAGMA(x) _Pragma(#x)
#if defined (__clang__)
#define CRYPTO_TARGET_BEGIN(t) CRYPTO_PRAGMA(clang attribute push(__attribute__((target(t))), apply_to = function))
#define CRYPTO_TARGET_END      CRYPTO_PRAGMA(clang attribute pop)
#elif defined (__GNUC__)
#define CRYPTO_TARGET_BEGIN(t) CRYPTO_PRAGMA(GCC push_options) CRYPTO_PRAGMA(GCC target(t))
#define CRYPTO_TARGET_END      CRYPTO_PRAGMA(GCC pop_options)
#else
#define CRYPTO_TARGET_BEGIN(t)
#define CRYPTO_TARGET_END
#endif


// A context, zeroed and aligned for the vectors of its variants; NULL
// without memory
static inline void *crypto_ctx_alloc (size_t size, size_t align) {

    void *p = NULL;

#if defined (_WIN32)
    p = _aligned_malloc(size, align);
#else
    if(posix_memalign(&p, align, size)) {
        p = NULL;
    }
#endif
    if(p) {
        memset(p, 0, size);
    }
    return p;
}

static inline void crypto_ctx_free (void *p) {

#if defined (_WIN32)
    _aligned_free(p);
#else
    free(p);
#endif
}


// The name of a variant ("AES-NI", "plain C") is what the configuration
// asks for, in any case, with or without its blanks and dashes: "aesni",
// "plainc" and "avx-512" do
static inline bool crypto_impl_named (const char *name, const char *asked) {

    for(;;) {
        while(*name && !isalnum((unsigned char)*name)) {
            name++;
        }
        while(*asked && !isalnum((unsigned char)*asked)) {
            asked++;
        }
        if(!*name || !*asked) {
            return !*name && !*asked;
        }
        if(tolower((unsigned char)*name) != tolower((unsigned char)*asked)) {
            return false;
        }
        name++;
        asked++;
    }
}


#endif // CRYPTO_IMPL_H
