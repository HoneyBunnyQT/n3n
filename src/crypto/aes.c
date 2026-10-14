/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * AES's variants, chosen at runtime as Speck's are (speck.c): every one the
 * build can have is built, each with the extension it needs for its own
 * functions only, and a context gets the fastest the CPU at hand has -
 * AES-NI or the ARMv8 Cryptography Extension where the CPU has them, else
 * OpenSSL's (where built with it, which brings variants of its own for
 * CPUs without them), else plain C.  A build for the baseline of x86-64 or
 * aarch64, as distributions make them, so uses the AES instructions where
 * there are any.
 *
 * The x86 extensions are asked of the CPU (__builtin_cpu_supports); those
 * of aarch64 of the system (getauxval() on Linux and Android, elf_aux_info()
 * on FreeBSD; every Apple CPU has them).  On 32 bit ARM, the Cryptography
 * Extension is built only where the build's baseline has it.
 */


#include <stdbool.h>    // for bool
#include <stddef.h>     // for NULL

#include "config.h"     // for HAVE_LIBCRYPTO
#include "aes.h"
#include "crypto_impl.h"  // for crypto_ctx_alloc, crypto_impl_named

#if defined (__aarch64__) && (defined (__linux__) || defined (__ANDROID__))
#include <sys/auxv.h>   // for getauxval, AT_HWCAP
#ifndef HWCAP_AES
#define HWCAP_AES       (1 << 3)
#endif
#elif defined (__aarch64__) && defined (__FreeBSD__)
#include <sys/auxv.h>   // for elf_aux_info, AT_HWCAP
#include <machine/elf.h> // for HWCAP_AES
#elif defined (__aarch64__) && defined (_WIN32)
#include <windows.h>    // for IsProcessorFeaturePresent
#endif


extern const struct aes_impl aes_impl_plainc;
#if defined (HAVE_LIBCRYPTO)
extern const struct aes_impl aes_impl_openssl;
#endif
#if defined (AES_X86)
extern const struct aes_impl aes_impl_aesni;
#endif
#if defined (AES_ARMCE)
extern const struct aes_impl aes_impl_armce;
#endif


#if defined (AES_X86)
static bool has_aesni (void) {
#if defined (__GNUC__) || defined (__clang__)
    return __builtin_cpu_supports("aes") && __builtin_cpu_supports("sse2");
#else
    return false;
#endif
}
#endif

#if defined (AES_ARMCE)
static bool has_armce (void) {
#if defined (__ARM_FEATURE_AES) || defined (__ARM_FEATURE_CRYPTO)
    // the build's baseline has them, so every CPU it runs on does
    return true;
#elif defined (__linux__) || defined (__ANDROID__)
    return (getauxval(AT_HWCAP) & HWCAP_AES) != 0;
#elif defined (__FreeBSD__)
    unsigned long hwcap = 0;
    return !elf_aux_info(AT_HWCAP, &hwcap, sizeof(hwcap)) && (hwcap & HWCAP_AES);
#elif defined (__APPLE__)
    return true;
#elif defined (_WIN32)
    return IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) != 0;
#else
    return false;
#endif
}
#endif


// Slowest first, and whether this CPU can run it (NULL: any)
static const struct {
    const struct aes_impl *impl;
    bool (*usable)(void);
} variants[] = {
    { &aes_impl_plainc, NULL },
#if defined (HAVE_LIBCRYPTO)
    { &aes_impl_openssl, NULL },
#endif
#if defined (AES_X86)
    { &aes_impl_aesni, has_aesni },
#endif
#if defined (AES_ARMCE)
    { &aes_impl_armce, has_armce },
#endif
};

#define VARIANTS ((int)(sizeof(variants) / sizeof(variants[0])))

static bool usable (int i) {

    return !variants[i].usable || variants[i].usable();
}


int aes_impls (const struct aes_impl **list, int max) {

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


const struct aes_impl *aes_impl_chosen (void) {

    for(int i = VARIANTS - 1; i > 0; i--) {
        if(usable(i)) {
            return variants[i].impl;
        }
    }

    return &aes_impl_plainc;
}


const struct aes_impl *aes_impl_find (const char *name) {

    for(int i = 0; i < VARIANTS; i++) {
        if(crypto_impl_named(variants[i].impl->name, name)) {
            return usable(i) ? variants[i].impl : NULL;
        }
    }

    return NULL;
}


int aes_init_impl (const unsigned char *key, size_t key_size, aes_context_t **ctx,
                   const struct aes_impl *impl) {

    *ctx = NULL;
    if((key_size != AES128_KEY_BYTES) && (key_size != AES192_KEY_BYTES) && (key_size != AES256_KEY_BYTES)) {
        return -1;
    }

    *ctx = crypto_ctx_alloc(sizeof(aes_context_t), 16);
    if(!*ctx) {
        return -1;
    }
    if(impl->setup(*ctx, key, key_size)) {
        crypto_ctx_free(*ctx);
        *ctx = NULL;
        return -1;
    }
    (*ctx)->impl = impl;

    return 0;
}


int aes_init (const unsigned char *key, size_t key_size, aes_context_t **ctx) {

    return aes_init_impl(key, key_size, ctx, aes_impl_chosen());
}


int aes_deinit (aes_context_t *ctx) {

    if(ctx) {
        crypto_ctx_free(ctx);
    }

    return 0;
}


int aes_cbc_encrypt (unsigned char *out, const unsigned char *in, size_t in_len,
                     const unsigned char *iv, aes_context_t *ctx) {

    return ctx->impl->cbc_encrypt(out, in, in_len, iv, ctx);
}


int aes_cbc_encrypt_multi (unsigned char *out[], const unsigned char *in[], const size_t in_len[],
                           const unsigned char *iv, aes_context_t *ctx, int count) {

    return ctx->impl->cbc_encrypt_multi(out, in, in_len, iv, ctx, count);
}


int aes_cbc_decrypt (unsigned char *out, const unsigned char *in, size_t in_len,
                     const unsigned char *iv, aes_context_t *ctx) {

    return ctx->impl->cbc_decrypt(out, in, in_len, iv, ctx);
}


int aes_ecb_decrypt (unsigned char *out, const unsigned char *in, aes_context_t *ctx) {

    return ctx->impl->ecb_decrypt(out, in, ctx);
}
