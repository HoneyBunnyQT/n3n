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

#include "config.h"     // for HAVE_LIBCRYPTO

#include <n3n/logging.h> // for traceEvent
#include <stdint.h>  // for uint32_t, uint8_t
#include <stdlib.h>  // for calloc, free
#include <string.h>  // for memcpy, size_t
#include "aes.h"     // for AES_BLOCK_SIZE, aes_context_t, AES128_KEY_BYTES
#include "portable_endian.h"  // for be32toh, htobe32
#include "../thread_local.h"  // for N3N_THREAD_LOCAL, n3n_thread_on_cleanup


#if defined (HAVE_LIBCRYPTO)   // OpenSSL -------------------------------------------------------------------------

#include <openssl/aes.h>    // for AES_KEY, AES_set_decrypt_key, AES_ecb_encrypt
#include <openssl/err.h>    // for ERR_print_errors
#include <openssl/evp.h>    // for EVP_EncryptInit_ex, EVP_CIPHER_CTX_set_p...

// a key as this variant has it, in its context's priv
typedef struct {
    const EVP_CIPHER    *cipher;                 /* cipher to use: e.g. EVP_aes_128_cbc */
    uint8_t key[AES256_KEY_BYTES];               /* the pure key data for payload encryption & decryption */
    AES_KEY ecb_dec_key;                         /* one step ecb decryption key */
} ctx_t;

_Static_assert(sizeof(ctx_t) <= AES_PRIV_BYTES, "the key fits");

// get any erorr message out of openssl
// taken from https://en.wikibooks.org/wiki/OpenSSL/Error_handling
static char *openssl_err_as_string (void) {

    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char *buf = NULL;
    size_t len = BIO_get_mem_data(bio, &buf);
    char *ret = (char *) calloc(1, 1 + len);

    if(ret)
        memcpy(ret, buf, len);

    BIO_free(bio);

    return ret;
}


// OpenSSL's EVP context is scratch space here: every call below sets it up
// with cipher, key and IV and resets it when done, so it carries nothing from
// one call to the next - but two threads must never use the same one. So every
// thread gets its own on first use, shared by all aes contexts of that
// thread.
static N3N_THREAD_LOCAL EVP_CIPHER_CTX *evp_ctx;


static void evp_ctx_free (void) {

    EVP_CIPHER_CTX_free(evp_ctx);
    evp_ctx = NULL;
}


static EVP_CIPHER_CTX *evp_ctx_get (void) {

    if(!evp_ctx) {
        evp_ctx = EVP_CIPHER_CTX_new();
        if(!evp_ctx) {
            traceEvent(TRACE_ERROR, "aes openssl's evp_* context creation failed: %s",
                       openssl_err_as_string());
            return NULL;
        }
        n3n_thread_on_cleanup(evp_ctx_free);
    }

    return evp_ctx;
}


static int cbc_encrypt (unsigned char *out, const unsigned char *in, size_t in_len,
                        const unsigned char *iv, ctx_t *ctx) {

    EVP_CIPHER_CTX *evp = evp_ctx_get();
    int evp_len;
    int evp_ciphertext_len;

    if(!evp) {
        return -1;
    }

    if(1 == EVP_EncryptInit_ex(evp, ctx->cipher, NULL, ctx->key, iv)) {
        if(1 == EVP_CIPHER_CTX_set_padding(evp, 0)) {
            if(1 == EVP_EncryptUpdate(evp, out, &evp_len, in, in_len)) {
                evp_ciphertext_len = evp_len;
                if(1 == EVP_EncryptFinal_ex(evp, out + evp_len, &evp_len)) {
                    evp_ciphertext_len += evp_len;
                    if(evp_ciphertext_len != in_len)
                        traceEvent(TRACE_ERROR, "aes_cbc_encrypt openssl encryption: encrypted %u bytes where %u were expected",
                                   evp_ciphertext_len, in_len);
                } else
                    traceEvent(TRACE_ERROR, "aes_cbc_encrypt openssl final encryption: %s",
                               openssl_err_as_string());
            } else
                traceEvent(TRACE_ERROR, "aes_cbc_encrypt openssl encrpytion: %s",
                           openssl_err_as_string());
        } else
            traceEvent(TRACE_ERROR, "aes_cbc_encrypt openssl padding setup: %s",
                       openssl_err_as_string());
    } else
        traceEvent(TRACE_ERROR, "aes_cbc_encrypt openssl init: %s",
                   openssl_err_as_string());

    EVP_CIPHER_CTX_reset(evp);

    return 0;
}


// encrypts several packets, each with its own CBC chain (see the AES-NI code for
// why this exists); without AES-NI there is nothing to interleave, so this is a loop
static int cbc_encrypt_multi (unsigned char *out[], const unsigned char *in[], const size_t in_len[],
                              const unsigned char *iv, ctx_t *ctx, int count) {

    int i;

    for(i = 0; i < count; i++) {
        cbc_encrypt(out[i], in[i], in_len[i], iv, ctx);
    }

    return 0;
}


static int cbc_decrypt (unsigned char *out, const unsigned char *in, size_t in_len,
                        const unsigned char *iv, ctx_t *ctx) {

    EVP_CIPHER_CTX *evp = evp_ctx_get();
    int evp_len;
    int evp_plaintext_len;

    if(!evp) {
        return -1;
    }

    if(1 == EVP_DecryptInit_ex(evp, ctx->cipher, NULL, ctx->key, iv)) {
        if(1 == EVP_CIPHER_CTX_set_padding(evp, 0)) {
            if(1 == EVP_DecryptUpdate(evp, out, &evp_len, in, in_len)) {
                evp_plaintext_len = evp_len;
                if(1 == EVP_DecryptFinal_ex(evp, out + evp_len, &evp_len)) {
                    evp_plaintext_len += evp_len;
                    if(evp_plaintext_len != in_len)
                        traceEvent(TRACE_ERROR, "aes_cbc_decrypt openssl decryption: decrypted %u bytes where %u were expected",
                                   evp_plaintext_len, in_len);
                } else
                    traceEvent(TRACE_ERROR, "aes_cbc_decrypt openssl final decryption: %s",
                               openssl_err_as_string());
            } else
                traceEvent(TRACE_ERROR, "aes_cbc_decrypt openssl decrpytion: %s",
                           openssl_err_as_string());
        } else
            traceEvent(TRACE_ERROR, "aes_cbc_decrypt openssl padding setup: %s",
                       openssl_err_as_string());
    } else
        traceEvent(TRACE_ERROR, "aes_cbc_decrypt openssl init: %s",
                   openssl_err_as_string());

    EVP_CIPHER_CTX_reset(evp);

    return 0;
}


static int ecb_decrypt (unsigned char *out, const unsigned char *in, ctx_t *ctx) {

    AES_ecb_encrypt(in, out, &(ctx->ecb_dec_key), AES_DECRYPT);

    return 0;
}


static int setup (ctx_t *ctx, const unsigned char *key, size_t key_size) {

    switch(key_size) {
        case AES128_KEY_BYTES:
            ctx->cipher = EVP_aes_128_cbc();
            break;
        case AES192_KEY_BYTES:
            ctx->cipher = EVP_aes_192_cbc();
            break;
        default:
            ctx->cipher = EVP_aes_256_cbc();
            break;
    }

    // key materiel handling
    memcpy(ctx->key, key, key_size);
    AES_set_decrypt_key(key, key_size * 8, &(ctx->ecb_dec_key));

    return 0;
}


static inline ctx_t *priv (aes_context_t *ctx) {
    return (ctx_t *)(void *)ctx->priv;
}

static int w_setup (aes_context_t *ctx, const unsigned char *key, size_t key_size) {
    return setup(priv(ctx), key, key_size);
}

static int w_cbc_encrypt (unsigned char *out, const unsigned char *in, size_t in_len,
                          const unsigned char *iv, aes_context_t *ctx) {
    return cbc_encrypt(out, in, in_len, iv, priv(ctx));
}

static int w_cbc_encrypt_multi (unsigned char *out[], const unsigned char *in[], const size_t in_len[],
                                const unsigned char *iv, aes_context_t *ctx, int count) {
    return cbc_encrypt_multi(out, in, in_len, iv, priv(ctx), count);
}

static int w_cbc_decrypt (unsigned char *out, const unsigned char *in, size_t in_len,
                          const unsigned char *iv, aes_context_t *ctx) {
    return cbc_decrypt(out, in, in_len, iv, priv(ctx));
}

static int w_ecb_decrypt (unsigned char *out, const unsigned char *in, aes_context_t *ctx) {
    return ecb_decrypt(out, in, priv(ctx));
}


const struct aes_impl aes_impl_openssl = {
    .name = "OpenSSL",
    .setup = w_setup,
    .cbc_encrypt = w_cbc_encrypt,
    .cbc_encrypt_multi = w_cbc_encrypt_multi,
    .cbc_decrypt = w_cbc_decrypt,
    .ecb_decrypt = w_ecb_decrypt,
};


#endif // HAVE_LIBCRYPTO
