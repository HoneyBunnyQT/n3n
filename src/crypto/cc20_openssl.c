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


#ifdef HAVE_LIBCRYPTO // openSSL 1.1 ---------------------------------------------------------------------


#include <n3n/logging.h> // for traceEvent
#include <stdlib.h>     // for calloc, free, size_t
#include <string.h>     // for memcpy

#include "cc20.h"
#include "config.h"  // HAVE_LIBCRYPTO
#include "portable_endian.h"  // for htole32
#include "../thread_local.h"  // for N3N_THREAD_LOCAL, n3n_thread_on_cleanup


// get any erorr message out of openssl
// taken from https://en.wikibooks.org/wiki/OpenSSL/Error_handling
static char *openssl_err_as_string (void) {

    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char *buf = NULL;
    size_t len = BIO_get_mem_data(bio, &buf);
    char *ret = (char *)calloc(1, 1 + len);

    if(ret)
        memcpy(ret, buf, len);

    BIO_free(bio);

    return ret;
}


// OpenSSL's EVP context is scratch space here: every call below sets it up
// with cipher, key and IV and resets it when done, so it carries nothing from
// one call to the next - but two threads must never use the same one. So every
// thread gets its own on first use, shared by all cc20 contexts of that
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
            traceEvent(TRACE_ERROR, "cc20 openssl's evp_* context creation failed: %s",
                       openssl_err_as_string());
            return NULL;
        }
        n3n_thread_on_cleanup(evp_ctx_free);
    }

    return evp_ctx;
}


// encryption == decryption
int cc20_crypt (unsigned char *out, const unsigned char *in, size_t in_len,
                const unsigned char *iv, cc20_context_t *ctx) {

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
                        traceEvent(TRACE_ERROR, "cc20_crypt openssl encryption: encrypted %u bytes where %u were expected",
                                   evp_ciphertext_len, in_len);
                } else
                    traceEvent(TRACE_ERROR, "cc20_crypt openssl final encryption: %s",
                               openssl_err_as_string());
            } else
                traceEvent(TRACE_ERROR, "cc20_encrypt openssl encrpytion: %s",
                           openssl_err_as_string());
        } else
            traceEvent(TRACE_ERROR, "cc20_encrypt openssl padding setup: %s",
                       openssl_err_as_string());
    } else
        traceEvent(TRACE_ERROR, "cc20_encrypt openssl init: %s",
                   openssl_err_as_string());

    EVP_CIPHER_CTX_reset(evp);

    return 0;
}


int cc20_init (const unsigned char *key, cc20_context_t **ctx) {

    // allocate context...
    *ctx = (cc20_context_t*)calloc(1, sizeof(cc20_context_t));
    if(!(*ctx))
        return -1;
    (*ctx)->cipher = EVP_chacha20();
    memcpy((*ctx)->key, key, CC20_KEY_BYTES);

    return 0;
}


int cc20_deinit (cc20_context_t *ctx) {

    free(ctx);
    return 0;
}


#elif defined (__AVX512F__)  // AVX512 ------------------------------------------------------------------------------
#elif defined (__AVX2__)  // AVX2 -----------------------------------------------------------------------------------
#elif defined (__SSE2__)  // SSE2 ---------------------------------------------------------------------------------
#else // plain C --------------------------------------------------------------------------------------------------
#endif // openSSL 1.1, plain C ------------------------------------------------------------------------------------
