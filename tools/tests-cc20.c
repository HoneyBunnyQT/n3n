/*
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Unit tests of ChaCha20's variants (src/crypto/cc20.c): every one this
 * CPU has gives the RFC 8439 vector, the same keystream for every length,
 * unaligned and in place - and the same bytes as plain C.
 *
 * The output is the same on every CPU: which variants there are goes to
 * stderr.
 */

#include <stdio.h>             // for printf
#include <string.h>            // for memcmp, memset
#include "../src/crypto/cc20.h" // for cc20_init_impl, cc20_crypt, cc20_impls


// RFC 8439 2.4.2: key 00 01 02 ... 1f, nonce 00 00 00 00 00 00 00 4a 00 00
// 00 00, block counter 1.  The IV of cc20_crypt() is the counter (little
// endian) followed by the nonce.
static const uint8_t rfc_iv[16] = {
    0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
};

static const char rfc_pt[] =
    "Ladies and Gentlemen of the class of '99: If I could offer you only one "
    "tip for the future, sunscreen would be it.";

static const uint8_t rfc_ct[114] = {
    0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
    0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
    0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
    0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
    0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
    0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
    0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
    0x87, 0x4d,
};


static int test_rfc (cc20_context_t *ctx) {
    uint8_t out[sizeof(rfc_ct)];
    uint8_t back[sizeof(rfc_ct)];
    int failed = 0;

    cc20_crypt(out, (const uint8_t *)rfc_pt, sizeof(rfc_ct), rfc_iv, ctx);
    failed |= memcmp(out, rfc_ct, sizeof(rfc_ct)) != 0;

    cc20_crypt(back, out, sizeof(rfc_ct), rfc_iv, ctx);
    failed |= memcmp(back, rfc_pt, sizeof(rfc_ct)) != 0;

    if(failed) {
        fprintf(stderr, "%s: not the RFC 8439 vector\n", ctx->impl->name);
    }
    return failed;
}


// The keystream does not depend on the length: every length has to give the
// start of what a long text gives - whichever of the paths for several
// blocks at once, single blocks and the rest of a block it takes.  Also from
// an unaligned buffer, and in place.
static int test_lengths (cc20_context_t *ctx) {
    enum { LONG = 1100 };
    uint8_t in[LONG + 1];
    uint8_t ref[LONG];
    uint8_t out[LONG + 1];
    uint8_t iv[16];
    int failed = 0;

    for(int i = 0; i <= LONG; i++) {
        in[i] = (uint8_t)(i * 7 + 3);
    }
    for(int i = 0; i < 16; i++) {
        iv[i] = (uint8_t)(0xf0 - i);
    }
    // a counter close to wrapping around
    iv[0] = 0xfd; iv[1] = 0xff; iv[2] = 0xff; iv[3] = 0xff;

    cc20_crypt(ref, in, LONG, iv, ctx);

    for(size_t len = 0; len <= LONG; len++) {
        memset(out, 0, sizeof(out));
        cc20_crypt(out, in, len, iv, ctx);
        failed |= memcmp(out, ref, len) != 0;

        // unaligned, in place
        memcpy(out + 1, in, len);
        cc20_crypt(out + 1, out + 1, len, iv, ctx);
        failed |= memcmp(out + 1, ref, len) != 0;
    }

    if(failed) {
        fprintf(stderr, "%s: not the same keystream for every length\n", ctx->impl->name);
    }
    return failed;
}


// The same bytes as plain C, for every length up to 1100 and a few keys
static int test_as_plainc (const struct cc20_impl *plain, const struct cc20_impl *impl) {
    enum { LONG = 1100 };
    uint8_t key[CC20_KEY_BYTES], iv[16], in[LONG], ref[LONG], out[LONG];
    cc20_context_t *a, *b;
    int failed = 0;

    for(int k = 0; k < 4; k++) {
        for(int i = 0; i < CC20_KEY_BYTES; i++) {
            key[i] = (uint8_t)(i * 13 + k * 101);
        }
        for(int i = 0; i < 16; i++) {
            iv[i] = (uint8_t)(i * 29 + k);
        }
        for(int i = 0; i < LONG; i++) {
            in[i] = (uint8_t)(i * 5 + k);
        }
        if(cc20_init_impl(key, &a, plain) || cc20_init_impl(key, &b, impl)) {
            return 1;
        }
        for(size_t len = 0; len <= LONG; len += 1 + (len % 3)) {
            cc20_crypt(ref, in, len, iv, a);
            cc20_crypt(out, in, len, iv, b);
            failed |= memcmp(out, ref, len) != 0;
        }
        cc20_deinit(a);
        cc20_deinit(b);
    }
    if(failed) {
        fprintf(stderr, "%s: not as plain C\n", impl->name);
    }
    return failed;
}


int main (int argc, char * argv[]) {
    // slowest first: plain C, then those of this CPU
    const struct cc20_impl *impl[8];
    int n = cc20_impls(impl, 8);
    uint8_t key[CC20_KEY_BYTES];
    int rfc = 0, lengths = 0, same = 0, chosen_listed = 0;

    fprintf(stderr, "variants:");
    for(int v = 0; v < n && v < 8; v++) {
        fprintf(stderr, " %s%s", impl[v]->name, impl[v] == cc20_impl_chosen() ? " (chosen)" : "");
        chosen_listed |= impl[v] == cc20_impl_chosen();
    }
    fprintf(stderr, "\n");

    for(int i = 0; i < CC20_KEY_BYTES; i++) {
        key[i] = i;
    }
    for(int v = 0; v < n && v < 8; v++) {
        cc20_context_t *ctx;
        if(cc20_init_impl(key, &ctx, impl[v])) {
            printf("ChaCha20: cc20_init_impl failed\n");
            return 1;
        }
        rfc |= test_rfc(ctx);
        lengths |= test_lengths(ctx);
        cc20_deinit(ctx);
        if(v > 0) {
            same |= test_as_plainc(impl[0], impl[v]);
        }
    }

    printf("ChaCha20: the variant chosen is one this CPU has: %s\n", chosen_listed && n >= 1 ? "ok" : "FAIL");
    printf("ChaCha20: RFC 8439 vector, every variant: %s\n", rfc ? "FAIL" : "ok");
    printf("ChaCha20: lengths 0 to 1100, unaligned, in place, every variant: %s\n", lengths ? "FAIL" : "ok");
    printf("ChaCha20: every variant as plain C: %s\n", same ? "FAIL" : "ok");

    return rfc | lengths | same | !chosen_listed;
}
