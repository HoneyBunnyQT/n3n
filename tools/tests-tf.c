/*
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Twofish's variants (src/crypto/tf.c):
 *
 *   - the known answers of the Twofish paper (ecb_tbl.txt), 128 and 256
 *     bit keys, encrypted and decrypted back
 *   - every variant this CPU has decrypts CBC as plain C does, for every
 *     number of blocks from 0 to 70 (the 16 at a time of AVX-512, and the
 *     three and single ones of plain C after them), unaligned and in place
 *
 * The output is the same on every CPU: which variants there are goes to
 * stderr.
 */

#include <stdint.h>     // for uint8_t
#include <stdio.h>      // for printf, fprintf
#include <string.h>     // for memcmp, memcpy, memset
#include "tf.h"         // for tf_init_impl, tf_cbc_decrypt, tf_impls


static int failed;

static void check (const char *what, int ok) {
    printf("%s: %s\n", what, ok ? "ok" : "FAIL");
    failed |= !ok;
}

static void hex (uint8_t *out, const char *in) {
    for(int i = 0; in[2 * i]; i++) {
        unsigned int b;
        sscanf(in + 2 * i, "%2x", &b);
        out[i] = (uint8_t)b;
    }
}

static int kat (int keysize, const char *key_hex, const char *ct_hex) {
    uint8_t key[32] = {0}, pt[16] = {0}, ct[16], out[16], back[16];
    tf_context_t *ctx;

    hex(key, key_hex);
    hex(ct, ct_hex);
    if(tf_init(key, keysize, &ctx)) {
        return 0;
    }
    tf_ecb_encrypt(out, pt, ctx);
    tf_ecb_decrypt(back, out, ctx);
    tf_deinit(ctx);
    return !memcmp(out, ct, 16) && !memcmp(back, pt, 16);
}

static uint64_t rnd_state = 0x9e3779b97f4a7c15ULL;

static uint8_t rnd (void) {
    rnd_state ^= rnd_state << 13;
    rnd_state ^= rnd_state >> 7;
    rnd_state ^= rnd_state << 17;
    return (uint8_t)rnd_state;
}

int main (int argc, char *argv[]) {

    // slowest first: plain C, then those of this CPU
    const struct tf_impl *impl[4];
    int n = tf_impls(impl, 4);
    enum { BLOCKS = 70 };
    static uint8_t text[BLOCKS * 16 + 8], ref[BLOCKS * 16], got[BLOCKS * 16 + 8], key[32], iv[16];

    fprintf(stderr, "variants:");
    int chosen_listed = 0;
    for(int v = 0; v < n && v < 4; v++) {
        fprintf(stderr, " %s%s", impl[v]->name, impl[v] == tf_impl_chosen() ? " (chosen)" : "");
        chosen_listed |= impl[v] == tf_impl_chosen();
    }
    fprintf(stderr, "\n");

    check("Twofish, 128 bit key, the paper's known answer",
          kat(128, "00000000000000000000000000000000", "9F589F5CF6122C32B6BFEC2F2AE8C35A"));
    check("Twofish, 256 bit key, the paper's known answer",
          kat(256, "0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF",
              "37527BE0052334B89F0CFCCAE87CFA20"));
    check("the variant chosen is one this CPU has", chosen_listed && n >= 1);

    int same = 1;
    for(int k = 0; k < 2; k++) {
        for(int i = 0; i < 32; i++) {
            key[i] = rnd();
        }
        tf_context_t *ctx[4];
        for(int v = 0; v < n && v < 4; v++) {
            tf_init_impl(key, 256, &ctx[v], impl[v]);
        }
        for(int blocks = 0; blocks <= BLOCKS; blocks++) {
            int len = blocks * 16, off = blocks % 7;
            for(int i = 0; i < len; i++) {
                text[off + i] = rnd();
            }
            for(int i = 0; i < 16; i++) {
                iv[i] = rnd();
            }
            tf_cbc_decrypt(ref, text + off, len, iv, ctx[0]);
            for(int v = 1; v < n && v < 4; v++) {
                memset(got, 0xa5, sizeof(got));
                tf_cbc_decrypt(got + 1, text + off, len, iv, ctx[v]);
                if(memcmp(got + 1, ref, len) || got[1 + len] != 0xa5) {
                    fprintf(stderr, "%s, %d blocks: not as plain C\n", impl[v]->name, blocks);
                    same = 0;
                }
                // in place
                memcpy(got + off, text + off, len);
                tf_cbc_decrypt(got + off, got + off, len, iv, ctx[v]);
                if(memcmp(got + off, ref, len)) {
                    fprintf(stderr, "%s, %d blocks in place: not as plain C\n", impl[v]->name, blocks);
                    same = 0;
                }
            }
        }
        for(int v = 0; v < n && v < 4; v++) {
            tf_deinit(ctx[v]);
        }
    }
    check("every variant decrypts as plain C, 0 to 70 blocks, unaligned, in place", same);

    return failed;
}
