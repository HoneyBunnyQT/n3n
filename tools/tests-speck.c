/*
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Speck's variants (src/crypto/speck.c), each against plain C:
 *
 *   - plain C gives the test vectors of the Speck implementation guide
 *     (Speck128/128 and Speck128/256: CTR with a block of zeros is the
 *     block cipher on the nonce)
 *   - every variant this CPU has gives the same bytes as plain C, for both
 *     key sizes, every length from 0 to 1100 bytes (each of a variant's
 *     chunk sizes and every tail), text and key stream on any alignment,
 *     and in place, as header encryption has it - and leaves the nonce as
 *     it was
 *   - the one block functions, which all contexts share, invert each other
 *
 * The output is the same on every CPU: which variants there are goes to
 * stderr.
 */

#include <stdint.h>     // for uint8_t, uint64_t
#include <stdio.h>      // for printf, fprintf
#include <string.h>     // for memcmp, memcpy, memset
#include "../src/crypto/speck.h" // for speck_init_impl, speck_ctr, speck_impls

static int failed;

static void check (const char *what, int ok) {
    printf("%s: %s\n", what, ok ? "ok" : "FAIL");
    failed |= !ok;
}

static uint64_t rnd_state = 0x9e3779b97f4a7c15ULL;

static uint8_t rnd (void) {
    rnd_state ^= rnd_state << 13;
    rnd_state ^= rnd_state >> 7;
    rnd_state ^= rnd_state << 17;
    return (uint8_t)rnd_state;
}

static void le64 (uint8_t *p, uint64_t v) {
    for(int i = 0; i < 8; i++) {
        p[i] = (uint8_t)(v >> (8 * i));
    }
}

// the guide's (x, y) in the nonce as speck_ctr() takes it: y, then x, each
// little endian - and a block of zeros, so that the output is the cipher
// text, y' then x'
static int kat (const struct speck_impl *plain, int keysize, uint64_t x, uint64_t y, uint64_t cx, uint64_t cy) {
    uint8_t key[32], nonce[16], zeros[16] = {0}, out[16], want[16];
    speck_context_t *ctx;

    for(int i = 0; i < 32; i++) {
        key[i] = (uint8_t)i;
    }
    le64(nonce, y);
    le64(nonce + 8, x);
    le64(want, cy);
    le64(want + 8, cx);
    if(speck_init_impl(&ctx, key, keysize, plain)) {
        return 0;
    }
    speck_ctr(out, zeros, 16, nonce, ctx);
    speck_deinit(ctx);
    return !memcmp(out, want, 16);
}

int main (int argc, char *argv[]) {

    // slowest first: plain C, then those of this CPU
    const struct speck_impl *impl[8];
    int n = speck_impls(impl, 8);
    static uint8_t text[1100 + 16], ref[1100 + 16], got[1100 + 16], key[32], nonce[16 + 8];

    fprintf(stderr, "variants:");
    for(int v = 0; v < n && v < 8; v++) {
        fprintf(stderr, " %s%s", impl[v]->name, impl[v] == speck_impl_chosen() ? " (chosen)" : "");
    }
    fprintf(stderr, "\n");

    check("Speck128/128, the guide's test vector",
          kat(impl[0], 128, 0x6c61766975716520ULL, 0x7469206564616d20ULL, 0xa65d985179783265ULL, 0x7860fedf5c570d18ULL));
    check("Speck128/256, the guide's test vector",
          kat(impl[0], 256, 0x65736f6874206e49ULL, 0x202e72656e6f6f70ULL, 0x4109010405c0f53eULL, 0x4eeeb48d9c188f43ULL));

    int chosen_listed = 0;
    for(int v = 0; v < n && v < 8; v++) {
        chosen_listed |= impl[v] == speck_impl_chosen();
    }
    check("the variant chosen is one this CPU has", chosen_listed && n >= 1);

    int same = 1, nonce_kept = 1;
    for(int keysize = 128; keysize <= 256; keysize += 128) {
        for(int i = 0; i < 32; i++) {
            key[i] = rnd();
        }
        speck_context_t *plain;
        speck_init_impl(&plain, key, keysize, impl[0]);
        speck_context_t *ctx[8];
        for(int v = 0; v < n && v < 8; v++) {
            speck_init_impl(&ctx[v], key, keysize, impl[v]);
        }
        for(int len = 0; len <= 1100; len++) {
            // the text, the output and the nonce each a little off
            // alignment, differently for every length
            int off_in = len % 5, off_out = (len / 5) % 3, off_n = len % 7;
            for(int i = 0; i < len; i++) {
                text[off_in + i] = rnd();
            }
            for(int i = 0; i < 16; i++) {
                nonce[off_n + i] = rnd();
            }
            uint8_t nonce_was[16];
            memcpy(nonce_was, nonce + off_n, 16);
            speck_ctr(ref, text + off_in, len, nonce + off_n, plain);

            for(int v = 1; v < n && v < 8; v++) {
                memset(got, 0xa5, sizeof(got));
                speck_ctr(got + off_out, text + off_in, len, nonce + off_n, ctx[v]);
                if(memcmp(got + off_out, ref, len) || got[off_out + len] != 0xa5) {
                    fprintf(stderr, "%s, %d bit key, %d bytes: not as plain C\n", impl[v]->name, keysize, len);
                    same = 0;
                }
                // in place
                memcpy(got + off_in, text + off_in, len);
                speck_ctr(got + off_in, got + off_in, len, nonce + off_n, ctx[v]);
                if(memcmp(got + off_in, ref, len)) {
                    fprintf(stderr, "%s, %d bit key, %d bytes in place: not as plain C\n", impl[v]->name, keysize, len);
                    same = 0;
                }
                if(memcmp(nonce + off_n, nonce_was, 16)) {
                    fprintf(stderr, "%s, %d bytes: the nonce changed\n", impl[v]->name, len);
                    nonce_kept = 0;
                }
            }
        }
        for(int v = 0; v < n && v < 8; v++) {
            speck_deinit(ctx[v]);
        }
        speck_deinit(plain);
    }
    check("every variant as plain C, 0 to 1100 bytes, any alignment, in place", same);
    check("the nonce as it was", nonce_kept);

    // the one block functions, on a context of the variant chosen
    {
        uint8_t block[16], was[16];
        speck_context_t *ctx;
        for(int i = 0; i < 16; i++) {
            key[i] = rnd();
            block[i] = rnd();
        }
        memcpy(was, block, 16);
        speck_init(&ctx, key, 128);
        speck_128_encrypt(block, ctx);
        int changed = memcmp(block, was, 16) != 0;
        speck_128_decrypt(block, ctx);
        check("one block: encrypted, and decrypted back", changed && !memcmp(block, was, 16));
        speck_deinit(ctx);
    }

    return failed;
}
