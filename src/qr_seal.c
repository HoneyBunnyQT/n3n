/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * A configuration sealed with a PIN, for a QR code that does not show what
 * it holds - not even that it is n3n's.  With the ciphers n3n has already:
 *
 *   salt        16 random bytes, also the IV
 *   key         the Pearson hash (256 bit) of PIN and salt, then again of
 *               the hash before, PIN and salt: 300000 times in all
 *   ciphertext  Speck in CTR mode over "n3n1\n" + the text
 *   the code    base64url without padding of salt + ciphertext
 *
 * "n3n1\n" at the start of what comes out tells that the PIN was right.
 * The rounds make each guess of the PIN slower, but the Pearson hash is no
 * cryptographic hash, and a short PIN can be found by trying them all: this
 * keeps a code from saying what it is at a glance, it does not protect the
 * key against a determined attacker.
 */

#include <n3n/qr_seal.h>
#include <pearson.h>          // for pearson_hash_256
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>            // for fopen, fread
#include <stdlib.h>
#include <string.h>

#include "crypto/speck.h"     // for speck_init, speck_ctr, speck_deinit

#define SEAL_MAGIC     "n3n1\n"
#define SEAL_ROUNDS    300000
#define SEAL_SALT      16
#define SEAL_KEY       32
#define SEAL_PIN_MAX   64


// ---- base64url without padding (RFC 4648) ------------------------------------

static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static char *b64_encode (const uint8_t *p, size_t n) {

    char *out = malloc(n / 3 * 4 + 5);
    char *o = out;

    if(!out) {
        return NULL;
    }
    for(size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)p[i] << 16;
        if(i + 1 < n) {
            v |= (uint32_t)p[i + 1] << 8;
        }
        if(i + 2 < n) {
            v |= p[i + 2];
        }
        *o++ = b64[(v >> 18) & 63];
        *o++ = b64[(v >> 12) & 63];
        if(i + 1 < n) {
            *o++ = b64[(v >> 6) & 63];
        }
        if(i + 2 < n) {
            *o++ = b64[v & 63];
        }
    }
    *o = 0;
    return out;
}

// -1 for a character that is no part of base64url
static int b64_value (char ch) {

    const char *p = (ch != 0) ? strchr(b64, ch) : NULL;

    return p ? (int)(p - b64) : -1;
}

static uint8_t *b64_decode (const char *s, size_t *n) {

    size_t len = strlen(s);
    uint8_t *out;
    uint32_t v = 0;
    int bits = 0;

    if(len % 4 == 1) {
        return NULL;
    }
    out = malloc(len * 3 / 4 + 1);
    if(!out) {
        return NULL;
    }
    *n = 0;
    for(size_t i = 0; i < len; i++) {
        int d = b64_value(s[i]);
        if(d < 0) {
            free(out);
            return NULL;
        }
        v = (v << 6) | (uint32_t)d;
        bits += 6;
        if(bits >= 8) {
            bits -= 8;
            out[(*n)++] = (uint8_t)(v >> bits);
        }
    }
    return out;
}


// ---- sealing -----------------------------------------------------------------

static void seal_key (const char *pin, const uint8_t salt[SEAL_SALT], uint8_t key[SEAL_KEY]) {

    uint8_t buf[SEAL_KEY + SEAL_PIN_MAX + SEAL_SALT];
    size_t pin_len = strlen(pin);

    if(pin_len > SEAL_PIN_MAX) {
        pin_len = SEAL_PIN_MAX;
    }
    memcpy(buf + SEAL_KEY, pin, pin_len);
    memcpy(buf + SEAL_KEY + pin_len, salt, SEAL_SALT);

    // the first round without a hash before it
    pearson_hash_256(key, buf + SEAL_KEY, pin_len + SEAL_SALT);
    for(int r = 1; r < SEAL_ROUNDS; r++) {
        memcpy(buf, key, SEAL_KEY);
        pearson_hash_256(key, buf, SEAL_KEY + pin_len + SEAL_SALT);
    }
    memset(buf, 0, sizeof(buf));
}

// Speck in CTR mode over len bytes in place: the same both ways
static int seal_crypt (uint8_t *p, size_t len, const char *pin, const uint8_t salt[SEAL_SALT]) {

    uint8_t key[SEAL_KEY];
    speck_context_t *ctx = NULL;

    seal_key(pin, salt, key);
    if(speck_init(&ctx, key, 256) != 0) {
        memset(key, 0, sizeof(key));
        return -1;
    }
    speck_ctr(p, p, len, salt, ctx);
    speck_deinit(ctx);
    memset(key, 0, sizeof(key));
    return 0;
}

int qr_seal (const char *text, const char *pin, char **out) {

    size_t magic = strlen(SEAL_MAGIC);
    size_t len = magic + strlen(text);
    uint8_t *buf = malloc(SEAL_SALT + len);
    FILE *rnd;
    int rc = -1;

    if(!buf) {
        return -1;
    }
    rnd = fopen("/dev/urandom", "rb");
    if(!rnd || (fread(buf, 1, SEAL_SALT, rnd) != SEAL_SALT)) {
        if(rnd) {
            fclose(rnd);
        }
        free(buf);
        return -1;
    }
    fclose(rnd);

    memcpy(buf + SEAL_SALT, SEAL_MAGIC, magic);
    memcpy(buf + SEAL_SALT + magic, text, len - magic);
    if(seal_crypt(buf + SEAL_SALT, len, pin, buf) == 0) {
        *out = b64_encode(buf, SEAL_SALT + len);
        rc = *out ? 0 : -1;
    }
    free(buf);
    return rc;
}

int qr_open (const char *code, const char *pin, char **out) {

    size_t magic = strlen(SEAL_MAGIC);
    size_t n;
    uint8_t *raw = b64_decode(code, &n);
    int rc = -1;

    if(!raw) {
        return -1;
    }
    if((n >= SEAL_SALT + magic) && (seal_crypt(raw + SEAL_SALT, n - SEAL_SALT, pin, raw) == 0)
       && !memcmp(raw + SEAL_SALT, SEAL_MAGIC, magic)) {
        size_t text_len = n - SEAL_SALT - magic;
        *out = malloc(text_len + 1);
        if(*out) {
            memcpy(*out, raw + SEAL_SALT + magic, text_len);
            (*out)[text_len] = 0;
            rc = 0;
        }
    }
    free(raw);
    return rc;
}

int qr_looks_sealed (const char *code) {

    size_t len = strlen(code);

    if((len < (SEAL_SALT + strlen(SEAL_MAGIC) + 2) * 4 / 3) || (len % 4 == 1)) {
        return 0;
    }
    for(size_t i = 0; i < len; i++) {
        if(b64_value(code[i]) < 0) {
            return 0;
        }
    }
    return 1;
}
