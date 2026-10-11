/*
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Base64 decoder
 *
 */

#include <stdlib.h>
#include <string.h>

#include "base64.h"

static int letter2number (const char ch) {
    if(ch >= 'A' && ch <= 'Z') {
        return ch-'A';
    }
    if(ch >= 'a' && ch <= 'z') {
        return ch-'a'+26;
    }
    if(ch >= '0' && ch <= '9') {
        return ch-'0'+52;
    }
    if(ch == '+') {
        return 62;
    }
    if(ch == '/') {
        return 63;
    }
    return -1;
}

char *base64decode (const char *in) {
    // three bytes out per four in, the quads rounded up so that an input
    // whose length is not a multiple of four still fits.  "len" is the
    // room left for decoded bytes; the buffer has one more for the NUL.
    // (The old ((strlen / 4) * 3) + 1 both undersized the buffer for a
    // trailing partial group - overflowing it - and let the NUL's byte
    // count as decoded room, so one more four-character group was read
    // than the input held: a padless base64 whose length is a multiple of
    // four, as the Authorization of many a user:password is, decoded to
    // NULL.)
    int len = ((strlen(in) + 3) / 4) * 3;
    char *out = malloc(len + 1);
    if(!out) {
        return NULL;
    }

    char *p = out;
    while(len) {
        // read one at a time and stop at the first character that is not
        // base64 (the end of the string among them): reading the whole
        // group first ran past the end of the input for a group cut short
        int i1 = letter2number(*in++);
        int i2 = (i1 != -1) ? letter2number(*in++) : -1;

        // a group needs at least its first two characters to give a byte;
        // a shorter tail is not valid - give up, and free what was
        // allocated above
        if(i1 == -1 || i2 == -1) {
            free(out);
            return NULL;
        }

        *p++ = (i1 << 2) | (i2 >> 4);
        len--;

        int i3 = letter2number(*in++);
        if(i3 == -1) break;

        *p++ = (i2 << 4) | (i3 >> 2);
        len--;

        int i4 = letter2number(*in++);
        if(i4 == -1) break;

        *p++ = (i3 << 6) | (i4);
        len--;
    }
    *p = 0;
    return out;
}
