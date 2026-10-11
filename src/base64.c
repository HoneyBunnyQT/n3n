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
    // whose length is not a multiple of four still fits, plus the NUL.
    // ((strlen / 4) * 3) + 1 was a byte short of the trailing group and
    // its NUL, and the loop below wrote past the buffer
    int len = (((strlen(in) + 3) / 4) * 3) + 1;
    char *out = malloc(len);
    if(!out) {
        return NULL;
    }

    char *p = out;
    while(len) {
        int i1 = letter2number(*in++);
        int i2 = letter2number(*in++);
        int i3 = letter2number(*in++);
        int i4 = letter2number(*in++);

        // a character that is not base64 (the end of the string among
        // them): give up, and free what was allocated above
        if(i1 == -1 || i2 == -1) {
            free(out);
            return NULL;
        }

        *p++ = (i1 << 2) | (i2 >> 4);
        len--;

        if(i3 == -1) break;

        *p++ = (i2 << 4) | (i3 >> 2);
        len--;

        if(i4 == -1) break;

        *p++ = (i3 << 6) | (i4);
        len--;
    }
    *p = 0;
    return out;
}
