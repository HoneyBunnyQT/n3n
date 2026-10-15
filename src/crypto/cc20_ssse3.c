/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * ChaCha20's SSSE3 variant: the SSE2 one, with its byte rotations by
 * SSSE3's shuffle (see cc20.c for how a variant is chosen)
 */

#define CC20_SSSE3
#include "cc20_sse2.c"
