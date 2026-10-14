/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Speck's SSSE3 variant: the SSE2 one, with its byte rotations by SSSE3's
 * shuffle (see speck.c for how a variant is chosen)
 */

#define SPECK_SSSE3
#include "speck_sse2.c"
