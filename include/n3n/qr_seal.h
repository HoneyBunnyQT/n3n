/**
 * Copyright (C) Honey Bunny QT
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * A configuration sealed with a PIN, for a QR code that does not show what
 * it holds: see src/qr_seal.c.  Used by tools/n3n-qr and the Android app.
 */

#ifndef N3N_QR_SEAL_H
#define N3N_QR_SEAL_H

// The text sealed with the PIN, as base64url: 0, and *out malloc()ed
int qr_seal (const char *text, const char *pin, char **out);

// The text of a sealed code, if the PIN opens it: 0, and *out malloc()ed;
// -1 if it is no sealed code, or the PIN is wrong
int qr_open (const char *code, const char *pin, char **out);

// Whether a text could be a sealed code at all (base64url, long enough):
// to ask for a PIN only then
int qr_looks_sealed (const char *code);

#endif
