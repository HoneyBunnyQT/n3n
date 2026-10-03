// Copyright (C) Honey Bunny QT
// SPDX-License-Identifier: GPL-3.0-only

package dev.n3n.android

/**
 * QR codes sealed with a PIN: the very code of tools/n3n-qr -P, from the
 * core in libn3n (src/qr_seal.c), so that both make and read the same.
 * Sealing and opening take a moment (on purpose): not on the UI thread.
 */
object Seal {

    init {
        System.loadLibrary("n3n")
    }

    /** The text sealed with the PIN, or null */
    external fun seal(text: String, pin: String): String?

    /** The text of a sealed code, or null: no sealed code, or not the right PIN */
    external fun open(code: String, pin: String): ByteArray?

    /** Whether a text could be a sealed code at all, to ask for a PIN only then */
    external fun looksSealed(code: String): Boolean
}
