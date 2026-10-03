// Copyright (C) Honey Bunny QT
// SPDX-License-Identifier: GPL-3.0-only

package dev.n3n.android

import android.graphics.Bitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/** QR codes on the phone, with ZXing's core, like tools/n3n-qr makes them */
object QrEncode {

    /** Dark on light, each module a square of pixels; WriterException when it does not fit */
    fun bitmap(text: String, pixels: Int = 10): Bitmap {
        val hints = mapOf(
            EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
            EncodeHintType.MARGIN to 4,
            EncodeHintType.CHARACTER_SET to "UTF-8",
        )
        val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, hints)
        val size = matrix.width * pixels
        val colors = IntArray(size * size)
        for (y in 0 until size) {
            for (x in 0 until size) {
                colors[y * size + x] = if (matrix.get(x / pixels, y / pixels)) 0xFF000000.toInt() else 0xFFFFFFFF.toInt()
            }
        }
        return Bitmap.createBitmap(colors, size, size, Bitmap.Config.ARGB_8888)
    }
}
