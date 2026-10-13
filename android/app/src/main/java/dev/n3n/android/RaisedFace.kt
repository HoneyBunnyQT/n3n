// Copyright (C) Honey Bunny QT
// SPDX-License-Identifier: GPL-3.0-only

package dev.n3n.android

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.Shader

/**
 * The face of a raised round button, as the connect button and the keys
 * below it have it: lit from above, a rim around it, and a light edge
 * along its top, just inside the rim.  The view gives the shadow (its
 * elevation) and the press (res/animator/press.xml).
 */
class RaisedFace(context: Context, private val rimWidth: Float, private val edgeWidth: Float) {

    private val face = context.getColor(R.color.card)
    private val light = context.getColor(R.color.button_edge)

    private val facePaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val rimPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = rimWidth
        color = context.getColor(R.color.button_rim)
    }
    private val edgePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = edgeWidth
    }

    /** For a face of radius r at height cy: from onSizeChanged() */
    fun layout(cy: Float, r: Float) {
        facePaint.shader = LinearGradient(
            0f, cy - r, 0f, cy + r, mix(face, Color.WHITE, 0.10f), mix(face, Color.BLACK, 0.06f), Shader.TileMode.CLAMP)
        edgePaint.shader = LinearGradient(0f, cy - r, 0f, cy, light, light and 0x00FFFFFF, Shader.TileMode.CLAMP)
    }

    fun draw(canvas: Canvas, cx: Float, cy: Float, r: Float) {
        canvas.drawCircle(cx, cy, r, facePaint)
        canvas.drawCircle(cx, cy, r - rimWidth / 2, rimPaint)
        canvas.drawCircle(cx, cy, r - rimWidth - edgeWidth / 2, edgePaint)
    }
}

/** The colour, with some of another mixed in (0 none .. 1 all of it) */
internal fun mix(color: Int, with: Int, amount: Float): Int {
    val keep = 1 - amount
    return Color.rgb(
        (Color.red(color) * keep + Color.red(with) * amount).toInt(),
        (Color.green(color) * keep + Color.green(with) * amount).toInt(),
        (Color.blue(color) * keep + Color.blue(with) * amount).toInt(),
    )
}
