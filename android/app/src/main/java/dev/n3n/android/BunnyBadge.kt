// Copyright (C) Honey Bunny QT
// SPDX-License-Identifier: GPL-3.0-only

package dev.n3n.android

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Typeface
import android.graphics.drawable.Drawable
import android.util.AttributeSet
import android.view.View
import android.view.accessibility.AccessibilityNodeInfo
import android.widget.Button
import android.widget.Toast

/**
 * The bunny in the corner of the main screen, and below it "BUNNY EDITION"
 * in small capitals, as wide as the bunny.  A tap says which build this
 * is: the app's version, and the core's (git describe of the tree).
 */
class BunnyBadge(context: Context, attrs: AttributeSet?) : View(context, attrs) {

    private val density = resources.displayMetrics.density
    private val bunny: Drawable = context.getDrawable(R.drawable.bunny)!!
    private val label = context.getString(R.string.bunny_edition)
    private val gap = 2 * density
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = context.getColor(R.color.accent)
        typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
        textAlign = Paint.Align.CENTER
    }

    init {
        isClickable = true
        isFocusable = true
        contentDescription = label
        setOnClickListener { showVersion() }
    }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val w = bunny.intrinsicWidth
        // the text as wide as the bunny: its size from its width at 1px
        paint.textSize = 1f
        paint.textSize = w / paint.measureText(label)
        val text = paint.fontMetrics.let { it.descent - it.ascent }
        setMeasuredDimension(w, (bunny.intrinsicHeight + gap + text).toInt() + 1)
    }

    override fun onDraw(canvas: Canvas) {
        bunny.setBounds(0, 0, bunny.intrinsicWidth, bunny.intrinsicHeight)
        bunny.draw(canvas)
        val baseline = bunny.intrinsicHeight + gap - paint.fontMetrics.ascent
        canvas.drawText(label, width / 2f, baseline, paint)
    }

    private fun showVersion() {
        val app = try {
            context.packageManager.getPackageInfo(context.packageName, 0).versionName
        } catch (e: Exception) {
            null
        }
        Toast.makeText(
            context, context.getString(R.string.bunny_version, app ?: "?", Core.version()), Toast.LENGTH_LONG).show()
    }

    override fun onInitializeAccessibilityNodeInfo(info: AccessibilityNodeInfo) {
        super.onInitializeAccessibilityNodeInfo(info)
        info.className = Button::class.java.name
    }
}
