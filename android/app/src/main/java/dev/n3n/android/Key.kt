// Copyright (C) Honey Bunny QT
// SPDX-License-Identifier: GPL-3.0-only

package dev.n3n.android

import android.animation.AnimatorInflater
import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Canvas
import android.graphics.Outline
import android.graphics.drawable.Drawable
import android.graphics.drawable.RippleDrawable
import android.graphics.drawable.ShapeDrawable
import android.graphics.drawable.shapes.OvalShape
import android.text.TextUtils
import android.util.AttributeSet
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewOutlineProvider
import android.view.accessibility.AccessibilityNodeInfo
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import kotlin.math.min

/**
 * A key of the main screen: a small round button built as the connect
 * button is (RaisedFace, the shadow that goes down while pressed), its
 * symbol on it in the accent colour, and its name below.  android:src and
 * android:text give them.  The whole key takes the tap, the name too; it
 * is read out as one button.
 */
class Key(context: Context, attrs: AttributeSet?) : LinearLayout(context, attrs) {

    private val density = resources.displayMetrics.density
    private val cap = Cap(context)
    private val label = TextView(context)

    init {
        orientation = VERTICAL
        gravity = Gravity.CENTER_HORIZONTAL
        isClickable = true
        isFocusable = true
        // room for the shadow above the cap, and a touch target of 48dp
        // and more
        setPadding(0, (4 * density).toInt(), 0, (4 * density).toInt())

        // sorted by id, as obtainStyledAttributes() wants them
        val a = context.obtainStyledAttributes(attrs, intArrayOf(android.R.attr.src, android.R.attr.text))
        cap.icon = a.getDrawable(0)?.mutate()?.apply {
            setTintList(ColorStateList.valueOf(context.getColor(R.color.accent)))
        }
        label.text = a.getText(1)
        a.recycle()

        val side = (56 * density).toInt()
        // pressed with the key, wherever on it the finger is
        cap.isDuplicateParentStateEnabled = true
        addView(cap, LayoutParams(side, side))
        label.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
        label.setTextColor(context.getColor(R.color.text))
        label.gravity = Gravity.CENTER
        label.maxLines = 1
        label.ellipsize = TextUtils.TruncateAt.END
        addView(label, LayoutParams(LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT).apply {
            topMargin = (8 * density).toInt()
        })
        contentDescription = label.text
        cap.importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_NO
        label.importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_NO
    }

    /** A key that does nothing yet looks it: faded */
    override fun setEnabled(enabled: Boolean) {
        super.setEnabled(enabled)
        alpha = if (enabled) 1f else 0.38f
    }

    override fun onInitializeAccessibilityNodeInfo(info: AccessibilityNodeInfo) {
        super.onInitializeAccessibilityNodeInfo(info)
        info.className = Button::class.java.name
    }

    /** The round part, with the symbol */
    private class Cap(context: Context) : View(context) {

        private val density = resources.displayMetrics.density
        private val face = RaisedFace(context, 2.5f * density, 1f * density)
        private val iconSize = (24 * density).toInt()

        var icon: Drawable? = null

        init {
            outlineProvider = object : ViewOutlineProvider() {
                override fun getOutline(view: View, outline: Outline) {
                    outline.setOval(0, 0, view.width, view.height)
                }
            }
            elevation = 4 * density
            stateListAnimator = AnimatorInflater.loadStateListAnimator(context, R.animator.press)
            foreground = RippleDrawable(
                ColorStateList.valueOf(context.getColor(R.color.button_ripple)), null, ShapeDrawable(OvalShape()))
        }

        override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
            super.onSizeChanged(w, h, oldw, oldh)
            face.layout(h / 2f, min(w, h) / 2f)
            val x = (w - iconSize) / 2
            val y = (h - iconSize) / 2
            icon?.setBounds(x, y, x + iconSize, y + iconSize)
        }

        override fun onDraw(canvas: Canvas) {
            face.draw(canvas, width / 2f, height / 2f, min(width, height) / 2f)
            icon?.draw(canvas)
        }
    }
}
