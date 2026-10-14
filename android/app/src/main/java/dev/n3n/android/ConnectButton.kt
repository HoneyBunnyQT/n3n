// Copyright (C) Honey Bunny QT
// SPDX-License-Identifier: GPL-3.0-only

package dev.n3n.android

import android.animation.AnimatorInflater
import android.animation.ValueAnimator
import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Matrix
import android.graphics.Outline
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RadialGradient
import android.graphics.RectF
import android.graphics.Shader
import android.graphics.Typeface
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
import android.view.animation.LinearInterpolator
import android.widget.Button
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import kotlin.math.min

/**
 * The big round button of the main screen: it connects and disconnects,
 * and it shows the state - in a word or two, what it is doing right now
 * (or what a tap does), and an LED.  Its symbol is in the accent colour,
 * and grey while a tap cannot connect yet (no configuration, say): the
 * line below the title says what is missing.
 *
 * The LED is never colour alone, as night modes and grayscale screens do
 * not keep colours apart: off it is dark, connected it is lit (pink, as
 * the accent), and on the way there purple stripes run through it, from
 * left to right.
 *
 * A raised button: a shadow from its elevation, which goes down while it
 * is pressed (res/animator/press.xml), a face lit from above, a light edge
 * at the top (RaisedFace); the LED sits in a window let into the face.
 */
class ConnectButton(context: Context, attrs: AttributeSet?) : LinearLayout(context, attrs) {

    enum class Look { OFF, BUSY, ON }

    private val density = resources.displayMetrics.density
    private val rimWidth = 4 * density
    private val edgeWidth = 1.5f * density

    private val icon = ImageView(context)
    private val title = TextView(context)
    private val detail = TextView(context)
    private val led = Led(context)

    private var actionLabel: String? = null

    private val face = RaisedFace(context, rimWidth, edgeWidth)

    init {
        orientation = VERTICAL
        gravity = Gravity.CENTER
        setWillNotDraw(false)
        isClickable = true
        isFocusable = true
        val side = (28 * density).toInt()
        setPadding(side, 0, side, 0)

        // round, for the shadow and the ripple
        outlineProvider = object : ViewOutlineProvider() {
            override fun getOutline(view: View, outline: Outline) {
                val d = min(view.width, view.height)
                val x = (view.width - d) / 2
                val y = (view.height - d) / 2
                outline.setOval(x, y, x + d, y + d)
            }
        }
        elevation = 6 * density
        stateListAnimator = AnimatorInflater.loadStateListAnimator(context, R.animator.press)
        foreground = RippleDrawable(
            ColorStateList.valueOf(context.getColor(R.color.button_ripple)), null, ShapeDrawable(OvalShape()))

        val iconSize = (30 * density).toInt()
        icon.setImageResource(R.drawable.ic_power)
        addView(icon, LayoutParams(iconSize, iconSize))
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 19f)
        title.typeface = Typeface.DEFAULT_BOLD
        title.setTextColor(context.getColor(R.color.text))
        title.gravity = Gravity.CENTER
        title.maxLines = 1
        title.ellipsize = TextUtils.TruncateAt.END
        addView(title, LayoutParams(LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT).apply {
            topMargin = (6 * density).toInt()
        })
        detail.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
        detail.setTextColor(context.getColor(R.color.text_dim))
        // always two lines high, so that symbol, title and LED stay where
        // they are, whether the line below the title takes one or two
        detail.gravity = Gravity.CENTER_HORIZONTAL or Gravity.TOP
        detail.setLines(2)
        detail.ellipsize = TextUtils.TruncateAt.END
        addView(detail, LayoutParams(LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT).apply {
            topMargin = (2 * density).toInt()
        })
        // 52 x 16 dp, and room for the glow around it
        addView(led, LayoutParams((52 * density + 2 * led.glow).toInt(), (16 * density + 2 * led.glow).toInt()).apply {
            topMargin = (12 * density - led.glow).toInt()
        })
        // the button is read out as one, see onInitializeAccessibilityNodeInfo
        for (child in arrayOf(icon, title, detail, led)) {
            child.importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_NO
        }
    }

    /**
     * The look, the state in a word or two, the line below it, what a tap
     * does (for screen readers: "double-tap to <action>"), and whether it
     * can do that now: else the symbol is grey
     */
    fun show(look: Look, title: String, detail: String?, action: String?, usable: Boolean = true) {
        icon.imageTintList = ColorStateList.valueOf(
            if (usable) context.getColor(R.color.accent) else context.getColor(R.color.text_dim) and 0x00FFFFFF or 0x80000000.toInt())
        this.title.text = title
        this.detail.text = detail ?: ""
        actionLabel = action
        contentDescription = if (detail.isNullOrEmpty()) title else "$title. $detail"
        led.look = look
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        face.layout(h / 2f, min(w, h) / 2f)
    }

    override fun onDraw(canvas: Canvas) {
        face.draw(canvas, width / 2f, height / 2f, min(width, height) / 2f)
    }

    override fun onInitializeAccessibilityNodeInfo(info: AccessibilityNodeInfo) {
        super.onInitializeAccessibilityNodeInfo(info)
        info.className = Button::class.java.name
        actionLabel?.let {
            info.addAction(AccessibilityNodeInfo.AccessibilityAction(AccessibilityNodeInfo.ACTION_CLICK, it))
        }
    }

    /**
     * The LED, in an oval window let into the face: dark glass when off,
     * lit pink when connected, and thick purple diagonals that run to the
     * right while on the way, each shaded round as it passes.  Lit, it is
     * brighter in its middle and glows around its window.  Its colours are
     * the same by day and by night, as a real LED's.
     */
    private class Led(context: Context) : View(context) {

        private val density = resources.displayMetrics.density
        private val bezel = 2 * density
        // around the window, for the glow while lit
        val glow = 7 * density
        // the stripes: one purple and one dark per period
        private val period = 12 * density

        var look = Look.OFF
            set(value) {
                if (field != value) {
                    field = value
                    spinIfBusy()
                    invalidate()
                }
            }

        private val window = RectF()
        private val glass = RectF()
        private val clip = Path()
        private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
        private val darkPaint = Paint(Paint.ANTI_ALIAS_FLAG)
        private val stripePaint = Paint(Paint.ANTI_ALIAS_FLAG)
        private val stripeMatrix = Matrix()
        private val bezelPaint = Paint(Paint.ANTI_ALIAS_FLAG)
        private val glowOn = Paint(Paint.ANTI_ALIAS_FLAG)
        private val glowWait = Paint(Paint.ANTI_ALIAS_FLAG)
        private val hotOn = Paint(Paint.ANTI_ALIAS_FLAG)
        private val hotWait = Paint(Paint.ANTI_ALIAS_FLAG)
        private val shinePaint = Paint(Paint.ANTI_ALIAS_FLAG)

        private var shift = 0f
        private val run = ValueAnimator.ofFloat(0f, 1f).apply {
            duration = 600
            repeatCount = ValueAnimator.INFINITE
            interpolator = LinearInterpolator()
            addUpdateListener {
                shift = it.animatedValue as Float * period
                stripeMatrix.setTranslate(shift, 0f)
                stripePaint.shader?.setLocalMatrix(stripeMatrix)
                invalidate()
            }
        }

        override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
            window.set(glow, glow, w - glow, h - glow)
            glass.set(window.left + bezel, window.top + bezel, window.right - bezel, window.bottom - bezel)
            clip.reset()
            clip.addRoundRect(glass, glass.height() / 2, glass.height() / 2, Path.Direction.CW)
            // a window let in: darker at its top edge, lighter at the bottom
            bezelPaint.shader = LinearGradient(
                0f, window.top, 0f, window.bottom, 0x59000000, 0x26FFFFFF, Shader.TileMode.CLAMP)
            glowOn.shader = glow(w, h, context.getColor(R.color.led_on), 0x73)
            glowWait.shader = glow(w, h, context.getColor(R.color.led_wait), 0x4D)
            // the glass, dark: a little lighter in its middle, as it
            // reflects the light around it
            val off = context.getColor(R.color.led_off)
            darkPaint.shader = RadialGradient(
                0f, 0f, 1f, mix(off, Color.WHITE, 0.12f), off, Shader.TileMode.CLAMP).apply {
                setLocalMatrix(Matrix().apply {
                    setScale(glass.width() / 2, glass.height() / 2)
                    postTranslate(glass.centerX(), glass.centerY())
                })
            }
            stripePaint.shader = stripes(off, context.getColor(R.color.led_wait)).apply {
                setLocalMatrix(stripeMatrix)
            }
            // lit, brighter at its middle; less so over the stripes, whose
            // dark ones would go grey
            hotOn.shader = RadialGradient(
                w / 2f, h / 2f, glass.width() / 2, 0x59FFFFFF, 0x00FFFFFF, Shader.TileMode.CLAMP)
            hotWait.shader = RadialGradient(
                w / 2f, h / 2f, glass.width() / 2, 0x33FFFFFF, 0x00FFFFFF, Shader.TileMode.CLAMP)
            shinePaint.shader = LinearGradient(
                0f, glass.top, 0f, glass.centerY(), 0x66FFFFFF, 0x00FFFFFF, Shader.TileMode.CLAMP)
        }

        /** A glow of the colour, an ellipse as wide as the view */
        private fun glow(w: Int, h: Int, color: Int, alpha: Int): Shader {
            val c = color and 0x00FFFFFF
            val a = c or (alpha shl 24)
            return RadialGradient(0f, 0f, 1f, intArrayOf(a, a, c), floatArrayOf(0f, 0.55f, 1f), Shader.TileMode.CLAMP)
                .apply {
                    setLocalMatrix(Matrix().apply {
                        setScale(w / 2f, h / 2f)
                        postTranslate(w / 2f, h / 2f)
                    })
                }
        }

        /**
         * The stripes, a dark and a purple one per period, leaning right:
         * one gradient along x + y, repeated, so that they move with its
         * matrix.  Each is shaded across, darker at its edges and lighter
         * in its middle - the purple as a lit, round bar, the dark as
         * glass.
         */
        private fun stripes(dark: Int, lit: Int): Shader {
            val darkEdge = mix(dark, Color.BLACK, 0.4f)
            val darkMiddle = mix(dark, Color.WHITE, 0.12f)
            val litEdge = mix(lit, Color.BLACK, 0.18f)
            val litMiddle = mix(lit, Color.WHITE, 0.45f)
            return LinearGradient(
                0f, 0f, period / 2, period / 2,
                intArrayOf(darkEdge, darkMiddle, darkEdge, litEdge, lit, litMiddle, lit, litEdge, darkEdge),
                floatArrayOf(0f, 0.24f, 0.47f, 0.51f, 0.62f, 0.74f, 0.86f, 0.96f, 1f),
                Shader.TileMode.REPEAT)
        }

        override fun onDraw(canvas: Canvas) {
            when (look) {
                Look.ON -> canvas.drawRect(0f, 0f, width.toFloat(), height.toFloat(), glowOn)
                Look.BUSY -> canvas.drawRect(0f, 0f, width.toFloat(), height.toFloat(), glowWait)
                Look.OFF -> {}
            }
            canvas.drawRoundRect(window, window.height() / 2, window.height() / 2, bezelPaint)
            canvas.save()
            canvas.clipPath(clip)
            when (look) {
                Look.OFF -> canvas.drawRect(glass, darkPaint)
                Look.ON -> {
                    paint.color = context.getColor(R.color.led_on)
                    canvas.drawRect(glass, paint)
                    canvas.drawRect(glass, hotOn)
                }
                Look.BUSY -> {
                    canvas.drawRect(glass, stripePaint)
                    canvas.drawRect(glass, hotWait)
                }
            }
            // the glass: a shine on its upper half
            canvas.drawRect(glass, shinePaint)
            canvas.restore()
        }

        override fun onAttachedToWindow() {
            super.onAttachedToWindow()
            spinIfBusy()
        }

        override fun onDetachedFromWindow() {
            run.cancel()
            super.onDetachedFromWindow()
        }

        override fun onVisibilityAggregated(isVisible: Boolean) {
            super.onVisibilityAggregated(isVisible)
            if (isVisible) spinIfBusy() else run.cancel()
        }

        private fun spinIfBusy() {
            if (look == Look.BUSY && isAttachedToWindow) {
                if (!run.isStarted) run.start()
            } else {
                run.cancel()
            }
        }
    }
}
