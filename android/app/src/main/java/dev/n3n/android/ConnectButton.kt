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
 * (or what a tap does), and an LED.
 *
 * The LED is never colour alone, as night modes and grayscale screens do
 * not keep colours apart: off it is dark, connected it is lit, and on the
 * way there yellow stripes run through it.
 *
 * A raised button: a shadow from its elevation, which goes down while it
 * is pressed (res/animator/press.xml), a face lit from above, a light edge
 * at the top; the LED sits in a window let into the face.
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

    private val facePaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val rimPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = rimWidth
    }
    private val edgePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = edgeWidth
    }

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
        icon.imageTintList = ColorStateList.valueOf(context.getColor(R.color.text_dim))
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
        rimPaint.color = context.getColor(R.color.button_rim)
    }

    /**
     * The look, the state in a word or two, the line below it, and what a
     * tap does (for screen readers: "double-tap to <action>")
     */
    fun show(look: Look, title: String, detail: String?, action: String?) {
        this.title.text = title
        this.detail.text = detail ?: ""
        actionLabel = action
        contentDescription = if (detail.isNullOrEmpty()) title else "$title. $detail"
        led.look = look
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        val cy = h / 2f
        val r = min(w, h) / 2f
        val face = context.getColor(R.color.card)
        facePaint.shader = LinearGradient(
            0f, cy - r, 0f, cy + r, mix(face, Color.WHITE, 0.10f), mix(face, Color.BLACK, 0.06f), Shader.TileMode.CLAMP)
        val light = context.getColor(R.color.button_edge)
        edgePaint.shader = LinearGradient(0f, cy - r, 0f, cy, light, light and 0x00FFFFFF, Shader.TileMode.CLAMP)
    }

    override fun onDraw(canvas: Canvas) {
        val cx = width / 2f
        val cy = height / 2f
        val r = min(width, height) / 2f
        canvas.drawCircle(cx, cy, r, facePaint)
        canvas.drawCircle(cx, cy, r - rimWidth / 2, rimPaint)
        // the light along the top, just inside the rim
        canvas.drawCircle(cx, cy, r - rimWidth - edgeWidth / 2, edgePaint)
    }

    override fun onInitializeAccessibilityNodeInfo(info: AccessibilityNodeInfo) {
        super.onInitializeAccessibilityNodeInfo(info)
        info.className = Button::class.java.name
        actionLabel?.let {
            info.addAction(AccessibilityNodeInfo.AccessibilityAction(AccessibilityNodeInfo.ACTION_CLICK, it))
        }
    }

    /**
     * The LED, in an oval window let into the face: dark when off, lit
     * green (with a glow) when connected, and thick yellow diagonals that
     * run to the left while on the way.  Its colours are the same by day
     * and by night, as a real LED's.
     */
    private class Led(context: Context) : View(context) {

        private val density = resources.displayMetrics.density
        private val bezel = 2 * density
        // around the window, for the glow while lit
        val glow = 7 * density
        // the stripes: one yellow and one dark per period
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
        private val stripe = Path()
        private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
        private val bezelPaint = Paint(Paint.ANTI_ALIAS_FLAG)
        private val glowPaint = Paint(Paint.ANTI_ALIAS_FLAG)
        private val hotPaint = Paint(Paint.ANTI_ALIAS_FLAG)
        private val shinePaint = Paint(Paint.ANTI_ALIAS_FLAG)

        private var shift = 0f
        private val run = ValueAnimator.ofFloat(0f, 1f).apply {
            duration = 600
            repeatCount = ValueAnimator.INFINITE
            interpolator = LinearInterpolator()
            addUpdateListener {
                shift = it.animatedValue as Float * period
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
            // the glow around it, an ellipse as wide as the view
            val on = context.getColor(R.color.led_on) and 0x00FFFFFF
            glowPaint.shader = RadialGradient(
                0f, 0f, 1f, intArrayOf(on or 0x73000000, on or 0x73000000, on), floatArrayOf(0f, 0.55f, 1f),
                Shader.TileMode.CLAMP).apply {
                setLocalMatrix(Matrix().apply {
                    setScale(w / 2f, h / 2f)
                    postTranslate(w / 2f, h / 2f)
                })
            }
            // and brighter at its middle
            hotPaint.shader = RadialGradient(
                w / 2f, h / 2f, glass.width() / 2, 0x59FFFFFF, 0x00FFFFFF, Shader.TileMode.CLAMP)
            shinePaint.shader = LinearGradient(
                0f, glass.top, 0f, glass.centerY(), 0x66FFFFFF, 0x00FFFFFF, Shader.TileMode.CLAMP)
        }

        override fun onDraw(canvas: Canvas) {
            if (look == Look.ON) {
                canvas.drawRect(0f, 0f, width.toFloat(), height.toFloat(), glowPaint)
            }
            canvas.drawRoundRect(window, window.height() / 2, window.height() / 2, bezelPaint)
            canvas.save()
            canvas.clipPath(clip)
            when (look) {
                Look.OFF -> {
                    paint.color = context.getColor(R.color.led_off)
                    canvas.drawRect(glass, paint)
                }
                Look.ON -> {
                    paint.color = context.getColor(R.color.led_on)
                    canvas.drawRect(glass, paint)
                    canvas.drawRect(glass, hotPaint)
                }
                Look.BUSY -> {
                    paint.color = context.getColor(R.color.led_off)
                    canvas.drawRect(glass, paint)
                    paint.color = context.getColor(R.color.led_wait)
                    val h = glass.height()
                    // each stripe leans right, 45 degrees; shift moves them left
                    var x = glass.left - h - period - shift
                    while (x < glass.right + period) {
                        stripe.reset()
                        stripe.moveTo(x, glass.bottom)
                        stripe.lineTo(x + h, glass.top)
                        stripe.lineTo(x + h + period / 2, glass.top)
                        stripe.lineTo(x + period / 2, glass.bottom)
                        stripe.close()
                        canvas.drawPath(stripe, paint)
                        x += period
                    }
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

    private fun mix(color: Int, with: Int, amount: Float): Int {
        val keep = 1 - amount
        return Color.rgb(
            (Color.red(color) * keep + Color.red(with) * amount).toInt(),
            (Color.green(color) * keep + Color.green(with) * amount).toInt(),
            (Color.blue(color) * keep + Color.blue(with) * amount).toInt(),
        )
    }
}
