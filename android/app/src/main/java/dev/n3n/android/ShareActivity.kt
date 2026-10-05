// Copyright (C) Honey Bunny QT
// SPDX-License-Identifier: GPL-3.0-only

package dev.n3n.android

import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.view.WindowManager
import android.view.inputmethod.InputMethodManager
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import com.google.zxing.WriterException

/**
 * The configuration as a QR code on the screen, for another phone to join
 * with: as it is, or sealed with a PIN (the same as tools/n3n-qr -P), with
 * this phone's address or without it.
 */
class ShareActivity : Activity() {

    private lateinit var code: ImageView
    private lateinit var busy: ProgressBar
    private lateinit var what: TextView
    private lateinit var leaveOut: CheckBox
    private lateinit var addressNote: TextView
    private lateinit var usePin: Switch
    private lateinit var changePin: Button
    private var text = ""
    private var address: String? = null
    // the PIN the code is sealed with, while "Protect with a PIN" is on
    private var pin: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_share)
        setupBar(R.string.share)
        // the code stays as long as it is shown, and out of screenshots of others
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON or WindowManager.LayoutParams.FLAG_SECURE)

        code = findViewById(R.id.code)
        busy = findViewById(R.id.busy)
        what = findViewById(R.id.what)
        leaveOut = findViewById(R.id.leave_out_address)
        addressNote = findViewById(R.id.address_note)
        usePin = findViewById(R.id.use_pin)
        changePin = findViewById(R.id.change_pin)

        text = Store.load(this)
        address = Config(text).address?.let { "${it.first}/${it.second}" }

        // a hint, no rule: who scans it may as well change the address after
        leaveOut.isEnabled = address != null
        leaveOut.setOnCheckedChangeListener { _, _ -> render() }
        usePin.setOnCheckedChangeListener { _, on ->
            changePin.visibility = if (on) View.VISIBLE else View.GONE
            findViewById<View>(R.id.pin_note).visibility = if (on) View.VISIBLE else View.GONE
            if (on) {
                // nothing shown until there is a PIN
                code.setImageDrawable(null)
                what.text = ""
                askPin()
            } else {
                pin = null
                render()
            }
        }
        changePin.setOnClickListener { askPin() }

        render()
    }

    private fun askPin() {
        val field = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
            hint = getString(R.string.pin)
        }
        val frame = FrameLayout(this).apply {
            val pad = (20 * resources.displayMetrics.density).toInt()
            setPadding(pad, 0, pad, 0)
            addView(field)
        }
        var made = false
        val dialog = AlertDialog.Builder(this)
            .setTitle(R.string.pin_title)
            .setView(frame)
            .setPositiveButton(R.string.seal) { _, _ ->
                val p = field.text.toString()
                if (p.isEmpty()) {
                    Toast.makeText(this, R.string.pin_empty, Toast.LENGTH_SHORT).show()
                } else {
                    made = true
                    pin = p
                    render()
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .create()
        // no PIN, no protection: back to the code as it was, if none yet
        dialog.setOnDismissListener {
            if (!made && pin == null) {
                usePin.isChecked = false
            }
        }
        dialog.window?.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_VISIBLE)
        dialog.show()
        field.requestFocus()
    }

    private fun render() {
        val addr = address
        addressNote.text = if (addr == null || leaveOut.isChecked) {
            getString(R.string.address_note_without)
        } else {
            getString(R.string.address_note_with, addr)
        }

        val payload = Config.compact(text, leaveOut.isChecked)
        if (!usePin.isChecked) {
            draw(payload, false)
            return
        }
        val p = pin ?: return
        busy.visibility = View.VISIBLE
        Thread {
            val sealed = Seal.seal(payload, p)
            runOnUiThread {
                busy.visibility = View.GONE
                // still wanted as it was asked for
                if (!isFinishing && sealed != null && usePin.isChecked && pin == p) {
                    draw(sealed, true)
                }
            }
        }.start()
    }

    // the PIN dialog's keyboard can linger, and with adjustResize it leaves
    // the window - and the scroll view in it - shrunk, so the code ends up
    // out of reach above the fold
    private fun hideKeyboard() {
        val imm = getSystemService(Context.INPUT_METHOD_SERVICE) as? InputMethodManager
        val token = currentFocus?.windowToken ?: window.decorView.windowToken
        imm?.hideSoftInputFromWindow(token, 0)
        currentFocus?.clearFocus()
    }

    private fun draw(content: String, sealed: Boolean) {
        val scroll = findViewById<ScrollView>(R.id.share_scroll)
        hideKeyboard()
        // after the keyboard is gone and the window is its full height again,
        // bring the code into view at the top
        scroll.post { scroll.smoothScrollTo(0, 0) }
        try {
            code.setImageBitmap(QrEncode.bitmap(content))
            what.setText(if (sealed) R.string.code_sealed else R.string.code_plain)
        } catch (e: WriterException) {
            code.setImageDrawable(null)
            what.setText(R.string.code_too_big)
        } catch (e: IllegalArgumentException) {
            code.setImageDrawable(null)
            what.setText(R.string.code_too_big)
        }
    }
}
