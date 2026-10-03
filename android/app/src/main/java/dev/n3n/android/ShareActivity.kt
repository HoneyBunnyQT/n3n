// Copyright (C) Honey Bunny QT
// SPDX-License-Identifier: GPL-3.0-only

package dev.n3n.android

import android.app.Activity
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.view.inputmethod.InputMethodManager
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
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
    private lateinit var pin: EditText
    private var text = ""
    private var address: String? = null

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
        pin = findViewById(R.id.pin)

        text = Store.load(this)
        address = Config(text).address?.let { "${it.first}/${it.second}" }

        // a hint, no rule: who scans it may as well change the address after
        leaveOut.isEnabled = address != null
        leaveOut.setOnCheckedChangeListener { _, _ -> render() }
        usePin.setOnCheckedChangeListener { _, on ->
            findViewById<View>(R.id.pin_row).visibility = if (on) View.VISIBLE else View.GONE
            findViewById<View>(R.id.pin_note).visibility = if (on) View.VISIBLE else View.GONE
            if (!on) {
                render()
            } else {
                // nothing shown until there is a PIN
                code.setImageDrawable(null)
                what.text = ""
                pin.requestFocus()
            }
        }
        findViewById<Button>(R.id.seal).setOnClickListener {
            // the keyboard away, and back up to where the code appears
            getSystemService(InputMethodManager::class.java)?.hideSoftInputFromWindow(pin.windowToken, 0)
            pin.clearFocus()
            render()
        }

        render()
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
        val p = pin.text.toString()
        if (p.isEmpty()) {
            Toast.makeText(this, R.string.pin_empty, Toast.LENGTH_SHORT).show()
            return
        }
        busy.visibility = View.VISIBLE
        Thread {
            val sealed = Seal.seal(payload, p)
            runOnUiThread {
                busy.visibility = View.GONE
                if (!isFinishing && sealed != null) {
                    draw(sealed, true)
                }
            }
        }.start()
    }

    private fun draw(content: String, sealed: Boolean) {
        val scroll = findViewById<ScrollView>(R.id.share_scroll)
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
