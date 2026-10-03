// Copyright (C) Honey Bunny QT
// SPDX-License-Identifier: GPL-3.0-only

package dev.n3n.android

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import android.text.InputType
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.Toast

/**
 * The configuration: written here, imported from a .conf file, or taken
 * from a QR code (camera or image), sealed with a PIN or not.  Saved when
 * the screen is left.
 */
class EditActivity : Activity() {

    companion object {
        const val EXTRA_SCAN = "scan"
        private const val REQUEST_SCAN = 1
        private const val REQUEST_FILE = 2
    }

    private lateinit var config: EditText

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_edit)
        setupBar(R.string.edit)

        config = findViewById(R.id.config)
        if (savedInstanceState == null) {
            config.setText(Store.load(this))
        }

        findViewById<Button>(R.id.scan).setOnClickListener { scan() }
        findViewById<Button>(R.id.import_file).setOnClickListener {
            val pick = Intent(Intent.ACTION_OPEN_DOCUMENT)
                .addCategory(Intent.CATEGORY_OPENABLE)
                .setType("*/*")
            startActivityForResult(pick, REQUEST_FILE)
        }

        if (savedInstanceState == null && intent.getBooleanExtra(EXTRA_SCAN, false)) {
            scan()
        }
    }

    override fun onPause() {
        save()
        super.onPause()
    }

    private fun save() {
        val text = config.text.toString()
        if (text != Store.load(this)) {
            Store.save(this, text)
            if (N3nVpnService.running) {
                Toast.makeText(this, R.string.saved_reconnect, Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun scan() {
        startActivityForResult(Intent(this, ScanActivity::class.java), REQUEST_SCAN)
    }

    @Deprecated("the platform's own Activity, no AndroidX")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode != RESULT_OK) {
            return
        }
        when (requestCode) {
            REQUEST_SCAN -> fromQr(data?.getStringExtra(ScanActivity.EXTRA_TEXT) ?: return)
            REQUEST_FILE -> {
                val uri = data?.data ?: return
                if (contentResolver.getType(uri)?.startsWith("image/") == true) {
                    // a QR code sent to the phone, or a screenshot of one
                    val text = QrDecode.fromImage(this, uri)
                    if (text == null) {
                        Toast.makeText(this, R.string.qr_none, Toast.LENGTH_LONG).show()
                    } else {
                        fromQr(text)
                    }
                    return
                }
                contentResolver.openInputStream(uri)?.use {
                    take(it.bufferedReader().readText(), R.string.qr_replace)
                }
            }
        }
    }

    /** The text of a QR code: a configuration, a sealed one, or something else */
    private fun fromQr(text: String) {
        val code = text.trim()
        when {
            Config(text).community != null -> take(text, R.string.qr_replace)
            Seal.looksSealed(code) -> askPin(code)
            else -> Toast.makeText(this, R.string.qr_not_n3n, Toast.LENGTH_LONG).show()
        }
    }

    /** Nothing in the code says that it is n3n's: it may be, with the PIN */
    private fun askPin(code: String) {
        val pin = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            hint = getString(R.string.pin)
        }
        val frame = FrameLayout(this).apply {
            val pad = (20 * resources.displayMetrics.density).toInt()
            setPadding(pad, 0, pad, 0)
            addView(pin)
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.qr_pin_title)
            .setMessage(R.string.qr_pin_message)
            .setView(frame)
            .setPositiveButton(R.string.open) { _, _ -> open(code, pin.text.toString()) }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun open(code: String, pin: String) {
        Thread {
            val bytes = Seal.open(code, pin)
            runOnUiThread {
                if (isFinishing) {
                    return@runOnUiThread
                }
                val text = bytes?.toString(Charsets.UTF_8)
                if (text == null || Config(text).community == null) {
                    Toast.makeText(this, R.string.qr_pin_wrong, Toast.LENGTH_LONG).show()
                } else {
                    take(text, R.string.qr_replace)
                }
            }
        }.start()
    }

    /** A configuration from outside; asks before it replaces another */
    private fun take(text: String, question: Int) {
        val replace = {
            config.setText(text)
            save()
            Toast.makeText(this, R.string.qr_taken, Toast.LENGTH_SHORT).show()
        }
        val current = config.text.toString().trim()
        if (current.isEmpty() || current == text.trim()) {
            replace()
        } else {
            AlertDialog.Builder(this)
                .setMessage(question)
                .setPositiveButton(android.R.string.ok) { _, _ -> replace() }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
        }
    }
}
