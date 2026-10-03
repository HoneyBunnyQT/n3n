// Copyright (C) Honey Bunny QT
// SPDX-License-Identifier: GPL-3.0-only

package dev.n3n.android

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast

/**
 * One screen: the configuration (typed, pasted, imported from a .conf file
 * or read from a QR code of tools/n3n-qr), connect and disconnect, and the
 * edge's log.
 */
class MainActivity : Activity() {

    private companion object {
        const val PREFS = "n3n"
        const val KEY_CONFIG = "config"
        const val REQUEST_VPN = 1
        const val REQUEST_FILE = 2
        const val REQUEST_SCAN = 3
    }

    private lateinit var config: EditText
    private lateinit var connect: Button
    private lateinit var log: TextView
    private lateinit var logScroll: ScrollView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        config = findViewById(R.id.config)
        connect = findViewById(R.id.connect)
        log = findViewById(R.id.log)
        logScroll = findViewById(R.id.log_scroll)

        config.setText(getSharedPreferences(PREFS, MODE_PRIVATE).getString(KEY_CONFIG, ""))

        findViewById<Button>(R.id.import_file).setOnClickListener {
            val pick = Intent(Intent.ACTION_OPEN_DOCUMENT)
                .addCategory(Intent.CATEGORY_OPENABLE)
                .setType("*/*")
            startActivityForResult(pick, REQUEST_FILE)
        }
        findViewById<Button>(R.id.scan).setOnClickListener {
            startActivityForResult(Intent(this, ScanActivity::class.java), REQUEST_SCAN)
        }
        connect.setOnClickListener {
            if (N3nVpnService.running) {
                startService(Intent(this, N3nVpnService::class.java).setAction(N3nVpnService.ACTION_STOP))
            } else {
                save()
                // asks the user the first time; null when allowed already
                val ask = VpnService.prepare(this)
                if (ask != null) {
                    startActivityForResult(ask, REQUEST_VPN)
                } else {
                    onActivityResult(REQUEST_VPN, RESULT_OK, null)
                }
            }
        }

        if (Build.VERSION.SDK_INT >= 33) {
            requestPermissions(arrayOf("android.permission.POST_NOTIFICATIONS"), 0)
        }
    }

    override fun onResume() {
        super.onResume()
        log.text = N3nVpnService.log.joinToString("\n")
        N3nVpnService.logListener = { line ->
            log.append(if (log.text.isEmpty()) line else "\n" + line)
            logScroll.post { logScroll.fullScroll(ScrollView.FOCUS_DOWN) }
            updateButton()
        }
        updateButton()
    }

    override fun onPause() {
        N3nVpnService.logListener = null
        save()
        super.onPause()
    }

    @Deprecated("the platform's own Activity, no AndroidX")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode != RESULT_OK) {
            return
        }
        when (requestCode) {
            REQUEST_VPN -> {
                val start = Intent(this, N3nVpnService::class.java)
                    .setAction(N3nVpnService.ACTION_START)
                    .putExtra(N3nVpnService.EXTRA_CONFIG, config.text.toString())
                if (Build.VERSION.SDK_INT >= 26) startForegroundService(start) else startService(start)
                connect.postDelayed({ updateButton() }, 500)
            }
            REQUEST_FILE -> {
                val uri = data?.data ?: return
                if (contentResolver.getType(uri)?.startsWith("image/") == true) {
                    // a QR code sent to the phone, or a screenshot of one
                    val text = QrDecode.fromImage(this, uri)
                    if (text == null) {
                        Toast.makeText(this, R.string.qr_none, Toast.LENGTH_LONG).show()
                    } else {
                        takeFromQr(text)
                    }
                    return
                }
                contentResolver.openInputStream(uri)?.use {
                    config.setText(it.bufferedReader().readText())
                    save()
                }
            }
            REQUEST_SCAN -> {
                takeFromQr(data?.getStringExtra(ScanActivity.EXTRA_TEXT) ?: return)
            }
        }
    }

    /** The text of a QR code, if it is a configuration; asks before replacing another */
    private fun takeFromQr(text: String) {
        if (Config(text).community == null) {
            Toast.makeText(this, R.string.qr_not_n3n, Toast.LENGTH_LONG).show()
            return
        }
        val take = {
            config.setText(text)
            save()
            Toast.makeText(this, R.string.qr_taken, Toast.LENGTH_SHORT).show()
        }
        val current = config.text.toString().trim()
        if (current.isEmpty() || current == text.trim()) {
            take()
        } else {
            AlertDialog.Builder(this)
                .setMessage(R.string.qr_replace)
                .setPositiveButton(android.R.string.ok) { _, _ -> take() }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
        }
    }

    private fun save() {
        getSharedPreferences(PREFS, MODE_PRIVATE).edit()
            .putString(KEY_CONFIG, config.text.toString())
            .apply()
    }

    private fun updateButton() {
        connect.setText(if (N3nVpnService.running) R.string.disconnect else R.string.connect)
    }
}
