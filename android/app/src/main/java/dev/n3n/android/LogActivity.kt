// Copyright (C) Honey Bunny QT
// SPDX-License-Identifier: GPL-3.0-only

package dev.n3n.android

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.os.Bundle
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast

/** The edge's log, the last lines of it, as they come */
class LogActivity : Activity() {

    private lateinit var log: TextView
    private lateinit var scroll: ScrollView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_log)
        setupBar(R.string.log, R.string.copy) {
            val clipboard = getSystemService(ClipboardManager::class.java)
            clipboard.setPrimaryClip(ClipData.newPlainText("n3n log", log.text))
            Toast.makeText(this, R.string.copied, Toast.LENGTH_SHORT).show()
        }
        log = findViewById(R.id.log)
        scroll = findViewById(R.id.log_scroll)
    }

    override fun onResume() {
        super.onResume()
        log.text = N3nVpnService.log.joinToString("\n")
        scroll.post { scroll.fullScroll(ScrollView.FOCUS_DOWN) }
        N3nVpnService.logListener = { line ->
            log.append(if (log.text.isEmpty()) line else "\n" + line)
            scroll.post { scroll.fullScroll(ScrollView.FOCUS_DOWN) }
        }
    }

    override fun onPause() {
        N3nVpnService.logListener = null
        super.onPause()
    }
}
