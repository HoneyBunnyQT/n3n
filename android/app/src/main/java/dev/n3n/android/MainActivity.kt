// Copyright (C) Honey Bunny QT
// SPDX-License-Identifier: GPL-3.0-only

package dev.n3n.android

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.Button
import android.widget.TextView

/**
 * The network at a glance: connect and disconnect, the state of the
 * connection as the edge reports it, and the way to the other screens.
 */
class MainActivity : Activity() {

    private companion object {
        const val REQUEST_VPN = 1
        const val POLL_MS = 2000L
    }

    private enum class State { OFF, WAIT, ON }

    private lateinit var connect: Button
    private lateinit var dot: View
    private lateinit var state: TextView
    private lateinit var network: TextView
    private lateinit var address: TextView
    private lateinit var supernode: TextView
    private lateinit var peers: TextView
    private lateinit var hint: TextView

    private val main = Handler(Looper.getMainLooper())
    private var asking = false
    private val poll = object : Runnable {
        override fun run() {
            refresh()
            main.postDelayed(this, POLL_MS)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        connect = findViewById(R.id.connect)
        dot = findViewById(R.id.dot)
        state = findViewById(R.id.state)
        network = findViewById(R.id.network)
        address = findViewById(R.id.address)
        supernode = findViewById(R.id.supernode)
        peers = findViewById(R.id.peers)
        hint = findViewById(R.id.hint)

        connect.setOnClickListener { toggle() }
        findViewById<Button>(R.id.scan).setOnClickListener {
            startActivity(Intent(this, EditActivity::class.java).putExtra(EditActivity.EXTRA_SCAN, true))
        }
        findViewById<Button>(R.id.edit).setOnClickListener {
            startActivity(Intent(this, EditActivity::class.java))
        }
        findViewById<Button>(R.id.share).setOnClickListener {
            startActivity(Intent(this, ShareActivity::class.java))
        }
        findViewById<Button>(R.id.log).setOnClickListener {
            startActivity(Intent(this, LogActivity::class.java))
        }

        if (Build.VERSION.SDK_INT >= 33) {
            requestPermissions(arrayOf("android.permission.POST_NOTIFICATIONS"), 0)
        }
    }

    override fun onResume() {
        super.onResume()
        showConfig()
        main.post(poll)
    }

    override fun onPause() {
        main.removeCallbacks(poll)
        super.onPause()
    }

    private fun showConfig() {
        val text = Store.load(this)
        val config = Config(text)
        val addr = config.address
        network.text = config.community ?: getString(R.string.no_network)
        address.text = if (addr != null) "${addr.first}/${addr.second}" else getString(R.string.none)
        findViewById<Button>(R.id.share).isEnabled = text.isNotBlank()
        when {
            text.isBlank() -> showHint(R.string.no_config_hint)
            addr == null -> showHint(R.string.no_address)
            else -> hint.visibility = View.GONE
        }
    }

    private fun showHint(text: Int) {
        hint.setText(text)
        hint.visibility = View.VISIBLE
    }

    private fun toggle() {
        if (N3nVpnService.running) {
            startService(Intent(this, N3nVpnService::class.java).setAction(N3nVpnService.ACTION_STOP))
            main.postDelayed({ refresh() }, 300)
            return
        }
        val config = Config(Store.load(this))
        if (config.community == null || config.address == null) {
            AlertDialog.Builder(this)
                .setMessage(if (config.community == null) R.string.no_config_hint else R.string.no_address)
                .setPositiveButton(R.string.edit) { _, _ ->
                    startActivity(Intent(this, EditActivity::class.java))
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
            return
        }
        // asks the user the first time; null when allowed already
        val ask = VpnService.prepare(this)
        if (ask != null) {
            startActivityForResult(ask, REQUEST_VPN)
        } else {
            start()
        }
    }

    private fun start() {
        val intent = Intent(this, N3nVpnService::class.java)
            .setAction(N3nVpnService.ACTION_START)
            .putExtra(N3nVpnService.EXTRA_CONFIG, Store.load(this))
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent) else startService(intent)
        main.postDelayed({ refresh() }, 300)
    }

    @Deprecated("the platform's own Activity, no AndroidX")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN && resultCode == RESULT_OK) {
            start()
        }
    }

    /** The state, from the service and what the edge reports */
    private fun refresh() {
        if (!N3nVpnService.running) {
            show(State.OFF, null)
            return
        }
        if (asking) {
            return
        }
        asking = true
        Thread {
            val info = Status.query(this)
            main.post {
                asking = false
                if (N3nVpnService.running) {
                    show(if (info?.registered == true) State.ON else State.WAIT, info)
                } else {
                    show(State.OFF, null)
                }
            }
        }.start()
    }

    private fun show(s: State, info: Status.Info?) {
        val color = getColor(
            when (s) {
                State.ON -> R.color.state_on
                State.WAIT -> R.color.state_wait
                State.OFF -> R.color.state_off
            }
        )
        val ring = (connect.background.mutate() as RippleDrawable).getDrawable(0) as GradientDrawable
        ring.setStroke((6 * resources.displayMetrics.density).toInt(), color)
        (dot.background.mutate() as GradientDrawable).setColor(color)

        connect.setText(if (s == State.OFF) R.string.connect else R.string.disconnect)
        state.setText(
            when (s) {
                State.ON -> R.string.state_on
                State.WAIT -> R.string.state_wait
                State.OFF -> R.string.state_off
            }
        )

        val sn = info?.supernode
        val rtt = info?.rttMs
        supernode.text = when {
            sn.isNullOrEmpty() -> getString(R.string.none)
            rtt != null -> getString(R.string.rtt, sn, rtt)
            else -> sn
        }
        peers.text = if (info != null) getString(R.string.peers_count, info.peers, info.direct) else getString(R.string.none)
    }
}
