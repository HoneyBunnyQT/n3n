// Copyright (C) Honey Bunny QT
// SPDX-License-Identifier: GPL-3.0-only

package dev.n3n.android

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast

/**
 * The network at a glance: connect and disconnect, the state of the
 * connection as N3nVpnService has it from the edge, and the way to the
 * other screens.
 */
class MainActivity : Activity() {

    private companion object {
        const val REQUEST_VPN = 1
    }

    private lateinit var connect: ConnectButton
    private lateinit var network: TextView
    private lateinit var address: TextView
    private lateinit var supernode: TextView
    private lateinit var peers: TextView
    private lateinit var hint: TextView
    private lateinit var routeAll: Switch
    private lateinit var gateway: EditText
    private lateinit var dns: EditText

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        connect = findViewById(R.id.connect)
        network = findViewById(R.id.network)
        address = findViewById(R.id.address)
        supernode = findViewById(R.id.supernode)
        peers = findViewById(R.id.peers)
        hint = findViewById(R.id.hint)
        routeAll = findViewById(R.id.route_all)
        gateway = findViewById(R.id.gateway)
        dns = findViewById(R.id.dns)
        setupRoute()

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
        N3nVpnService.watch { show(it) }
    }

    override fun onPause() {
        N3nVpnService.watch(null)
        super.onPause()
    }

    /** The routing card: kept in the preferences as it is changed */
    private fun setupRoute() {
        val route = Store.route(this)
        routeAll.isChecked = route.all
        gateway.setText(route.gateway.ifEmpty { Config(Store.load(this)).gateway ?: "" })
        dns.setText(route.dns)
        findViewById<View>(R.id.route_row).visibility = if (route.all) View.VISIBLE else View.GONE

        val save = {
            Store.saveRoute(this, Store.Route(routeAll.isChecked, gateway.text.toString().trim(), dns.text.toString().trim()))
        }
        routeAll.setOnCheckedChangeListener { _, on ->
            findViewById<View>(R.id.route_row).visibility = if (on) View.VISIBLE else View.GONE
            save()
            if (N3nVpnService.running) {
                Toast.makeText(this, R.string.route_reconnect, Toast.LENGTH_SHORT).show()
            }
        }
        val watcher = object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) = save()
        }
        gateway.addTextChangedListener(watcher)
        dns.addTextChangedListener(watcher)
    }

    private fun showConfig() {
        val text = Store.load(this)
        val config = Config(text)
        val addr = config.address
        // the peer's own name; never the community's, which may be the key
        // of the headers
        network.text = when {
            text.isBlank() -> getString(R.string.no_network)
            else -> config.description ?: getString(R.string.unnamed)
        }
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
        val route = Store.route(this)
        if (route.all && !Store.isIpv4(route.gateway)) {
            Toast.makeText(this, R.string.route_need_gateway, Toast.LENGTH_LONG).show()
            gateway.requestFocus()
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
        val route = Store.route(this)
        if (route.all) {
            intent.putExtra(N3nVpnService.EXTRA_GATEWAY, route.gateway)
            intent.putExtra(N3nVpnService.EXTRA_DNS, if (Store.isIpv4(route.dns)) route.dns else "1.1.1.1")
        }
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent) else startService(intent)
    }

    @Deprecated("the platform's own Activity, no AndroidX")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN && resultCode == RESULT_OK) {
            start()
        }
    }

    /** What the connection is doing, see Connection.kt */
    private fun show(s: Snapshot) {
        val look = when {
            s.phase == Phase.CONNECTED -> ConnectButton.Look.ON
            s.phase.busy -> ConnectButton.Look.BUSY
            else -> ConnectButton.Look.OFF
        }
        // what it is doing, or else what a tap does
        val detail = s.doing(this) ?: getString(
            when {
                s.failed -> R.string.stopped_see_log
                s.phase == Phase.CONNECTED -> R.string.tap_disconnect
                else -> R.string.tap_connect
            }
        )
        // a tap while stopping connects again, once the edge is down
        val starts = s.phase == Phase.OFF || s.phase == Phase.STOPPING
        connect.show(look, s.title(this), detail, getString(if (starts) R.string.connect else R.string.disconnect))

        val info = if (s.phase == Phase.OFF) null else s.info
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
