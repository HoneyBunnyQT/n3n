// Copyright (C) Honey Bunny QT
// SPDX-License-Identifier: GPL-3.0-only

package dev.n3n.android

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

/**
 * The tile in the quick settings: connect and disconnect without the app,
 * on while an edge runs (or is on its way), and the state below the name
 * of the network (Android 10 and later).
 *
 * What only the app can do - the first time, Android asks whether the app
 * may be a VPN; a configuration that cannot be started as it is - opens
 * the main screen instead, which connects as Connect does there: asks, or
 * says what is missing.  On a locked phone it asks for the unlock first.
 */
class ConnectTile : TileService() {

    companion object {
        // the tile while the quick settings show it; main thread
        private var listening: ConnectTile? = null

        /** The state changed, see N3nVpnService.setState() */
        fun update(context: Context) {
            listening?.render()
        }
    }

    override fun onStartListening() {
        super.onStartListening()
        listening = this
        render()
    }

    override fun onStopListening() {
        if (listening === this) {
            listening = null
        }
        super.onStopListening()
    }

    override fun onClick() {
        super.onClick()
        if (isLocked) unlockAndRun { toggle() } else toggle()
    }

    private fun toggle() {
        if (N3nVpnService.running) {
            N3nVpnService.stop(this)
            return
        }
        if (N3nVpnService.notReady(this) != null || VpnService.prepare(this) != null) {
            openApp()
            return
        }
        try {
            N3nVpnService.start(this)
        } catch (e: Exception) {
            // Android did not let the service start from here: the app does
            openApp()
        }
    }

    /** The main screen, which connects at once (see MainActivity.EXTRA_CONNECT) */
    private fun openApp() {
        val intent = Intent(this, MainActivity::class.java)
            .putExtra(MainActivity.EXTRA_CONNECT, true)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        if (Build.VERSION.SDK_INT >= 34) {
            startActivityAndCollapse(
                PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT))
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }

    private fun render() {
        val tile = qsTile ?: return
        val s = N3nVpnService.state
        tile.state = if (s.phase == Phase.OFF) Tile.STATE_INACTIVE else Tile.STATE_ACTIVE
        // the peer's own name, never the community's, which may be the key
        // of the headers
        tile.label = Config(Store.load(this)).description ?: getString(R.string.app_name)
        if (Build.VERSION.SDK_INT >= 29) {
            tile.subtitle = s.title(this)
        }
        tile.updateTile()
    }
}
