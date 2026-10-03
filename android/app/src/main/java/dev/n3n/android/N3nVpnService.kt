// Copyright (C) Honey Bunny QT
// SPDX-License-Identifier: GPL-3.0-only

package dev.n3n.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper

/**
 * The VPN: Android gives the device, set up with the address and route of
 * the configuration, and the edge of the core (libn3n, see
 * src/main/cpp/n3n_jni.c) runs on it in a thread of its own.  Every socket
 * the edge opens comes back here to protect(), so that it does not go into
 * the VPN itself.
 */
class N3nVpnService : VpnService() {

    companion object {
        const val ACTION_START = "dev.n3n.android.START"
        const val ACTION_STOP = "dev.n3n.android.STOP"
        const val EXTRA_CONFIG = "config"
        // routing all traffic through an exit peer, when given
        const val EXTRA_GATEWAY = "gateway"
        const val EXTRA_DNS = "dns"
        private const val CHANNEL = "vpn"
        private const val NOTIFICATION = 1

        init {
            System.loadLibrary("n3n")
        }

        /** The last lines of the log, and who wants the new ones (the UI) */
        val log = ArrayDeque<String>()
        var logListener: ((String) -> Unit)? = null
        @Volatile var running = false

        private val main = Handler(Looper.getMainLooper())

        fun addLog(line: String) {
            main.post {
                log.addLast(line)
                while (log.size > 300) {
                    log.removeFirst()
                }
                logListener?.invoke(line)
            }
        }
    }

    private var edge: Thread? = null

    private external fun nativeRun(config: String, tunFd: Int, rundir: String): Int
    private external fun nativeStop()

    /** From the native code, for every line of the edge's log */
    @Suppress("unused")
    fun onLog(level: Int, line: String) {
        addLog(line)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopEdge()
            return START_NOT_STICKY
        }
        val configText = intent?.getStringExtra(EXTRA_CONFIG) ?: return START_NOT_STICKY
        val gateway = intent.getStringExtra(EXTRA_GATEWAY)
        val dns = intent.getStringExtra(EXTRA_DNS)
        // the edge sends what is not for the network to the exit peer
        // (tuntap.gateway); a later value overrides one in the configuration
        val text = if (gateway != null) "$configText\n\n[tuntap]\ngateway = $gateway\n" else configText
        if (edge != null) {
            return START_NOT_STICKY
        }
        val config = Config(text)
        val address = config.address
        val network = config.network
        if (address == null || network == null) {
            addLog(getString(R.string.no_address))
            stopSelf()
            return START_NOT_STICKY
        }

        startForeground(gateway)

        // the name Android shows for the VPN: never the community's, which
        // may be the key of the headers
        val builder = Builder()
            .setSession(config.description ?: "n3n")
            .addAddress(address.first, address.second)
            .addRoute(network.first, network.second)
            .setMtu(config.mtu)
        if (gateway != null) {
            // everything into the device; the edge's own sockets stay out
            // of it through protect().  IPv6 too, where it is dropped: the
            // exit peer takes IPv4 only, and nothing should go around it.
            builder.addRoute("0.0.0.0", 0)
            try {
                builder.addRoute("::", 0)
            } catch (e: IllegalArgumentException) {
            }
            if (dns != null) {
                builder.addDnsServer(dns)
            }
        }
        val tun = try {
            builder.establish()
        } catch (e: Exception) {
            addLog("the VPN cannot be set up: ${e.message}")
            null
        }
        if (tun == null) {
            addLog("the VPN is not allowed (anymore)")
            stopSelf()
            return START_NOT_STICKY
        }

        // the edge takes the device over, and closes it
        val fd = tun.detachFd()
        running = true
        edge = Thread({
            val rc = nativeRun(text, fd, filesDir.absolutePath)
            addLog("edge stopped ($rc)")
            running = false
            edge = null
            main.post {
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }, "n3n-edge").also { it.start() }
        return START_STICKY
    }

    private fun stopEdge() {
        if (edge != null) {
            nativeStop()
        } else {
            stopSelf()
        }
    }

    override fun onRevoke() {
        // another VPN took over, or the user withdrew the permission
        stopEdge()
    }

    override fun onDestroy() {
        stopEdge()
        super.onDestroy()
    }

    private fun startForeground(gateway: String?) {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= 26) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL, getString(R.string.channel), NotificationManager.IMPORTANCE_LOW))
        }
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val builder = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, CHANNEL) else Notification.Builder(this)
        val notification = builder
            .setSmallIcon(R.drawable.ic_n3n)
            .setContentTitle(if (gateway != null) getString(R.string.running_route, gateway) else getString(R.string.running))
            .setContentIntent(open)
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION, notification)
        }
    }
}
