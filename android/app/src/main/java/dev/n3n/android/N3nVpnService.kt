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
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
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

        // The edge's thread, and whether it was asked to stop: here, not in
        // the service object, as Android may make a new one for the next
        // intent while the edge of the last one still runs.  Main thread.
        private var edge: Thread? = null
        private var stopping = false
        // a start that came while the last edge was stopping: it follows
        private var next: Intent? = null

        /** For the UI: an edge runs, or is about to, and not on its way out */
        @Volatile var running = false
            private set

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

    private external fun nativeRun(config: String, tunFd: Int, rundir: String): Int
    private external fun nativeStop()
    private external fun nativeNetworkChanged()

    /* The networks the phone has (WiFi, mobile data) changed: the edge
     * registers again at once, rather than with its next round - an app may
     * not watch netlink, as the edge does on Linux by itself.  Any change
     * counts - a network comes or goes, its addresses change - as the
     * phone may move its traffic to another one while the first stays (back
     * to WiFi, mobile data kept as a backup); a few too many cost one
     * registration each, and the core takes a burst of them as one. */
    private var watching: ConnectivityManager.NetworkCallback? = null
    private val networks = HashMap<Network, List<String>>()
    private var watchingSince = 0L

    private fun watchNetwork() {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                main.post { networkIs(network, cm.getLinkProperties(network), "network") }
            }

            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) {
                main.post { networkIs(network, lp, "addresses") }
            }

            override fun onLost(network: Network) {
                main.post {
                    if (networks.remove(network) != null) {
                        changed("network lost")
                    }
                }
            }
        }
        // the networks the phone could use, not this VPN itself
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        try {
            watchingSince = System.currentTimeMillis()
            cm.registerNetworkCallback(request, callback)
            watching = callback
        } catch (e: RuntimeException) {
            addLog("cannot watch the network: ${e.message}")
        }
    }

    // main thread
    private fun networkIs(network: Network, lp: LinkProperties?, why: String) {
        val addresses = lp?.linkAddresses?.map { it.toString() }?.sorted() ?: emptyList()
        if (networks[network] == addresses) {
            return
        }
        networks[network] = addresses
        changed(why)
    }

    private fun changed(why: String) {
        // what the registration itself tells about the networks there are
        if (System.currentTimeMillis() - watchingSince < 2000) {
            return
        }
        if (edge != null && !stopping) {
            addLog("the phone's network changed ($why)")
            nativeNetworkChanged()
        }
    }

    private fun unwatchNetwork() {
        val callback = watching ?: return
        watching = null
        networks.clear()
        try {
            getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(callback)
        } catch (e: RuntimeException) {
        }
    }

    /** From the native code, for every line of the edge's log */
    @Suppress("unused")
    fun onLog(level: Int, line: String) {
        addLog(line)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            next = null
            stopEdge()
            return START_NOT_STICKY
        }
        if (intent?.getStringExtra(EXTRA_CONFIG) == null) {
            // a restart by the system, without the configuration
            if (edge == null) {
                stopSelf()
            }
            return START_NOT_STICKY
        }
        if (edge != null) {
            if (stopping) {
                // once the last edge has stopped, see the end of its thread
                next = intent
                running = true
                // Android wants it in the foreground soon after
                // startForegroundService(), whenever the edge gets going
                startForeground(intent.getStringExtra(EXTRA_GATEWAY))
            }
            return START_NOT_STICKY
        }
        return if (startEdge(intent)) START_STICKY else START_NOT_STICKY
    }

    private fun startEdge(intent: Intent): Boolean {
        val configText = intent.getStringExtra(EXTRA_CONFIG) ?: return false
        val gateway = intent.getStringExtra(EXTRA_GATEWAY)
        val dns = intent.getStringExtra(EXTRA_DNS)
        // the edge sends what is not for the network to the exit peer
        // (tuntap.gateway); a later value overrides one in the configuration
        val text = if (gateway != null) "$configText\n\n[tuntap]\ngateway = $gateway\n" else configText
        val config = Config(text)
        val address = config.address
        val network = config.network
        if (address == null || network == null) {
            addLog(getString(R.string.no_address))
            stopSelf()
            return false
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
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return false
        }

        // the edge takes the device over, and closes it
        val fd = tun.detachFd()
        running = true
        stopping = false
        val thread = Thread({
            val rc = nativeRun(text, fd, filesDir.absolutePath)
            addLog("edge stopped ($rc)")
            main.post { edgeEnded() }
        }, "n3n-edge")
        edge = thread
        thread.start()
        if (watching == null) {
            watchNetwork()
        }
        return true
    }

    /** Main thread, once the edge's thread is through */
    private fun edgeEnded() {
        edge = null
        stopping = false
        val start = next
        next = null
        if (start != null && startEdge(start)) {
            return
        }
        running = false
        unwatchNetwork()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun stopEdge() {
        if (edge != null) {
            // the edge ends, and then its thread the service
            stopping = true
            running = false
            nativeStop()
        } else {
            running = false
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    override fun onRevoke() {
        // another VPN took over, or the user withdrew the permission
        stopEdge()
    }

    override fun onDestroy() {
        unwatchNetwork()
        // the edge's thread outlives this object; it is told to stop, if
        // nothing waits to follow it
        if (edge != null && next == null) {
            stopping = true
            running = false
            nativeStop()
        }
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
