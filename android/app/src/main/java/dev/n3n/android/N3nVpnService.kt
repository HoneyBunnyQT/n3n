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
import android.graphics.drawable.Icon
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.SystemClock

/**
 * The VPN: Android gives the device, set up with the address and route of
 * the configuration, and the edge of the core (libn3n, see
 * src/main/cpp/n3n_jni.c) runs on it in a thread of its own.  Every socket
 * the edge opens comes back here to protect(), so that it does not go into
 * the VPN itself.
 *
 * It also keeps what the connection is doing (state, see Connection.kt):
 * from its own steps, and from the edge's management API while the edge
 * runs.  The notification says that, and so does the main screen.
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
        // how often the edge is asked for its state: while on the way, while
        // the main screen shows it, and else
        private const val POLL_BUSY_MS = 1000L
        private const val POLL_SHOWN_MS = 2000L
        private const val POLL_IDLE_MS = 10000L
        // not registered for this long: no supernode answers
        private const val NO_ANSWER_MS = 15000L

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

        /** What the connection is doing; main thread */
        var state = Snapshot(Phase.OFF)
            private set
        private var stateListener: ((Snapshot) -> Unit)? = null
        // the service that asks the edge, while an edge runs
        private var poller: N3nVpnService? = null

        /**
         * The main screen, while it is shown: gets the state at once and
         * with every change, and the edge is asked more often meanwhile.
         * null: no longer.  Main thread.
         */
        fun watch(listener: ((Snapshot) -> Unit)?) {
            stateListener = listener
            if (listener != null) {
                listener(state)
                poller?.pollSoon()
            }
        }

        /**
         * Why the configuration and route kept (Store) cannot be started as
         * they are - a string for the user - or null: no configuration (or
         * no community in it), no IPv4 address, the exit peer without one
         */
        fun notReady(context: Context): Int? {
            val config = Config(Store.load(context))
            val route = Store.route(context)
            return when {
                config.community == null -> R.string.no_config_hint
                config.addressInvalid -> R.string.no_address
                route.all && !Store.isIpv4(route.gateway) -> R.string.route_need_gateway
                else -> null
            }
        }

        /**
         * Starts the edge with the configuration and route kept, once the
         * VPN is allowed (VpnService.prepare()) - from Connect, and from
         * the tile in the quick settings
         */
        fun start(context: Context) {
            val (config, gateway, dns) = startWith(context)
            val intent = Intent(context, N3nVpnService::class.java)
                .setAction(ACTION_START)
                .putExtra(EXTRA_CONFIG, config)
            if (gateway != null) {
                intent.putExtra(EXTRA_GATEWAY, gateway)
                intent.putExtra(EXTRA_DNS, dns)
            }
            if (Build.VERSION.SDK_INT >= 26) context.startForegroundService(intent) else context.startService(intent)
        }

        /** What a start now takes: the configuration, and the exit peer and DNS if routed through one */
        private fun startWith(context: Context): Triple<String, String?, String?> {
            val route = Store.route(context)
            if (!route.all) {
                return Triple(Store.load(context), null, null)
            }
            return Triple(Store.load(context), route.gateway, if (Store.isIpv4(route.dns)) route.dns else "1.1.1.1")
        }

        // what the edge that runs was started with; main thread
        private var startedWith: Triple<String, String?, String?>? = null

        /**
         * An edge runs, and the configuration or the route have changed
         * since it started: they apply once it connects again
         */
        fun changedSinceStart(context: Context): Boolean {
            val was = startedWith ?: return false
            return running && was != startWith(context)
        }

        fun stop(context: Context) {
            context.startService(Intent(context, N3nVpnService::class.java).setAction(ACTION_STOP))
        }

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

    // this run of the edge, for the state and the notification
    private var via: String? = null
    private var name: String? = null
    private var address: String? = null
    private var answered = false
    private var everRegistered = false
    private var lostSince = 0L
    private var asking = false
    // in the foreground, with the notification: what it says
    private var foreground = false
    private var shownKey: String? = null
    private val poll = Runnable { pollNow() }

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

    // what a start sets the device up with, see onDevice()
    private class Starting(val config: Config, val gateway: String?, val dns: String?)

    @Volatile
    private var starting: Starting? = null

    /**
     * From the native code, on the edge's thread: the device, with the
     * edge's IPv4 address - that of tuntap.address, or the one a supernode
     * handed out, which comes only once the edge has registered.  Its file
     * descriptor, which the edge takes over, or -1.
     */
    @Suppress("unused")
    fun onDevice(address: String, bits: Int): Int {
        val s = starting ?: return -1
        val config = s.config
        // tuntap.address6: worked out by the core, as the edge does it,
        // from this IPv4 address
        val address6 = try {
            config.address6For(address)
        } catch (e: IllegalArgumentException) {
            addLog(e.message ?: "tuntap.address6 cannot be used")
            return -1
        }
        main.post { this.address = address }

        val network = Config.networkOf(address, bits) ?: return -1
        // the name Android shows for the VPN: never the community's, which
        // may be the key of the headers
        val builder = Builder()
            .setSession(config.description ?: "n3n")
            .addAddress(address, bits)
            .addRoute(network.first, network.second)
            .setMtu(config.mtu)
        if (address6 != null) {
            addLog("IPv6 address of the device: ${address6.first}/${address6.second}")
            val net6 = Config.networkOf(address6.first, address6.second)!!
            builder.addAddress(address6.first, address6.second)
                .addRoute(net6.first, net6.second)
        }
        if (s.gateway != null) {
            // everything into the device; the edge's own sockets stay out
            // of it through protect().  IPv6 too: what is not for the
            // community's prefix goes to the exit peer, which drops it
            // unless it routes IPv6 - nothing should go around it.
            builder.addRoute("0.0.0.0", 0)
            try {
                builder.addRoute("::", 0)
            } catch (e: IllegalArgumentException) {
            }
            if (s.dns != null) {
                builder.addDnsServer(s.dns)
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
            return -1
        }
        // the edge takes the device over, and closes it
        return tun.detachFd()
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
                via = intent.getStringExtra(EXTRA_GATEWAY)
                setState(Snapshot(Phase.STARTING))
                // Android wants it in the foreground soon after
                // startForegroundService(), whenever the edge gets going
                startForeground()
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
        if (config.addressInvalid) {
            addLog(getString(R.string.no_address))
            setState(Snapshot(Phase.OFF, failed = true))
            stopSelf()
            return false
        }

        via = gateway
        name = config.description
        // with tuntap.address; else the supernode's, once onDevice() has it
        this.address = config.address?.first
        answered = false
        everRegistered = false
        lostSince = 0L
        setState(Snapshot(Phase.STARTING))
        startForeground()
        // what onDevice() sets the device up with
        starting = Starting(config, gateway, dns)
        startedWith = Triple(configText, gateway, dns)

        running = true
        stopping = false
        val thread = Thread({
            // no device yet: the edge asks for it, see onDevice()
            val rc = nativeRun(text, -1, filesDir.absolutePath)
            addLog("edge stopped ($rc)")
            main.post { edgeEnded() }
        }, "n3n-edge")
        edge = thread
        thread.start()
        if (watching == null) {
            watchNetwork()
        }
        poller = this
        pollSoon()
        return true
    }

    /** Main thread, once the edge's thread is through */
    private fun edgeEnded() {
        // not asked to stop: it ended by itself, the log says why
        val asked = stopping
        edge = null
        stopping = false
        stopPolling()
        val start = next
        next = null
        if (start != null && startEdge(start)) {
            return
        }
        running = false
        if (start == null) {
            setState(Snapshot(Phase.OFF, failed = !asked))
        }
        unwatchNetwork()
        leaveForeground()
        stopSelf()
    }

    private fun stopEdge() {
        if (edge != null) {
            // the edge ends, and then its thread the service
            stopping = true
            running = false
            stopPolling()
            setState(Snapshot(Phase.STOPPING, state.info))
            nativeStop()
        } else {
            running = false
            setState(Snapshot(Phase.OFF))
            leaveForeground()
            stopSelf()
        }
    }

    override fun onRevoke() {
        // another VPN took over, or the user withdrew the permission
        stopEdge()
    }

    override fun onDestroy() {
        // the notification goes with the service
        foreground = false
        unwatchNetwork()
        stopPolling()
        // the edge's thread outlives this object; it is told to stop, if
        // nothing waits to follow it
        if (edge != null && next == null) {
            stopping = true
            running = false
            setState(Snapshot(Phase.STOPPING, state.info))
            nativeStop()
        }
        super.onDestroy()
    }

    /* Asking the edge for its state, on a thread of its own: its
     * management API on the unix socket, see Status. */
    private fun pollSoon() {
        main.removeCallbacks(poll)
        main.post(poll)
    }

    private fun stopPolling() {
        main.removeCallbacks(poll)
        if (poller === this) {
            poller = null
        }
    }

    private fun pollNow() {
        if (edge == null || stopping || asking) {
            // a query on its way schedules the next one
            return
        }
        asking = true
        val context = applicationContext
        Thread({
            val info = Status.query(context)
            main.post {
                asking = false
                statusIs(info)
            }
        }, "n3n-status").start()
    }

    // main thread, with the answer of the edge (null: none)
    private fun statusIs(info: Status.Info?) {
        if (edge == null || stopping || poller !== this) {
            return
        }
        val now = SystemClock.elapsedRealtime()
        val phase = when {
            // not up yet; later, one missed answer (a timeout) changes nothing
            info == null -> if (answered) state.phase else Phase.STARTING
            info.registered -> Phase.CONNECTED
            everRegistered -> Phase.RECONNECTING
            else -> Phase.CONNECTING
        }
        if (info != null) {
            answered = true
            if (info.registered) {
                everRegistered = true
                lostSince = 0L
            } else if (lostSince == 0L) {
                lostSince = now
            }
        }
        val noAnswer = lostSince != 0L && now - lostSince > NO_ANSWER_MS
        setState(Snapshot(phase, info ?: state.info, noAnswer))
        main.postDelayed(poll, when {
            phase.busy -> POLL_BUSY_MS
            stateListener != null -> POLL_SHOWN_MS
            else -> POLL_IDLE_MS
        })
    }

    // main thread
    private fun setState(s: Snapshot) {
        val was = state
        state = s
        stateListener?.invoke(s)
        if (s.phase != was.phase || s.noAnswer != was.noAnswer) {
            ConnectTile.update(this)
        }
        if (foreground && s.phase != Phase.OFF) {
            val key = notificationText(s).joinToString("\n")
            if (key != shownKey) {
                shownKey = key
                manager().notify(NOTIFICATION, notification(s))
            }
        }
    }

    /** Title, text and the line in the header of the notification */
    private fun notificationText(s: Snapshot): List<String> {
        val info = s.info
        val text = when {
            s.phase == Phase.CONNECTED && info != null ->
                resources.getQuantityString(R.plurals.notify_connected, info.peers, address ?: "", info.peers, info.direct)
            else -> s.doing(this) ?: ""
        }
        val sub = via?.let { getString(R.string.notify_via, it) } ?: name ?: ""
        return listOf(s.title(this), text, sub)
    }

    private fun manager(): NotificationManager {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= 26) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL, getString(R.string.channel), NotificationManager.IMPORTANCE_LOW))
        }
        return manager
    }

    private fun notification(s: Snapshot): Notification {
        val (title, text, sub) = notificationText(s)
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(
            this, 1, Intent(this, N3nVpnService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE)
        val builder = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, CHANNEL) else Notification.Builder(this)
        builder
            // white on nothing, as the system wants it: it tints the icon
            .setSmallIcon(R.drawable.ic_notification)
            // the icon in bunny-pink, not in the system's colour
            .setColor(getColor(R.color.accent))
            .setContentTitle(title)
            .setContentText(text)
            .setContentIntent(open)
            .setCategory(Notification.CATEGORY_SERVICE)
            .setShowWhen(false)
            .setOnlyAlertOnce(true)
            .setOngoing(true)
        if (sub.isNotEmpty()) {
            builder.setSubText(sub)
        }
        if (s.phase != Phase.STOPPING) {
            builder.addAction(
                Notification.Action.Builder(
                    Icon.createWithResource(this, R.drawable.ic_power), getString(R.string.disconnect), stop).build())
        }
        return builder.build()
    }

    private fun startForeground() {
        manager()
        val notification = notification(state)
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION, notification)
        }
        foreground = true
        shownKey = notificationText(state).joinToString("\n")
    }

    private fun leaveForeground() {
        foreground = false
        shownKey = null
        stopForeground(STOP_FOREGROUND_REMOVE)
    }
}
