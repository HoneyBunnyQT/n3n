// Copyright (C) Honey Bunny QT
// SPDX-License-Identifier: GPL-3.0-only

package dev.n3n.android

import android.content.Context

/**
 * What the connection is doing, in one place: N3nVpnService works it out
 * from its own state (starting, stopping) and what the edge reports, and
 * both the notification and the main screen show it - so that neither
 * says "connected" before the edge is registered.
 */
enum class Phase {
    OFF,
    // the edge is starting, its management API does not answer yet
    STARTING,
    // registering with a supernode, for the first time since the start
    CONNECTING,
    CONNECTED,
    // registered once, then lost: registering again
    RECONNECTING,
    // asked to stop, the edge is on its way out
    STOPPING,
    ;

    /** Between OFF and CONNECTED, on the way to one of them */
    val busy: Boolean
        get() = this != OFF && this != CONNECTED
}

class Snapshot(
    val phase: Phase,
    val info: Status.Info? = null,
    // no supernode has answered for a while
    val noAnswer: Boolean = false,
    // OFF: the edge ended without being asked to, see the log
    val failed: Boolean = false,
) {
    /** In a word or two: what the button and the notification say first */
    fun title(context: Context): String = context.getString(
        when (phase) {
            Phase.OFF -> R.string.state_off
            Phase.STARTING, Phase.CONNECTING -> R.string.state_connecting
            Phase.CONNECTED -> R.string.state_on
            Phase.RECONNECTING -> R.string.state_reconnecting
            Phase.STOPPING -> R.string.state_stopping
        }
    )

    /** What it is doing right now, while busy; null in OFF and CONNECTED */
    fun doing(context: Context): String? = when (phase) {
        Phase.STARTING -> context.getString(R.string.doing_start)
        Phase.CONNECTING, Phase.RECONNECTING -> context.getString(
            when {
                noAnswer -> R.string.doing_no_answer
                info?.tcp == true -> R.string.doing_register_tcp
                else -> R.string.doing_register
            }
        )
        Phase.STOPPING -> context.getString(R.string.doing_stop)
        Phase.OFF, Phase.CONNECTED -> null
    }
}
