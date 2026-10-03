// Copyright (C) Honey Bunny QT
// SPDX-License-Identifier: GPL-3.0-only

package dev.n3n.android

import android.app.Activity
import android.content.Context
import android.view.View
import android.widget.Button
import android.widget.TextView

/** The configuration, kept in the app's preferences */
object Store {
    private const val PREFS = "n3n"
    private const val KEY_CONFIG = "config"

    fun load(context: Context): String =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_CONFIG, "") ?: ""

    fun save(context: Context, text: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(KEY_CONFIG, text).apply()
    }

    /** Routing all traffic through an exit peer: whether, through which, and its DNS */
    class Route(val all: Boolean, val gateway: String, val dns: String)

    fun route(context: Context): Route {
        val p = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return Route(
            p.getBoolean("route_all", false),
            p.getString("route_gateway", "") ?: "",
            p.getString("route_dns", "") ?: "",
        )
    }

    fun saveRoute(context: Context, route: Route) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putBoolean("route_all", route.all)
            .putString("route_gateway", route.gateway)
            .putString("route_dns", route.dns)
            .apply()
    }

    private val ipv4 = Regex("^((25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1?\\d?\\d)$")

    fun isIpv4(text: String) = ipv4.matches(text)
}

/** The top bar of the screens besides the main one (layout/bar.xml) */
fun Activity.setupBar(title: Int, action: Int? = null, onAction: (() -> Unit)? = null) {
    findViewById<View>(R.id.back).setOnClickListener { finish() }
    findViewById<TextView>(R.id.bar_title).setText(title)
    val button = findViewById<Button>(R.id.bar_action)
    if (action != null) {
        button.setText(action)
        button.visibility = View.VISIBLE
        button.setOnClickListener { onAction?.invoke() }
    }
}
