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
