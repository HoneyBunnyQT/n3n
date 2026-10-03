// Copyright (C) Honey Bunny QT
// SPDX-License-Identifier: GPL-3.0-only

package dev.n3n.android

import android.content.Context
import android.net.LocalSocket
import android.net.LocalSocketAddress
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * What the running edge says about itself, from its management API on the
 * unix socket in the app's directory (session "app"), as n3nctl asks it.
 * Blocking: not on the UI thread.
 */
object Status {

    class Info(
        val registered: Boolean,
        val supernode: String?,
        val rttMs: Long?,
        val peers: Int,
        val direct: Int,
    )

    fun query(context: Context): Info? {
        val supernodes = callList(context, "get_supernodes") ?: return null
        val edges = callList(context, "get_edges") ?: JSONArray()
        // as the edge itself sees it: still registered while its periodic
        // re-registration waits for the answer
        val info = callObject(context, "get_info")

        var registered = false
        var supernode: String? = null
        var rttMs: Long? = null
        val now = System.currentTimeMillis() / 1000
        for (i in 0 until supernodes.length()) {
            val sn = supernodes.optJSONObject(i) ?: continue
            // 2: the current one too, while its re-registration waits for
            // the answer
            if (sn.optInt("current") != 0) {
                supernode = sn.optString("sockaddr")
                val rtt = sn.optLong("rtt_us")
                rttMs = if (rtt > 0) (rtt + 500) / 1000 else null
                // an edge from before "registered": the supernode's last word
                registered = now - sn.optLong("last_seen") < 90
            }
        }
        if (info != null && info.has("registered")) {
            registered = info.optInt("registered") == 1
        }
        var direct = 0
        for (i in 0 until edges.length()) {
            if (edges.optJSONObject(i)?.optString("mode") == "p2p") {
                direct++
            }
        }
        return Info(registered, supernode, rttMs, edges.length(), direct)
    }

    private fun callList(context: Context, method: String): JSONArray? =
        call(context, method)?.optJSONArray("result")

    private fun callObject(context: Context, method: String): JSONObject? =
        call(context, method)?.optJSONObject("result")

    private fun call(context: Context, method: String): JSONObject? {
        val path = File(context.filesDir, "app/mgmt").absolutePath
        val socket = LocalSocket()
        return try {
            socket.connect(LocalSocketAddress(path, LocalSocketAddress.Namespace.FILESYSTEM))
            socket.soTimeout = 2000
            val body = "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"$method\"}"
            // HTTP/1.0: the edge closes the connection after its reply
            val request = "POST /v1 HTTP/1.0\r\nHost: app\r\nContent-Length: ${body.length}\r\n\r\n$body"
            socket.outputStream.write(request.toByteArray())
            socket.outputStream.flush()
            val reply = socket.inputStream.readBytes().toString(Charsets.UTF_8)
            JSONObject(reply.substringAfter("\r\n\r\n"))
        } catch (e: Exception) {
            null
        } finally {
            try {
                socket.close()
            } catch (e: Exception) {
            }
        }
    }
}
