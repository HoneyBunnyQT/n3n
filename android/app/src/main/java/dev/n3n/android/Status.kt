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
        val supernodes = call(context, "get_supernodes") ?: return null
        val edges = call(context, "get_edges") ?: JSONArray()

        var registered = false
        var supernode: String? = null
        var rttMs: Long? = null
        val now = System.currentTimeMillis() / 1000
        for (i in 0 until supernodes.length()) {
            val sn = supernodes.optJSONObject(i) ?: continue
            if (sn.optInt("current") == 1) {
                supernode = sn.optString("sockaddr")
                val rtt = sn.optLong("rtt_us")
                rttMs = if (rtt > 0) (rtt + 500) / 1000 else null
                // registering again every 20 seconds or so
                registered = now - sn.optLong("last_seen") < 90
            }
        }
        var direct = 0
        for (i in 0 until edges.length()) {
            if (edges.optJSONObject(i)?.optString("mode") == "p2p") {
                direct++
            }
        }
        return Info(registered, supernode, rttMs, edges.length(), direct)
    }

    private fun call(context: Context, method: String): JSONArray? {
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
            JSONObject(reply.substringAfter("\r\n\r\n")).optJSONArray("result")
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
