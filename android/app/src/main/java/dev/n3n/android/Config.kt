// Copyright (C) Honey Bunny QT
// SPDX-License-Identifier: GPL-3.0-only

package dev.n3n.android

/**
 * The few settings the app needs from a configuration itself - to set up
 * the device before the edge starts - read the way n3n reads its .conf
 * files: [section] headers, option = value lines, # and ; comments.  The
 * edge reads the whole configuration again, see N3nVpnService.
 */
class Config(text: String) {

    companion object {
        /**
         * The text for a QR code, as tools/n3n-qr makes it: without comments,
         * "a = b" as "a=b", blank lines in a row as one - and, if asked,
         * without the address of this phone (tuntap.address)
         */
        fun compact(text: String, withoutAddress: Boolean = false): String {
            val out = StringBuilder()
            var section = ""
            var blank = false
            for (raw in text.lines()) {
                var line = raw.trim()
                if (line.isEmpty()) {
                    blank = out.isNotEmpty()
                    continue
                }
                if (line.startsWith("#") || line.startsWith(";")) {
                    continue
                }
                val hash = line.indexOf('#')
                if (hash >= 0) {
                    line = line.substring(0, hash).trim()
                    if (line.isEmpty()) {
                        continue
                    }
                }
                if (line.startsWith("[")) {
                    section = line.removePrefix("[").substringBefore("]").trim()
                        .split(Regex("\\s+"))[0].lowercase()
                } else {
                    val eq = line.indexOf('=')
                    if (eq >= 0) {
                        val key = line.substring(0, eq).trim()
                        if (withoutAddress && section == "tuntap" && key.equals("address", ignoreCase = true)) {
                            continue
                        }
                        line = key + "=" + line.substring(eq + 1).trim()
                    }
                }
                if (blank) {
                    out.append('\n')
                    blank = false
                }
                out.append(line).append('\n')
            }
            return out.toString().trimEnd('\n')
        }
    }

    private val values = HashMap<String, String>()

    init {
        var section = ""
        for (raw in text.lines()) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#") || line.startsWith(";")) {
                continue
            }
            if (line.startsWith("[") && line.endsWith("]")) {
                // "[community home]" is the community section too
                section = line.substring(1, line.length - 1).trim().split(Regex("\\s+"))[0]
                continue
            }
            val eq = line.indexOf('=')
            if (eq < 0) {
                continue
            }
            val key = line.substring(0, eq).trim()
            var value = line.substring(eq + 1).trim()
            val comment = value.indexOf('#')
            if (comment >= 0) {
                value = value.substring(0, comment).trim()
            }
            values.putIfAbsent("$section.$key", value)
        }
    }

    operator fun get(key: String): String? = values[key]

    /** tuntap.address, as address and prefix length (24 if none given) */
    val address: Pair<String, Int>?
        get() {
            val a = values["tuntap.address"] ?: return null
            val parts = a.split("/")
            val bits = if (parts.size > 1) parts[1].toIntOrNull() ?: 24 else 24
            if (parts[0].split(".").size != 4 || bits !in 1..32) {
                return null
            }
            return parts[0] to bits
        }

    /** The network of tuntap.address, for the route into the device */
    val network: Pair<String, Int>?
        get() {
            val (addr, bits) = address ?: return null
            val octets = addr.split(".").map { it.toIntOrNull() ?: return null }
            val ip = octets.fold(0L) { acc, o -> (acc shl 8) or (o.toLong() and 0xff) }
            val mask = if (bits == 0) 0L else (0xffffffffL shl (32 - bits)) and 0xffffffffL
            val net = ip and mask
            val text = (3 downTo 0).joinToString(".") { ((net shr (it * 8)) and 0xff).toString() }
            return text to bits
        }

    val mtu: Int
        get() = values["tuntap.mtu"]?.toIntOrNull()?.takeIf { it in 576..9000 } ?: 1290

    val community: String?
        get() = values["community.name"]
}
