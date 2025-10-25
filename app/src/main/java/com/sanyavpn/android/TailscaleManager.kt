package com.sanyavpn.android

import java.io.BufferedReader
import java.io.InputStreamReader

object TailscaleManager {

    fun enableVpn(exitNodeIp: String) {
        executeCommand("tailscale up --exit-node=$exitNodeIp --exit-node-allow-lan-access")
    }

    fun disableVpn() {
        executeCommand("tailscale down")
    }

    fun getExitNodeIp(): String {
        val jsonString = executeCommand("tailscale status --json")
        if (jsonString.isBlank()) return "N/A"

        return try {
            val json = org.json.JSONObject(jsonString)
            val self = json.optJSONObject("Self")
            val exitNodePeerID = self?.optString("ExitNodeID", "")

            if (exitNodePeerID.isNullOrBlank()) {
                return "N/A"
            }

            val peer = json.getJSONObject("Peer")
            val peerInfo = peer.optJSONObject(exitNodePeerID)

            if (peerInfo != null) {
                val ips = peerInfo.optJSONArray("TailscaleIPs")
                if (ips != null && ips.length() > 0) {
                    return ips.getString(0)
                }
            }
            "N/A"
        } catch (e: Exception) {
            e.printStackTrace()
            "N/A"
        }
    }

    private fun executeCommand(command: String): String {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", command))
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val output = StringBuilder()
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                output.append(line).append("\n")
            }
            process.waitFor()
            output.toString()
        } catch (e: Exception) {
            e.printStackTrace()
            ""
        }
    }
}
