package com.sanyavpn.android

import androidx.lifecycle.MutableLiveData
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader

object PingMonitor {

    suspend fun startPinging(
        raspberryPiStatus: MutableLiveData<Boolean>,
        internetAccessStatus: MutableLiveData<Boolean>,
        raspberryPiIp: String
    ) {
        withContext(Dispatchers.IO) {
            while (true) {
                val piReachable = isHostReachable(raspberryPiIp)
                val internetReachable = isHostReachable("google.com")

                raspberryPiStatus.postValue(piReachable)
                internetAccessStatus.postValue(internetReachable)

                delay(5000) // Ping every 5 seconds
            }
        }
    }

    private fun isHostReachable(host: String): Boolean {
        return try {
            val process = Runtime.getRuntime().exec("ping -c 1 $host")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            var line: String?
            val output = StringBuilder()
            while (reader.readLine().also { line = it } != null) {
                output.append(line).append("\n")
            }
            val exitCode = process.waitFor()
            exitCode == 0
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }
}
