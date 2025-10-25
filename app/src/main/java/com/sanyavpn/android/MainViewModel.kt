package com.sanyavpn.android

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class MainViewModel : ViewModel() {

    private val _raspberryPiStatus = MutableLiveData<Boolean>()
    val raspberryPiStatus: LiveData<Boolean> = _raspberryPiStatus

    private val _internetAccessStatus = MutableLiveData<Boolean>()
    val internetAccessStatus: LiveData<Boolean> = _internetAccessStatus

    private val _vpnStatus = MutableLiveData<Boolean>()
    val vpnStatus: LiveData<Boolean> = _vpnStatus

    private val _exitNodeIp = MutableLiveData<String>()
    val exitNodeIp: LiveData<String> = _exitNodeIp

    init {
        // Set initial values
        _raspberryPiStatus.value = false
        _internetAccessStatus.value = false
        _vpnStatus.value = false
        loadExitNodeIp()
        startMonitoring()
    }

    private fun startMonitoring() {
        viewModelScope.launch {
            val raspberryPiIp = _exitNodeIp.value ?: "192.168.1.1" // Fallback IP
            PingMonitor.startPinging(_raspberryPiStatus, _internetAccessStatus, raspberryPiIp)
        }
    }

    fun enableVpn() {
        viewModelScope.launch(Dispatchers.IO) {
            val ip = _exitNodeIp.value ?: return@launch
            TailscaleManager.enableVpn(ip)
            _vpnStatus.postValue(true)
        }
    }

    fun disableVpn() {
        viewModelScope.launch(Dispatchers.IO) {
            TailscaleManager.disableVpn()
            _vpnStatus.postValue(false)
        }
    }

    private fun loadExitNodeIp() {
        viewModelScope.launch(Dispatchers.IO) {
            val ip = TailscaleManager.getExitNodeIp()
            _exitNodeIp.postValue(ip)
        }
    }
}
