package com.sanyavpn.android

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import androidx.activity.viewModels
import com.sanyavpn.android.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val viewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)

        setupObservers()
        setupClickListeners()
    }

    private fun setupObservers() {
        viewModel.raspberryPiStatus.observe(this) { isOnline ->
            val statusIcon = if (isOnline) R.drawable.ic_status_online else R.drawable.ic_status_offline
            binding.raspberryPiStatusIcon.setImageResource(statusIcon)
        }

        viewModel.internetAccessStatus.observe(this) { isOnline ->
            val statusIcon = if (isOnline) R.drawable.ic_status_online else R.drawable.ic_status_offline
            binding.internetAccessStatusIcon.setImageResource(statusIcon)
        }

        viewModel.vpnStatus.observe(this) { isEnabled ->
            val statusIcon = if (isEnabled) R.drawable.ic_status_online else R.drawable.ic_status_offline
            binding.vpnStatusIcon.setImageResource(statusIcon)
            binding.enableVpnButton.isEnabled = !isEnabled
            binding.disableVpnButton.isEnabled = isEnabled
        }

        viewModel.exitNodeIp.observe(this) { ipAddress ->
            binding.exitNodeIp.text = ipAddress
        }
    }

    private fun setupClickListeners() {
        binding.enableVpnButton.setOnClickListener {
            viewModel.enableVpn()
        }

        binding.disableVpnButton.setOnClickListener {
            viewModel.disableVpn()
        }
    }
}
