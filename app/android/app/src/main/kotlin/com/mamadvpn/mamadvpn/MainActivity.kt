package com.mamadvpn.mamadvpn

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import com.mamadvpn.mamadvpn.vpn.MamadVpnService

class MainActivity : FlutterActivity() {
    companion object {
        const val VPN_REQUEST_CODE = 1001
        const val CHANNEL = "com.mamadvpn/vpn"
    }

    private var pendingResult: MethodChannel.Result? = null

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        // Store engine reference for VpnService to send TUN fd
        MamadVpnService.engineRef = flutterEngine

        // Set up MethodChannel for VPN control from Flutter
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "saveConfig" -> {
                        // Persist config to SharedPreferences before VPN permission request
                        val configJson = call.arguments as? String ?: "{}"
                        val prefs = getSharedPreferences("mamadvpn_vpn", MODE_PRIVATE)
                        prefs.edit().putString("last_config", configJson).apply()
                        result.success(true)
                    }
                    "requestVpn" -> {
                        val intent = VpnService.prepare(this@MainActivity)
                        if (intent != null) {
                            // First time — need to show VPN permission dialog
                            pendingResult = result
                            startActivityForResult(intent, VPN_REQUEST_CODE)
                        } else {
                            // Already granted — launch directly
                            val configJson = call.argument<String>("config") ?: "{}"
                            launchVpnService(configJson)
                            result.success(true)
                        }
                    }
                    "stopVpn" -> {
                        stopVpnService()
                        result.success(true)
                    }
                    else -> result.notImplemented()
                }
            }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode == VPN_REQUEST_CODE) {
            if (resultCode == Activity.RESULT_OK) {
                // Permission granted — config was saved by Flutter before requesting
                val prefs = getSharedPreferences("mamadvpn_vpn", MODE_PRIVATE)
                val configJson = prefs.getString("last_config", "{}") ?: "{}"
                launchVpnService(configJson)

                pendingResult?.success(true)
            } else {
                pendingResult?.success(false)
            }
            pendingResult = null
        }
    }

    private fun launchVpnService(configJson: String) {
        val intent = Intent(this, MamadVpnService::class.java).apply {
            action = MamadVpnService.ACTION_CONNECT
            putExtra("config_json", configJson)
        }
        startService(intent)
    }

    private fun stopVpnService() {
        val intent = Intent(this, MamadVpnService::class.java).apply {
            action = MamadVpnService.ACTION_DISCONNECT
        }
        startService(intent)
    }
}
