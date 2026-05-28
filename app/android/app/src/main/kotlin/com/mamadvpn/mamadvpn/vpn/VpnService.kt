package com.mamadvpn.mamadvpn.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * Android VpnService for MamadVPN.
 *
 * Creates a TUN virtual interface and passes the file descriptor to the Rust
 * engine via the Flutter MethodChannel.  Packet I/O is handled by the Rust
 * platform backend reading/writing the TUN fd directly.
 */
class MamadVpnService : VpnService() {

    private var tunFd: ParcelFileDescriptor? = null
    private var readThread: Thread? = null

    companion object {
        const val ACTION_CONNECT = "com.mamadvpn.action.CONNECT"
        const val ACTION_DISCONNECT = "com.mamadvpn.action.DISCONNECT"
        const val CHANNEL_ID = "mamadvpn_vpn_channel"

        // Held as a static reference so the service can access it after binding
        var engineRef: FlutterEngine? = null
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> startVpn(intent)
            ACTION_DISCONNECT -> stopVpn()
        }
        return START_STICKY
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    private fun startVpn(intent: Intent) {
        // Read config from Intent extras (passed from Flutter via MainActivity)
        val configJson = intent.getStringExtra("config_json") ?: "{}"

        // Build the VpnService.Builder — establishes the TUN virtual interface
        val builder = Builder()
            .setSession("MamadVPN")
            .setMtu(1500)
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("8.8.8.8")
            .addDnsServer("1.1.1.1")
            .setBlocking(false)

        // Exclude this app from its own VPN route so native outbound sockets
        // cannot be captured recursively by the TUN interface.
        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: Exception) {
            // Ignore on older API versions
        }

        // Foreground service notification
        val notification = createNotification()
        startForeground(1, notification)

        // Establish TUN interface
        val fd = builder.establish()
        if (fd == null) {
            stopVpn()
            return
        }
        tunFd = fd

        // Notify Flutter / Rust about the TUN file descriptor
        try {
            val engine = engineRef
            if (engine != null) {
                val channel = MethodChannel(
                    engine.dartExecutor.binaryMessenger,
                    "com.mamadvpn/vpn"
                )
                // Pass the raw fd integer to Rust via Dart FFI
                channel.invokeMethod("onTunFd", fd.fd)
                channel.invokeMethod("onVpnState", "connected")
            }
        } catch (_: Exception) {
            // If Flutter engine isn't ready, the Rust JNI layer can
            // pick up the fd via nativeReadPacket/nativeWritePacket
        }
    }

    private fun stopVpn() {
        // Stop the foreground notification
        try {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } catch (_: Exception) {}

        // Close the TUN fd
        tunFd?.close()
        tunFd = null

        // Notify Flutter
        try {
            val engine = engineRef
            if (engine != null) {
                val channel = MethodChannel(
                    engine.dartExecutor.binaryMessenger,
                    "com.mamadvpn/vpn"
                )
                channel.invokeMethod("onDisconnected", null)
            }
        } catch (_: Exception) {}

        stopSelf()
    }

    // ── Notification ──────────────────────────────────────────────

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "MamadVPN Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "VPN service notification"
                setShowBadge(false)
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            Notification.Builder(this)
        }
        return builder
            .setContentTitle("MamadVPN")
            .setContentText("VPN is active — bypassing censorship")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .setPriority(Notification.PRIORITY_LOW)
            .build()
    }

}
