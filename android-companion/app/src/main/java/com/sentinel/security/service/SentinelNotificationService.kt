package com.sentinel.security.service

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import com.sentinel.security.network.SentinelApiClient
import com.sentinel.security.util.SecurityAlertNotification
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class SentinelNotificationService : NotificationListenerService() {

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Known SMS package identifiers
    private val smsPackages = setOf(
        "com.google.android.apps.messaging",
        "com.samsung.android.messaging",
        "com.android.mms",
        "com.truecaller",
        "org.thoughtcrime.securesms"
    )

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        super.onNotificationPosted(sbn)
        if (sbn == null) return

        val pkg = sbn.packageName ?: ""
        // Check if notification is from an SMS or messaging app
        if (!smsPackages.contains(pkg) && !pkg.contains("mms") && !pkg.contains("sms") && !pkg.contains("messaging")) {
            return
        }

        val extras = sbn.notification.extras ?: return
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString() ?: ""
        val text = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString() ?: ""

        if (text.isBlank() || title.isBlank()) return

        // Read user config from SharedPreferences
        val prefs = getSharedPreferences("sentinel_prefs", MODE_PRIVATE)
        val isMonitoring = prefs.getBoolean("monitoring_enabled", false)
        val serverUrl = prefs.getString("server_url", "http://10.0.2.2:5000") ?: "http://10.0.2.2:5000"
        val pairingKey = prefs.getString("pairing_key", "") ?: ""

        if (!isMonitoring || pairingKey.isBlank()) {
            Log.d(TAG, "SMS notification received but monitoring disabled or pairing key missing.")
            return
        }

        Log.d(TAG, "Intercepted incoming SMS notification from $title: ${text.take(30)}...")

        serviceScope.launch {
            val result = SentinelApiClient.analyzeSms(
                context = applicationContext,
                sender = title,
                message = text,
                serverUrl = serverUrl,
                pairingKey = pairingKey
            )

            result.onSuccess { verdict ->
                Log.d(TAG, "Analysis verdict for SMS from $title: ${verdict.riskLevel} (Score: ${verdict.riskScore})")
                if (verdict.shouldAlert) {
                    SecurityAlertNotification.showAlert(
                        context = applicationContext,
                        title = verdict.alertTitle ?: "⚠️ Potential Scam Message",
                        message = verdict.alertMessage ?: "Suspicious content detected from $title",
                        riskLevel = verdict.riskLevel
                    )
                }
            }.onFailure { err ->
                Log.e(TAG, "Failed to analyze SMS with Sentinel server: ${err.message}")
            }
        }
    }

    companion object {
        private const val TAG = "SentinelNotifService"
    }
}
