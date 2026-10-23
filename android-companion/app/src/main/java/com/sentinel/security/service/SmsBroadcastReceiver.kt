package com.sentinel.security.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.util.Log
import com.sentinel.security.network.SentinelApiClient
import com.sentinel.security.util.SecurityAlertNotification
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class SmsBroadcastReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context?, intent: Intent?) {
        if (context == null || intent?.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return

        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        if (messages.isNullOrEmpty()) return

        val prefs = context.getSharedPreferences("sentinel_prefs", Context.MODE_PRIVATE)
        val isMonitoring = prefs.getBoolean("monitoring_enabled", false)
        val serverUrl = prefs.getString("server_url", "http://10.0.2.2:5000") ?: "http://10.0.2.2:5000"
        val pairingKey = prefs.getString("pairing_key", "") ?: ""

        if (!isMonitoring || pairingKey.isBlank()) return

        for (sms in messages) {
            val sender = sms.displayOriginatingAddress ?: "Unknown"
            val body = sms.displayMessageBody ?: ""

            if (body.isBlank()) continue

            Log.d("SentinelSmsReceiver", "Direct SMS received from $sender: ${body.take(30)}...")

            CoroutineScope(Dispatchers.IO).launch {
                SentinelApiClient.analyzeSms(
                    context = context,
                    sender = sender,
                    message = body,
                    serverUrl = serverUrl,
                    pairingKey = pairingKey
                ).onSuccess { verdict ->
                    if (verdict.shouldAlert) {
                        SecurityAlertNotification.showAlert(
                            context = context,
                            title = verdict.alertTitle ?: "⚠️ Scam Alert",
                            message = verdict.alertMessage ?: "Scam indicators detected in SMS from $sender",
                            riskLevel = verdict.riskLevel
                        )
                    }
                }
            }
        }
    }
}
