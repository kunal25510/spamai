package com.sentinel.security.util

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import androidx.core.app.NotificationCompat

object SecurityAlertNotification {
    private const val CHANNEL_ID = "sentinel_scam_alerts"
    private const val CHANNEL_NAME = "Sentinel Scam Alerts"

    fun showAlert(context: Context, title: String, message: String, riskLevel: String) {
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                CHANNEL_NAME,
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "High-priority security alerts for detected fraudulent SMS and scams"
                enableVibration(true)
            }
            manager.createNotificationChannel(channel)
        }

        val icon = android.R.drawable.ic_dialog_alert
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(icon)
            .setContentTitle(title)
            .setContentText(message)
            .setStyle(NotificationCompat.BigTextStyle().bigText(message))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .build()

        manager.notify((System.currentTimeMillis() % 10000).toInt(), notification)
    }
}
