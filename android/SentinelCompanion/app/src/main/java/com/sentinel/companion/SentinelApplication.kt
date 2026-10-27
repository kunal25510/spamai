package com.sentinel.companion

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import com.sentinel.companion.data.local.AppDatabase
import com.sentinel.companion.data.preferences.SecurePreferencesManager

class SentinelApplication : Application() {

    companion object {
        const val SYNC_CHANNEL_ID = "sentinel_sync_channel"
        lateinit var instance: SentinelApplication
            private set
    }

    val database: AppDatabase by lazy { AppDatabase.getInstance(this) }
    val prefs: SecurePreferencesManager by lazy { SecurePreferencesManager.getInstance(this) }

    override fun onCreate() {
        super.onCreate()
        instance = this
        createNotificationChannel()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val name = "Sentinel Security Sync"
            val descriptionText = "Notifications for SMS security analysis and synchronization"
            val importance = NotificationManager.IMPORTANCE_LOW
            val channel = NotificationChannel(SYNC_CHANNEL_ID, name, importance).apply {
                description = descriptionText
            }
            val notificationManager: NotificationManager =
                getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.createNotificationChannel(channel)
        }
    }
}
