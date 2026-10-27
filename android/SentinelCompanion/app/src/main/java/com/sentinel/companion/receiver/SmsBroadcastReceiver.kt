package com.sentinel.companion.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import com.sentinel.companion.data.local.AppDatabase
import com.sentinel.companion.data.local.SmsEntity
import com.sentinel.companion.data.preferences.SecurePreferencesManager
import com.sentinel.companion.sync.SmsSyncWorker
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * BroadcastReceiver for incoming SMS broadcasts.
 * Handles multipart SMS concatenation, queues messages into Room DB without blocking the main thread,
 * and schedules reliable background sync via WorkManager.
 */
class SmsBroadcastReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context?, intent: Intent?) {
        if (context == null || intent == null) return

        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) {
            return
        }

        val prefs = SecurePreferencesManager.getInstance(context)
        if (!prefs.isPaired()) {
            // Do not capture or sync messages if device is not paired
            return
        }

        val pendingResult = goAsync()

        CoroutineScope(Dispatchers.IO).launch {
            try {
                val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
                if (messages.isNullOrEmpty()) {
                    pendingResult.finish()
                    return@launch
                }

                // Group multipart PDUs by sender and approximate timestamp
                val grouped = messages.groupBy { sms ->
                    val addr = sms.displayOriginatingAddress ?: sms.originatingAddress ?: "Unknown"
                    addr
                }

                val db = AppDatabase.getInstance(context)
                val entitiesToInsert = mutableListOf<SmsEntity>()

                for ((sender, segments) in grouped) {
                    val fullBody = StringBuilder()
                    var timestamp = 0L

                    for (segment in segments) {
                        val bodyPart = segment.displayMessageBody ?: segment.messageBody ?: ""
                        fullBody.append(bodyPart)
                        if (timestamp == 0L) {
                            timestamp = segment.timestampMillis
                        }
                    }

                    if (timestamp == 0L) {
                        timestamp = System.currentTimeMillis()
                    }

                    val providerId = "inc_${timestamp}_${Math.abs(sender.hashCode())}"

                    val entity = SmsEntity(
                        providerId = providerId,
                        sender = sender,
                        body = fullBody.toString(),
                        timestamp = timestamp,
                        messageType = "inbox",
                        syncStatus = SmsEntity.STATUS_PENDING
                    )
                    entitiesToInsert.add(entity)
                }

                if (entitiesToInsert.isNotEmpty()) {
                    db.smsDao().insertAll(entitiesToInsert)
                    android.util.Log.d("SmsReceiver", "Queued ${entitiesToInsert.size} new SMS for synchronization.")

                    // Trigger WorkManager for background delivery
                    SmsSyncWorker.enqueueImmediateSync(context)
                }
            } catch (e: Exception) {
                android.util.Log.e("SmsReceiver", "Error processing incoming SMS: ${e.message}")
            } finally {
                pendingResult.finish()
            }
        }
    }
}
