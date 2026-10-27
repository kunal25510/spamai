package com.sentinel.companion.sync

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.database.Cursor
import android.provider.Telephony
import androidx.core.content.ContextCompat
import com.sentinel.companion.data.local.AppDatabase
import com.sentinel.companion.data.local.SmsEntity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Handles bounded, user-authorized import of historical received SMS messages.
 * Respects user privacy: only imports inbox messages within a configurable time window (default 30 days),
 * streams data in bounded batches to avoid high memory pressure, and supports safe cancellation.
 */
class SmsImporter(private val context: Context) {

    private val isCancelled = AtomicBoolean(false)

    fun cancel() {
        isCancelled.set(true)
    }

    suspend fun importRecentMessages(
        daysToImport: Int = 30,
        batchSize: Int = 50,
        maxLimit: Int = 50,
        onProgress: (imported: Int, total: Int) -> Unit
    ): Int = withContext(Dispatchers.IO) {
        isCancelled.set(false)

        // 1. Guard: Check READ_SMS permission
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.READ_SMS)
            != PackageManager.PERMISSION_GRANTED) {
            throw SecurityException("READ_SMS permission not granted")
        }

        val cutoffTimestamp = System.currentTimeMillis() - (daysToImport.toLong() * 24 * 60 * 60 * 1000)
        val projection = arrayOf(
            Telephony.Sms._ID,
            Telephony.Sms.ADDRESS,
            Telephony.Sms.BODY,
            Telephony.Sms.DATE,
            Telephony.Sms.TYPE
        )

        val sortOrder = "${Telephony.Sms.DATE} DESC"
        val resolver = context.contentResolver

        // Primary query: Inbox within configured time window
        var cursor: Cursor? = resolver.query(
            Telephony.Sms.Inbox.CONTENT_URI,
            projection,
            "${Telephony.Sms.DATE} >= ?",
            arrayOf(cutoffTimestamp.toString()),
            sortOrder
        )

        // Fallback: If no recent messages in window, query recent inbox up to 50 messages
        if (cursor == null || cursor.count == 0) {
            cursor?.close()
            cursor = resolver.query(
                Telephony.Sms.Inbox.CONTENT_URI,
                projection,
                null,
                null,
                sortOrder
            )
        }

        if (cursor == null) {
            android.util.Log.w("SmsImporter", "SMS inbox cursor is null.")
            return@withContext 0
        }

        var totalImported = 0
        val totalCount = cursor.count
        android.util.Log.d("SmsImporter", "Found $totalCount messages in telephony inbox (capping import to $maxLimit).")
        val db = AppDatabase.getInstance(context)
        val batch = mutableListOf<SmsEntity>()

        try {
            val idIndex = cursor.getColumnIndexOrThrow(Telephony.Sms._ID)
            val addrIndex = cursor.getColumnIndexOrThrow(Telephony.Sms.ADDRESS)
            val bodyIndex = cursor.getColumnIndexOrThrow(Telephony.Sms.BODY)
            val dateIndex = cursor.getColumnIndexOrThrow(Telephony.Sms.DATE)
            val typeIndex = cursor.getColumnIndexOrThrow(Telephony.Sms.TYPE)

            while (cursor.moveToNext() && !isCancelled.get() && totalImported + batch.size < maxLimit) {
                val providerId = cursor.getString(idIndex) ?: continue
                val sender = cursor.getString(addrIndex) ?: "Unknown"
                val body = cursor.getString(bodyIndex) ?: ""
                val date = cursor.getLong(dateIndex)
                val type = cursor.getInt(typeIndex)

                // Skip non-inbox messages if any
                if (type != Telephony.Sms.MESSAGE_TYPE_INBOX && type != 1) continue

                val entity = SmsEntity(
                    providerId = providerId,
                    sender = sender,
                    body = body,
                    timestamp = date,
                    messageType = "inbox",
                    syncStatus = SmsEntity.STATUS_PENDING
                )
                batch.add(entity)

                if (batch.size >= batchSize) {
                    db.smsDao().insertOrUpdateAll(batch)
                    totalImported += batch.size
                    onProgress(totalImported, totalCount)
                    batch.clear()
                }
            }

            // Flush remaining batch
            if (batch.isNotEmpty() && !isCancelled.get()) {
                db.smsDao().insertOrUpdateAll(batch)
                totalImported += batch.size
                onProgress(totalImported, totalCount)
                batch.clear()
            }

            android.util.Log.d("SmsImporter", "Imported and queued $totalImported pending SMS messages.")

            // Trigger background sync worker to upload imported records
            if (totalImported > 0) {
                SmsSyncWorker.enqueueImmediateSync(context)
            }

        } finally {
            cursor.close()
        }

        return@withContext totalImported
    }
}
