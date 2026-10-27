package com.sentinel.companion.sync

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import androidx.core.content.ContextCompat
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.sentinel.companion.data.local.AppDatabase
import com.sentinel.companion.data.model.SmsItemDto
import com.sentinel.companion.data.model.SmsSyncPayload
import com.sentinel.companion.data.preferences.SecurePreferencesManager
import com.sentinel.companion.network.ApiClient
import java.util.concurrent.TimeUnit

/**
 * Reliable WorkManager worker for uploading pending SMS batches to Sentinel AI backend.
 * Respects Android background battery restrictions and handles retries with exponential backoff.
 */
class SmsSyncWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(appContext, workerParams) {

    companion object {
        const val UNIQUE_ONE_TIME_WORK = "sentinel_sms_sync_onetime"
        const val UNIQUE_PERIODIC_WORK = "sentinel_sms_sync_periodic"
        private const val BATCH_SIZE = 50
        private const val MAX_CONSECUTIVE_BATCHES = 1

        /**
         * Enqueues an immediate one-time sync task when new SMS arrives or user initiates sync.
         */
        fun enqueueImmediateSync(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()

            val request = OneTimeWorkRequestBuilder<SmsSyncWorker>()
                .setConstraints(constraints)
                .build()

            WorkManager.getInstance(context).enqueueUniqueWork(
                UNIQUE_ONE_TIME_WORK,
                ExistingWorkPolicy.REPLACE,
                request
            )
        }

        /**
         * Sets up periodic background sync for maintaining protection and reporting status.
         */
        fun schedulePeriodicSync(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()

            val periodicRequest = PeriodicWorkRequestBuilder<SmsSyncWorker>(6, TimeUnit.HOURS)
                .setConstraints(constraints)
                .build()

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                UNIQUE_PERIODIC_WORK,
                ExistingPeriodicWorkPolicy.KEEP,
                periodicRequest
            )
        }
    }

    override suspend fun doWork(): Result {
        val prefs = SecurePreferencesManager.getInstance(applicationContext)

        // 1. Guard: check device pairing
        if (!prefs.isPaired()) {
            android.util.Log.d("SmsSyncWorker", "Device not paired. Skipping sync.")
            return Result.success()
        }

        val token = prefs.getDeviceToken()
        if (token.isNullOrBlank()) {
            android.util.Log.w("SmsSyncWorker", "Missing device token.")
            return Result.failure()
        }

        val apiService = ApiClient.getService(applicationContext)
        val authHeader = "Bearer $token"

        // 2. Guard: check if user paused sync (verify with backend in case resumed remotely)
        if (prefs.isSyncPaused()) {
            try {
                val statusRes = apiService.getSyncStatus(authHeader)
                val statusBody = statusRes.body()
                val isPaused = statusBody?.syncPaused == true || statusBody?.syncState == "PAUSED"
                if (statusRes.isSuccessful && !isPaused) {
                    android.util.Log.i("SmsSyncWorker", "Sync resumed by backend. Resuming sync.")
                    prefs.setSyncPaused(false)
                } else {
                    android.util.Log.d("SmsSyncWorker", "SMS sync is paused by user settings.")
                    return Result.success()
                }
            } catch (e: Exception) {
                android.util.Log.d("SmsSyncWorker", "SMS sync paused check failed: ${e.message}")
                return Result.success()
            }
        }

        // 3. Determine actual permission state
        val readGranted = ContextCompat.checkSelfPermission(
            applicationContext,
            Manifest.permission.READ_SMS
        ) == PackageManager.PERMISSION_GRANTED

        val receiveGranted = ContextCompat.checkSelfPermission(
            applicationContext,
            Manifest.permission.RECEIVE_SMS
        ) == PackageManager.PERMISSION_GRANTED

        val permissionState = when {
            readGranted && receiveGranted -> "GRANTED"
            readGranted || receiveGranted -> "PARTIAL"
            else -> "DENIED"
        }
        prefs.setPermissionReported(permissionState)

        val smsDao = AppDatabase.getInstance(applicationContext).smsDao()

        try {
            var batchesProcessed = 0

            while (batchesProcessed < MAX_CONSECUTIVE_BATCHES) {
                val pendingList = smsDao.getPendingMessages(BATCH_SIZE)

                // If no messages pending, send heartbeat/permission status once if first batch
                if (pendingList.isEmpty()) {
                    if (batchesProcessed == 0) {
                        val emptyPayload = SmsSyncPayload(
                            permissionState = permissionState,
                            messages = emptyList()
                        )
                        val heartbeatResponse = apiService.syncSms(authHeader, emptyPayload)
                        if (heartbeatResponse.isSuccessful) {
                            val body = heartbeatResponse.body()
                            if (body?.syncState == "ACTIVE") {
                                prefs.setSyncPaused(false)
                            } else if (body?.syncState == "PAUSED") {
                                prefs.setSyncPaused(true)
                            }
                            prefs.setLastSyncTimestamp(System.currentTimeMillis())
                            prefs.setLastSyncStatus("Up to date")
                            prefs.setLastSyncError(null)
                        } else if (heartbeatResponse.code() == 403) {
                            prefs.markRevoked()
                            return Result.failure()
                        }
                    }
                    break
                }

                val dtos = pendingList.map { entity ->
                    SmsItemDto(
                        providerId = entity.providerId,
                        sender = entity.sender,
                        body = entity.body,
                        timestamp = entity.timestamp,
                        messageType = entity.messageType
                    )
                }

                val payload = SmsSyncPayload(
                    permissionState = permissionState,
                    messages = dtos
                )

                val response = apiService.syncSms(authHeader, payload)

                if (response.isSuccessful) {
                    val body = response.body()
                    val idsToMark = pendingList.map { it.id }
                    smsDao.markAsSynced(idsToMark)

                    prefs.setLastSyncTimestamp(System.currentTimeMillis())
                    prefs.setLastSyncStatus("Synchronized")
                    prefs.setLastSyncError(null)
                    android.util.Log.i("SmsSyncWorker", "Uploaded batch of ${dtos.size} SMS messages successfully.")

                    // If backend reported PAUSED state, sync local flag
                    if (body?.syncState == "PAUSED") {
                        prefs.setSyncPaused(true)
                        break
                    } else if (body?.syncState == "ACTIVE") {
                        prefs.setSyncPaused(false)
                    }

                    batchesProcessed++
                } else {
                    val code = response.code()
                    if (code == 403) {
                        // Device has been revoked by dashboard administrator
                        android.util.Log.e("SmsSyncWorker", "Device access revoked (403).")
                        prefs.markRevoked()
                        prefs.setLastSyncStatus("Revoked")
                        return Result.failure()
                    } else if (code == 401) {
                        android.util.Log.e("SmsSyncWorker", "Invalid device credentials (401).")
                        prefs.setLastSyncStatus("Auth Failed")
                        return Result.failure()
                    } else {
                        val errMsg = "HTTP error $code"
                        prefs.setLastSyncStatus("Error")
                        prefs.setLastSyncError(errMsg)
                        return Result.retry()
                    }
                }
            }

            // If more messages remain after batch limit, enqueue a continuation
            if (smsDao.countPending() > 0 && !prefs.isSyncPaused()) {
                enqueueImmediateSync(applicationContext)
            }

            return Result.success()
        } catch (e: Exception) {
            android.util.Log.e("SmsSyncWorker", "Sync exception: ${e.message}")
            prefs.setLastSyncStatus("Network Error")
            prefs.setLastSyncError(e.message ?: "Connection failure")
            return Result.retry()
        }
    }
}
