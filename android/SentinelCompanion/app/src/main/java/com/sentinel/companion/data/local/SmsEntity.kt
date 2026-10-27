package com.sentinel.companion.data.local

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "pending_sms",
    indices = [
        Index(value = ["providerId"], unique = true),
        Index(value = ["syncStatus"])
    ]
)
data class SmsEntity(
    @PrimaryKey
    val id: String = java.util.UUID.randomUUID().toString(),
    val providerId: String,
    val sender: String,
    val body: String,
    val timestamp: Long,
    val messageType: String = "inbox",
    val syncStatus: String = STATUS_PENDING, // PENDING, SYNCED, FAILED
    val retryCount: Int = 0,
    val createdAt: Long = System.currentTimeMillis()
) {
    companion object {
        const val STATUS_PENDING = "PENDING"
        const val STATUS_SYNCED = "SYNCED"
        const val STATUS_FAILED = "FAILED"
    }
}
