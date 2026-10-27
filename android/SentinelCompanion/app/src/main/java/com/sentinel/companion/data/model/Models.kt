package com.sentinel.companion.data.model

import com.google.gson.annotations.SerializedName

/**
 * Data transfer models for Sentinel AI Companion API communication.
 */

data class PairingRequest(
    @SerializedName("pairingCode") val pairingCode: String,
    @SerializedName("deviceName") val deviceName: String,
    @SerializedName("model") val model: String,
    @SerializedName("osVersion") val osVersion: String
)

data class PairingResponse(
    @SerializedName("success") val success: Boolean,
    @SerializedName("deviceId") val deviceId: String?,
    @SerializedName("deviceName") val deviceName: String?,
    @SerializedName("token") val token: String?,
    @SerializedName("message") val message: String?
)

data class SmsItemDto(
    @SerializedName("providerId") val providerId: String,
    @SerializedName("sender") val sender: String,
    @SerializedName("body") val body: String,
    @SerializedName("timestamp") val timestamp: Long,
    @SerializedName("messageType") val messageType: String = "inbox"
)

data class SmsSyncPayload(
    @SerializedName("permissionState") val permissionState: String,
    @SerializedName("messages") val messages: List<SmsItemDto>
)

data class SmsSyncResponse(
    @SerializedName("success") val success: Boolean,
    @SerializedName("message") val message: String?,
    @SerializedName("acceptedCount") val acceptedCount: Int?,
    @SerializedName("duplicateCount") val duplicateCount: Int?,
    @SerializedName("syncState") val syncState: String?
)

data class SyncStatusResponse(
    @SerializedName("success") val success: Boolean,
    @SerializedName("syncState") val syncState: String?,
    @SerializedName("syncPaused") val syncPaused: Boolean?,
    @SerializedName("activeDevices") val activeDevices: Int?,
    @SerializedName("totalSms") val totalSms: Int?,
    @SerializedName("lastSync") val lastSync: String?,
    @SerializedName("byCategory") val byCategory: Map<String, Int>?
)

data class GeneralApiResponse(
    @SerializedName("success") val success: Boolean,
    @SerializedName("message") val message: String?
)

data class BackendHealthResponse(
    @SerializedName("status") val status: String?,
    @SerializedName("service") val service: String?,
    @SerializedName("uptime") val uptime: Double?
)

data class HeartbeatRequest(
    @SerializedName("sms_permission") val smsPermission: String = "GRANTED"
)

data class HeartbeatResponse(
    @SerializedName("success") val success: Boolean,
    @SerializedName("deviceId") val deviceId: String?,
    @SerializedName("status") val status: String?
)

data class SmsRecordDto(
    @SerializedName("id") val id: String,
    @SerializedName("sender") val sender: String?,
    @SerializedName("from") val from: String?,
    @SerializedName("body") val body: String?,
    @SerializedName("snippet") val snippet: String?,
    @SerializedName("timestamp") val timestamp: Long,
    @SerializedName("category") val category: String?,
    @SerializedName("risk") val risk: String?,
    @SerializedName("score") val score: Int?,
    @SerializedName("reasons") val reasons: List<String>?,
    @SerializedName("evidence") val evidence: List<String>?,
    @SerializedName("deviceId") val deviceId: String?,
    @SerializedName("date") val date: String?
)

data class SmsListResponse(
    @SerializedName("success") val success: Boolean,
    @SerializedName("count") val count: Int,
    @SerializedName("total") val total: Int,
    @SerializedName("sms") val sms: List<SmsRecordDto>
)

data class ActivityItemDto(
    @SerializedName("id") val id: String,
    @SerializedName("event_type") val eventType: String?,
    @SerializedName("category") val category: String?,
    @SerializedName("title") val title: String?,
    @SerializedName("description") val description: String?,
    @SerializedName("severity") val severity: String?,
    @SerializedName("timestamp") val timestamp: Long
)

data class ActivityListResponse(
    @SerializedName("success") val success: Boolean,
    @SerializedName("count") val count: Int,
    @SerializedName("total") val total: Int,
    @SerializedName("activities") val activities: List<ActivityItemDto>
)

data class FeedbackRequest(
    @SerializedName("emailId") val emailId: String,
    @SerializedName("feedbackType") val feedbackType: String,
    @SerializedName("notes") val notes: String = "",
    @SerializedName("emailSummary") val emailSummary: Map<String, Any> = emptyMap()
)

/**
 * High-level UI model representing an SMS message on screen
 */
data class UiSmsMessage(
    val id: String,
    val sender: String,
    val body: String,
    val timestamp: Long,
    val category: String, // FORWARDED, LEGITIMATE, SPAM, PHISHING, SUSPICIOUS, BLOCKED
    val riskScore: Int,
    val reasons: List<String>,
    val evidence: List<String>,
    val syncStatus: String, // SYNCED, PENDING, FAILED
    val deviceName: String = "Mobile (Android)"
)
