package com.sentinel.security.network

import android.content.Context
import com.google.gson.Gson
import com.google.gson.JsonObject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit

data class AnalysisVerdict(
    val status: String,
    val riskLevel: String,
    val riskScore: Int,
    val reasons: List<String>,
    val shouldAlert: Boolean,
    val alertTitle: String?,
    val alertMessage: String?
)

object SentinelApiClient {
    private val client = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(8, TimeUnit.SECONDS)
        .build()

    private val gson = Gson()
    private val JSON_MEDIA = "application/json; charset=utf-8".toMediaType()

    suspend fun analyzeSms(
        context: Context,
        sender: String,
        message: String,
        serverUrl: String,
        pairingKey: String
    ): Result<AnalysisVerdict> = withContext(Dispatchers.IO) {
        try {
            val endpoint = if (serverUrl.endsWith("/")) "${serverUrl}api/sms/ingest" else "$serverUrl/api/sms/ingest"

            val payload = JsonObject().apply {
                addProperty("sender", sender)
                addProperty("message", message)
                addProperty("pairingKey", pairingKey)
            }

            val request = Request.Builder()
                .url(endpoint)
                .addHeader("Content-Type", "application/json")
                .addHeader("x-sentinel-key", pairingKey)
                .post(payload.toString().toRequestBody(JSON_MEDIA))
                .build()

            client.newCall(request).execute().use { response ->
                val body = response.body?.string() ?: ""
                if (!response.isSuccessful) {
                    return@withContext Result.failure(Exception("HTTP ${response.code}: $body"))
                }

                val json = gson.fromJson(body, JsonObject::class.java)
                val reasonsList = mutableListOf<String>()
                json.getAsJsonArray("reasons")?.forEach {
                    reasonsList.add(it.asString)
                }

                val verdict = AnalysisVerdict(
                    status = json.get("status")?.asString ?: "completed",
                    riskLevel = json.get("risk_level")?.asString ?: "LOW",
                    riskScore = json.get("risk_score")?.asInt ?: 0,
                    reasons = reasonsList,
                    shouldAlert = json.get("should_alert")?.asBoolean ?: false,
                    alertTitle = json.get("alert_title")?.asString,
                    alertMessage = json.get("alert_message")?.asString
                )

                Result.success(verdict)
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
