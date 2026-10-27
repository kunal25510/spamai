package com.sentinel.companion.network

import com.sentinel.companion.data.model.ActivityListResponse
import com.sentinel.companion.data.model.BackendHealthResponse
import com.sentinel.companion.data.model.FeedbackRequest
import com.sentinel.companion.data.model.GeneralApiResponse
import com.sentinel.companion.data.model.HeartbeatRequest
import com.sentinel.companion.data.model.HeartbeatResponse
import com.sentinel.companion.data.model.PairingRequest
import com.sentinel.companion.data.model.PairingResponse
import com.sentinel.companion.data.model.SmsListResponse
import com.sentinel.companion.data.model.SmsSyncPayload
import com.sentinel.companion.data.model.SmsSyncResponse
import com.sentinel.companion.data.model.SyncStatusResponse
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * Retrofit definition for Sentinel AI Backend API.
 */
interface SentinelApiService {

    @GET("api/health")
    suspend fun checkHealth(): Response<BackendHealthResponse>

    @POST("api/devices/pair")
    suspend fun pairDevice(
        @Body request: PairingRequest
    ): Response<PairingResponse>

    @POST("api/devices/heartbeat")
    suspend fun sendHeartbeat(
        @Header("Authorization") authHeader: String,
        @Body request: HeartbeatRequest = HeartbeatRequest()
    ): Response<HeartbeatResponse>

    @POST("api/sms/sync")
    suspend fun syncSms(
        @Header("Authorization") authHeader: String,
        @Body payload: SmsSyncPayload
    ): Response<SmsSyncResponse>

    @GET("api/sms/sync-status")
    suspend fun getSyncStatus(
        @Header("Authorization") authHeader: String
    ): Response<SyncStatusResponse>

    @GET("api/sms")
    suspend fun getSmsList(
        @Header("Authorization") authHeader: String? = null,
        @Query("limit") limit: Int = 100,
        @Query("offset") offset: Int = 0,
        @Query("category") category: String? = null,
        @Query("search") search: String? = null
    ): Response<SmsListResponse>

    @GET("api/activity")
    suspend fun getActivity(
        @Header("Authorization") authHeader: String? = null,
        @Query("limit") limit: Int = 20
    ): Response<ActivityListResponse>

    @POST("api/feedback")
    suspend fun submitFeedback(
        @Body request: FeedbackRequest
    ): Response<GeneralApiResponse>

    @POST("api/sms/sync/pause")
    suspend fun pauseSync(
        @Header("Authorization") authHeader: String
    ): Response<GeneralApiResponse>

    @POST("api/sms/sync/resume")
    suspend fun resumeSync(
        @Header("Authorization") authHeader: String
    ): Response<GeneralApiResponse>

    @DELETE("api/devices/{deviceId}")
    suspend fun revokeDevice(
        @Header("Authorization") authHeader: String,
        @Path("deviceId") deviceId: String
    ): Response<GeneralApiResponse>

    @DELETE("api/sms")
    suspend fun deleteSyncedData(
        @Header("Authorization") authHeader: String
    ): Response<GeneralApiResponse>
}
