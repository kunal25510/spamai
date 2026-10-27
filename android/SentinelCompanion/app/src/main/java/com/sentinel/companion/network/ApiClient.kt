package com.sentinel.companion.network

import android.content.Context
import com.sentinel.companion.data.preferences.SecurePreferencesManager
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Response
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.util.concurrent.TimeUnit

/**
 * Factory for creating configured SentinelApiService instances.
 * Implements privacy-safe logging that avoids leaking auth tokens and SMS message bodies in Logcat.
 */
object ApiClient {

    private const val DEFAULT_TIMEOUT_SECONDS = 30L

    @Volatile
    private var cachedService: SentinelApiService? = null
    @Volatile
    private var cachedBaseUrl: String? = null

    fun getService(context: Context): SentinelApiService {
        val prefs = SecurePreferencesManager.getInstance(context)
        var baseUrl = prefs.getServerUrl().trim()
        if (!baseUrl.endsWith("/")) {
            baseUrl += "/"
        }

        // Return cached instance if URL hasn't changed
        if (cachedService != null && cachedBaseUrl == baseUrl) {
            return cachedService!!
        }

        synchronized(this) {
            if (cachedService != null && cachedBaseUrl == baseUrl) {
                return cachedService!!
            }

            val okHttpClient = OkHttpClient.Builder()
                .connectTimeout(DEFAULT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .readTimeout(DEFAULT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .writeTimeout(DEFAULT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .addInterceptor(SanitizedLoggingInterceptor())
                .build()

            val retrofit = Retrofit.Builder()
                .baseUrl(baseUrl)
                .client(okHttpClient)
                .addConverterFactory(GsonConverterFactory.create())
                .build()

            val service = retrofit.create(SentinelApiService::class.java)
            cachedService = service
            cachedBaseUrl = baseUrl
            return service
        }
    }

    /**
     * Resets the cached service when the user updates the server URL.
     */
    fun resetClient() {
        synchronized(this) {
            cachedService = null
            cachedBaseUrl = null
        }
    }

    /**
     * Privacy-first logging interceptor:
     * Logs HTTP status and paths without printing message bodies or Bearer tokens to Logcat.
     */
    private class SanitizedLoggingInterceptor : Interceptor {
        override fun intercept(chain: Interceptor.Chain): Response {
            val request = chain.request()
            val startTime = System.nanoTime()

            val response: Response
            try {
                response = chain.proceed(request)
            } catch (e: Exception) {
                android.util.Log.e("SentinelApi", "--> ${request.method} ${request.url.encodedPath} FAILED: ${e.message}")
                throw e
            }

            val tookMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTime)
            android.util.Log.d("SentinelApi", "<-- ${response.code} ${request.method} ${request.url.encodedPath} (${tookMs}ms)")

            return response
        }
    }
}
