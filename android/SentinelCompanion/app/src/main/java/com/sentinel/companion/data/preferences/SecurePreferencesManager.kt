package com.sentinel.companion.data.preferences

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Manages encrypted storage for device credentials and sync settings.
 * Uses Android Keystore-backed AES256 encryption.
 */
class SecurePreferencesManager private constructor(context: Context) {

    private val prefs: SharedPreferences

    init {
        prefs = try {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()

            EncryptedSharedPreferences.create(
                context,
                PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        } catch (e: Exception) {
            Log.w(TAG, "EncryptedSharedPreferences initialization failed, falling back to private prefs: ${e.message}")
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        }
    }

    fun getServerUrl(): String {
        val url = prefs.getString(KEY_SERVER_URL, DEFAULT_SERVER_URL) ?: DEFAULT_SERVER_URL
        if (url.contains("192.168.137.1")) {
            setServerUrl(DEFAULT_SERVER_URL)
            return DEFAULT_SERVER_URL
        }
        return url
    }

    fun setServerUrl(url: String) {
        prefs.edit().putString(KEY_SERVER_URL, url.trim()).apply()
    }

    fun getDeviceId(): String? {
        return prefs.getString(KEY_DEVICE_ID, null)
    }

    fun getDeviceName(): String? {
        return prefs.getString(KEY_DISPLAY_NAME, "Android Phone")
    }

    fun getDeviceToken(): String? {
        return prefs.getString(KEY_CREDENTIAL_TOKEN, null)
    }

    fun isPaired(): Boolean {
        return !getDeviceId().isNullOrBlank() && !getDeviceToken().isNullOrBlank()
    }

    fun saveDeviceToken(deviceId: String, deviceName: String, token: String) {
        prefs.edit()
            .putString(KEY_DEVICE_ID, deviceId)
            .putString(KEY_DISPLAY_NAME, deviceName)
            .putString(KEY_CREDENTIAL_TOKEN, token)
            .apply()
    }

    fun clearPairing() {
        prefs.edit()
            .remove(KEY_DEVICE_ID)
            .remove(KEY_CREDENTIAL_TOKEN)
            .remove(KEY_LAST_SYNC_TS)
            .remove(KEY_LAST_SYNC_STATUS)
            .remove(KEY_LAST_SYNC_ERROR)
            .remove(KEY_SYNC_PAUSED)
            .apply()
    }

    fun isSyncPaused(): Boolean {
        return prefs.getBoolean(KEY_SYNC_PAUSED, false)
    }

    fun setSyncPaused(paused: Boolean) {
        prefs.edit().putBoolean(KEY_SYNC_PAUSED, paused).apply()
    }

    fun getLastSyncTimestamp(): Long {
        return prefs.getLong(KEY_LAST_SYNC_TS, 0L)
    }

    fun setLastSyncTimestamp(ts: Long) {
        prefs.edit().putLong(KEY_LAST_SYNC_TS, ts).apply()
    }

    fun getLastSyncStatus(): String? {
        return prefs.getString(KEY_LAST_SYNC_STATUS, "Idle")
    }

    fun setLastSyncStatus(status: String) {
        prefs.edit().putString(KEY_LAST_SYNC_STATUS, status).apply()
    }

    fun getLastSyncError(): String? {
        return prefs.getString(KEY_LAST_SYNC_ERROR, null)
    }

    fun setLastSyncError(error: String?) {
        if (error == null) {
            prefs.edit().remove(KEY_LAST_SYNC_ERROR).apply()
        } else {
            prefs.edit().putString(KEY_LAST_SYNC_ERROR, error).apply()
        }
    }

    fun getPermissionReported(): String {
        return prefs.getString(KEY_PERM_STATE, "UNKNOWN") ?: "UNKNOWN"
    }

    fun setPermissionReported(state: String) {
        prefs.edit().putString(KEY_PERM_STATE, state).apply()
    }

    fun markRevoked() {
        prefs.edit()
            .remove(KEY_CREDENTIAL_TOKEN)
            .putString(KEY_LAST_SYNC_STATUS, "Revoked")
            .apply()
    }

    fun isAutoSync(): Boolean {
        return prefs.getBoolean(KEY_AUTO_SYNC, true)
    }

    fun setAutoSync(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_AUTO_SYNC, enabled).apply()
    }

    fun isSyncOnlyNew(): Boolean {
        return prefs.getBoolean(KEY_SYNC_ONLY_NEW, false)
    }

    fun setSyncOnlyNew(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_SYNC_ONLY_NEW, enabled).apply()
    }

    fun getAppTheme(): String {
        return prefs.getString(KEY_APP_THEME, "SYSTEM") ?: "SYSTEM"
    }

    fun setAppTheme(theme: String) {
        prefs.edit().putString(KEY_APP_THEME, theme).apply()
    }

    fun getLastHeartbeatTimestamp(): Long {
        return prefs.getLong(KEY_LAST_HEARTBEAT_TS, 0L)
    }

    fun setLastHeartbeatTimestamp(ts: Long) {
        prefs.edit().putLong(KEY_LAST_HEARTBEAT_TS, ts).apply()
    }

    companion object {
        private const val TAG = "SecurePrefs"
        private const val PREFS_NAME = "sentinel_secure_prefs"
        const val DEFAULT_SERVER_URL = "http://10.139.80.176:5000"

        private const val KEY_SERVER_URL = "server_url"
        private const val KEY_DEVICE_ID = "device_id"
        private const val KEY_CREDENTIAL_TOKEN = "credential_token"
        private const val KEY_DISPLAY_NAME = "display_name"
        private const val KEY_SYNC_PAUSED = "sync_paused"
        private const val KEY_LAST_SYNC_TS = "last_sync_ts"
        private const val KEY_LAST_SYNC_STATUS = "last_sync_status"
        private const val KEY_LAST_SYNC_ERROR = "last_sync_error"
        private const val KEY_PERM_STATE = "perm_state"
        private const val KEY_AUTO_SYNC = "auto_sync"
        private const val KEY_SYNC_ONLY_NEW = "sync_only_new"
        private const val KEY_APP_THEME = "app_theme"
        private const val KEY_LAST_HEARTBEAT_TS = "last_heartbeat_ts"

        @Volatile
        private var instance: SecurePreferencesManager? = null

        fun getInstance(context: Context): SecurePreferencesManager {
            return instance ?: synchronized(this) {
                instance ?: SecurePreferencesManager(context.applicationContext).also { instance = it }
            }
        }
    }
}
