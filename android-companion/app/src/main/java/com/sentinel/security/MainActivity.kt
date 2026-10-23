package com.sentinel.security

import android.content.ComponentName
import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.text.TextUtils
import android.widget.Button
import android.widget.EditText
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.sentinel.security.network.SentinelApiClient
import com.sentinel.security.service.SentinelNotificationService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    private lateinit var editServerUrl: EditText
    private lateinit var editPairingKey: EditText
    private lateinit var switchMonitoring: Switch
    private lateinit var txtNotifStatus: TextView
    private lateinit var btnGrantNotif: Button
    private lateinit var btnSaveConfig: Button
    private lateinit var btnTestConnection: Button
    private lateinit var txtTestResult: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        editServerUrl = findViewById(R.id.editServerUrl)
        editPairingKey = findViewById(R.id.editPairingKey)
        switchMonitoring = findViewById(R.id.switchMonitoring)
        txtNotifStatus = findViewById(R.id.txtNotifStatus)
        btnGrantNotif = findViewById(R.id.btnGrantNotif)
        btnSaveConfig = findViewById(R.id.btnSaveConfig)
        btnTestConnection = findViewById(R.id.btnTestConnection)
        txtTestResult = findViewById(R.id.txtTestResult)

        loadPreferences()

        btnGrantNotif.setOnClickListener {
            // Open Android system Notification Access settings
            val intent = Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
            startActivity(intent)
        }

        btnSaveConfig.setOnClickListener {
            savePreferences()
            Toast.makeText(this, "Sentinel configuration saved", Toast.LENGTH_SHORT).show()
        }

        btnTestConnection.setOnClickListener {
            testBackendConnection()
        }

        switchMonitoring.setOnCheckedChangeListener { _, isChecked ->
            savePreferences()
            val msg = if (isChecked) "Automatic SMS scam detection ENABLED" else "Automatic SMS scam detection DISABLED"
            Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
        }
    }

    override fun onResume() {
        super.onResume()
        checkNotificationAccess()
    }

    private fun loadPreferences() {
        val prefs = getSharedPreferences("sentinel_prefs", MODE_PRIVATE)
        editServerUrl.setText(prefs.getString("server_url", "http://10.0.2.2:5000"))
        editPairingKey.setText(prefs.getString("pairing_key", ""))
        switchMonitoring.isChecked = prefs.getBoolean("monitoring_enabled", false)
    }

    private fun savePreferences() {
        val prefs = getSharedPreferences("sentinel_prefs", MODE_PRIVATE)
        prefs.edit()
            .putString("server_url", editServerUrl.text.toString().trim())
            .putString("pairing_key", editPairingKey.text.toString().trim())
            .putBoolean("monitoring_enabled", switchMonitoring.isChecked)
            .apply()
    }

    private fun checkNotificationAccess() {
        val cn = ComponentName(this, SentinelNotificationService::class.java)
        val flat = Settings.Secure.getString(contentResolver, "enabled_notification_listeners")
        val isEnabled = flat != null && flat.contains(cn.flattenToString())

        if (isEnabled) {
            txtNotifStatus.text = "✓ Notification Access: GRANTED"
            txtNotifStatus.setTextColor(0xFF50FA7B.toInt())
            btnGrantNotif.isEnabled = false
            btnGrantNotif.text = "Permission Active"
        } else {
            txtNotifStatus.text = "⚠ Notification Access: NOT GRANTED"
            txtNotifStatus.setTextColor(0xFFFF5555.toInt())
            btnGrantNotif.isEnabled = true
            btnGrantNotif.text = "Grant Notification Access"
        }
    }

    private fun testBackendConnection() {
        savePreferences()
        val url = editServerUrl.text.toString().trim()
        val key = editPairingKey.text.toString().trim()

        if (url.isBlank()) {
            Toast.makeText(this, "Please enter your Sentinel Backend URL", Toast.LENGTH_SHORT).show()
            return
        }

        txtTestResult.text = "Testing connection to $url..."

        CoroutineScope(Dispatchers.IO).launch {
            val result = SentinelApiClient.analyzeSms(
                context = applicationContext,
                sender = "TEST-VERIFY",
                message = "Testing connection from Sentinel Android Companion App",
                serverUrl = url,
                pairingKey = key
            )

            withContext(Dispatchers.Main) {
                result.onSuccess { verdict ->
                    txtTestResult.text = "✓ Connection Successful!\nSentinel AI Engine: Active (Risk: ${verdict.riskLevel})"
                    txtTestResult.setTextColor(0xFF50FA7B.toInt())
                }.onFailure { err ->
                    txtTestResult.text = "✗ Connection Failed: ${err.message}"
                    txtTestResult.setTextColor(0xFFFF5555.toInt())
                }
            }
        }
    }
}
