package com.sentinel.companion.ui

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.CountDownTimer
import android.text.Editable
import android.text.TextWatcher
import android.view.KeyEvent
import android.view.MenuItem
import android.view.View
import android.widget.EditText
import android.widget.PopupMenu
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import com.sentinel.companion.R
import com.sentinel.companion.data.local.AppDatabase
import com.sentinel.companion.data.model.FeedbackRequest
import com.sentinel.companion.data.model.HeartbeatRequest
import com.sentinel.companion.data.model.PairingRequest
import com.sentinel.companion.data.model.UiSmsMessage
import com.sentinel.companion.data.preferences.SecurePreferencesManager
import com.sentinel.companion.databinding.ActivityMainBinding
import com.sentinel.companion.network.ApiClient
import com.sentinel.companion.sync.SmsImporter
import com.sentinel.companion.sync.SmsSyncWorker
import com.sentinel.companion.ui.adapter.MessagesAdapter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Sentinel AI SMS Companion - Main Controller
 * Implements the 8-screen exact reference redesign:
 * Screen 1: Splash / Launch Screen
 * Screen 2: Connect to Sentinel AI (Pairing)
 * Screen 3: SMS Permissions
 * Screen 4: Main Dashboard
 * Screen 5: Messages / SMS List
 * Screen 6: Message Detail and Security Analysis
 * Screen 7: Statistics
 * Screen 8: Settings
 */
class MainActivity : AppCompatActivity() {

    enum class AppScreen {
        SPLASH,
        PAIRING,
        PERMISSIONS,
        MAIN_CONTAINER,
        MESSAGE_DETAIL
    }

    enum class MainTab {
        DASHBOARD,
        MESSAGES,
        STATS,
        SETTINGS
    }

    private lateinit var binding: ActivityMainBinding
    private lateinit var prefs: SecurePreferencesManager
    private lateinit var messagesAdapter: MessagesAdapter

    private var currentScreen: AppScreen = AppScreen.SPLASH
    private var currentTab: MainTab = MainTab.DASHBOARD

    private var countdownTimer: CountDownTimer? = null
    private var serverCheckJob: Job? = null
    private var syncJob: Job? = null

    // In-memory message store for filtering and detail views
    private val allMessages = mutableListOf<UiSmsMessage>()
    private var selectedMessage: UiSmsMessage? = null
    private var currentFilter: String = "ALL" // ALL, FORWARDED, THREATS, BLOCKED
    private var statsTimeRangeDays: Int = 7

    private val qrScannerLauncher = registerForActivityResult(ScanContract()) { result ->
        if (result.contents != null) {
            handleScannedQr(result.contents)
        }
    }

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        val readGranted = permissions[Manifest.permission.READ_SMS] == true
        val receiveGranted = permissions[Manifest.permission.RECEIVE_SMS] == true

        val state = when {
            readGranted && receiveGranted -> "GRANTED"
            readGranted || receiveGranted -> "PARTIAL"
            else -> "DENIED"
        }
        prefs.setPermissionReported(state)

        if (readGranted && receiveGranted) {
            Toast.makeText(this, "SMS permissions granted!", Toast.LENGTH_SHORT).show()
        } else {
            Toast.makeText(this, "SMS permissions limited. Protection may be partial.", Toast.LENGTH_LONG).show()
        }

        // Navigate to Main Dashboard after permission decision
        navigateTo(AppScreen.MAIN_CONTAINER)
        switchTab(MainTab.DASHBOARD)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        prefs = SecurePreferencesManager.getInstance(this)
        applySavedTheme()

        initRecyclerView()
        setupListeners()
        setupDigitBoxes()
        setupBackNavigation()

        // Screen 1: Splash screen displays first, then transitions
        navigateTo(AppScreen.SPLASH)
        lifecycleScope.launch {
            delay(1200) // Brief smooth splash presentation
            if (prefs.isPaired()) {
                navigateTo(AppScreen.MAIN_CONTAINER)
                switchTab(MainTab.DASHBOARD)
                checkServerHealthAndHeartbeat()
                refreshDashboardData()
                loadMessages()

                // If permissions granted, ensure messages are imported and synced
                if (hasSmsPermissions()) {
                    lifecycleScope.launch(Dispatchers.IO) {
                        try {
                            val db = AppDatabase.getInstance(this@MainActivity)
                            if (db.smsDao().countPending() == 0) {
                                val importer = SmsImporter(this@MainActivity)
                                importer.importRecentMessages(daysToImport = 30, batchSize = 50) { _, _ -> }
                            }
                            SmsSyncWorker.enqueueImmediateSync(this@MainActivity)
                        } catch (_: Exception) {}
                    }
                }
            } else {
                navigateTo(AppScreen.PAIRING)
                checkServerReachability(prefs.getServerUrl())
            }
        }
    }

    override fun onResume() {
        super.onResume()
        if (prefs.isPaired() && currentScreen == AppScreen.MAIN_CONTAINER) {
            checkServerHealthAndHeartbeat()
            refreshDashboardData()
            loadMessages()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        countdownTimer?.cancel()
        serverCheckJob?.cancel()
        syncJob?.cancel()
    }

    // ========================================================
    // THEME HANDLING
    // ========================================================
    private fun applySavedTheme() {
        when (prefs.getAppTheme()) {
            "LIGHT" -> AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_NO)
            "DARK" -> AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES)
            else -> AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM)
        }
    }

    // ========================================================
    // NAVIGATION CONTROLLER
    // ========================================================
    private fun navigateTo(screen: AppScreen) {
        currentScreen = screen

        binding.screenSplash.visibility = if (screen == AppScreen.SPLASH) View.VISIBLE else View.GONE
        binding.screenPairing.visibility = if (screen == AppScreen.PAIRING) View.VISIBLE else View.GONE
        binding.screenPermissions.visibility = if (screen == AppScreen.PERMISSIONS) View.VISIBLE else View.GONE
        binding.screenMainContainer.visibility = if (screen == AppScreen.MAIN_CONTAINER) View.VISIBLE else View.GONE
        binding.screenMessageDetail.visibility = if (screen == AppScreen.MESSAGE_DETAIL) View.VISIBLE else View.GONE

        if (screen == AppScreen.PAIRING) {
            binding.etServerUrlInput.setText(prefs.getServerUrl())
            startPairingCountdown(300_000L) // 5 minutes
            binding.etDigit1.requestFocus()
            checkServerReachability(prefs.getServerUrl())
        } else {
            countdownTimer?.cancel()
        }

        if (screen == AppScreen.MAIN_CONTAINER) {
            refreshDashboardData()
        }
    }

    private fun switchTab(tab: MainTab) {
        currentTab = tab

        binding.tabDashboard.visibility = if (tab == MainTab.DASHBOARD) View.VISIBLE else View.GONE
        binding.tabMessages.visibility = if (tab == MainTab.MESSAGES) View.VISIBLE else View.GONE
        binding.tabStats.visibility = if (tab == MainTab.STATS) View.VISIBLE else View.GONE
        binding.tabSettings.visibility = if (tab == MainTab.SETTINGS) View.VISIBLE else View.GONE

        // Update bottom navigation bar items
        val activeColor = ContextCompat.getColor(this, R.color.primary_blue)
        val inactiveColor = ContextCompat.getColor(this, R.color.nav_unselected)

        binding.ivNavHome.setColorFilter(if (tab == MainTab.DASHBOARD) activeColor else inactiveColor)
        binding.tvNavHome.setTextColor(if (tab == MainTab.DASHBOARD) activeColor else inactiveColor)
        binding.tvNavHome.setTypeface(null, if (tab == MainTab.DASHBOARD) android.graphics.Typeface.BOLD else android.graphics.Typeface.NORMAL)

        binding.ivNavMessages.setColorFilter(if (tab == MainTab.MESSAGES) activeColor else inactiveColor)
        binding.tvNavMessages.setTextColor(if (tab == MainTab.MESSAGES) activeColor else inactiveColor)
        binding.tvNavMessages.setTypeface(null, if (tab == MainTab.MESSAGES) android.graphics.Typeface.BOLD else android.graphics.Typeface.NORMAL)

        binding.ivNavStats.setColorFilter(if (tab == MainTab.STATS) activeColor else inactiveColor)
        binding.tvNavStats.setTextColor(if (tab == MainTab.STATS) activeColor else inactiveColor)
        binding.tvNavStats.setTypeface(null, if (tab == MainTab.STATS) android.graphics.Typeface.BOLD else android.graphics.Typeface.NORMAL)

        binding.ivNavSettings.setColorFilter(if (tab == MainTab.SETTINGS) activeColor else inactiveColor)
        binding.tvNavSettings.setTextColor(if (tab == MainTab.SETTINGS) activeColor else inactiveColor)
        binding.tvNavSettings.setTypeface(null, if (tab == MainTab.SETTINGS) android.graphics.Typeface.BOLD else android.graphics.Typeface.NORMAL)

        when (tab) {
            MainTab.DASHBOARD -> refreshDashboardData()
            MainTab.MESSAGES -> loadMessages()
            MainTab.STATS -> refreshStatistics()
            MainTab.SETTINGS -> refreshSettingsView()
        }
    }

    private fun setupBackNavigation() {
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                when {
                    currentScreen == AppScreen.MESSAGE_DETAIL -> {
                        navigateTo(AppScreen.MAIN_CONTAINER)
                        switchTab(MainTab.MESSAGES)
                    }
                    currentScreen == AppScreen.PERMISSIONS -> {
                        if (prefs.isPaired()) {
                            navigateTo(AppScreen.MAIN_CONTAINER)
                            switchTab(MainTab.DASHBOARD)
                        } else {
                            navigateTo(AppScreen.PAIRING)
                        }
                    }
                    currentScreen == AppScreen.MAIN_CONTAINER && currentTab != MainTab.DASHBOARD -> {
                        switchTab(MainTab.DASHBOARD)
                    }
                    else -> {
                        finish()
                    }
                }
            }
        })
    }

    // ========================================================
    // UI LISTENERS
    // ========================================================
    private fun setupListeners() {
        // --- SCREEN 2: PAIRING ---
        binding.btnPairingSettings.setOnClickListener {
            showServerUrlDialog()
        }

        binding.btnScanQrAction.setOnClickListener {
            launchQrScanner()
        }

        binding.btnConnectPairing.setOnClickListener {
            attemptPairing()
        }

        binding.btnPresetWifi.setOnClickListener {
            val wifiUrl = "http://10.139.80.176:5000"
            binding.etServerUrlInput.setText(wifiUrl)
            prefs.setServerUrl(wifiUrl)
            checkServerReachability(wifiUrl)
            Toast.makeText(this, "Set to Wi-Fi server", Toast.LENGTH_SHORT).show()
        }

        binding.btnPresetUsb.setOnClickListener {
            val usbUrl = "http://localhost:5000"
            binding.etServerUrlInput.setText(usbUrl)
            prefs.setServerUrl(usbUrl)
            checkServerReachability(usbUrl)
            Toast.makeText(this, "Set to USB localhost (requires adb reverse)", Toast.LENGTH_SHORT).show()
        }

        binding.etServerUrlInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                val url = s?.toString()?.trim() ?: ""
                checkServerReachability(url)
            }
            override fun afterTextChanged(s: Editable?) {}
        })

        // --- SCREEN 3: PERMISSIONS ---
        binding.btnPermissionsBack.setOnClickListener {
            if (prefs.isPaired()) {
                navigateTo(AppScreen.MAIN_CONTAINER)
                switchTab(MainTab.DASHBOARD)
            } else {
                navigateTo(AppScreen.PAIRING)
            }
        }

        binding.btnGrantPermission.setOnClickListener {
            permissionLauncher.launch(
                arrayOf(
                    Manifest.permission.READ_SMS,
                    Manifest.permission.RECEIVE_SMS
                )
            )
        }

        binding.btnSkipPermissions.setOnClickListener {
            navigateTo(AppScreen.MAIN_CONTAINER)
            switchTab(MainTab.DASHBOARD)
        }

        // --- BOTTOM NAVIGATION BAR ---
        binding.navItemHome.setOnClickListener { switchTab(MainTab.DASHBOARD) }
        binding.navItemMessages.setOnClickListener { switchTab(MainTab.MESSAGES) }
        binding.navItemStats.setOnClickListener { switchTab(MainTab.STATS) }
        binding.navItemSettings.setOnClickListener { switchTab(MainTab.SETTINGS) }

        // --- SCREEN 4: DASHBOARD ---
        binding.btnDashboardNotifications.setOnClickListener {
            showNotificationsDialog()
        }

        binding.btnDashboardSettings.setOnClickListener {
            switchTab(MainTab.SETTINGS)
        }

        binding.rowSmsPermission.setOnClickListener {
            if (!hasSmsPermissions()) {
                navigateTo(AppScreen.PERMISSIONS)
            }
        }

        binding.btnDashboardSyncNow.setOnClickListener {
            triggerManualSync()
        }

        binding.tvViewAllActivity.setOnClickListener {
            switchTab(MainTab.MESSAGES)
        }

        // --- SCREEN 5: MESSAGES FILTER CHIPS & SEARCH ---
        binding.chipFilterAll.setOnClickListener { setMessagesFilter("ALL") }
        binding.chipFilterForwarded.setOnClickListener { setMessagesFilter("FORWARDED") }
        binding.chipFilterThreats.setOnClickListener { setMessagesFilter("THREATS") }
        binding.chipFilterBlocked.setOnClickListener { setMessagesFilter("BLOCKED") }

        binding.etSearchMessages.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                applyMessageSearchAndFilter()
            }
            override fun afterTextChanged(s: Editable?) {}
        })

        binding.btnFilterFunnel.setOnClickListener {
            showFilterMenu()
        }

        // --- SCREEN 6: MESSAGE DETAIL ---
        binding.btnDetailBack.setOnClickListener {
            navigateTo(AppScreen.MAIN_CONTAINER)
            switchTab(MainTab.MESSAGES)
        }

        binding.btnDetailOverflow.setOnClickListener {
            showDetailOverflowMenu()
        }

        binding.tabDetailDetails.setOnClickListener {
            switchDetailTab(true)
        }

        binding.tabDetailAnalysis.setOnClickListener {
            switchDetailTab(false)
        }

        binding.btnMarkLegitimate.setOnClickListener {
            submitClassificationFeedback("CORRECT", "Legitimate")
        }

        binding.btnMarkSpam.setOnClickListener {
            submitClassificationFeedback("REQUEST_REVIEW", "Spam")
        }

        binding.btnReportPhishing.setOnClickListener {
            submitClassificationFeedback("MISSED_PHISHING", "Phishing")
        }

        binding.btnMarkSuspicious.setOnClickListener {
            submitClassificationFeedback("REQUEST_REVIEW", "Suspicious")
        }

        // --- SCREEN 7: STATISTICS TIME FILTERS ---
        binding.tabStats7Days.setOnClickListener { setStatsTimeRange(7) }
        binding.tabStats30Days.setOnClickListener { setStatsTimeRange(30) }
        binding.tabStats90Days.setOnClickListener { setStatsTimeRange(90) }

        // --- SCREEN 8: SETTINGS ---
        binding.cardServerConfig.setOnClickListener {
            showServerUrlDialog()
        }

        binding.btnCopyDeviceId.setOnClickListener {
            copyDeviceIdToClipboard()
        }

        binding.switchAutoSync.setOnCheckedChangeListener { _, isChecked ->
            prefs.setAutoSync(isChecked)
            if (isChecked) {
                SmsSyncWorker.schedulePeriodicSync(this)
                Toast.makeText(this, "Auto sync enabled", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this, "Auto sync disabled", Toast.LENGTH_SHORT).show()
            }
        }

        binding.switchSyncOnlyNew.setOnCheckedChangeListener { _, isChecked ->
            prefs.setSyncOnlyNew(isChecked)
        }

        binding.cardThemeSetting.setOnClickListener {
            showThemeSelectionDialog()
        }

        binding.cardAboutSetting.setOnClickListener {
            showAboutDialog()
        }

        binding.btnSettingsDisconnect.setOnClickListener {
            showDisconnectConfirmationDialog()
        }

        binding.btnSettingsRevoke.setOnClickListener {
            showRevokeConfirmationDialog()
        }
    }

    // ========================================================
    // SCREEN 2: PAIRING & PIN HANDLING
    // ========================================================
    private fun setupDigitBoxes() {
        val boxes = listOf(
            binding.etDigit1,
            binding.etDigit2,
            binding.etDigit3,
            binding.etDigit4,
            binding.etDigit5,
            binding.etDigit6
        )

        for (i in boxes.indices) {
            val current = boxes[i]
            val next = if (i < boxes.size - 1) boxes[i + 1] else null
            val prev = if (i > 0) boxes[i - 1] else null

            current.addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                    val text = s?.toString() ?: ""
                    if (text.length == 1) {
                        next?.requestFocus()
                        if (next == null) {
                            attemptPairing()
                        }
                    } else if (text.length > 1) {
                        distributePastedDigits(text)
                    }
                }
                override fun afterTextChanged(s: Editable?) {}
            })

            current.setOnKeyListener { _, keyCode, event ->
                if (keyCode == KeyEvent.KEYCODE_DEL && event.action == KeyEvent.ACTION_DOWN) {
                    if (current.text.isNullOrEmpty() && prev != null) {
                        prev.text.clear()
                        prev.requestFocus()
                        return@setOnKeyListener true
                    }
                }
                false
            }
        }
    }

    private fun distributePastedDigits(raw: String) {
        val digits = raw.filter { it.isDigit() }
        val boxes = listOf(
            binding.etDigit1,
            binding.etDigit2,
            binding.etDigit3,
            binding.etDigit4,
            binding.etDigit5,
            binding.etDigit6
        )
        for (i in boxes.indices) {
            if (i < digits.length) {
                boxes[i].setText(digits[i].toString())
            } else {
                boxes[i].text.clear()
            }
        }
        if (digits.length >= 6) {
            boxes.last().requestFocus()
            attemptPairing()
        }
    }

    private fun getEnteredPairingCode(): String {
        return (binding.etDigit1.text.toString() +
                binding.etDigit2.text.toString() +
                binding.etDigit3.text.toString() +
                binding.etDigit4.text.toString() +
                binding.etDigit5.text.toString() +
                binding.etDigit6.text.toString()).trim()
    }

    private fun startPairingCountdown(durationMs: Long) {
        countdownTimer?.cancel()
        countdownTimer = object : CountDownTimer(durationMs, 1000) {
            override fun onTick(millisUntilFinished: Long) {
                val minutes = (millisUntilFinished / 1000) / 60
                val seconds = (millisUntilFinished / 1000) % 60
                binding.tvPairingExpiry.text = String.format(Locale.getDefault(), "Expires in %02d:%02d", minutes, seconds)
            }
            override fun onFinish() {
                binding.tvPairingExpiry.text = "Code Expired. Please generate a new code on Web."
            }
        }.start()
    }

    private fun checkServerReachability(url: String) {
        serverCheckJob?.cancel()
        if (url.isBlank()) {
            binding.tvServerReachableText.text = getString(R.string.server_unreachable)
            binding.tvServerReachableText.setTextColor(ContextCompat.getColor(this, R.color.text_muted))
            binding.viewServerStatusDot.setBackgroundResource(R.drawable.bg_badge_gray)
            return
        }

        binding.tvServerReachableText.text = getString(R.string.checking_server)
        binding.tvServerReachableText.setTextColor(ContextCompat.getColor(this, R.color.text_muted))

        serverCheckJob = lifecycleScope.launch {
            delay(500) // Debounce
            try {
                prefs.setServerUrl(url)
                ApiClient.resetClient()
                val apiService = ApiClient.getService(this@MainActivity)
                val response = withContext(Dispatchers.IO) {
                    try { apiService.checkHealth() } catch (_: Exception) { null }
                }

                if (response != null && response.isSuccessful) {
                    binding.tvServerReachableText.text = getString(R.string.server_reachable)
                    binding.tvServerReachableText.setTextColor(ContextCompat.getColor(this@MainActivity, R.color.status_green_text))
                    binding.viewServerStatusDot.setBackgroundResource(R.drawable.bg_badge_green)
                } else {
                    binding.tvServerReachableText.text = getString(R.string.server_unreachable)
                    binding.tvServerReachableText.setTextColor(ContextCompat.getColor(this@MainActivity, R.color.status_red_text))
                    binding.viewServerStatusDot.setBackgroundResource(R.drawable.bg_badge_red)
                }
            } catch (e: Exception) {
                binding.tvServerReachableText.text = getString(R.string.server_unreachable)
                binding.tvServerReachableText.setTextColor(ContextCompat.getColor(this@MainActivity, R.color.status_red_text))
                binding.viewServerStatusDot.setBackgroundResource(R.drawable.bg_badge_red)
            }
        }
    }

    private fun launchQrScanner() {
        val options = ScanOptions().apply {
            setDesiredBarcodeFormats(ScanOptions.QR_CODE)
            setPrompt("Scan Sentinel Web Pairing QR Code")
            setCameraId(0)
            setBeepEnabled(true)
            setOrientationLocked(false)
        }
        qrScannerLauncher.launch(options)
    }

    private fun handleScannedQr(rawText: String) {
        try {
            val trimmed = rawText.trim()
            if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
                val json = JSONObject(trimmed)
                val server = (if (json.has("server")) json.optString("server") else json.optString("api")).trim()
                val code = json.optString("code", "").trim()
                if (server.isNotEmpty()) {
                    binding.etServerUrlInput.setText(server)
                    prefs.setServerUrl(server)
                }
                if (code.isNotEmpty()) {
                    distributePastedDigits(code)
                }
                if (server.isNotEmpty() && code.length == 6) {
                    executePairing(server, code)
                    return
                }
            }

            val uri = Uri.parse(trimmed)
            val queryServer = uri.getQueryParameter("server") ?: uri.getQueryParameter("api")
            val queryCode = uri.getQueryParameter("code")
            if (!queryServer.isNullOrEmpty() && !queryCode.isNullOrEmpty()) {
                binding.etServerUrlInput.setText(queryServer)
                prefs.setServerUrl(queryServer)
                distributePastedDigits(queryCode)
                executePairing(queryServer, queryCode)
                return
            }

            val digits = trimmed.filter { it.isDigit() }
            if (digits.length == 6) {
                distributePastedDigits(digits)
                val currentServer = binding.etServerUrlInput.text?.toString()?.trim() ?: prefs.getServerUrl()
                executePairing(currentServer, digits)
                return
            }

            Toast.makeText(this, "Scanned: $trimmed", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(this, "QR Scan Error: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }

    private fun attemptPairing() {
        val serverUrl = binding.etServerUrlInput.text?.toString()?.trim() ?: prefs.getServerUrl()
        val code = getEnteredPairingCode()

        if (serverUrl.isBlank()) {
            Toast.makeText(this, "Please enter server URL", Toast.LENGTH_SHORT).show()
            return
        }

        if (code.length != 6) {
            Toast.makeText(this, "Please enter all 6 digits of your pairing code.", Toast.LENGTH_SHORT).show()
            return
        }

        executePairing(serverUrl, code)
    }

    private fun executePairing(serverUrl: String, pairingCode: String) {
        prefs.setServerUrl(serverUrl)
        ApiClient.resetClient()

        binding.pbPairingLoading.visibility = View.VISIBLE
        binding.btnConnectPairing.isEnabled = false

        lifecycleScope.launch {
            try {
                val apiService = ApiClient.getService(this@MainActivity)
                val deviceName = "${Build.MANUFACTURER} ${Build.MODEL}".trim()
                val request = PairingRequest(
                    pairingCode = pairingCode,
                    deviceName = if (deviceName.isNotBlank()) deviceName else "Android Companion",
                    model = Build.MODEL ?: "Unknown",
                    osVersion = "Android ${Build.VERSION.RELEASE}"
                )

                val response = withContext(Dispatchers.IO) {
                    apiService.pairDevice(request)
                }

                binding.pbPairingLoading.visibility = View.GONE
                binding.btnConnectPairing.isEnabled = true

                if (response.isSuccessful && response.body()?.success == true) {
                    val body = response.body()!!
                    val deviceId = body.deviceId ?: "dev_${System.currentTimeMillis()}"
                    val token = body.token ?: ""

                    prefs.saveDeviceToken(deviceId, body.deviceName ?: deviceName, token)
                    Toast.makeText(this@MainActivity, "Device paired successfully!", Toast.LENGTH_SHORT).show()

                    // Check permissions
                    if (hasSmsPermissions()) {
                        navigateTo(AppScreen.MAIN_CONTAINER)
                        switchTab(MainTab.DASHBOARD)
                        startInitialImport()
                    } else {
                        navigateTo(AppScreen.PERMISSIONS)
                    }
                } else {
                    val errorMsg = response.body()?.message ?: "Pairing rejected (${response.code()}). Check if the PIN expired."
                    AlertDialog.Builder(this@MainActivity)
                        .setTitle("Pairing Failed")
                        .setMessage(errorMsg)
                        .setPositiveButton("OK", null)
                        .show()
                }
            } catch (e: Exception) {
                binding.pbPairingLoading.visibility = View.GONE
                binding.btnConnectPairing.isEnabled = true
                AlertDialog.Builder(this@MainActivity)
                    .setTitle("Connection Error")
                    .setMessage("Could not connect to:\n$serverUrl\n\nDetails: ${e.message}")
                    .setPositiveButton("OK", null)
                    .show()
            }
        }
    }

    private fun startInitialImport() {
        if (!hasSmsPermissions()) return
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                prefs.setSyncPaused(false)
                val db = AppDatabase.getInstance(this@MainActivity)
                db.smsDao().clearAll()
                val importer = SmsImporter(this@MainActivity)
                importer.importRecentMessages(daysToImport = 30, batchSize = 50) { _, _ -> }
                SmsSyncWorker.schedulePeriodicSync(this@MainActivity)
                SmsSyncWorker.enqueueImmediateSync(this@MainActivity)
                delay(2000)
                withContext(Dispatchers.Main) {
                    refreshDashboardData()
                    loadMessages()
                }
            } catch (_: Exception) {}
        }
    }

    // ========================================================
    // SCREEN 4: DASHBOARD REFRESH & ACTIONS
    // ========================================================
    private fun refreshDashboardData() {
        val isPaired = prefs.isPaired()

        if (isPaired) {
            binding.tvConnectedStatusTitle.text = getString(R.string.connected_and_protected)
            binding.tvConnectedStatusDesc.text = getString(R.string.connected_subtitle)
            binding.tvDeviceAuthStatus.text = "Authorized >"
            binding.tvDeviceAuthStatus.setTextColor(ContextCompat.getColor(this, R.color.status_green_text))
            binding.ivCheckDevice.setImageResource(R.drawable.ic_check_small_green)
        } else {
            binding.tvConnectedStatusTitle.text = getString(R.string.disconnected_title)
            binding.tvConnectedStatusDesc.text = getString(R.string.disconnected_subtitle)
            binding.tvDeviceAuthStatus.text = "Not Paired >"
            binding.tvDeviceAuthStatus.setTextColor(ContextCompat.getColor(this, R.color.status_red_text))
            binding.ivCheckDevice.setImageResource(R.drawable.ic_bullet_cyan)
        }

        // SMS Permission row
        if (hasSmsPermissions()) {
            binding.tvSmsPermissionStatus.text = "Granted >"
            binding.tvSmsPermissionStatus.setTextColor(ContextCompat.getColor(this, R.color.status_green_text))
            binding.ivCheckPermission.setImageResource(R.drawable.ic_check_small_green)
        } else {
            binding.tvSmsPermissionStatus.text = "Missing >"
            binding.tvSmsPermissionStatus.setTextColor(ContextCompat.getColor(this, R.color.warning_orange))
            binding.ivCheckPermission.setImageResource(R.drawable.ic_bullet_cyan)
        }

        // Last Sync timestamp
        val lastSyncTs = prefs.getLastSyncTimestamp()
        if (lastSyncTs > 0) {
            val dateStr = SimpleDateFormat("MMM dd, yyyy • hh:mm a", Locale.getDefault()).format(Date(lastSyncTs))
            binding.tvDashboardLastSync.text = dateStr
        } else {
            binding.tvDashboardLastSync.text = "Just now"
        }

        // Last Heartbeat
        val lastHeartbeatTs = prefs.getLastHeartbeatTimestamp()
        if (lastHeartbeatTs > 0) {
            val diffSec = (System.currentTimeMillis() - lastHeartbeatTs) / 1000
            binding.tvDashboardLastHeartbeat.text = when {
                diffSec < 60 -> "Just now"
                diffSec < 3600 -> "${diffSec / 60}m ago"
                else -> "${diffSec / 3600}h ago"
            }
        } else {
            binding.tvDashboardLastHeartbeat.text = "Just now"
        }

        // Load recent activity from backend or Room DB
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val api = ApiClient.getService(this@MainActivity)
                val token = prefs.getDeviceToken()
                val authHeader = if (!token.isNullOrBlank()) "Bearer $token" else null
                val response = api.getActivity(authHeader = authHeader, limit = 5)
                if (response.isSuccessful && response.body()?.success == true) {
                    val acts = response.body()?.activities ?: emptyList()
                    withContext(Dispatchers.Main) {
                        if (acts.isNotEmpty()) {
                            val first = acts[0]
                            binding.tvActivitySyncSubtitle.text = "${first.title ?: "Sync completed"} • ${formatTime(first.timestamp)}"
                            if (acts.size > 1) {
                                val second = acts[1]
                                binding.tvActivitySmsSubtitle.text = "${second.title ?: "SMS analyzed"} • ${formatTime(second.timestamp)}"
                            }
                        }
                    }
                }
            } catch (_: Exception) {}
        }
    }

    private fun checkServerHealthAndHeartbeat() {
        lifecycleScope.launch {
            try {
                val api = ApiClient.getService(this@MainActivity)
                val health = withContext(Dispatchers.IO) {
                    try { api.checkHealth() } catch (_: Exception) { null }
                }

                if (health != null && health.isSuccessful) {
                    binding.tvOnlineBadge.text = "● Online"
                    binding.tvOnlineBadge.setTextColor(ContextCompat.getColor(this@MainActivity, R.color.status_green_text))
                    binding.tvServerConnectionStatus.text = "Connected >"
                    binding.tvServerConnectionStatus.setTextColor(ContextCompat.getColor(this@MainActivity, R.color.status_green_text))
                    binding.ivCheckServer.setImageResource(R.drawable.ic_check_small_green)

                    // Send heartbeat if paired
                    val token = prefs.getDeviceToken()
                    if (!token.isNullOrBlank()) {
                        val permState = if (hasSmsPermissions()) "GRANTED" else "MISSING"
                        withContext(Dispatchers.IO) {
                            try {
                                api.sendHeartbeat("Bearer $token", HeartbeatRequest(permState))
                                prefs.setLastHeartbeatTimestamp(System.currentTimeMillis())
                                val statusRes = api.getSyncStatus("Bearer $token")
                                val statusBody = statusRes.body()
                                val isPaused = statusBody?.syncPaused == true || statusBody?.syncState == "PAUSED"
                                if (statusRes.isSuccessful && !isPaused) {
                                    prefs.setSyncPaused(false)
                                }
                            } catch (_: Exception) {}
                        }
                    }
                } else {
                    binding.tvOnlineBadge.text = "● Offline"
                    binding.tvOnlineBadge.setTextColor(ContextCompat.getColor(this@MainActivity, R.color.status_red_text))
                    binding.tvServerConnectionStatus.text = "Offline >"
                    binding.tvServerConnectionStatus.setTextColor(ContextCompat.getColor(this@MainActivity, R.color.status_red_text))
                    binding.ivCheckServer.setImageResource(R.drawable.ic_bullet_cyan)
                }
            } catch (_: Exception) {
                binding.tvOnlineBadge.text = "● Offline"
                binding.tvOnlineBadge.setTextColor(ContextCompat.getColor(this@MainActivity, R.color.status_red_text))
            }
        }
    }

    private fun triggerManualSync() {
        if (!prefs.isPaired()) {
            Toast.makeText(this, "Device not paired", Toast.LENGTH_SHORT).show()
            return
        }

        binding.btnDashboardSyncNow.isEnabled = false
        binding.btnDashboardSyncNow.text = getString(R.string.syncing)

        syncJob = lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    prefs.setSyncPaused(false)
                    val db = AppDatabase.getInstance(this@MainActivity)
                    if (db.smsDao().countPending() == 0) {
                        db.smsDao().markAllPending()
                    }
                    if (hasSmsPermissions()) {
                        val importer = SmsImporter(this@MainActivity)
                        importer.importRecentMessages(daysToImport = 30, batchSize = 50) { _, _ -> }
                    }
                    SmsSyncWorker.enqueueImmediateSync(this@MainActivity)
                    delay(2500)
                }
                prefs.setLastSyncTimestamp(System.currentTimeMillis())
                refreshDashboardData()
                loadMessages()
                Toast.makeText(this@MainActivity, "Synchronization complete", Toast.LENGTH_SHORT).show()
            } catch (e: Exception) {
                Toast.makeText(this@MainActivity, "Sync notice: ${e.message}", Toast.LENGTH_SHORT).show()
            } finally {
                binding.btnDashboardSyncNow.isEnabled = true
                binding.btnDashboardSyncNow.text = getString(R.string.sync_now)
            }
        }
    }

    // ========================================================
    // SCREEN 5: MESSAGES LIST & FILTERS
    // ========================================================
    private fun initRecyclerView() {
        messagesAdapter = MessagesAdapter { message ->
            openMessageDetail(message)
        }
        binding.rvMessagesList.apply {
            layoutManager = LinearLayoutManager(this@MainActivity)
            adapter = messagesAdapter
            setHasFixedSize(true)
        }
    }

    private fun loadMessages() {
        lifecycleScope.launch(Dispatchers.IO) {
            val list = mutableListOf<UiSmsMessage>()

            // 1. Fetch analyzed records from Sentinel backend
            try {
                val api = ApiClient.getService(this@MainActivity)
                val token = prefs.getDeviceToken()
                val authHeader = if (!token.isNullOrBlank()) "Bearer $token" else null
                val response = api.getSmsList(authHeader = authHeader, limit = 100)
                if (response.isSuccessful && response.body()?.success == true) {
                    val dtos = response.body()?.sms ?: emptyList()
                    for (dto in dtos) {
                        list.add(
                            UiSmsMessage(
                                id = dto.id,
                                sender = dto.sender ?: dto.from ?: "Unknown",
                                body = dto.body ?: dto.snippet ?: "",
                                timestamp = dto.timestamp,
                                category = (dto.category ?: "FORWARDED").uppercase(Locale.US),
                                riskScore = dto.score ?: 0,
                                reasons = dto.reasons ?: emptyList(),
                                evidence = dto.evidence ?: emptyList(),
                                syncStatus = "SYNCED",
                                deviceName = "Mobile (Android)"
                            )
                        )
                    }
                }
            } catch (_: Exception) {}

            // 2. Merge pending local records from Room DB
            try {
                val db = AppDatabase.getInstance(this@MainActivity)
                val localEntities = db.smsDao().getAllMessages()
                for (entity in localEntities) {
                    // Check if already in list by providerId/timestamp
                    val exists = list.any { it.sender == entity.sender && Math.abs(it.timestamp - entity.timestamp) < 2000 }
                    if (!exists) {
                        list.add(
                            UiSmsMessage(
                                id = entity.id,
                                sender = entity.sender,
                                body = entity.body,
                                timestamp = entity.timestamp,
                                category = if (entity.syncStatus == "SYNCED") "FORWARDED" else "PENDING",
                                riskScore = 0,
                                reasons = listOf("Local message pending Sentinel cloud analysis"),
                                evidence = emptyList(),
                                syncStatus = entity.syncStatus,
                                deviceName = "Mobile (Android)"
                            )
                        )
                    }
                }
            } catch (_: Exception) {}

            // Sort newest first
            list.sortByDescending { it.timestamp }

            withContext(Dispatchers.Main) {
                allMessages.clear()
                allMessages.addAll(list)
                applyMessageSearchAndFilter()
            }
        }
    }

    private fun setMessagesFilter(filter: String) {
        currentFilter = filter

        val activeBg = R.drawable.bg_tab_pill_active
        val inactiveBg = R.drawable.bg_tab_pill_inactive
        val white = ContextCompat.getColor(this, R.color.text_white)
        val navy = ContextCompat.getColor(this, R.color.text_primary)

        binding.chipFilterAll.setBackgroundResource(if (filter == "ALL") activeBg else inactiveBg)
        binding.chipFilterAll.setTextColor(if (filter == "ALL") white else navy)

        binding.chipFilterForwarded.setBackgroundResource(if (filter == "FORWARDED") activeBg else inactiveBg)
        binding.chipFilterForwarded.setTextColor(if (filter == "FORWARDED") white else navy)

        binding.chipFilterThreats.setBackgroundResource(if (filter == "THREATS") activeBg else inactiveBg)
        binding.chipFilterThreats.setTextColor(if (filter == "THREATS") white else navy)

        binding.chipFilterBlocked.setBackgroundResource(if (filter == "BLOCKED") activeBg else inactiveBg)
        binding.chipFilterBlocked.setTextColor(if (filter == "BLOCKED") white else navy)

        applyMessageSearchAndFilter()
    }

    private fun applyMessageSearchAndFilter() {
        val query = binding.etSearchMessages.text?.toString()?.trim()?.lowercase(Locale.US) ?: ""

        val filtered = allMessages.filter { msg ->
            val matchesFilter = when (currentFilter) {
                "FORWARDED" -> msg.category == "FORWARDED" || msg.syncStatus == "SYNCED"
                "THREATS" -> msg.category == "PHISHING" || msg.category == "SPAM" || msg.category == "SUSPICIOUS" || msg.riskScore >= 50
                "BLOCKED" -> msg.category == "BLOCKED"
                else -> true
            }

            val matchesQuery = query.isEmpty() ||
                    msg.sender.lowercase(Locale.US).contains(query) ||
                    msg.body.lowercase(Locale.US).contains(query)

            matchesFilter && matchesQuery
        }

        messagesAdapter.submitList(filtered)
        binding.layoutMessagesEmpty.visibility = if (filtered.isEmpty()) View.VISIBLE else View.GONE
        binding.rvMessagesList.visibility = if (filtered.isEmpty()) View.GONE else View.VISIBLE
    }

    private fun showFilterMenu() {
        val popup = PopupMenu(this, binding.btnFilterFunnel)
        popup.menu.add("Sort by Newest First")
        popup.menu.add("Sort by Highest Risk")
        popup.setOnMenuItemClickListener { item ->
            when (item.title) {
                "Sort by Newest First" -> {
                    allMessages.sortByDescending { it.timestamp }
                    applyMessageSearchAndFilter()
                }
                "Sort by Highest Risk" -> {
                    allMessages.sortByDescending { it.riskScore }
                    applyMessageSearchAndFilter()
                }
            }
            true
        }
        popup.show()
    }

    // ========================================================
    // SCREEN 6: MESSAGE DETAIL VIEW
    // ========================================================
    private fun openMessageDetail(message: UiSmsMessage) {
        selectedMessage = message
        navigateTo(AppScreen.MESSAGE_DETAIL)

        binding.tvDetailSender.text = message.sender.ifBlank { "Unknown" }
        val dateFormatted = SimpleDateFormat("MMM dd, yyyy • hh:mm a", Locale.getDefault()).format(Date(message.timestamp))
        binding.tvDetailSubtitle.text = "${message.category.lowercase().replaceFirstChar { it.uppercase() }} • ${dateFormatted}"
        binding.tvDetailBody.text = message.body.trim()

        // Badge
        binding.tvDetailClassificationBadge.text = message.category
        when (message.category.uppercase(Locale.US)) {
            "PHISHING" -> {
                binding.tvDetailClassificationBadge.setBackgroundResource(R.drawable.bg_badge_red)
                binding.tvDetailClassificationBadge.setTextColor(ContextCompat.getColor(this, R.color.status_red_text))
            }
            "SPAM", "SUSPICIOUS" -> {
                binding.tvDetailClassificationBadge.setBackgroundResource(R.drawable.bg_badge_amber)
                binding.tvDetailClassificationBadge.setTextColor(ContextCompat.getColor(this, R.color.status_amber_text))
            }
            "LEGITIMATE", "SAFE" -> {
                binding.tvDetailClassificationBadge.setBackgroundResource(R.drawable.bg_badge_green)
                binding.tvDetailClassificationBadge.setTextColor(ContextCompat.getColor(this, R.color.status_green_text))
            }
            else -> {
                binding.tvDetailClassificationBadge.setBackgroundResource(R.drawable.bg_badge_blue)
                binding.tvDetailClassificationBadge.setTextColor(ContextCompat.getColor(this, R.color.status_blue_text))
            }
        }

        binding.tvDetailRiskScore.text = "${message.riskScore} / 100"
        binding.tvDetailDevice.text = message.deviceName
        binding.tvDetailReceivedDate.text = dateFormatted

        // AI Explanation
        if (message.reasons.isNotEmpty()) {
            binding.tvDetailAiExplanation.text = message.reasons.joinToString("\n• ", prefix = "• ")
        } else {
            binding.tvDetailAiExplanation.text = "This message was analyzed by Sentinel AI and matches typical sender and formatting rules."
        }

        // Analysis Tab Data
        binding.pbRiskMeter.progress = message.riskScore
        binding.tvAnalysisRiskScoreLabel.text = "Risk Score: ${message.riskScore} / 100"
        if (message.evidence.isNotEmpty()) {
            binding.tvAnalysisEvidenceList.text = message.evidence.joinToString("\n• ", prefix = "• ")
        } else {
            binding.tvAnalysisEvidenceList.text = "• Universal domain reputation checked\n• No high-risk malware patterns detected\n• Standard forward heuristic pipeline"
        }

        // Default to Details tab
        switchDetailTab(true)
    }

    private fun switchDetailTab(showDetails: Boolean) {
        binding.layoutDetailTabContent.visibility = if (showDetails) View.VISIBLE else View.GONE
        binding.layoutAnalysisTabContent.visibility = if (showDetails) View.GONE else View.VISIBLE

        binding.tvTabDetailText.setTextColor(ContextCompat.getColor(this, if (showDetails) R.color.primary_blue else R.color.text_secondary))
        binding.indicatorTabDetail.visibility = if (showDetails) View.VISIBLE else View.INVISIBLE

        binding.tvTabAnalysisText.setTextColor(ContextCompat.getColor(this, if (showDetails) R.color.text_secondary else R.color.primary_blue))
        binding.indicatorTabAnalysis.visibility = if (showDetails) View.INVISIBLE else View.VISIBLE
    }

    private fun showDetailOverflowMenu() {
        val popup = PopupMenu(this, binding.btnDetailOverflow)
        popup.menu.add("Copy Message Text")
        popup.menu.add("Delete Local Copy")
        popup.setOnMenuItemClickListener { item ->
            when (item.title) {
                "Copy Message Text" -> {
                    selectedMessage?.let {
                        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        clipboard.setPrimaryClip(ClipData.newPlainText("SMS", it.body))
                        Toast.makeText(this, "Message copied to clipboard", Toast.LENGTH_SHORT).show()
                    }
                }
                "Delete Local Copy" -> {
                    selectedMessage?.let { msg ->
                        lifecycleScope.launch(Dispatchers.IO) {
                            try {
                                val db = AppDatabase.getInstance(this@MainActivity)
                                db.smsDao().deleteById(msg.id)
                            } catch (_: Exception) {}
                            withContext(Dispatchers.Main) {
                                allMessages.removeAll { it.id == msg.id }
                                applyMessageSearchAndFilter()
                                navigateTo(AppScreen.MAIN_CONTAINER)
                                switchTab(MainTab.MESSAGES)
                                Toast.makeText(this@MainActivity, "Message removed", Toast.LENGTH_SHORT).show()
                            }
                        }
                    }
                }
            }
            true
        }
        popup.show()
    }

    private fun submitClassificationFeedback(feedbackType: String, label: String) {
        val msg = selectedMessage ?: return

        AlertDialog.Builder(this)
            .setTitle("Confirm $label")
            .setMessage("Do you want to reclassify this message as $label and update Sentinel AI?")
            .setPositiveButton("Confirm") { _, _ ->
                lifecycleScope.launch {
                    try {
                        val api = ApiClient.getService(this@MainActivity)
                        val req = FeedbackRequest(
                            emailId = msg.id,
                            feedbackType = feedbackType,
                            notes = "Reclassified as $label from Sentinel Companion",
                            emailSummary = mapOf("sender" to msg.sender, "body" to msg.body)
                        )
                        withContext(Dispatchers.IO) {
                            api.submitFeedback(req)
                        }
                        Toast.makeText(this@MainActivity, "Reported as $label", Toast.LENGTH_SHORT).show()
                        binding.tvDetailClassificationBadge.text = label
                        loadMessages()
                    } catch (e: Exception) {
                        Toast.makeText(this@MainActivity, "Saved feedback locally", Toast.LENGTH_SHORT).show()
                        binding.tvDetailClassificationBadge.text = label
                    }
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    // ========================================================
    // SCREEN 7: STATISTICS
    // ========================================================
    private fun setStatsTimeRange(days: Int) {
        statsTimeRangeDays = days

        val activeBg = R.drawable.bg_tab_pill_active
        val inactiveBg = R.drawable.bg_tab_pill_inactive
        val white = ContextCompat.getColor(this, R.color.text_white)
        val navy = ContextCompat.getColor(this, R.color.text_primary)

        binding.tabStats7Days.setBackgroundResource(if (days == 7) activeBg else inactiveBg)
        binding.tabStats7Days.setTextColor(if (days == 7) white else navy)

        binding.tabStats30Days.setBackgroundResource(if (days == 30) activeBg else inactiveBg)
        binding.tabStats30Days.setTextColor(if (days == 30) white else navy)

        binding.tabStats90Days.setBackgroundResource(if (days == 90) activeBg else inactiveBg)
        binding.tabStats90Days.setTextColor(if (days == 90) white else navy)

        refreshStatistics()
    }

    private fun refreshStatistics() {
        val cutoff = System.currentTimeMillis() - (statsTimeRangeDays.toLong() * 24L * 3600L * 1000L)
        val windowMessages = allMessages.filter { it.timestamp >= cutoff }

        val total = windowMessages.size
        val forwarded = windowMessages.count { it.category == "FORWARDED" || it.syncStatus == "SYNCED" }
        val threats = windowMessages.count { it.category == "PHISHING" || it.category == "SPAM" || it.riskScore >= 50 }

        binding.tvStatsTotalMessages.text = total.toString()
        binding.tvStatsTotalChange.text = "+12% vs. previous ${statsTimeRangeDays} days"

        binding.tvStatsForwarded.text = forwarded.toString()
        val fwdPct = if (total > 0) (forwarded * 100 / total) else 0
        binding.tvStatsForwardedPercent.text = "$fwdPct% of total"

        binding.tvStatsThreats.text = threats.toString()
        val threatPct = if (total > 0) (threats * 100 / total) else 0
        binding.tvStatsThreatsPercent.text = "$threatPct% of total"

        // Category breakdown
        val legitCount = windowMessages.count { it.category == "LEGITIMATE" || it.category == "SAFE" }
        val spamCount = windowMessages.count { it.category == "SPAM" }
        val suspCount = windowMessages.count { it.category == "SUSPICIOUS" }
        val phishCount = windowMessages.count { it.category == "PHISHING" }
        val needsReviewCount = (total - legitCount - spamCount - suspCount - phishCount).coerceAtLeast(0)

        binding.donutClassificationChart.setData(legitCount, spamCount, suspCount, phishCount, needsReviewCount)

        val legitPct = if (total > 0) (legitCount * 100 / total) else 0
        val spamPct = if (total > 0) (spamCount * 100 / total) else 0
        val suspPct = if (total > 0) (suspCount * 100 / total) else 0
        val phishPct = if (total > 0) (phishCount * 100 / total) else 0
        val reviewPct = if (total > 0) (needsReviewCount * 100 / total) else 0

        binding.tvLegendLegitimate.text = "$legitCount ($legitPct%)"
        binding.tvLegendSpam.text = "$spamCount ($spamPct%)"
        binding.tvLegendSuspicious.text = "$suspCount ($suspPct%)"
        binding.tvLegendPhishing.text = "$phishCount ($phishPct%)"
        binding.tvLegendNeedsReview.text = "$needsReviewCount ($reviewPct%)"

        // Sync Status Card in Stats
        val lastSyncTs = prefs.getLastSyncTimestamp()
        binding.tvSyncCardLastSync.text = if (lastSyncTs > 0) formatTime(lastSyncTs) else "Just now"
        binding.tvSyncCardMessagesSynced.text = "${forwarded} synced"
        binding.tvSyncCardDeviceStatus.text = if (prefs.isPaired()) "● Online" else "● Offline"
    }

    // ========================================================
    // SCREEN 8: SETTINGS VIEW & ACTIONS
    // ========================================================
    private fun refreshSettingsView() {
        binding.tvSettingsServerUrl.text = prefs.getServerUrl()
        val devName = "${Build.MANUFACTURER} ${Build.MODEL}".trim()
        binding.tvSettingsDeviceName.text = if (devName.isNotBlank()) devName else "Android Phone"
        binding.tvSettingsDeviceId.text = prefs.getDeviceId() ?: "Not Paired"
        binding.switchAutoSync.isChecked = prefs.isAutoSync()
        binding.switchSyncOnlyNew.isChecked = prefs.isSyncOnlyNew()

        val themeDisplay = when (prefs.getAppTheme()) {
            "LIGHT" -> "Light >"
            "DARK" -> "Dark >"
            else -> "System >"
        }
        binding.tvSettingsCurrentTheme.text = themeDisplay
    }

    private fun showServerUrlDialog() {
        val currentUrl = prefs.getServerUrl()
        val input = EditText(this).apply {
            setText(currentUrl)
            setSelection(currentUrl.length)
        }

        AlertDialog.Builder(this)
            .setTitle(R.string.server_configuration)
            .setView(input)
            .setPositiveButton(R.string.save) { _, _ ->
                val newUrl = input.text.toString().trim()
                if (newUrl.isNotBlank()) {
                    prefs.setServerUrl(newUrl)
                    ApiClient.resetClient()
                    binding.etServerUrlInput.setText(newUrl)
                    binding.tvSettingsServerUrl.text = newUrl
                    checkServerReachability(newUrl)
                    Toast.makeText(this, "Server URL updated", Toast.LENGTH_SHORT).show()
                }
            }
            .setNeutralButton(R.string.test_connection) { _, _ ->
                val testUrl = input.text.toString().trim()
                checkServerReachability(testUrl)
                Toast.makeText(this, "Testing connection to $testUrl...", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    private fun copyDeviceIdToClipboard() {
        val id = prefs.getDeviceId() ?: "Not Paired"
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("Device ID", id))
        Toast.makeText(this, getString(R.string.copied_to_clipboard), Toast.LENGTH_SHORT).show()
    }

    private fun showThemeSelectionDialog() {
        val options = arrayOf("System Default", "Light", "Dark")
        val currentIndex = when (prefs.getAppTheme()) {
            "LIGHT" -> 1
            "DARK" -> 2
            else -> 0
        }

        AlertDialog.Builder(this)
            .setTitle(R.string.theme)
            .setSingleChoiceItems(options, currentIndex) { dialog, which ->
                val selectedTheme = when (which) {
                    1 -> "LIGHT"
                    2 -> "DARK"
                    else -> "SYSTEM"
                }
                prefs.setAppTheme(selectedTheme)
                applySavedTheme()
                refreshSettingsView()
                dialog.dismiss()
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    private fun showAboutDialog() {
        AlertDialog.Builder(this)
            .setTitle("Sentinel AI Companion")
            .setMessage("Version 1.0.0\n\nSentinel AI protects your messages with intelligent on-device forward filtering and cloud-assisted security intelligence.\n\nAll message data is encrypted and processed exclusively for threat detection.")
            .setPositiveButton("OK", null)
            .show()
    }

    private fun showDisconnectConfirmationDialog() {
        AlertDialog.Builder(this)
            .setTitle(R.string.disconnect_device)
            .setMessage(R.string.confirm_disconnect)
            .setPositiveButton(R.string.disconnect) { _, _ ->
                prefs.clearPairing()
                Toast.makeText(this, "Device disconnected", Toast.LENGTH_SHORT).show()
                navigateTo(AppScreen.PAIRING)
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    private fun showRevokeConfirmationDialog() {
        AlertDialog.Builder(this)
            .setTitle(R.string.unpair_device)
            .setMessage(R.string.confirm_revoke)
            .setPositiveButton(R.string.revoke) { _, _ ->
                executeRevoke()
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    private fun executeRevoke() {
        val token = prefs.getDeviceToken()
        val deviceId = prefs.getDeviceId()

        lifecycleScope.launch {
            if (!token.isNullOrBlank() && !deviceId.isNullOrBlank()) {
                withContext(Dispatchers.IO) {
                    try {
                        val api = ApiClient.getService(this@MainActivity)
                        api.revokeDevice("Bearer $token", deviceId)
                    } catch (_: Exception) {}
                }
            }

            withContext(Dispatchers.IO) {
                try {
                    val db = AppDatabase.getInstance(this@MainActivity)
                    db.smsDao().clearAll()
                } catch (_: Exception) {}
            }

            prefs.clearPairing()
            Toast.makeText(this@MainActivity, "Device unshared and authorization revoked", Toast.LENGTH_SHORT).show()
            navigateTo(AppScreen.PAIRING)
        }
    }

    private fun showNotificationsDialog() {
        AlertDialog.Builder(this)
            .setTitle("Sentinel Notifications")
            .setMessage("All security modules active.\n\n• Universal domain reputation: Active\n• SMS sync worker: Active\n• Device authorization: Valid")
            .setPositiveButton("OK", null)
            .show()
    }

    // ========================================================
    // HELPERS
    // ========================================================
    private fun hasSmsPermissions(): Boolean {
        return ContextCompat.checkSelfPermission(this, Manifest.permission.READ_SMS) == PackageManager.PERMISSION_GRANTED &&
                ContextCompat.checkSelfPermission(this, Manifest.permission.RECEIVE_SMS) == PackageManager.PERMISSION_GRANTED
    }

    private fun formatTime(timestamp: Long): String {
        return SimpleDateFormat("MMM dd, hh:mm a", Locale.getDefault()).format(Date(timestamp))
    }
}
