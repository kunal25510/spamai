$adb = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"
$apk = "D:\agentai\spamai\android\SentinelCompanion\app\build\outputs\apk\debug\app-debug.apk"

Write-Host "Auto-installer daemon started. Waiting for phone USB debugging..." -ForegroundColor Cyan

while ($true) {
    $devs = & $adb devices
    if ($devs -match "\b([A-Za-z0-9_-]+)\s+device\b") {
        $serial = $Matches[1]
        Write-Host "Device detected: $serial" -ForegroundColor Green
        Write-Host "Configuring port reverse: tcp:5000 -> tcp:5000..." -ForegroundColor Cyan
        & $adb reverse tcp:5000 tcp:5000
        Write-Host "Installing APK directly to phone..." -ForegroundColor Cyan
        & $adb install -r -t $apk
        Write-Host "Launching Sentinel Companion on phone..." -ForegroundColor Green
        & $adb shell am start -n com.sentinel.companion.debug/com.sentinel.companion.ui.MainActivity
        Write-Host "ALL DONE! Application installed and running." -ForegroundColor Green
        break
    }
    Start-Sleep -Seconds 1
}
