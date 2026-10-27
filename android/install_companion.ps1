$adb = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"
$apk = "D:\agentai\spamai\android\SentinelCompanion\app\build\outputs\apk\debug\app-debug.apk"

if (-not (Test-Path $adb)) {
    Write-Error "adb.exe not found at $adb"
    exit 1
}

if (-not (Test-Path $apk)) {
    Write-Host "Building APK first..."
    Push-Location "D:\agentai\spamai\android\SentinelCompanion"
    ./gradlew.bat assembleDebug
    Pop-Location
}

Write-Host "Checking for connected Android devices via ADB..."
$devicesOutput = & $adb devices
Write-Host $devicesOutput

$deviceFound = $false
foreach ($line in ($devicesOutput -split "`n")) {
    if ($line -match "^\s*([^\s]+)\s+device\b") {
        $deviceFound = $true
        $deviceId = $matches[1]
        Write-Host "Found active authorized device: $deviceId"
        break
    }
}

if (-not $deviceFound) {
    Write-Host "Waiting for device authorization (please allow USB debugging on your phone screen)..."
    & $adb wait-for-device
}

Write-Host "Installing Sentinel Companion APK on device..."
& $adb install -r -d $apk

Write-Host "Configuring USB ADB reverse tunnel (tcp:5000 -> localhost:5000)..."
& $adb reverse tcp:5000 tcp:5000

Write-Host "Launching Sentinel AI Companion..."
& $adb shell am start -n com.sentinel.companion.debug/com.sentinel.companion.ui.MainActivity

Write-Host "Installation and launch complete! Companion can reach backend at http://localhost:5000 (via USB) or http://10.139.80.176:5000 (via Wi-Fi)."

