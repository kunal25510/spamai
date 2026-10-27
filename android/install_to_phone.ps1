$ErrorActionPreference = "Stop"

$adb = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"
if (-not (Test-Path $adb)) {
    Write-Error "adb.exe not found at $adb"
    exit 1
}

$apk = "D:\agentai\spamai\android\SentinelCompanion\app\build\outputs\apk\debug\app-debug.apk"
if (-not (Test-Path $apk)) {
    Write-Error "APK not found at $apk. Please run ./gradlew assembleDebug first."
    exit 1
}

Write-Host "Waiting for authorized Android device via USB..." -ForegroundColor Cyan

$maxAttempts = 60
$attempt = 0
$deviceFound = $false

while ($attempt -lt $maxAttempts) {
    $devicesOutput = & $adb devices
    $lines = $devicesOutput -split "`n" | Where-Object { $_ -match "\S" }
    
    foreach ($line in $lines) {
        if ($line -match "^([A-Za-z0-9_-]+)\s+device$") {
            $serial = $Matches[1]
            Write-Host "Found authorized device: $serial" -ForegroundColor Green
            $deviceFound = $true
            break
        } elseif ($line -match "^([A-Za-z0-9_-]+)\s+unauthorized$") {
            Write-Host "Device detected ($($Matches[1])) but UNAUTHORIZED! Check phone screen and tap 'Allow USB debugging'." -ForegroundColor Yellow
        }
    }
    
    if ($deviceFound) {
        break
    }
    
    Start-Sleep -Seconds 2
    $attempt++
}

if (-not $deviceFound) {
    Write-Warning "No authorized device detected yet. Make sure USB Debugging is turned ON."
    exit 2
}

Write-Host "Setting up port reverse (tcp:5000 -> tcp:5000) for seamless USB backend connection..." -ForegroundColor Cyan
& $adb reverse tcp:5000 tcp:5000

Write-Host "Installing Sentinel Companion APK..." -ForegroundColor Cyan
& $adb install -r -t $apk

Write-Host "Launching Sentinel Companion on phone..." -ForegroundColor Green
& $adb shell am start -n com.sentinel.companion.debug/com.sentinel.companion.ui.MainActivity

Write-Host "`nSUCCESS! Sentinel Companion is now running on your mobile device." -ForegroundColor Green
