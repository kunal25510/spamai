# 🛡️ Sentinel AI Android Companion App
## Automatic Phone SMS Scam Defense Integration

The **Sentinel Android Companion** is a dedicated mobile security agent designed to bridge your Android smartphone with the **Sentinel AI Security Engine**. It monitors incoming SMS notifications in real-time, inspects message contents against Sentinel's AI threat models, and immediately alerts you if an incoming message is a fraudulent scam.

---

## 📱 Android SMS Policy & Technical Architecture

### Google Play Restrictions & Default SMS App Requirements
Google Play and modern Android versions (Android 10 through 14+) enforce strict privacy restrictions on reading SMS messages:
1. **`RECEIVE_SMS` & `READ_SMS` Policies**:
   - Google Play restricts `RECEIVE_SMS` permissions **exclusively to the user's default SMS application**.
   - If a security app requests `RECEIVE_SMS`, Google Play requires the user to replace Google Messages or Samsung Messages with the third-party app as their primary SMS handler.
2. **The Compliant & User-Friendly Solution: `NotificationListenerService`**:
   - Sentinel utilizes Android's official `NotificationListenerService` (`android.permission.BIND_NOTIFICATION_LISTENER_SERVICE`).
   - **Why this is superior:**
     - **No default app replacement:** You keep using your favorite SMS app (Google Messages, Samsung Messages, Truecaller, etc.).
     - **OS-Level User Consent:** Android requires users to explicitly grant notification access in **Settings > Notification Access**.
     - **Zero Secret Access:** The app cannot secretly poll your entire inbox history or read private messages behind your back; it only receives notifications when a new message arrives with your active consent.
3. **Optional Sideloaded / Enterprise Mode (`SMS_RECEIVED`)**:
   - For internal deployments or sideloaded APKs where the user explicitly grants `RECEIVE_SMS`, Sentinel also includes a standalone `SmsBroadcastReceiver`.

---

## 🔄 How the Automatic Detection Pipeline Works

```
[ Incoming SMS on Phone ]
       │
       ▼
[ Android Notification Generated (e.g. from Google Messages) ]
       │
       ▼
[ SentinelNotificationListenerService intercepts Title & Text ]
       │
       ▼
[ Encrypted HTTP POST to Sentinel Backend (/api/sms/ingest) ]
       │
       ▼
[ Sentinel Hybrid AI Engine Evaluates Message + Embedded Links ]
       │
       ▼
[ Analysis Verdict: LOW, MEDIUM, or HIGH Risk ]
       │
       ├─────────────────────────────────┬─────────────────────────────────┐
       ▼                                 ▼                                 ▼
[ Display on Sentinel Web Dashboard ]    [ High Risk Scam Detected? ]      [ Safe Message ]
                                         │                                 │
                                         ▼                                 ▼
                         [ Push Immediate Android Warning ]      [ Silent / Safe Log ]
                         "🚨 CRITICAL SCAM DETECTED:
                          Fake Bank KYC lure from VK-SBIINB"
```

---

## 🛠️ Step-by-Step Setup & Pairing Guide

### 1. Configure the Sentinel Backend
Ensure your Sentinel AI backend is running on your computer:
```bash
cd spamai
npm run start-all
```
Your backend will run on `http://localhost:5000` (or your local network IP, e.g. `http://192.168.1.50:5000`).

### 2. Verify Your Phone on the Sentinel Web Dashboard
1. Open the Sentinel Web Dashboard at `http://localhost:5173`.
2. Click **Connect Phone** in the dashboard topbar or the Phone & SMS node card.
3. Enter your phone number with your country code (e.g. `+91 98765 43210` for India).
4. Enter the 6-digit verification code.
5. Once verified, Sentinel will generate your unique **Device Pairing Key** (e.g. `sentinel_pair_xxxx`).

### 3. Build & Install the Android Companion App
1. Open the `android-companion` directory in **Android Studio**.
2. Build the project:
   - Select **Build > Build Bundle(s) / APK(s) > Build APK(s)**.
3. Install the generated APK on your Android device (or run via USB Debugging).

### 4. Pair Your Phone
1. Open **Sentinel Companion** on your phone.
2. In the **Backend Server URL** field, enter your PC's IP address (e.g. `http://192.168.1.50:5000`).
3. Paste the **Device Pairing Key** from your web dashboard.
4. Tap **Grant Notification Access** and switch on Sentinel in your phone's Android Settings.
5. Tap **Enable Automatic Scam Detection**.

You're all set! Whenever an incoming SMS arrives on your phone, Sentinel will automatically inspect it, protect your device, and sync the intelligence to your Sentinel Command Center.
