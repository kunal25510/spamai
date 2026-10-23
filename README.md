# 🛡️ Sentinel AI Security Agent: Beginner-Friendly Guide

Welcome to the **Sentinel Security Agent** guide! This document explains in **simple terms** how the application works, step by step, and exactly which file or method handles each job.

---

## 💡 What is Sentinel?
**Sentinel** is an intelligent security system that acts like a personal guard for your Gmail inbox. It automatically reads incoming emails and tells you if an email is **SAFE (Low Risk)**, **SUSPICIOUS (Medium Risk)**, or a **DANGEROUS PHISHING SCAM (High Risk)**.

---

## 🔄 Step-by-Step: How the App Works

Imagine you are using Sentinel. Here is what happens behind the scenes in 5 simple steps:

```
[1. Open Sentinel UI] ➔ [2. Connect Gmail] ➔ [3. Fetch Latest Emails] ➔ [4. AI Deep Security Check] ➔ [5. See Results]
```

### 📍 Step 1: You Open the Sentinel App
- **What happens:** You open `http://localhost:5173` in your browser.
- **Where it happens:** `frontend/src/App.jsx`
- **What you see:** A sleek dark security dashboard that shows your current protection status.

---

### 📍 Step 2: You Click "Connect your Gmail"
- **What happens:** Sentinel asks Google for safe, **read-only permission** to check your inbox.
- **Where it happens:** `backend/server.js` (using Google OAuth 2.0).
- **Why it's safe:** Sentinel can **never** send emails, delete emails, or see your passwords. It only gets a temporary digital key to read text.

---

### 📍 Step 3: Sentinel Ingests Your Latest Emails
- **What happens:** Every few seconds, Sentinel asks Gmail: *"What are the latest 20 emails?"*
- **Where it happens:** `backend/server.js` (Route: `/api/emails`)
- **How it runs fast:** It fetches all 20 emails together in parallel using JavaScript `Promise.all` so your dashboard loads in 1-2 seconds.

---

### 📍 Step 4: Sentinel Runs 5 AI Security Checks on Each Email
- **What happens:** The backend sends the text of each email to the Python AI Engine (`http://127.0.0.1:8000/predict`).
- **Where it happens:** `ai/ai_server.py`
- **What the AI asks:**
  1. *Does this email come from a trusted company like Google, ZeroSSL, or IPPB?* (If yes, mark SAFE).
  2. *Is it asking you to click a link and type your password or sign in to view a document?* (If yes, flag as DANGEROUS PHISHING).
  3. *What does the Machine Learning model think based on past scam emails?*
  4. *What does Naive Bayes word analysis think?*
  5. *What does Fuzzy Logic tone analysis think?*

---

### 📍 Step 5: You See the Final Result on Your Screen
- **What happens:** The frontend displays:
  - 🟢 **LOW RISK (Green)**: Safe emails (e.g., Google Security Alert, newsletters, banking receipts).
  - 🟡 **MEDIUM RISK (Amber)**: Emails with slight urgency or unknown links.
  - 🔴 **HIGH RISK (Red)**: Fake document lures, fake login requests, or password stealing attempts.

---

## 🛠️ Which Method Works Where? (Plain Language Breakdown)

Here is a clear breakdown of every file in the project and what method it uses:

| File Name | Method / Component | Simple Explanation |
| :--- | :--- | :--- |
| `frontend/src/App.jsx` | **User Interface (React)** | Displays dashboard, Gmail scan status, and the 5-mode Threat Detection Workbench. |
| `backend/server.js` | **Gateway & API Server (Node.js)** | Connects to Gmail, validates inputs, and exposes `/api/analyze` to dispatch requests to the AI engine. |
| `ai/ai_server.py` | **Master Decision Server (Python Flask)** | Orchestrates multi-mode `/analyze`, batch predictions, and hybrid scoring. |
| `ai/url_analyzer.py` | **Safe Local URL Analyzer (Python)** | Parses URLs offline with `urllib`, checking lookalikes, IP hosts, shorteners, and credential paths without remote requests. |
| `ai/message_rules.py` | **Multi-Platform Heuristic Rules** | Detects SMS/WhatsApp scams, fake job registration fees, and GitHub/LinkedIn malicious script lures. |
| `ai/security_rules.py` | **Rule-Based System (Forward Chaining)** | Looks for keyword traps like *"sign in"*, *"confirm access"*, *"account suspended"*, and suspicious `http://` links. |
| `ai/train_model.py` | **Machine Learning Trainer** | Teaches the AI using past scam emails. Uses **Logistic Regression** and **TF-IDF** word patterns. |
| `ai/predict.py` | **Machine Learning Classifier** | Takes a new email and gives an ML score (e.g., 85% probability it is phishing). |
| `ai/bayes_risk.py` | **Naive Bayes Math** | Calculates word statistics (e.g., how often words like "winner" or "verify" appear in scams vs normal emails). |
| `ai/fuzzy_risk.py` | **Fuzzy Logic Engine** | Measures "gray area" risk like email tone, link counts, and domain trust. |

---

## 🚀 Sentinel AI: Automatic Multi-Channel Scam Defense

Sentinel is an automated scam detection system that continuously monitors your **Gmail inbox** and **Android smartphone SMS messages** in real time, alerting you to fraudulent lures, fake bank KYC threats, and credential phishing attempts.

---

## 🏗️ Architecture & Component Roles

```
 ┌──────────────────────────────────────────────────────────────┐
 │                      SENTINEL DASHBOARD                      │
 │                 React + Vite (localhost:5173)                │
 └──────────────┬───────────────────────────────▲───────────────┘
                │                               │
                ▼                               │ Live Feed / Alerts
 ┌──────────────────────────────────────────────┴───────────────┐
 │               SENTINEL API GATEWAY & MONITOR                 │
 │                  Node.js (localhost:5000)                    │
 │  • Auto-polls Gmail inbox (every 20s, deduplicates IDs)     │
 │  • Ingests incoming SMS from Android Companion               │
 │  • Handles Phone OTP verification & Device Pairing Key       │
 └──────────────┬───────────────────────────────▲───────────────┘
                │                               │
                ▼                               │ Verdict: LOW / MED / HIGH
 ┌──────────────────────────────────────────────┴───────────────┐
 │                  HYBRID AI SECURITY ENGINE                   │
 │                 Python Flask (localhost:8000)                │
 │  • TF-IDF Vectorizer + Logistic Regression Model             │
 │  • Forward-Chaining Security Expert Rules                    │
 │  • Bayesian Risk Probability Model                           │
 │  • Fuzzy Logic Uncertainty Engine                            │
 │  • Safe Offline URL Analysis (urllib local parser)           │
 └──────────────────────────────────────────────────────────────┘
```

---

## 🔑 Google Cloud Console & Gmail API Configuration

To enable automatic Gmail inbox scanning:

1. Go to the [Google Cloud Console](https://console.cloud.google.com/).
2. Create or select a project.
3. Enable the **Gmail API**:
   - Navigate to **APIs & Services > Library**.
   - Search for **Gmail API** and click **Enable**.
4. Configure the **OAuth Consent Screen**:
   - Choose **External** user type.
   - Enter your App name (e.g., `Sentinel AI`) and your developer email.
   - Under **Scopes**, add `https://www.googleapis.com/auth/gmail.readonly`.
   - Under **Test Users**, add your personal Gmail address.
5. Create OAuth Credentials:
   - Go to **APIs & Services > Credentials > Create Credentials > OAuth Client ID**.
   - Application type: **Web application**.
   - Authorized redirect URIs: `http://localhost:5000/auth/google/callback`.
6. Copy your **Client ID** and **Client Secret** into `backend/.env`:
   ```ini
   GOOGLE_CLIENT_ID=your_id.apps.googleusercontent.com
   GOOGLE_CLIENT_SECRET=your_client_secret
   GOOGLE_REDIRECT_URI=http://localhost:5000/auth/google/callback
   ```

### 🔒 Privacy & Permissions Guarantee
- **Read-Only:** Sentinel only requests `gmail.readonly`. It can never send, delete, or modify emails.
- **No Password Access:** Sentinel uses Google OAuth 2.0 temporary tokens. It never sees or stores your Google password.
- **Disconnect & Revoke:**
  - Click **Disconnect** in Sentinel anytime to delete tokens from the server.
  - Revoke permissions directly from your Google Account at [Google Account Permissions](https://myaccount.google.com/permissions).

---

## 📱 Automatic SMS Scam Detection (Android Companion)

Sentinel includes a native Android companion app located in [`android-companion/`](file:///c:/Users/Bhushan/Desktop/spamAI/spamai/android-companion/README.md).

### How it Works:
1. **Notification Access (`NotificationListenerService`)**:
   - Google Play restricts `RECEIVE_SMS` to default SMS apps. Sentinel uses Android's compliant `NotificationListenerService` instead.
   - You keep your favorite SMS app (Google Messages, Samsung Messages, Truecaller).
   - When an SMS arrives, Sentinel intercepts the notification, extracts sender & text, and forwards it to your Sentinel backend (`POST /api/sms/ingest`).
2. **Instant Threat Alert**:
   - If the AI engine flags the SMS as **HIGH** or **MEDIUM** risk, your phone immediately triggers a high-priority heads-up notification:
     *🚨 CRITICAL SCAM DETECTED: Bank KYC threat from VK-SBIINB*.
3. **Interactive Simulator**:
   - Don't have an Android device nearby? Test the defense live using the **Interactive SMS Simulator** on the Sentinel dashboard with 1 click!

---

## 💻 Operating Environment & Background Monitoring

- **Local Execution:** Automatic background polling and SMS ingestion continue actively as long as your Sentinel backend service is running on your computer.
- **Continuous 24/7 Deployment:** For non-stop monitoring when your PC is turned off, the backend and AI server can be deployed to any low-cost VPS (AWS EC2, DigitalOcean, or Render) with an HTTPS reverse proxy.

---

## 🚀 How to Run the Application

Run all three components simultaneously:

```bash
cd spamai
npm run start-all
```

- **Web Dashboard:** `http://localhost:5173`
- **Backend Gateway:** `http://localhost:5000`
- **AI Decision Node:** `http://127.0.0.1:8000`

