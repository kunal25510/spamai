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
| `frontend/src/App.jsx` | **User Interface (React)** | Displays the dashboard, live threat list, security score counter, and buttons. |
| `backend/server.js` | **Gateway & API Server (Node.js)** | Connects to Gmail, pulls emails fast using `Promise.all`, and sends text to the Python AI. |
| `ai/ai_server.py` | **Master Decision Server (Python Flask)** | Receives email text, calls all AI methods, checks trusted Whitelists, and makes the final decision. |
| `ai/security_rules.py` | **Rule-Based System (Forward Chaining)** | Looks for keyword traps like *"sign in"*, *"confirm access"*, *"account suspended"*, and suspicious `http://` links. |
| `ai/train_model.py` | **Machine Learning Trainer** | Teaches the AI using past scam emails. Uses **Logistic Regression** and **TF-IDF** word patterns. |
| `ai/predict.py` | **Machine Learning Classifier** | Takes a new email and gives an ML score (e.g., 85% probability it is phishing). |
| `ai/bayes_risk.py` | **Naive Bayes Math** | Calculates word statistics (e.g., how often words like "winner" or "verify" appear in scams vs normal emails). |
| `ai/fuzzy_risk.py` | **Fuzzy Logic Engine** | Measures "gray area" risk like email tone, link counts, and domain trust. |

---

## ⚖️ How Sentinel Avoids Errors

1. **How it stops False Positives (Good emails marked bad):**
   - Legitimate emails like **Google Security Alerts**, **IPPB Banking**, or **ZeroSSL** contain words like "security" or "account".
   - Sentinel has a **Trusted Service Whitelist** (`ai/ai_server.py`). If the sender is official Google or IPPB, Sentinel immediately knows it's genuine and flags it **LOW RISK**.

2. **How it stops False Negatives (Bad emails marked good):**
   - Fake "Document Access" emails say *"Click here to view document"*.
   - Even if the AI model is uncertain, `security_rules.py` detects the combination of `link` + `document sign-in lure` and forces the risk to **HIGH**.

---

## 🚀 Summary

Sentinel uses a **hybrid approach** (Rules + Machine Learning + Whitelists + Fuzzy Logic) so it acts like a smart human security expert: quick, accurate, and reliable.
