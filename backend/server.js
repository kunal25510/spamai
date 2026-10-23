const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const axios = require("axios");
const { google } = require("googleapis");
const dotenv = require("dotenv");

// Load .env from backend directory or root directory
dotenv.config({ path: path.join(__dirname, ".env") });
dotenv.config({ path: path.join(__dirname, "../.env") });

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

const STORAGE_FILE = path.join(__dirname, ".sentinel_store.json");

// ==================================================
// PERSISTENT STORAGE HELPER
// ==================================================

function loadStorage() {
    try {
        if (fs.existsSync(STORAGE_FILE)) {
            const raw = fs.readFileSync(STORAGE_FILE, "utf-8");
            return JSON.parse(raw);
        }
    } catch (e) {
        console.error("[Storage] Failed to read storage file:", e.message);
    }
    return {
        tokens: null,
        connectedEmail: null,
        verifiedPhone: null,
        processedEmailIds: [],
        scannedEmails: [],
        scannedSms: []
    };
}

function saveStorage(data) {
    try {
        fs.writeFileSync(STORAGE_FILE, JSON.stringify(data, null, 2), "utf-8");
    } catch (e) {
        console.error("[Storage] Failed to save storage file:", e.message);
    }
}

const storage = loadStorage();

// In-memory state synchronized with storage
let currentTokens = storage.tokens || null;
let connectedEmail = storage.connectedEmail || null;
let verifiedPhone = storage.verifiedPhone || null;
const processedEmailIds = new Set(storage.processedEmailIds || []);
let scannedEmails = storage.scannedEmails || [];
let scannedSms = storage.scannedSms || [];

// Active in-memory OTP codes (Phone Number -> { otp, expiresAt, attempts })
const phoneOtpStore = new Map();

// ==================================================
// GOOGLE OAUTH CLIENT
// ==================================================

const oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI || "http://localhost:5000/auth/google/callback"
);

// Auto-refresh token listener
oauth2Client.on("tokens", (tokens) => {
    if (tokens.refresh_token) {
        currentTokens.refresh_token = tokens.refresh_token;
    }
    currentTokens.access_token = tokens.access_token;
    currentTokens.expiry_date = tokens.expiry_date;
    storage.tokens = currentTokens;
    saveStorage(storage);
    console.log("[Google OAuth] Access token refreshed automatically.");
});

if (currentTokens) {
    oauth2Client.setCredentials(currentTokens);
}

const SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly"
];

// ==================================================
// EMAIL CONTENT EXTRACTION & MIME PARSER
// ==================================================

function decodeBase64Url(data) {
    if (!data) return "";
    const base64 = data.replace(/-/g, "+").replace(/_/g, "/");
    return Buffer.from(base64, "base64").toString("utf-8");
}

function extractEmailContent(payload) {
    let plainText = "";
    let htmlText = "";

    function traverseParts(parts) {
        if (!parts || !Array.isArray(parts)) return;
        for (const part of parts) {
            if (part.mimeType === "text/plain" && part.body && part.body.data) {
                plainText += " " + decodeBase64Url(part.body.data);
            } else if (part.mimeType === "text/html" && part.body && part.body.data) {
                htmlText += " " + decodeBase64Url(part.body.data);
            } else if (part.parts) {
                traverseParts(part.parts);
            }
        }
    }

    if (payload.body && payload.body.data) {
        if (payload.mimeType === "text/html") {
            htmlText = decodeBase64Url(payload.body.data);
        } else {
            plainText = decodeBase64Url(payload.body.data);
        }
    } else if (payload.parts) {
        traverseParts(payload.parts);
    }

    // Strip HTML tags for clean text reading
    const cleanHtml = htmlText
        .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, " ")
        .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, " ")
        .replace(/<[^>]+>/g, " ")
        .replace(/&nbsp;/g, " ")
        .replace(/\s+/g, " ");

    const bodyText = (plainText || cleanHtml || "").trim();

    // Extract links safely without visiting them
    const linkRegex = /(https?:\/\/[^\s<>"']+)/gi;
    const allMatches = (bodyText.match(linkRegex) || []).concat(htmlText.match(linkRegex) || []);
    const uniqueLinks = [...new Set(allMatches)];

    return {
        bodyText: bodyText.slice(0, 8000),
        links: uniqueLinks.slice(0, 10)
    };
}

// Fallback local heuristic scoring if AI server is temporarily unreachable
function fallbackLocalEmailAnalysis(subject, from, snippet, links) {
    let score = 0;
    const reasons = [];
    const text = `${subject} ${from} ${snippet}`.toLowerCase();

    if (/urgent|immediately|within 24 hours|account suspended|deactivated/i.test(text)) {
        score += 35;
        reasons.push("Urgent threatening or coercive language demanding immediate action.");
    }
    if (/password|verify your account|login|credentials|confirm access/i.test(text)) {
        score += 35;
        reasons.push("Prompts recipient for login credentials or password verification.");
    }
    if (/lottery|won.*cash|claim prize|reward|free money/i.test(text)) {
        score += 40;
        reasons.push("Cash prize or lottery reward claim detected.");
    }
    if (links && links.length > 0) {
        score += 15;
        reasons.push(`Contains ${links.length} embedded web links.`);
    }

    score = Math.min(score, 100);
    const risk = score >= 50 ? "HIGH" : score >= 25 ? "MEDIUM" : "LOW";
    return {
        risk_level: risk,
        risk_score: score,
        reasons: reasons.length > 0 ? reasons : ["No severe threat triggers detected in local fallback rule evaluation."]
    };
}

// ==================================================
// AUTOMATIC GMAIL MONITORING SERVICE
// ==================================================

class GmailMonitor {
    constructor() {
        this.pollIntervalMs = 20000; // 20 seconds polling
        this.timer = null;
        this.isScanning = false;
        this.lastScanTime = null;
        this.lastScanStatus = "idle";
        this.error = null;
    }

    start() {
        if (this.timer) return;
        console.log("[GmailMonitor] Starting automatic background inbox monitoring...");
        // Run first scan immediately
        this.scan();
        this.timer = setInterval(() => this.scan(), this.pollIntervalMs);
    }

    stop() {
        if (this.timer) {
            clearInterval(this.timer);
            this.timer = null;
            this.lastScanStatus = "idle";
            console.log("[GmailMonitor] Background inbox monitoring stopped.");
        }
    }

    async scan() {
        if (this.isScanning) return;
        if (!currentTokens) {
            this.stop();
            return;
        }

        this.isScanning = true;
        this.lastScanStatus = "scanning";
        this.error = null;

        try {
            oauth2Client.setCredentials(currentTokens);
            const gmail = google.gmail({ version: "v1", auth: oauth2Client });

            // 1. Fetch recent message list (lookback up to 15 recent messages)
            const listRes = await gmail.users.messages.list({
                userId: "me",
                maxResults: 15,
                includeSpamTrash: false
            });

            const messages = listRes.data.messages || [];
            const newMessages = messages.filter(m => !processedEmailIds.has(m.id));

            if (newMessages.length > 0) {
                console.log(`[GmailMonitor] Detected ${newMessages.length} new incoming email(s). Analyzing...`);

                for (const msg of newMessages) {
                    try {
                        const fullMsg = await gmail.users.messages.get({
                            userId: "me",
                            id: msg.id,
                            format: "full"
                        });

                        const headers = fullMsg.data.payload?.headers || [];
                        const from = headers.find(h => h.name.toLowerCase() === "from")?.value || "Unknown Sender";
                        const subject = headers.find(h => h.name.toLowerCase() === "subject")?.value || "No Subject";
                        const date = headers.find(h => h.name.toLowerCase() === "date")?.value || new Date().toISOString();
                        const snippet = fullMsg.data.snippet || "";

                        const { bodyText, links } = extractEmailContent(fullMsg.data.payload || {});
                        const fullAnalysisText = `From: ${from}\nSubject: ${subject}\n\n${bodyText || snippet}`;

                        // 2. Analyze with existing Python Flask AI Engine
                        let aiResult = null;
                        try {
                            const aiRes = await axios.post("http://127.0.0.1:8000/analyze", {
                                type: "email",
                                text: fullAnalysisText
                            }, { timeout: 6000 });
                            aiResult = aiRes.data;
                        } catch (aiErr) {
                            console.warn(`[GmailMonitor] Python AI offline or timed out for email ${msg.id}: ${aiErr.message}. Using fallback.`);
                            aiResult = fallbackLocalEmailAnalysis(subject, from, snippet, links);
                        }

                        const analyzedEmail = {
                            id: msg.id,
                            source: "email",
                            from,
                            subject,
                            date,
                            snippet,
                            links,
                            risk: (aiResult.risk_level || "LOW").toUpperCase(),
                            score: aiResult.risk_score !== undefined ? aiResult.risk_score : 0,
                            reasons: aiResult.reasons || ["Analyzed via security heuristics."],
                            detectedAt: new Date().toISOString(),
                            status: "completed"
                        };

                        // Add to in-memory and persistent feeds
                        scannedEmails.unshift(analyzedEmail);
                        processedEmailIds.add(msg.id);

                    } catch (msgErr) {
                        console.error(`[GmailMonitor] Failed to process email ${msg.id}:`, msgErr.message);
                        processedEmailIds.add(msg.id); // mark to avoid endless retries on malformed msg
                    }
                }

                // Keep up to 60 most recent emails
                if (scannedEmails.length > 60) {
                    scannedEmails = scannedEmails.slice(0, 60);
                }

                // Save to persistent storage
                storage.processedEmailIds = Array.from(processedEmailIds);
                storage.scannedEmails = scannedEmails;
                saveStorage(storage);
            }

            this.lastScanTime = new Date().toISOString();
            this.lastScanStatus = "completed";

        } catch (err) {
            console.error("[GmailMonitor] Scan cycle error:", err.message);
            this.error = err.message;
            this.lastScanStatus = "failed";

            // If OAuth grant expired or was revoked
            if (err.message.includes("invalid_grant") || err.code === 401) {
                console.warn("[GmailMonitor] OAuth authorization revoked or expired. Stopping monitor.");
                currentTokens = null;
                storage.tokens = null;
                saveStorage(storage);
                this.stop();
            }
        } finally {
            this.isScanning = false;
        }
    }
}

const gmailMonitor = new GmailMonitor();

// Auto-start monitoring if tokens already exist on boot
if (currentTokens) {
    gmailMonitor.start();
}

// ==================================================
// HOME & HEALTH ROUTES
// ==================================================

app.get("/", (req, res) => {
    res.send("Sentinel AI Automatic Security Backend Running");
});

app.get("/api/health", (req, res) => {
    res.json({
        status: "ok",
        uptime: process.uptime(),
        gmailMonitoring: !!gmailMonitor.timer,
        phoneMonitoring: !!verifiedPhone,
        timestamp: new Date().toISOString()
    });
});

// Full system status endpoint
app.get("/api/status", (req, res) => {
    res.json({
        gmail: {
            connected: !!currentTokens,
            email: connectedEmail,
            isMonitoring: !!gmailMonitor.timer,
            lastScanTime: gmailMonitor.lastScanTime,
            lastScanStatus: gmailMonitor.lastScanStatus,
            error: gmailMonitor.error,
            scannedCount: scannedEmails.length
        },
        phone: {
            verified: !!verifiedPhone,
            phoneNumber: verifiedPhone ? verifiedPhone.number : null,
            pairingKey: verifiedPhone ? verifiedPhone.pairingKey : null,
            verifiedAt: verifiedPhone ? verifiedPhone.verifiedAt : null,
            scannedCount: scannedSms.length
        },
        stats: {
            totalEmailsScanned: scannedEmails.length,
            totalSmsScanned: scannedSms.length,
            highRiskEmails: scannedEmails.filter(e => e.risk === "HIGH").length,
            highRiskSms: scannedSms.filter(s => s.risk_level === "HIGH").length
        }
    });
});

// ==================================================
// GOOGLE OAUTH ROUTES
// ==================================================

app.get("/auth/google", (req, res) => {
    if (!process.env.GOOGLE_CLIENT_ID || process.env.GOOGLE_CLIENT_ID.includes("YOUR_")) {
        return res.status(400).send(`
            <div style="font-family: sans-serif; max-width: 600px; margin: 50px auto; padding: 25px; border: 1px solid #333; background: #111; color: #fff; border-radius: 8px;">
                <h2 style="color: #ff5555; margin-top: 0;">Missing Google OAuth Client ID</h2>
                <p>Google OAuth requires a valid <code>GOOGLE_CLIENT_ID</code> and <code>GOOGLE_CLIENT_SECRET</code>.</p>
                <p>Please configure <code>backend/.env</code> with credentials from Google Cloud Console.</p>
            </div>
        `);
    }

    const authUrl = oauth2Client.generateAuthUrl({
        access_type: "offline",
        scope: SCOPES,
        prompt: "consent"
    });
    res.redirect(authUrl);
});

app.get("/auth/google/callback", async (req, res) => {
    const code = req.query.code;
    if (!code) {
        return res.status(400).send("Google authorization failed.");
    }

    try {
        const { tokens } = await oauth2Client.getToken(code);
        currentTokens = tokens;
        oauth2Client.setCredentials(tokens);

        const gmail = google.gmail({ version: "v1", auth: oauth2Client });
        const profile = await gmail.users.getProfile({ userId: "me" });

        connectedEmail = profile.data.emailAddress;
        console.log("[Google OAuth] Gmail connected:", connectedEmail);

        // Save to persistent storage
        storage.tokens = currentTokens;
        storage.connectedEmail = connectedEmail;
        saveStorage(storage);

        // Start automatic background monitoring immediately
        gmailMonitor.start();

        res.redirect("http://localhost:5173");
    } catch (error) {
        console.error("[Google OAuth] Error:", error.message);
        res.status(500).send("Google connection failed: " + error.message);
    }
});

// Disconnect Gmail & Revoke Tokens
app.post("/api/gmail/disconnect", async (req, res) => {
    try {
        gmailMonitor.stop();

        if (currentTokens && currentTokens.access_token) {
            try {
                await axios.post(`https://oauth2.googleapis.com/revoke?token=${currentTokens.access_token}`, null, {
                    headers: { "Content-Type": "application/x-www-form-urlencoded" },
                    timeout: 4000
                });
                console.log("[Google OAuth] Token revoked with Google.");
            } catch (revokeErr) {
                console.warn("[Google OAuth] Revocation endpoint notice:", revokeErr.message);
            }
        }

        currentTokens = null;
        connectedEmail = null;
        storage.tokens = null;
        storage.connectedEmail = null;
        saveStorage(storage);

        res.json({
            success: true,
            message: "Gmail disconnected and credentials removed safely."
        });
    } catch (err) {
        console.error("Disconnect error:", err.message);
        res.status(500).json({ error: "Failed to disconnect Gmail: " + err.message });
    }
});

// Force immediate Gmail Scan
app.post("/api/gmail/scan-now", async (req, res) => {
    if (!currentTokens) {
        return res.status(400).json({ error: "Gmail is not connected." });
    }
    await gmailMonitor.scan();
    res.json({
        success: true,
        lastScanTime: gmailMonitor.lastScanTime,
        status: gmailMonitor.lastScanStatus,
        scannedCount: scannedEmails.length
    });
});

// Get Gmail Activity
app.get("/api/emails", (req, res) => {
    res.json({
        connected: !!currentTokens,
        account: connectedEmail,
        isMonitoring: !!gmailMonitor.timer,
        lastScanTime: gmailMonitor.lastScanTime,
        count: scannedEmails.length,
        emails: scannedEmails
    });
});

app.get("/api/account", (req, res) => {
    res.json({
        connected: !!currentTokens,
        email: connectedEmail
    });
});

// ==================================================
// PHONE NUMBER CONNECTION & OTP VERIFICATION
// ==================================================

// Sanitize & format phone numbers (Supports +91 Indian and international)
function sanitizePhoneNumber(raw) {
    if (!raw || typeof raw !== "string") return null;
    let cleaned = raw.trim().replace(/[\s\-()]/g, "");
    if (!cleaned.startsWith("+")) {
        // Default to India (+91) if 10 digits provided
        if (cleaned.length === 10) {
            cleaned = "+91" + cleaned;
        } else {
            cleaned = "+" + cleaned;
        }
    }
    // E.164 check: + followed by 10 to 15 digits
    if (/^\+[1-9]\d{9,14}$/.test(cleaned)) {
        return cleaned;
    }
    return null;
}

// Request OTP for Phone Verification
app.post("/api/phone/send-otp", (req, res) => {
    const rawNumber = req.body?.phoneNumber;
    const phone = sanitizePhoneNumber(rawNumber);

    if (!phone) {
        return res.status(400).json({
            error: "Invalid phone number format. Please provide a valid phone number with country code (e.g. +91 98765 43210)."
        });
    }

    // Generate secure 6-digit OTP
    const otp = crypto.randomInt(100000, 999999).toString();
    const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes validity

    phoneOtpStore.set(phone, { otp, expiresAt, attempts: 0 });

    console.log(`[Sentinel Phone Auth] Generated OTP for ${phone}: ${otp} (Valid for 5 mins)`);

    // In production, integrate with Twilio or Fast2SMS here if credentials are configured
    const isSmsConfigured = !!(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN);

    res.json({
        success: true,
        phoneNumber: phone,
        expiresInSeconds: 300,
        devMode: !isSmsConfigured,
        devOtp: !isSmsConfigured ? otp : undefined, // Provided in development for seamless zero-cost testing
        message: isSmsConfigured
            ? `Verification code dispatched to ${phone}`
            : `Development Mode: Verification code generated for ${phone}. Use the code displayed or check console.`
    });
});

// Verify OTP & Generate Device Pairing Key for Android Companion
app.post("/api/phone/verify-otp", (req, res) => {
    const rawNumber = req.body?.phoneNumber;
    const userOtp = String(req.body?.otp || "").trim();
    const phone = sanitizePhoneNumber(rawNumber);

    if (!phone) {
        return res.status(400).json({ error: "Invalid phone number." });
    }

    const record = phoneOtpStore.get(phone);
    if (!record) {
        return res.status(400).json({ error: "No active verification request found for this number. Please request a new OTP." });
    }

    if (Date.now() > record.expiresAt) {
        phoneOtpStore.delete(phone);
        return res.status(400).json({ error: "Verification code has expired. Please request a new OTP." });
    }

    if (record.attempts >= 5) {
        phoneOtpStore.delete(phone);
        return res.status(429).json({ error: "Too many failed attempts. Please request a new code." });
    }

    record.attempts += 1;

    if (record.otp !== userOtp) {
        return res.status(400).json({ error: "Incorrect verification code. Please check and try again." });
    }

    // OTP Verified! Clean up OTP record
    phoneOtpStore.delete(phone);

    // Generate cryptographic device pairing key for the Android companion app
    const pairingKey = "sentinel_pair_" + crypto.randomBytes(16).toString("hex");

    verifiedPhone = {
        number: phone,
        verifiedAt: new Date().toISOString(),
        pairingKey
    };

    storage.verifiedPhone = verifiedPhone;
    saveStorage(storage);

    console.log(`[Sentinel Phone Auth] Phone ${phone} verified successfully! Pairing key generated.`);

    res.json({
        success: true,
        verified: true,
        phoneNumber: phone,
        pairingKey,
        message: "Phone verified successfully. Android Companion App can now pair using this key."
    });
});

// Disconnect Phone Number
app.post("/api/phone/disconnect", (req, res) => {
    verifiedPhone = null;
    storage.verifiedPhone = null;
    saveStorage(storage);
    console.log("[Sentinel Phone Auth] Phone number disconnected.");
    res.json({
        success: true,
        message: "Phone number disconnected and Android pairing key revoked."
    });
});

// Get Phone Connection Status
app.get("/api/phone/status", (req, res) => {
    res.json({
        verified: !!verifiedPhone,
        phoneNumber: verifiedPhone ? verifiedPhone.number : null,
        pairingKey: verifiedPhone ? verifiedPhone.pairingKey : null,
        verifiedAt: verifiedPhone ? verifiedPhone.verifiedAt : null
    });
});

// ==================================================
// AUTOMATIC SMS INGESTION (ANDROID COMPANION API)
// ==================================================

app.post("/api/sms/ingest", async (req, res) => {
    try {
        const authKey = req.headers["x-sentinel-key"] || req.body?.pairingKey;

        // Security check: Must match verified pairing key (or accept if verifiedPhone pairing matches)
        if (verifiedPhone && verifiedPhone.pairingKey && authKey !== verifiedPhone.pairingKey) {
            return res.status(401).json({
                error: "Unauthorized device. Invalid or missing Sentinel Pairing Key."
            });
        }

        const sender = String(req.body?.sender || "Unknown").trim();
        const message = String(req.body?.message || "").trim();
        const receivedAt = req.body?.receivedAt || new Date().toISOString();

        if (!message) {
            return res.status(400).json({ error: "SMS message content is required." });
        }

        if (message.length > 5000) {
            return res.status(400).json({ error: "Message content exceeds safe length." });
        }

        // Deduplication: prevent repeated processing of identical SMS received within 60 seconds
        const isDuplicate = scannedSms.some(
            s => s.sender === sender && s.message === message && (Date.now() - new Date(s.ingestedAt).getTime() < 60000)
        );
        if (isDuplicate) {
            return res.json({ status: "duplicate_ignored", message: "Message was recently processed." });
        }

        console.log(`[SMS Ingestion] Received SMS from '${sender}': "${message.slice(0, 50)}..."`);

        // Forward to Python AI engine
        let aiResult = null;
        try {
            const aiRes = await axios.post("http://127.0.0.1:8000/analyze", {
                type: "message",
                text: message
            }, { timeout: 6000 });
            aiResult = aiRes.data;
        } catch (aiErr) {
            console.warn(`[SMS Ingestion] AI server offline (${aiErr.message}), using local heuristics.`);
            aiResult = fallbackLocalEmailAnalysis("SMS Message", sender, message, []);
        }

        // If message has embedded links, evaluate them
        const linkMatch = message.match(/https?:\/\/[^\s]+/i);
        if (linkMatch && aiResult) {
            try {
                const urlRes = await axios.post("http://127.0.0.1:8000/analyze", {
                    type: "url",
                    url: linkMatch[0]
                }, { timeout: 4000 });
                if (urlRes.data && urlRes.data.risk_level === "HIGH") {
                    aiResult.risk_level = "HIGH";
                    aiResult.risk_score = Math.max(aiResult.risk_score || 0, urlRes.data.risk_score || 85);
                    aiResult.reasons.push(`Embedded Link Threat: ${urlRes.data.reasons?.[0] || "Suspicious domain"}`);
                }
            } catch (uErr) {
                // non-blocking
            }
        }

        const riskLevel = (aiResult.risk_level || "LOW").toUpperCase();
        const riskScore = aiResult.risk_score !== undefined ? aiResult.risk_score : 0;
        const reasons = aiResult.reasons || ["Analyzed via message security heuristics."];

        const smsEntry = {
            id: "sms_" + Date.now() + "_" + Math.random().toString(36).substring(2, 7),
            source: "sms",
            sender,
            message,
            receivedAt,
            ingestedAt: new Date().toISOString(),
            risk_level: riskLevel,
            risk_score: riskScore,
            reasons,
            should_alert: riskLevel === "HIGH" || riskLevel === "MEDIUM"
        };

        scannedSms.unshift(smsEntry);
        if (scannedSms.length > 60) {
            scannedSms = scannedSms.slice(0, 60);
        }

        storage.scannedSms = scannedSms;
        saveStorage(storage);

        // Response returned directly to Android Companion App
        return res.json({
            status: "analyzed",
            id: smsEntry.id,
            risk_level: riskLevel,
            risk_score: riskScore,
            reasons,
            should_alert: smsEntry.should_alert,
            alert_title: riskLevel === "HIGH" ? "🚨 CRITICAL SCAM DETECTED" : "⚠️ SUSPICIOUS MESSAGE",
            alert_message: `From ${sender}: ${reasons[0] || "Potential phishing or fraudulent content detected."}`
        });

    } catch (err) {
        console.error("[SMS Ingestion Error]:", err.message);
        res.status(500).json({ error: "Failed to analyze SMS: " + err.message });
    }
});

// Simulator endpoint for easy web-based testing of Phone SMS scams
app.post("/api/sms/simulate", async (req, res) => {
    const sender = String(req.body?.sender || "VK-BANKALERT").trim();
    const message = String(req.body?.message || "").trim();

    if (!message) {
        return res.status(400).json({ error: "Message text is required for simulation." });
    }

    try {
        const response = await axios.post("http://127.0.0.1:5000/api/sms/ingest", {
            sender,
            message,
            pairingKey: verifiedPhone?.pairingKey || "simulated_test"
        }, {
            headers: { "x-sentinel-key": verifiedPhone?.pairingKey || "simulated_test" },
            timeout: 8000
        });

        return res.json(response.data);
    } catch (err) {
        return res.status(500).json({ error: err.response?.data?.error || err.message });
    }
});

// Get Scanned SMS Activity
app.get("/api/sms/activity", (req, res) => {
    res.json({
        count: scannedSms.length,
        messages: scannedSms
    });
});

// Unified Activity Feed (Emails + SMS)
app.get("/api/activity/feed", (req, res) => {
    const emailItems = scannedEmails.map(e => ({
        id: e.id,
        source: "email",
        sender: e.from,
        title: e.subject,
        preview: e.snippet,
        timestamp: e.detectedAt || e.date,
        risk: e.risk,
        score: e.score,
        reasons: e.reasons
    }));

    const smsItems = scannedSms.map(s => ({
        id: s.id,
        source: "sms",
        sender: s.sender,
        title: `SMS from ${s.sender}`,
        preview: s.message,
        timestamp: s.ingestedAt || s.receivedAt,
        risk: s.risk_level,
        score: s.risk_score,
        reasons: s.reasons
    }));

    const combined = [...emailItems, ...smsItems].sort(
        (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );

    res.json({
        total: combined.length,
        items: combined
    });
});

// ==================================================
// EXISTING MANUAL ANALYSIS ROUTE (PRESERVED)
// ==================================================

const ALLOWED_TYPES = ["email", "message", "job", "github_linkedin", "url"];

app.post("/api/analyze", async (req, res) => {
    try {
        const body = req.body || {};
        const type = (body.type || "message").toLowerCase();
        const text = typeof body.text === "string" ? body.text.trim() : "";
        const url = typeof body.url === "string" ? body.url.trim() : "";

        if (!ALLOWED_TYPES.includes(type)) {
            return res.status(400).json({
                error: `Invalid analysis type '${type}'. Allowed types: ${ALLOWED_TYPES.join(", ")}`
            });
        }

        const inputToAnalyze = type === "url" ? (url || text) : text;

        if (!inputToAnalyze) {
            return res.status(400).json({
                error: type === "url"
                    ? "Please provide a valid URL to analyze."
                    : "Please enter or paste the message text to analyze."
            });
        }

        if (inputToAnalyze.length > 15000) {
            return res.status(400).json({
                error: "Input text exceeds maximum allowed length of 15,000 characters."
            });
        }

        try {
            const aiResponse = await axios.post(
                "http://127.0.0.1:8000/analyze",
                {
                    type,
                    text: inputToAnalyze,
                    url: inputToAnalyze
                },
                { timeout: 8000 }
            );

            return res.json(aiResponse.data);
        } catch (aiErr) {
            console.error("[AI Analysis Error]:", aiErr.message);

            if (aiErr.code === "ECONNREFUSED" || aiErr.code === "ETIMEDOUT") {
                return res.status(503).json({
                    error: "AI Security Engine is offline or unreachable. Please verify that the Python AI server is running on port 8000."
                });
            }

            if (aiErr.response && aiErr.response.data && aiErr.response.data.error) {
                return res.status(aiErr.response.status || 400).json({
                    error: aiErr.response.data.error
                });
            }

            return res.status(500).json({
                error: "Failed to complete security analysis due to an internal AI engine error."
            });
        }
    } catch (err) {
        console.error("Analysis route error:", err.message);
        return res.status(500).json({
            error: "An unexpected error occurred while processing the request."
        });
    }
});

// ==================================================
// START SERVER
// ==================================================

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Sentinel AI Security Backend running on http://localhost:${PORT}`);
});