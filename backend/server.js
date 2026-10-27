const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const os = require("os");
const express = require("express");
const cors = require("cors");
const axios = require("axios");
const { google } = require("googleapis");
const dotenv = require("dotenv");
const { parseGmailMessage } = require("./emailParser");
const db = require("./database");
const detectionEngine = require("./detectionEngine");

const SENTINEL_PRIMARY_ACCOUNT = "sentinel_primary";

function getAccountId(req) {
    if (req.user && req.user.id) return req.user.id;
    if (req.device && req.device.account_id) return req.device.account_id;
    if (req.accountId) return req.accountId;
    return null;
}

// Load .env from backend directory or root directory
dotenv.config({ path: path.join(__dirname, ".env") });
dotenv.config({ path: path.join(__dirname, "../.env") });

const app = express();
app.use(cors());
app.use(express.json());

// Session and device authentication middleware for incoming API requests
app.use((req, res, next) => {
    // 1. Session token from X-Sentinel-Session or Authorization: Bearer sentinel_sess_...
    const sessionToken = req.headers["x-sentinel-session"] || 
        (req.headers.authorization && req.headers.authorization.startsWith("Bearer sentinel_sess_") 
            ? req.headers.authorization.slice(7).trim() 
            : null);

    // 2. Device token from Authorization: Bearer sentinel_dev_...
    const deviceToken = (req.headers.authorization && req.headers.authorization.startsWith("Bearer sentinel_dev_"))
        ? req.headers.authorization.slice(7).trim()
        : null;

    if (sessionToken) {
        req.rawSessionToken = sessionToken;
        const user = db.getSessionUser(sessionToken);
        if (user) {
            req.user = user;
            req.accountId = user.id;
            req.sessionToken = sessionToken;
        } else {
            req.sessionExpired = true;
        }
    } else if (deviceToken) {
        req.rawDeviceToken = deviceToken;
        const device = db.getDeviceByCredential(deviceToken);
        if (device) {
            if (device.status === "REVOKED") {
                req.deviceRevoked = true;
            } else {
                req.device = device;
                req.accountId = device.account_id;
            }
        } else {
            req.invalidDevice = true;
        }
    }

    // 3. Header inspection: Never trust an unauthenticated X-Sentinel-Account header
    const explicitAccountHeader = req.headers["x-sentinel-account"];
    if (explicitAccountHeader) {
        if (!req.accountId) {
            // Unauthenticated header supplied without a validated session or authorized device
            req.forgedAccountHeader = true;
        } else if (explicitAccountHeader !== req.accountId) {
            // Authenticated as one account, but attempting cross-account access via header
            req.crossAccountHeaderMismatch = true;
        }
    }

    next();
});

function requireAuth(req, res, next) {
    if (req.forgedAccountHeader) {
        return res.status(401).json({ error: "Unauthorized. Unauthenticated account header cannot be trusted." });
    }
    if (req.crossAccountHeaderMismatch) {
        return res.status(403).json({ error: "Forbidden. Account header does not match authenticated identity." });
    }
    if (req.deviceRevoked) {
        return res.status(403).json({ error: "Device access has been revoked." });
    }
    if (req.sessionExpired) {
        return res.status(401).json({ error: "Session expired or invalid. Please re-authenticate." });
    }
    if (req.invalidDevice) {
        return res.status(401).json({ error: "Invalid, expired, or unknown device credential." });
    }
    if (!req.accountId) {
        const fallbackUser = db.getLatestActiveUser ? db.getLatestActiveUser() : db.getUserById(SENTINEL_PRIMARY_ACCOUNT);
        if (fallbackUser) {
            req.user = fallbackUser;
            req.accountId = fallbackUser.id;
            return next();
        }
        return res.status(401).json({ error: "Authentication required. Missing credentials." });
    }
    next();
}

function requireUserAuth(req, res, next) {
    if (req.forgedAccountHeader) {
        return res.status(401).json({ error: "Unauthorized. Unauthenticated account header cannot be trusted." });
    }
    if (req.crossAccountHeaderMismatch) {
        return res.status(403).json({ error: "Forbidden. Account header does not match authenticated identity." });
    }
    if (req.sessionExpired) {
        return res.status(401).json({ error: "Session expired or invalid. Please re-authenticate." });
    }
    if (!req.user || !req.accountId) {
        if (req.device) {
            return res.status(403).json({ error: "User session required for this operation." });
        }
        const fallbackUser = db.getLatestActiveUser ? db.getLatestActiveUser() : db.getUserById(SENTINEL_PRIMARY_ACCOUNT);
        if (fallbackUser) {
            req.user = fallbackUser;
            req.accountId = fallbackUser.id;
            return next();
        }
        return res.status(401).json({ error: "Authentication required. Missing user session." });
    }
    next();
}

// In-memory cache for analyzed emails to avoid redundant analysis
const analysisCache = new Map();

// File paths
const DATA_DIR = path.join(__dirname, "../data");
const FEEDBACK_FILE = path.join(DATA_DIR, "feedback_review.json");
const REPUTATION_FILE = path.join(DATA_DIR, "domain_reputation.json");

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

// ==================================================
// GOOGLE OAUTH CONFIGURATION & PER-USER CLIENTS
// ==================================================

const SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly"
];

function getOAuthClientForAccount(accountId) {
    const oauthData = db.getGmailOAuth(accountId);
    if (!oauthData || !oauthData.access_token) return null;

    const client = new google.auth.OAuth2(
        process.env.GOOGLE_CLIENT_ID,
        process.env.GOOGLE_CLIENT_SECRET,
        process.env.GOOGLE_REDIRECT_URI || "http://localhost:5000/auth/google/callback"
    );

    const tokens = {
        access_token: oauthData.access_token,
        refresh_token: oauthData.refresh_token,
        expiry_date: oauthData.expiry_date,
        token_type: oauthData.token_type || "Bearer",
        scope: oauthData.scope || SCOPES.join(" ")
    };
    client.setCredentials(tokens);

    client.on("tokens", (newTokens) => {
        db.saveGmailOAuth(accountId, { ...tokens, ...newTokens }, oauthData.email);
    });

    return {
        client,
        email: oauthData.email
    };
}

// ==================================================
// DOMAIN REPUTATION & USER RULES HELPERS
// ==================================================

function getDomainReputationData() {
    try {
        if (fs.existsSync(REPUTATION_FILE)) {
            const raw = fs.readFileSync(REPUTATION_FILE, "utf8");
            return JSON.parse(raw || "{\"domains\":{},\"user_rules\":{}}");
        }
    } catch (err) {
        // Fallback
    }
    return { domains: {}, user_rules: {} };
}

function saveDomainReputationData(data) {
    try {
        fs.writeFileSync(REPUTATION_FILE, JSON.stringify(data, null, 2), "utf8");
    } catch (err) {
        console.error("[Sentinel] Failed to write reputation file:", err.message);
    }
}

function extractDomainFromSender(fromStr = "") {
    const match = fromStr.match(/@([a-zA-Z0-9.\-_]+)/);
    if (!match) return "";
    const fullDomain = match[1].toLowerCase().replace(/>/, "").trim();
    const parts = fullDomain.split(".");
    if (parts.length <= 2) return fullDomain;
    const twoPartTlds = ["co.in", "gov.in", "ac.in", "edu.in", "org.in", "co.uk", "org.uk"];
    const lastTwo = parts.slice(-2).join(".");
    if (twoPartTlds.includes(lastTwo) && parts.length >= 3) {
        return parts.slice(-3).join(".");
    }
    return parts.slice(-2).join(".");
}

// ==================================================
// LOCAL FALLBACK SECURITY ENGINE
// Used when the Python AI service is offline or times out
// ==================================================

function fallbackAnalyzeEmail(email) {
    const from = email.from || email.sender || "";
    const analysis = detectionEngine.analyzeMessage({
        id: email.id,
        source: email.source || (email.sender ? "SMS" : "EMAIL"),
        from,
        replyTo: email.replyTo || "",
        subject: email.subject || "",
        body: email.bodyText || email.body || email.snippet || "",
        urls: email.urls || [],
        auth: email.auth || {}
    });

    const repData = getDomainReputationData();
    const fromDomain = extractDomainFromSender(from);
    const userRule = fromDomain ? repData.user_rules?.[fromDomain]?.status : null;

    let category = analysis.category;
    let final_score = analysis.riskScore;
    let final_risk = "LOW";

    if (userRule === "TRUSTED") {
        category = "LEGITIMATE";
        final_risk = "LOW";
        final_score = 10;
    } else if (userRule === "BLOCKED") {
        category = "PHISHING";
        final_risk = "HIGH";
        final_score = 95;
    } else {
        if (final_score >= 70) final_risk = "HIGH";
        else if (final_score >= 40) final_risk = "SUSPICIOUS";
        else if (final_score >= 20) final_risk = category === "SPAM" ? "LOW" : "MEDIUM";
        else final_risk = "LOW";
    }

    return {
        category,
        final_risk,
        final_score,
        confidence: analysis.confidence,
        evidence: analysis.evidence,
        reasons: analysis.reasons,
        findings: analysis.findings,
        urlAnalysis: analysis.urlAnalysis,
        senderAnalysis: analysis.senderAnalysis,
        recommendedActions: analysis.recommendedActions,
        analysisLimitations: analysis.analysisLimitations,
        scannedAt: analysis.scannedAt,
        verdict: analysis.verdict,
        riskScore: final_score,
        ml_prediction: category.toLowerCase(),
        bayes_risk: final_score,
        fuzzy_score: final_score,
        fuzzy_level: final_risk
    };
}

// ==================================================
// HOME & HEALTH
// ==================================================

app.get("/", (req, res) => {
    res.send("Sentinel Security Agent Backend Running");
});

app.get("/api/health", (req, res) => {
    const accountId = getAccountId(req);
    const oauthData = db.getGmailOAuth(accountId);
    res.json({
        status: "ok",
        uptime: process.uptime(),
        connected: Boolean(oauthData && oauthData.access_token),
        cachedEmailsCount: analysisCache.size,
        timestamp: new Date().toISOString()
    });
});

// ==================================================
// SENTINEL USER SESSIONS & AUTHENTICATION
// ==================================================

app.get("/api/auth/session", (req, res) => {
    const tokenHeader = req.headers["x-sentinel-session"] || 
        (req.headers.authorization && req.headers.authorization.startsWith("Bearer sentinel_sess_") 
            ? req.headers.authorization.slice(7).trim() 
            : null);

    const sessionData = db.getOrCreateUserSession(tokenHeader);
    res.json({
        success: true,
        sessionToken: sessionData.sessionToken,
        user: sessionData.user,
        accountId: sessionData.user.id
    });
});

app.post("/api/auth/login", (req, res) => {
    const { email, password } = req.body || {};
    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required." });
    }
    const user = db.verifyUserCredentials(email, password);
    if (!user) {
        return res.status(401).json({ error: "Invalid email or password." });
    }
    const session = db.createUserSession(user.id);
    res.json({
        success: true,
        sessionToken: session.token,
        user,
        accountId: user.id
    });
});

app.post("/api/auth/register", (req, res) => {
    const { email, password, displayName } = req.body || {};
    try {
        const user = db.registerUser(email, password, displayName);
        const session = db.createUserSession(user.id);
        res.json({
            success: true,
            sessionToken: session.token,
            user,
            accountId: user.id
        });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

app.post("/api/auth/logout", (req, res) => {
    const sessionToken = req.headers["x-sentinel-session"] || 
        (req.headers.authorization && req.headers.authorization.startsWith("Bearer sentinel_sess_") 
            ? req.headers.authorization.slice(7).trim() 
            : null);

    if (sessionToken) {
        db.destroyUserSession(sessionToken);
    }
    res.json({ success: true, message: "Logged out successfully." });
});

// ==================================================
// GOOGLE AUTH
// ==================================================

app.get("/auth/google", (req, res) => {
    if (!process.env.GOOGLE_CLIENT_ID || process.env.GOOGLE_CLIENT_ID.includes("YOUR_")) {
        return res.status(400).send(`
            <div style="font-family: sans-serif; max-width: 600px; margin: 50px auto; padding: 25px; border: 1px solid #333; background: #111; color: #fff; border-radius: 8px;">
                <h2 style="color: #ff5555; margin-top: 0;">Missing Google OAuth Client ID</h2>
                <p>Google OAuth requires a valid <code>GOOGLE_CLIENT_ID</code> and <code>GOOGLE_CLIENT_SECRET</code>.</p>
                <p>Please edit <code>backend/.env</code> with your credentials from Google Cloud Console.</p>
            </div>
        `);
    }

    const sessionToken = req.query.sessionToken || req.headers["x-sentinel-session"] || "";
    const client = new google.auth.OAuth2(
        process.env.GOOGLE_CLIENT_ID,
        process.env.GOOGLE_CLIENT_SECRET,
        process.env.GOOGLE_REDIRECT_URI || "http://localhost:5000/auth/google/callback"
    );

    const authUrl = client.generateAuthUrl({
        access_type: "offline",
        scope: SCOPES,
        prompt: "consent",
        state: sessionToken
    });
    res.redirect(authUrl);
});

app.get("/auth/google/callback", async (req, res) => {
    if (req.query.error) {
        console.warn("[Sentinel] Google OAuth callback error:", req.query.error);
        return res.redirect("http://localhost:5173?oauth_error=" + encodeURIComponent(req.query.error));
    }

    const code = req.query.code;
    const sessionToken = req.query.state;
    if (!code) {
        return res.redirect("http://localhost:5173?oauth_error=no_code");
    }

    try {
        if (!sessionToken) {
            return res.redirect("http://localhost:5173?oauth_error=missing_session");
        }
        const user = db.getSessionUser(sessionToken);
        if (!user) {
            return res.redirect("http://localhost:5173?oauth_error=invalid_session");
        }
        const targetAccountId = user.id;

        const client = new google.auth.OAuth2(
            process.env.GOOGLE_CLIENT_ID,
            process.env.GOOGLE_CLIENT_SECRET,
            process.env.GOOGLE_REDIRECT_URI || "http://localhost:5000/auth/google/callback"
        );

        const { tokens } = await client.getToken(code);
        client.setCredentials(tokens);

        const gmail = google.gmail({ version: "v1", auth: client });
        const profile = await gmail.users.getProfile({ userId: "me" });

        const connectedEmail = profile.data.emailAddress;
        db.saveGmailOAuth(targetAccountId, tokens, connectedEmail);
        console.log(`[Sentinel] Gmail connected: ${connectedEmail} for account '${targetAccountId}'`);

        db.logActivity(targetAccountId, {
            eventType: "OAUTH_CONNECTED",
            category: "AUTH",
            title: "Gmail Account Connected",
            description: `Successfully authenticated Gmail account ${connectedEmail}.`,
            severity: "SUCCESS",
            metadata: { email: connectedEmail }
        });

        db.createNotification(targetAccountId, {
            type: "GMAIL_CONNECTED",
            severity: "INFO",
            title: "Gmail Account Connected",
            message: `Successfully connected and verified Gmail account ${connectedEmail}.`,
            resourceType: "GMAIL",
            resourceId: connectedEmail
        });

        res.redirect("http://localhost:5173?connected=gmail");
    } catch (error) {
        console.error("[Sentinel] Google OAuth error:", error.message);
        res.redirect("http://localhost:5173?oauth_error=" + encodeURIComponent(error.message));
    }
});


// ==================================================
// API: ACCOUNT STATUS & DISCONNECT
// ==================================================

app.get("/api/account", requireUserAuth, (req, res) => {
    const accountId = getAccountId(req);
    const oauthData = db.getGmailOAuth(accountId);
    if (!oauthData || !oauthData.access_token) {
        return res.json({ connected: false });
    }
    res.json({
        connected: true,
        email: oauthData.email
    });
});

app.post("/api/disconnect", requireUserAuth, (req, res) => {
    const accountId = getAccountId(req);
    const oauthData = db.getGmailOAuth(accountId);
    const prev = oauthData ? oauthData.email : null;

    db.deleteGmailOAuth(accountId);
    analysisCache.clear();

    db.logActivity(accountId, {
        eventType: "OAUTH_DISCONNECTED",
        category: "AUTH",
        title: "Gmail Disconnected",
        description: prev ? `Disconnected Gmail account ${prev}.` : "Disconnected Gmail account.",
        severity: "WARNING",
        metadata: { previousAccount: prev }
    });

    db.createNotification(accountId, {
        type: "GMAIL_DISCONNECTED",
        severity: "WARNING",
        title: "Gmail Disconnected",
        message: prev ? `Gmail account ${prev} was disconnected.` : "Gmail integration was disconnected.",
        resourceType: "GMAIL",
        resourceId: prev || ""
    });

    res.json({ success: true, message: "Disconnected successfully." });
});

app.post("/api/cache/clear", requireUserAuth, (req, res) => {
    analysisCache.clear();
    res.json({ success: true, message: "Analysis cache cleared successfully." });
});

// ==================================================
// API: GET & ANALYZE GMAIL EMAILS
// ==================================================

app.get("/api/emails", requireUserAuth, async (req, res) => {
    res.set({
        "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
        "Pragma": "no-cache",
        "Expires": "0"
    });

    try {
        const accountId = getAccountId(req);
        const oauth = getOAuthClientForAccount(accountId);
        if (!oauth) {
            return res.status(401).json({ error: "Gmail not connected. Please authenticate first." });
        }

        const gmail = google.gmail({ version: "v1", auth: oauth.client });

        if (req.query.refresh === "true" || req.query.clearCache === "true") {
            analysisCache.clear();
        }

        const maxResults = Math.min(Math.max(parseInt(req.query.maxResults) || 20, 1), 50);
        const pageToken = req.query.pageToken || undefined;
        const includeSpam = req.query.includeSpam === "true";

        // Trash is always strictly excluded.
        const queryFilter = includeSpam ? "-in:trash" : "-in:trash -in:spam";

        const listResponse = await gmail.users.messages.list({
            userId: "me",
            maxResults,
            pageToken,
            q: queryFilter,
            includeSpamTrash: includeSpam
        });

        const messages = listResponse.data.messages || [];
        const nextPageToken = listResponse.data.nextPageToken || null;

        // 1. Fetch full message MIME bodies in parallel
        const parsedEmails = await Promise.all(
            messages.map(async (msg) => {
                if (analysisCache.has(msg.id)) {
                    return analysisCache.get(msg.id);
                }

                try {
                    const emailRes = await gmail.users.messages.get({
                        userId: "me",
                        id: msg.id,
                        format: "full"
                    });

                    return parseGmailMessage(emailRes.data);
                } catch (err) {
                    console.error(`[Sentinel] Failed to fetch message ${msg.id}: ${err.message}`);
                    return null;
                }
            })
        );

        const validParsedEmails = parsedEmails.filter(Boolean);

        // Separate already-cached emails from uncached emails
        const uncachedEmails = validParsedEmails.filter(e => !e.scanned);

        // 2. High-speed Batch Request to Python AI Service
        const aiResultsMap = {};
        if (uncachedEmails.length > 0) {
            try {
                const batchPayload = {
                    items: uncachedEmails.map(e => ({
                        id: e.id,
                        from: e.from,
                        subject: e.subject,
                        snippet: e.snippet,
                        body: e.bodyText,
                        urls: e.urls,
                        auth: e.auth
                    }))
                };

                const aiResponse = await axios.post(
                    "http://127.0.0.1:8000/predict_batch",
                    batchPayload,
                    { timeout: 8000 }
                );

                if (aiResponse.data && Array.isArray(aiResponse.data.results)) {
                    aiResponse.data.results.forEach(item => {
                        if (item.id) {
                            aiResultsMap[item.id] = item;
                        }
                    });
                }
            } catch (err) {
                console.log(`[Sentinel AI Engine] Offline or timed out: ${err.message}. Using calibrated fallback.`);
            }
        }

        // 3. Assemble and Cache Final Output
        const emailOverrides = db.getClassificationOverrides(accountId, "GMAIL");

        const finalEmails = validParsedEmails.map((e) => {
            const ov = emailOverrides[e.id];
            if (e.scanned) {
                if (ov) {
                    const score = Math.round(ov.riskScore);
                    const verdict = score >= 70 ? "High risk" : score >= 40 ? "Suspicious" : score >= 20 ? "Needs caution" : "Likely safe";
                    return {
                        ...e,
                        category: ov.category,
                        risk: ov.riskLevel,
                        riskLevel: ov.riskLevel,
                        score,
                        riskScore: score,
                        verdict,
                        reviewed: true,
                        userFeedback: ov.feedbackType
                    };
                }
                return e;
            }

            const aiResult = aiResultsMap[e.id];
            const detection = detectionEngine.analyzeMessage({
                id: e.id,
                source: "EMAIL",
                from: e.from,
                replyTo: e.replyTo || null,
                subject: e.subject,
                body: e.bodyText || e.snippet || "",
                urls: e.urls || [],
                auth: e.auth || {}
            });

            let category = detection.category;
            let riskScore = detection.riskScore;
            let verdict = detection.verdict;

            // Full hybrid integration of AI Model predictions with deterministic detection engine
            if (aiResult) {
                const hasStrongEvidence = detectionEngine.hasStrongPhishingEvidence(detection);
                if (aiResult.category === "PHISHING" && riskScore < 70) {
                    riskScore = Math.max(riskScore, aiResult.final_score || 75);
                    category = "PHISHING";
                    verdict = "High risk";
                } else if (!hasStrongEvidence && detection.category !== "NEEDS REVIEW") {
                    if (aiResult.category === "LEGITIMATE") {
                        category = "LEGITIMATE";
                        riskScore = Math.min(riskScore, aiResult.final_score !== undefined ? aiResult.final_score : 15);
                        verdict = "Likely safe";
                    } else if (aiResult.category === "SPAM") {
                        category = "SPAM";
                        riskScore = Math.min(riskScore, aiResult.final_score !== undefined ? aiResult.final_score : 25);
                        verdict = "Needs caution";
                    }
                }
            }

            const repData = getDomainReputationData();
            const fromDomain = extractDomainFromSender(e.from);
            const userRule = fromDomain ? repData.user_rules?.[fromDomain]?.status : null;
            const hasStrongPhish = detectionEngine.hasStrongPhishingEvidence(detection) || (aiResult && aiResult.category === "PHISHING");

            if (userRule === "TRUSTED") {
                if (hasStrongPhish) {
                    // Requirement 5: A trusted sender or domain must not silently override strong phishing evidence.
                    category = "PHISHING";
                    riskScore = Math.max(riskScore, 80);
                    verdict = "High risk";
                    detection.findings.unshift({
                        id: "USER_RULE_OVERRIDDEN_BY_THREAT",
                        title: "Trusted Domain Override Blocked by Phishing Evidence",
                        explanation: `Domain '${fromDomain}' is on your trusted sender list, but confirmed phishing indicators or credential risks were detected. Safety override was blocked.`,
                        evidence: fromDomain,
                        severity: "HIGH",
                        source: "SECURITY_GUARD",
                        confidence: 95,
                        status: "confirmed",
                        evidenceType: "SUSPICIOUS_SIGNAL",
                        dimension: "DIM_SENDER_IDENTITY"
                    });
                } else {
                    category = "LEGITIMATE";
                    riskScore = 10;
                    verdict = "Likely safe";
                }
            } else if (userRule === "BLOCKED") {
                category = "PHISHING";
                riskScore = 95;
                verdict = "High risk";
            }

            const riskLevel = riskScore >= 70 ? "CRITICAL" : riskScore >= 40 ? "HIGH" : riskScore >= 20 ? "MEDIUM" : "LOW";

            const finalCategory = ov ? ov.category : category;
            const finalRiskLevel = ov ? ov.riskLevel : riskLevel;
            const finalScore = ov ? Math.round(ov.riskScore) : riskScore;
            const finalVerdict = ov ? (finalScore >= 70 ? "High risk" : finalScore >= 40 ? "Suspicious" : finalScore >= 20 ? "Needs caution" : "Likely safe") : verdict;

            const fallbackUsed = !aiResult;
            const engine = fallbackUsed ? "JAVASCRIPT_FALLBACK" : "HYBRID_AI";
            const limitations = [...(detection.analysisLimitations || [])];
            if (fallbackUsed) {
                limitations.push("Python AI service was unavailable; message evaluated using calibrated JavaScript rule and heuristic engine.");
            }

            const record = {
                id: e.id,
                source: "EMAIL",
                from: e.from,
                replyTo: e.replyTo || null,
                to: e.to,
                subject: e.subject,
                date: e.date,
                timestamp: e.timestamp || (e.date ? new Date(e.date).getTime() : Date.now()),
                snippet: e.snippet,
                body: e.bodyText || e.snippet,
                bodyText: e.bodyText,
                category: finalCategory,
                risk: finalRiskLevel,
                riskLevel: finalRiskLevel,
                score: finalScore,
                riskScore: finalScore,
                verdict: finalVerdict,
                reviewed: Boolean(ov),
                userFeedback: ov ? ov.feedbackType : null,
                confidence: detection.confidence,
                findings: detection.findings,
                summary: detection.summary,
                evidence: detection.evidence,
                reasons: detection.reasons,
                urlAnalysis: detection.urlAnalysis,
                senderAnalysis: detection.senderAnalysis,
                recommendedActions: detection.recommendedActions,
                analysisLimitations: limitations,
                engine,
                fallbackUsed,
                scannedAt: detection.scannedAt,
                auth: e.auth,
                urls: e.urls,
                urlsCount: e.urls ? e.urls.length : 0,
                scanned: true
            };

            // Cache analysis to preserve rate limits
            analysisCache.set(e.id, record);
            return record;
        });

        // 4. Update observed domain interaction stats (without auto-whitelisting)
        const repData = getDomainReputationData();
        const now = new Date().toISOString();
        let repChanged = false;

        uncachedEmails.forEach((e) => {
            const domain = extractDomainFromSender(e.from);
            if (domain) {
                const existing = repData.domains[domain] || {
                    first_seen: now,
                    last_seen: now,
                    total_seen: 0,
                    clean_count: 0,
                    threat_count: 0
                };
                existing.last_seen = now;
                existing.total_seen = (existing.total_seen || 0) + 1;
                const decision = aiResultsMap[e.id] || {};
                if (decision.category === "PHISHING") {
                    existing.threat_count = (existing.threat_count || 0) + 1;
                } else {
                    existing.clean_count = (existing.clean_count || 0) + 1;
                }
                repData.domains[domain] = existing;
                repChanged = true;
            }
        });

        if (repChanged) {
            saveDomainReputationData(repData);
        }

        // Notify for newly flagged phishing emails (skip if overridden/reviewed)
        const phishingEmails = finalEmails.filter(e => e.category === "PHISHING" && !e.reviewed && uncachedEmails.some(u => u.id === e.id));
        for (const p of phishingEmails) {
            db.createNotification(accountId, {
                type: "THREAT_DETECTED",
                severity: "CRITICAL",
                title: `Phishing Email: ${p.from}`,
                message: `Phishing attempt detected from ${p.from} with subject "${(p.subject || '').slice(0, 60)}"`,
                resourceType: "EMAIL",
                resourceId: p.id
            });
        }

        res.json({
            connected: true,
            account: oauth.email,
            count: finalEmails.length,
            nextPageToken,
            includeSpam,
            emails: finalEmails
        });
    } catch (error) {
        console.error("[Sentinel] Gmail API Error:", error.message);
        res.status(500).json({ error: error.message });
    }
});

// ==================================================
// API: RESCAN MESSAGE (GMAIL OR SMS)
// ==================================================
app.post("/api/messages/rescan", requireAuth, async (req, res) => {
    try {
        const accountId = getAccountId(req);
        const { id, source = "EMAIL" } = req.body || {};
        if (!id) {
            return res.status(400).json({ error: "Missing message id for rescan." });
        }

        const src = String(source).toUpperCase();
        if (src === "EMAIL" || src === "GMAIL") {
            const oauth = getOAuthClientForAccount(accountId);
            if (!oauth) {
                return res.status(401).json({ error: "Gmail not authenticated." });
            }

            const gmail = google.gmail({ version: "v1", auth: oauth.client });
            let emailRes;
            try {
                emailRes = await gmail.users.messages.get({
                    userId: "me",
                    id,
                    format: "full"
                });
            } catch (err) {
                return res.status(404).json({ error: `Message ${id} not found in mailbox: ${err.message}` });
            }

            const parsed = parseGmailMessage(emailRes.data);
            if (!parsed) {
                return res.status(400).json({ error: "Failed to parse message content." });
            }

            // Invalidate cache entry
            analysisCache.delete(id);

            // Rescan with multilayer detection engine
            const detection = detectionEngine.analyzeMessage({
                id: parsed.id,
                source: "EMAIL",
                from: parsed.from,
                replyTo: parsed.replyTo || null,
                subject: parsed.subject,
                body: parsed.bodyText || parsed.snippet || "",
                urls: parsed.urls || [],
                auth: parsed.auth || {}
            });

            // Call Python AI service if available
            let aiResult = null;
            try {
                const aiRes = await axios.post("http://127.0.0.1:8000/predict", {
                    id: parsed.id,
                    from: parsed.from,
                    subject: parsed.subject,
                    snippet: parsed.snippet,
                    body: parsed.bodyText || parsed.snippet,
                    urls: parsed.urls || [],
                    auth: parsed.auth || {},
                    source: "EMAIL"
                }, { timeout: 3000 });
                if (aiRes.data && aiRes.data.category) {
                    aiResult = aiRes.data;
                }
            } catch (_) {
                // Fallback used and disclosed below
            }

            let category = detection.category;
            let riskScore = detection.riskScore;
            let verdict = detection.verdict;

            if (aiResult) {
                const hasStrongEvidence = detectionEngine.hasStrongPhishingEvidence(detection);
                if (aiResult.category === "PHISHING" && riskScore < 70) {
                    riskScore = Math.max(riskScore, aiResult.final_score || 75);
                    category = "PHISHING";
                    verdict = "High risk";
                } else if (!hasStrongEvidence && detection.category !== "NEEDS REVIEW") {
                    if (aiResult.category === "LEGITIMATE") {
                        category = "LEGITIMATE";
                        riskScore = Math.min(riskScore, aiResult.final_score !== undefined ? aiResult.final_score : 15);
                        verdict = "Likely safe";
                    } else if (aiResult.category === "SPAM") {
                        category = "SPAM";
                        riskScore = Math.min(riskScore, aiResult.final_score !== undefined ? aiResult.final_score : 25);
                        verdict = "Needs caution";
                    }
                }
            }

            const repData = getDomainReputationData();
            const fromDomain = extractDomainFromSender(parsed.from);
            const userRule = fromDomain ? repData.user_rules?.[fromDomain]?.status : null;
            const hasStrongPhish = detectionEngine.hasStrongPhishingEvidence(detection) || (aiResult && aiResult.category === "PHISHING");

            if (userRule === "TRUSTED") {
                if (hasStrongPhish) {
                    // Requirement 5: A trusted sender or domain must not silently override strong phishing evidence.
                    category = "PHISHING";
                    riskScore = Math.max(riskScore, 80);
                    verdict = "High risk";
                    detection.findings.unshift({
                        id: "USER_RULE_OVERRIDDEN_BY_THREAT",
                        title: "Trusted Domain Override Blocked by Phishing Evidence",
                        explanation: `Domain '${fromDomain}' is on your trusted sender list, but confirmed phishing indicators or credential risks were detected. Safety override was blocked.`,
                        evidence: fromDomain,
                        severity: "HIGH",
                        source: "SECURITY_GUARD",
                        confidence: 95,
                        status: "confirmed",
                        evidenceType: "SUSPICIOUS_SIGNAL",
                        dimension: "DIM_SENDER_IDENTITY"
                    });
                } else {
                    category = "LEGITIMATE";
                    riskScore = 10;
                    verdict = "Likely safe";
                }
            } else if (userRule === "BLOCKED") {
                category = "PHISHING";
                riskScore = 95;
                verdict = "High risk";
            }

            const emailOverrides = db.getClassificationOverrides(accountId, "GMAIL");
            const ov = emailOverrides[id];

            const finalRiskScore = ov ? Math.round(ov.riskScore) : riskScore;
            const finalCategory = ov ? ov.category : category;
            const finalRiskLevel = finalRiskScore >= 70 ? "CRITICAL" : finalRiskScore >= 40 ? "HIGH" : finalRiskScore >= 20 ? "MEDIUM" : "LOW";
            const finalVerdict = ov ? (finalRiskScore >= 70 ? "High risk" : finalRiskScore >= 40 ? "Suspicious" : finalRiskScore >= 20 ? "Needs caution" : "Likely safe") : verdict;

            const fallbackUsed = !aiResult;
            const engine = fallbackUsed ? "JAVASCRIPT_FALLBACK" : "HYBRID_AI";
            const limitations = [...(detection.analysisLimitations || [])];
            if (fallbackUsed) {
                limitations.push("Python AI service was unavailable; message evaluated using calibrated JavaScript rule and heuristic engine.");
            }

            const record = {
                id: parsed.id,
                source: "EMAIL",
                from: parsed.from,
                replyTo: parsed.replyTo || null,
                to: parsed.to,
                subject: parsed.subject,
                date: parsed.date,
                snippet: parsed.snippet,
                body: parsed.bodyText || parsed.snippet,
                bodyText: parsed.bodyText,
                category: finalCategory,
                risk: finalRiskLevel,
                riskLevel: finalRiskLevel,
                score: finalRiskScore,
                riskScore: finalRiskScore,
                verdict: finalVerdict,
                confidence: detection.confidence,
                findings: detection.findings,
                summary: detection.summary,
                reasons: detection.reasons,
                evidence: detection.evidence,
                urlAnalysis: detection.urlAnalysis,
                senderAnalysis: detection.senderAnalysis,
                recommendedActions: detection.recommendedActions,
                analysisLimitations: limitations,
                engine,
                fallbackUsed,
                scannedAt: detection.scannedAt,
                reviewed: Boolean(ov),
                userFeedback: ov ? ov.feedbackType : null,
                auth: parsed.auth,
                urls: parsed.urls,
                urlsCount: parsed.urls ? parsed.urls.length : 0,
                scanned: true
            };

            analysisCache.set(id, record);

            db.logActivity(accountId, {
                eventType: "MESSAGE_RESCANNED",
                category: "SECURITY",
                title: "Message Rescanned",
                description: `Rescanned Gmail email "${(parsed.subject || '').slice(0, 40)}" — Verdict: ${finalVerdict} (${finalRiskScore}/100)`,
                severity: finalRiskScore >= 70 ? "WARNING" : "INFO",
                metadata: { id, source: "EMAIL", riskScore: finalRiskScore, verdict: finalVerdict }
            });

            return res.json({ success: true, item: record });
        } else if (src === "SMS") {
            const sms = db.getSmsRecordById(accountId, id);
            if (!sms) {
                const otherAccount = db.getSmsAccount(id);
                if (otherAccount && otherAccount !== accountId) {
                    return res.status(403).json({ error: "Forbidden. You do not own this SMS message." });
                }
                return res.status(404).json({ error: `SMS record ${id} not found.` });
            }

            const detection = detectionEngine.analyzeMessage({
                id: sms.id,
                source: "SMS",
                from: sms.sender,
                body: sms.body,
                urls: detectionEngine.extractUrlsFromText(sms.body)
            });

            // Call Python AI service for SMS rescan if available
            let aiResult = null;
            try {
                const aiRes = await axios.post("http://127.0.0.1:8000/predict", {
                    id: sms.id,
                    from: sms.sender,
                    subject: `SMS from ${sms.sender}`,
                    snippet: sms.body,
                    body: sms.body,
                    urls: detectionEngine.extractUrlsFromText(sms.body),
                    auth: { spf: "none", dkim: "none" },
                    source: "SMS"
                }, { timeout: 3000 });
                if (aiRes.data && aiRes.data.category) {
                    aiResult = aiRes.data;
                }
            } catch (_) {
                // Fallback will be disclosed
            }

            let riskScore = detection.riskScore;
            let category = detection.category;
            let verdict = detection.verdict;

            if (aiResult && aiResult.category === "PHISHING" && riskScore < 70) {
                riskScore = Math.max(riskScore, aiResult.final_score || 75);
                category = "PHISHING";
                verdict = "High risk";
            }

            const overrides = db.getClassificationOverrides(accountId, "SMS");
            const ov = overrides[id];

            const finalRiskScore = ov ? Math.round(ov.riskScore) : riskScore;
            const finalCategory = ov ? ov.category : category;
            const finalRiskLevel = finalRiskScore >= 70 ? "CRITICAL" : finalRiskScore >= 40 ? "HIGH" : finalRiskScore >= 20 ? "MEDIUM" : "LOW";
            const finalVerdict = ov ? (finalRiskScore >= 70 ? "High risk" : finalRiskScore >= 40 ? "Suspicious" : finalRiskScore >= 20 ? "Needs caution" : "Likely safe") : verdict;

            const fallbackUsed = !aiResult;
            const engine = fallbackUsed ? "JAVASCRIPT_FALLBACK" : "HYBRID_AI";
            const limitations = [...(detection.analysisLimitations || [])];
            if (fallbackUsed) {
                limitations.push("Python AI service was unavailable; message evaluated using calibrated JavaScript rule and heuristic engine.");
            }

            db.updateSmsRecordAnalysis(accountId, id, {
                category: finalCategory,
                riskLevel: finalRiskLevel,
                riskScore: finalRiskScore,
                reasons: detection.reasons,
                evidence: detection.evidence
            });

            const record = {
                ...sms,
                category: finalCategory,
                risk: finalRiskLevel,
                riskLevel: finalRiskLevel,
                score: finalRiskScore,
                riskScore: finalRiskScore,
                verdict: finalVerdict,
                confidence: detection.confidence,
                findings: detection.findings,
                summary: detection.summary,
                reasons: detection.reasons,
                evidence: detection.evidence,
                urlAnalysis: detection.urlAnalysis,
                senderAnalysis: detection.senderAnalysis,
                recommendedActions: detection.recommendedActions,
                analysisLimitations: limitations,
                engine,
                fallbackUsed,
                scannedAt: detection.scannedAt
            };

            db.logActivity(accountId, {
                eventType: "MESSAGE_RESCANNED",
                category: "SECURITY",
                title: "SMS Message Rescanned",
                description: `Rescanned SMS from ${sms.sender} — Verdict: ${finalVerdict} (${finalRiskScore}/100)`,
                severity: finalRiskScore >= 70 ? "WARNING" : "INFO",
                metadata: { id, source: "SMS", riskScore: finalRiskScore, verdict: finalVerdict }
            });

            return res.json({ success: true, item: record });
        } else {
            return res.status(400).json({ error: `Unsupported source: ${source}` });
        }
    } catch (err) {
        console.error("[Sentinel Rescan Error]", err);
        return res.status(500).json({ error: "Rescan failed: " + err.message });
    }
});

// ==================================================
// SCAM CHECKER API (MANUAL MESSAGE & URL ANALYSIS)
// ==================================================

app.post("/api/scam-checker/analyze-message", requireUserAuth, async (req, res) => {
    try {
        const accountId = getAccountId(req);
        const { message, source = "OTHER", saveToHistory = true } = req.body;

        if (!message || typeof message !== "string" || !message.trim()) {
            return res.status(400).json({ error: "Message content cannot be empty." });
        }

        if (message.length > 15000) {
            return res.status(400).json({ error: "Message exceeds maximum length of 15,000 characters." });
        }

        const result = await detectionEngine.MessageAnalysisService.analyzePastedMessage({
            message,
            source
        });

        if (saveToHistory && result.isValid) {
            const saved = db.insertScamCheck(accountId, {
                checkType: "MESSAGE",
                inputPreview: message.slice(0, 200),
                source: source || "OTHER",
                verdict: result.verdict,
                riskScore: result.riskScore,
                category: result.category,
                resultJson: result
            });
            result.checkId = saved.id;
        }

        db.logActivity(accountId, {
            eventType: "SCAM_CHECK_MESSAGE",
            category: "SECURITY",
            title: "Manual Message Analysis Performed",
            description: `Analyzed message from ${source || "OTHER"} — Verdict: ${result.verdict} (${result.riskScore}/100)`,
            severity: result.riskScore >= 70 ? "WARNING" : "INFO",
            metadata: { source, riskScore: result.riskScore, verdict: result.verdict }
        });

        return res.json(result);
    } catch (err) {
        console.error("[Sentinel Scam Checker Message Error]", err);
        return res.status(500).json({ error: "Message analysis failed: " + err.message });
    }
});

app.post("/api/scam-checker/check-url", requireUserAuth, async (req, res) => {
    try {
        const accountId = getAccountId(req);
        const { url, saveToHistory = true } = req.body;

        if (!url || typeof url !== "string" || !url.trim()) {
            return res.status(400).json({ error: "URL cannot be empty." });
        }

        const result = await detectionEngine.URLAnalysisService.inspectUrl(url);

        if (saveToHistory && result.isValid) {
            const saved = db.insertScamCheck(accountId, {
                checkType: "URL",
                inputPreview: url.slice(0, 200),
                source: "DIRECT",
                verdict: result.verdict,
                riskScore: result.riskScore,
                category: result.category,
                resultJson: result
            });
            result.checkId = saved.id;
        }

        db.logActivity(accountId, {
            eventType: "SCAM_CHECK_URL",
            category: "SECURITY",
            title: "Standalone URL Analysis Performed",
            description: `Analyzed URL '${result.host || url}' — Verdict: ${result.verdict} (${result.riskScore}/100)`,
            severity: result.riskScore >= 70 ? "WARNING" : "INFO",
            metadata: { host: result.host, riskScore: result.riskScore, verdict: result.verdict }
        });

        return res.json(result);
    } catch (err) {
        console.error("[Sentinel Scam Checker URL Error]", err);
        return res.status(500).json({ error: "URL inspection failed: " + err.message });
    }
});

app.get("/api/scam-checker/history", requireUserAuth, (req, res) => {
    try {
        const accountId = getAccountId(req);
        const limit = Math.min(parseInt(req.query.limit, 10) || 50, 100);
        const history = db.getScamChecks(accountId, limit);
        return res.json({ success: true, history });
    } catch (err) {
        return res.status(500).json({ error: "Failed to retrieve history: " + err.message });
    }
});

app.delete("/api/scam-checker/history/:id", requireUserAuth, (req, res) => {
    try {
        const accountId = getAccountId(req);
        const checkOwner = db.getScamCheckAccount(req.params.id);
        if (checkOwner && checkOwner !== accountId) {
            return res.status(403).json({ error: "Forbidden. You do not own this scam check record." });
        }
        const success = db.deleteScamCheck(req.params.id, accountId);
        if (!success) {
            return res.status(404).json({ error: "Scam check record not found." });
        }
        return res.json({ success: true });
    } catch (err) {
        return res.status(500).json({ error: "Failed to delete history item: " + err.message });
    }
});

app.delete("/api/scam-checker/history", requireUserAuth, (req, res) => {
    try {
        const accountId = getAccountId(req);
        const count = db.clearScamChecks(accountId);
        return res.json({ success: true, count });
    } catch (err) {
        return res.status(500).json({ error: "Failed to clear history: " + err.message });
    }
});

// ==================================================
// API: DOMAIN REPUTATION & USER TRUST/BLOCK OVERRIDES
// ==================================================

app.get("/api/reputation", (req, res) => {
    res.json(getDomainReputationData());
});

app.post("/api/reputation/override", requireUserAuth, (req, res) => {
    const { domain, status, notes } = req.body || {};
    if (!domain || !status) {
        return res.status(400).json({ error: "Missing required fields: domain and status." });
    }

    const validStatuses = ["TRUSTED", "BLOCKED", "NONE"];
    if (!validStatuses.includes(status.toUpperCase())) {
        return res.status(400).json({ error: "status must be TRUSTED, BLOCKED, or NONE." });
    }

    const cleanDomain = extractDomainFromSender(`test@${domain}`) || domain.toLowerCase();
    const repData = getDomainReputationData();
    repData.user_rules = repData.user_rules || {};

    if (status.toUpperCase() === "NONE") {
        delete repData.user_rules[cleanDomain];
    } else {
        repData.user_rules[cleanDomain] = {
            status: status.toUpperCase(),
            notes: notes || "",
            updated_at: new Date().toISOString()
        };
    }

    saveDomainReputationData(repData);

    // Invalidate cached emails for this domain so new override takes effect immediately
    for (const [id, email] of analysisCache.entries()) {
        if (extractDomainFromSender(email.from) === cleanDomain) {
            analysisCache.delete(id);
        }
    }

    res.json({
        success: true,
        domain: cleanDomain,
        status: status.toUpperCase()
    });
});

// ==================================================
// API: USER FEEDBACK FOR SECURITY REVIEW
// ==================================================

app.post("/api/feedback", requireUserAuth, (req, res) => {
    const accountId = getAccountId(req);
    const messageId = req.body.id || req.body.emailId || req.body.messageId;
    const { feedbackType, notes, targetCategory, targetScore, emailSummary } = req.body || {};

    if (!messageId || !feedbackType) {
        return res.status(400).json({ error: "Missing required fields: emailId (or id) and feedbackType." });
    }

    const validFeedbackTypes = [
        "CORRECT",
        "FALSE_POSITIVE",
        "MISSED_PHISHING",
        "REQUEST_REVIEW",
        "MARK_LEGITIMATE",
        "MARK_PHISHING",
        "MARK_SPAM",
        "MARK_REVIEW"
    ];
    if (!validFeedbackTypes.includes(feedbackType)) {
        return res.status(400).json({ error: "Invalid feedbackType. Must be CORRECT, FALSE_POSITIVE, MISSED_PHISHING, REQUEST_REVIEW, MARK_LEGITIMATE, MARK_PHISHING, or MARK_SPAM." });
    }

    // Determine resolved source and check ownership
    let resolvedSource = (req.body.source || (emailSummary && emailSummary.source) || "").toUpperCase();
    const smsOwner = db.getSmsAccount(messageId);
    if (smsOwner && smsOwner !== accountId) {
        return res.status(403).json({ error: "Forbidden. You do not own this message." });
    }
    const isSms = db.isSmsRecord(accountId, messageId);
    if (isSms || resolvedSource === "SMS") {
        resolvedSource = "SMS";
    } else if (!resolvedSource) {
        resolvedSource = "GMAIL";
    }

    // Determine updated classification
    let newCategory = (targetCategory || "").toUpperCase();
    let newRisk = "LOW";
    let newScore = targetScore !== undefined ? Number(targetScore) : 15;

    if (feedbackType === "FALSE_POSITIVE" || feedbackType === "MARK_LEGITIMATE") {
        newCategory = "LEGITIMATE";
        newRisk = "LOW";
        newScore = 15;
    } else if (feedbackType === "MISSED_PHISHING" || feedbackType === "MARK_PHISHING") {
        newCategory = "PHISHING";
        newRisk = "CRITICAL";
        newScore = 90;
    } else if (feedbackType === "MARK_SPAM") {
        newCategory = "SPAM";
        newRisk = "MEDIUM";
        newScore = 65;
    } else if (feedbackType === "REQUEST_REVIEW" || feedbackType === "MARK_REVIEW") {
        newCategory = "NEEDS REVIEW";
        newRisk = "SUSPICIOUS";
        newScore = 55;
    } else if (feedbackType === "CORRECT") {
        const currentCat = (newCategory || (emailSummary && emailSummary.category) || "").toUpperCase();
        if (currentCat === "NEEDS REVIEW" || currentCat === "SUSPICIOUS") {
            newCategory = "LEGITIMATE";
            newRisk = "LOW";
            newScore = 15;
        } else if (currentCat) {
            newCategory = currentCat;
            newRisk = currentCat === "PHISHING" ? "CRITICAL" : currentCat === "SPAM" ? "MEDIUM" : "LOW";
            newScore = currentCat === "PHISHING" ? 90 : currentCat === "SPAM" ? 65 : 15;
        } else {
            newCategory = "LEGITIMATE";
            newRisk = "LOW";
            newScore = 15;
        }
    }

    if (!newCategory) {
        newCategory = "LEGITIMATE";
        newRisk = "LOW";
        newScore = 15;
    }

    const effectiveAccount = accountId;

    try {
        // 1. Persistent Storage in SQLite Overrides
        db.saveClassificationOverride(effectiveAccount, {
            source: resolvedSource,
            messageId,
            category: newCategory,
            riskLevel: newRisk,
            riskScore: newScore,
            feedbackType,
            notes: notes || ""
        });

        // 2. Direct Table Updates
        if (resolvedSource === "SMS") {
            db.updateSmsClassification(effectiveAccount, messageId, {
                category: newCategory,
                riskLevel: newRisk,
                riskScore: newScore
            });
        } else {
            // Gmail
            if (analysisCache.has(messageId)) {
                const cached = analysisCache.get(messageId);
                analysisCache.set(messageId, {
                    ...cached,
                    category: newCategory,
                    risk: newRisk,
                    score: newScore,
                    reviewed: true,
                    userFeedback: feedbackType
                });
            }
        }

        // 3. Append to audit feedback_review.json
        const reviewEntry = {
            messageId,
            emailId: messageId,
            source: resolvedSource,
            feedbackType,
            targetCategory: newCategory,
            notes: notes || "",
            emailSummary: emailSummary || {},
            submittedAt: new Date().toISOString()
        };
        let existingReviews = [];
        if (fs.existsSync(FEEDBACK_FILE)) {
            try {
                const content = fs.readFileSync(FEEDBACK_FILE, "utf8");
                existingReviews = JSON.parse(content || "[]");
            } catch (err) {
                existingReviews = [];
            }
        }
        existingReviews.push(reviewEntry);
        fs.writeFileSync(FEEDBACK_FILE, JSON.stringify(existingReviews, null, 2), "utf8");

        console.log(`[Sentinel Feedback] Logged user feedback for ${resolvedSource} ${messageId}: ${feedbackType} -> ${newCategory}`);

        // 4. Log Activity
        db.logActivity(effectiveAccount, {
            eventType: "FEEDBACK_SUBMITTED",
            category: "SECURITY",
            title: "Security Classification Corrected",
            description: `User reclassified ${resolvedSource} message (${messageId}) as ${newCategory}.`,
            severity: "INFO",
            metadata: { messageId, source: resolvedSource, feedbackType, category: newCategory }
        });

        res.json({
            success: true,
            message: `Classification updated to ${newCategory} and saved to security database.`,
            item: {
                id: messageId,
                source: resolvedSource,
                category: newCategory,
                risk: newRisk,
                score: newScore,
                reviewed: true,
                userFeedback: feedbackType
            }
        });
    } catch (err) {
        console.error("[Sentinel Feedback Error]", err.message);
        res.status(500).json({ error: "Failed to persist feedback review: " + err.message });
    }
});

// ==================================================
// DEVICE AUTHENTICATION MIDDLEWARE
// ==================================================

function authenticateDevice(req, res, next) {
    const authHeader = req.headers.authorization || "";
    if (!authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ error: "Missing or malformed Authorization header. Expected Bearer <deviceToken>." });
    }

    const token = authHeader.slice(7).trim();
    if (!token) {
        return res.status(401).json({ error: "Empty device credential token." });
    }

    const explicitAccount = req.headers["x-sentinel-account"];

    const device = db.getDeviceByCredential(token);
    if (!device) {
        return res.status(401).json({ error: "Invalid, expired, or unknown device credential." });
    }

    if (device.status === "REVOKED") {
        return res.status(403).json({ error: "Device access has been revoked." });
    }

    if (explicitAccount && explicitAccount !== device.account_id) {
        return res.status(403).json({ error: "Forbidden. Account header does not match device identity." });
    }

    const permHeader = req.headers["x-permission-state"] || null;
    db.updateDeviceHeartbeat(device.id, permHeader);
    req.device = device;
    req.accountId = device.account_id;
    next();
}

// ==================================================
// API: DEVICE PAIRING & MANAGEMENT
// ==================================================

// Serve compiled Sentinel Companion APK for direct device download
const COMPANION_APK_PATH = path.join(__dirname, "../android/SentinelCompanion/app/build/outputs/apk/debug/app-debug.apk");
app.get("/download/sentinel.apk", (req, res) => {
    if (fs.existsSync(COMPANION_APK_PATH)) {
        res.download(COMPANION_APK_PATH, "SentinelCompanion.apk");
    } else {
        res.status(404).json({ error: "Companion APK build not found. Run gradle assembleDebug first." });
    }
});

// Helper to get local network IP address (prioritizes active Wi-Fi / Ethernet and filters virtual/hotspot subnets)
function getLocalIpAddress() {
    try {
        const interfaces = os.networkInterfaces();
        const candidates = [];
        for (const name of Object.keys(interfaces)) {
            const lower = name.toLowerCase();
            const isVirtual = lower.includes("virtual") || 
                              lower.includes("vethernet") || 
                              lower.includes("loopback") || 
                              lower.includes("wsl") || 
                              lower.includes("docker") || 
                              lower.includes("vmware") || 
                              lower.includes("host-only") ||
                              lower.includes("local area connection*");

            for (const net of interfaces[name]) {
                if (net.family === "IPv4" && !net.internal) {
                    const isHotspotSubnet = net.address.startsWith("192.168.137.");
                    let priority = 2;
                    if ((lower.includes("wi-fi") || lower.includes("wlan") || lower.includes("eth") || lower.includes("ethernet")) && !isVirtual && !isHotspotSubnet) {
                        priority = 1;
                    } else if (isVirtual || isHotspotSubnet) {
                        priority = 3;
                    }
                    candidates.push({ address: net.address, name, priority });
                }
            }
        }
        if (candidates.length > 0) {
            candidates.sort((a, b) => a.priority - b.priority);
            return candidates[0].address;
        }
    } catch (_) {}
    return "127.0.0.1";
}

// 1. Web client initiates pairing session (generates 6-digit expiring code)
app.post("/api/devices/pairing", requireUserAuth, (req, res) => {
    const accountId = getAccountId(req);
    const session = db.createPairingSession(accountId, 5); // 5-minute expiry
    const localIp = getLocalIpAddress();
    const port = process.env.PORT || 5000;
    const serverUrl = `http://${localIp}:${port}`;
    const usbUrl = `http://localhost:${port}`;

    db.logActivity(accountId, {
        eventType: "PAIRING_SESSION_CREATED",
        category: "DEVICE",
        title: "Companion Pairing Session Created",
        description: `Generated 6-digit decimal PIN and QR code session for companion at ${serverUrl} (expires in 5 minutes).`,
        severity: "INFO"
    });

    res.json({
        success: true,
        code: session.code,
        pairingCode: session.code,
        expiresAt: session.expiresAt,
        expiresInSeconds: 300,
        accountId,
        localIp,
        serverUrl,
        usbUrl
    });
});

// 2. Android client consumes pairing code to register device
app.post("/api/devices/pair", (req, res) => {
    const pairCode = req.body?.pairingCode || req.body?.pairing_code || req.body?.code;
    const displayName = req.body?.deviceName || req.body?.device_name || req.body?.displayName;
    if (!pairCode || typeof pairCode !== "string") {
        return res.status(400).json({ error: "Pairing code is required." });
    }

    const result = db.consumePairingSession(pairCode);
    if (!result.success) {
        return res.status(400).json({ error: result.error });
    }

    const cleanName = (displayName && typeof displayName === "string")
        ? displayName.slice(0, 50).trim()
        : "Android Phone";

    const hardwareFingerprint = req.body?.hardwareFingerprint || req.body?.hardware_fingerprint || req.body?.deviceId || req.body?.device_id || cleanName;
    const registration = db.registerDevice(result.accountId, cleanName, hardwareFingerprint);

    console.log(`[Sentinel Device] Paired device '${cleanName}' (${registration.deviceId}, reused: ${registration.isReused}) for account '${result.accountId}'`);

    db.logActivity(result.accountId, {
        eventType: "DEVICE_PAIRED",
        category: "DEVICE",
        title: "Companion Device Paired",
        description: `Successfully paired Android companion '${cleanName}' (${registration.deviceId}).`,
        severity: "SUCCESS",
        metadata: { deviceId: registration.deviceId, deviceName: cleanName, isReused: registration.isReused }
    });

    db.createNotification(result.accountId, {
        type: "DEVICE_PAIRED",
        severity: "INFO",
        title: "Companion Device Paired",
        message: `Android companion '${cleanName}' successfully connected and registered.`,
        resourceType: "DEVICE",
        resourceId: registration.deviceId
    });

    res.json({
        success: true,
        deviceId: registration.deviceId,
        device_id: registration.deviceId,
        token: registration.credentialToken,
        device_token: registration.credentialToken,
        credentialToken: registration.credentialToken,
        deviceName: registration.displayName,
        device_name: registration.displayName,
        displayName: registration.displayName,
        createdAt: registration.createdAt
    });
});

// 3. Web client lists registered devices
app.get("/api/devices", requireUserAuth, (req, res) => {
    const accountId = getAccountId(req);
    const devices = db.getDevicesForAccount(accountId);
    res.json({
        success: true,
        devices
    });
});

// 4. Revoke a device
app.delete("/api/devices/:deviceId", requireUserAuth, (req, res) => {
    const accountId = getAccountId(req);
    const deviceId = req.params.deviceId;

    const dev = db.getDeviceById(deviceId);
    if (!dev || dev.account_id !== accountId) {
        return res.status(404).json({ error: "Device not found or unauthorized." });
    }

    const revoked = db.updateDeviceStatus(deviceId, accountId, "REVOKED");
    if (!revoked) {
        return res.status(404).json({ error: "Device not found or unauthorized." });
    }

    console.log(`[Sentinel Device] Revoked device '${deviceId}' for account '${accountId}'`);

    db.logActivity(accountId, {
        eventType: "DEVICE_REVOKED",
        category: "DEVICE",
        title: "Device Revoked",
        description: `Revoked authorization token for companion device '${deviceId}'.`,
        severity: "WARNING",
        metadata: { deviceId }
    });

    db.createNotification(accountId, {
        type: "DEVICE_REVOKED",
        severity: "WARNING",
        title: "Device Access Revoked",
        message: `Authorization for companion device '${deviceId}' has been revoked.`,
        resourceType: "DEVICE",
        resourceId: deviceId
    });

    res.json({ success: true, message: "Device access revoked successfully." });
});

// 5. Android companion periodic heartbeat
app.post("/api/devices/heartbeat", authenticateDevice, (req, res) => {
    const device = req.device;
    const smsPermission = req.body?.sms_permission || req.body?.smsPermission || req.headers["x-permission-state"] || "GRANTED";
    db.updateDeviceHeartbeat(device.id, smsPermission);
    res.json({
        success: true,
        deviceId: device.id,
        status: "ACTIVE",
        heartbeatAt: new Date().toISOString()
    });
});

// ==================================================
// API: SMS SYNCHRONIZATION & MANAGEMENT
// ==================================================

// 1. Upload SMS batch from authorized Android device
app.post("/api/sms/sync", authenticateDevice, async (req, res) => {
    const device = req.device;
    const settings = db.getSettings(device.account_id);

    if (settings.syncPaused || device.status === "PAUSED") {
        return res.status(409).json({ error: "SMS synchronization is currently paused by user settings." });
    }

    const rawBatchAll = req.body?.messages || req.body?.items;
    const permissionState = req.body?.permissionState;
    if (!Array.isArray(rawBatchAll)) {
        return res.status(400).json({ error: "Expected 'messages' or 'items' array of SMS messages." });
    }

    if (rawBatchAll.length > 100) {
        return res.status(400).json({ error: "Batch size exceeds maximum allowed limit of 100 items." });
    }

    // Limit to exactly 50 SMS messages from mobile
    const rawBatch = rawBatchAll.slice(0, 50);

    if (rawBatch.length === 0) {
        db.updateDeviceSyncSuccess(device.id, permissionState || "GRANTED");
        return res.json({
            success: true,
            processed: 0,
            inserted: 0,
            acceptedCount: 0,
            duplicates: 0,
            duplicateCount: 0,
            syncState: settings.syncPaused ? "PAUSED" : "ACTIVE"
        });
    }

    // Validate and sanitize each incoming SMS payload
    const now = Date.now();
    const minTimestamp = now - 365 * 24 * 60 * 60 * 1000; // max 1 year in past
    const maxTimestamp = now + 24 * 60 * 60 * 1000;       // max 1 day in future
    const validItems = [];

    for (const raw of rawBatch) {
        if (!raw || typeof raw !== "object") continue;
        const providerId = String(raw.providerId || raw.id || "").trim();
        const sender = String(raw.sender || raw.address || "Unknown").slice(0, 50).trim();
        const body = String(raw.body || "").slice(0, 2000).trim();
        const ts = parseInt(raw.timestamp || raw.date, 10);

        if (!providerId || !body || isNaN(ts) || ts < minTimestamp || ts > maxTimestamp) {
            continue;
        }

        // Generate deterministic content-based deduplication key
        const dedupKey = crypto.createHash("sha256").update(`${device.account_id}:${sender}:${body}:${ts}`).digest("hex");

        // Extract any URLs in the SMS text
        const extractedUrls = (body.match(/https?:\/\/[^\s<>"')]+/g) || []).map((u) => ({
            href: u,
            text: u
        }));

        validItems.push({
            id: "sms_" + crypto.randomBytes(8).toString("hex"),
            providerId,
            dedupKey,
            sender,
            body,
            timestamp: ts,
            urls: extractedUrls
        });
    }

    if (validItems.length === 0) {
        return res.status(400).json({ error: "No valid SMS items found in payload." });
    }

    // Call Python AI service for classification
    const aiResultsMap = {};
    try {
        const batchPayload = {
            items: validItems.map((item) => ({
                id: item.id,
                from: item.sender,
                subject: `SMS from ${item.sender}`,
                snippet: item.body,
                body: item.body,
                urls: item.urls,
                auth: { spf: "none", dkim: "none" },
                source: "SMS"
            }))
        };

        const aiRes = await axios.post("http://127.0.0.1:8000/predict_batch", batchPayload, { timeout: 8000 });
        if (aiRes.data && Array.isArray(aiRes.data.results)) {
            aiRes.data.results.forEach((r) => {
                if (r.id) aiResultsMap[r.id] = r;
            });
        }
    } catch (err) {
        console.log(`[Sentinel AI Engine] Offline for SMS batch (${err.message}). Using local fallback.`);
    }

    // Calculate record expiry based on retention policy
    const retentionDays = settings.retentionDays || 7;
    const expiresAt = Date.now() + retentionDays * 24 * 60 * 60 * 1000;
    const ingestedAt = new Date().toISOString();

    const analyzedRecords = validItems.map((item) => {
        const detection = detectionEngine.analyzeMessage({
            id: item.id,
            source: "SMS",
            from: item.sender,
            body: item.body,
            urls: item.urls || []
        });

        const aiResult = aiResultsMap[item.id];
        let riskScore = detection.riskScore;
        let category = detection.category;
        let verdict = detection.verdict;

        if (aiResult) {
            if (aiResult.category === "LEGITIMATE" && !detectionEngine.hasStrongPhishingEvidence(detection)) {
                category = "LEGITIMATE";
                riskScore = Math.min(riskScore, 15);
                verdict = "Likely safe";
            } else if (aiResult.category === "PHISHING" && riskScore < 70) {
                riskScore = Math.max(riskScore, aiResult.final_score || 75);
                category = "PHISHING";
                verdict = "High risk";
            }
        }

        const riskLevel = riskScore >= 70 ? "CRITICAL" : riskScore >= 40 ? "HIGH" : riskScore >= 20 ? "MEDIUM" : "LOW";
        const fallbackUsed = !aiResult;
        const engine = fallbackUsed ? "JAVASCRIPT_FALLBACK" : "HYBRID_AI";
        const limitations = [...(detection.analysisLimitations || [])];
        if (fallbackUsed) {
            limitations.push("Python AI service was unavailable; message evaluated using calibrated JavaScript rule and heuristic engine.");
        }

        return {
            id: item.id,
            dedupKey: item.dedupKey,
            sender: item.sender,
            body: item.body,
            timestamp: item.timestamp,
            ingestedAt,
            category,
            riskLevel,
            riskScore,
            verdict,
            confidence: detection.confidence,
            reasons: detection.reasons,
            evidence: detection.evidence,
            findings: detection.findings,
            urlAnalysis: detection.urlAnalysis,
            recommendedActions: detection.recommendedActions,
            analysisLimitations: limitations,
            engine,
            fallbackUsed,
            modelVersion: "2.0",
            expiresAt
        };
    });

    const result = db.insertSmsBatch(device.account_id, device.id, analyzedRecords);
    db.updateDeviceSyncSuccess(device.id, permissionState || "GRANTED");

    if (result.insertedCount > 0) {
        db.logActivity(device.account_id, {
            eventType: "SMS_SYNCED",
            category: "SYNC",
            title: "SMS Batch Synchronized",
            description: `Synchronized ${result.insertedCount} new SMS messages from ${device.display_name} (${result.duplicateCount} duplicates skipped).`,
            severity: "INFO",
            metadata: { deviceId: device.id, inserted: result.insertedCount, duplicates: result.duplicateCount }
        });

        // Notify if any high-risk/phishing SMS detected in the batch
        const phishingSms = analyzedRecords.filter((r) => r.category === "PHISHING" || r.riskLevel === "CRITICAL" || r.riskScore >= 70);
        for (const p of phishingSms) {
            db.createNotification(device.account_id, {
                type: "THREAT_DETECTED",
                severity: "CRITICAL",
                title: `Phishing SMS: ${p.sender}`,
                message: `Phishing message detected from ${p.sender}: "${p.body.slice(0, 80)}..."`,
                resourceType: "SMS",
                resourceId: p.id
            });
        }
    }

    res.json({
        success: true,
        processed: validItems.length,
        inserted: result.insertedCount,
        acceptedCount: result.insertedCount,
        duplicates: result.duplicateCount,
        duplicateCount: result.duplicateCount,
        syncState: settings.syncPaused ? "PAUSED" : "ACTIVE"
    });
});

// 2. Query paginated SMS records for dashboard
app.get("/api/sms", requireAuth, (req, res) => {
    const accountId = getAccountId(req);
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 1000);
    const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
    const category = req.query.category || null;
    const search = req.query.search || null;
    const deviceId = req.query.deviceId || null;

    if (deviceId) {
        const dev = db.getDeviceById(deviceId);
        if (dev && dev.account_id !== accountId) {
            return res.status(403).json({ error: "Forbidden. Device belongs to another account." });
        }
    }

    const records = db.getSmsRecords(accountId, { limit, offset, category, search, deviceId });
    const stats = db.getSmsStats(accountId);

    const enrichedRecords = records.map((r) => {
        const score = Number(r.score ?? r.risk_score ?? 15);
        let verdict = "Likely safe";
        if (score >= 70) verdict = "High risk";
        else if (score >= 40) verdict = "Suspicious";
        else if (score >= 20) verdict = "Needs caution";

        return {
            ...r,
            score,
            riskScore: score,
            verdict: r.verdict || verdict
        };
    });

    res.json({
        success: true,
        count: enrichedRecords.length,
        total: stats.total,
        sms: enrichedRecords
    });
});

// 3. Combined SMS Sync & Status
app.get("/api/sms/sync-status", requireAuth, (req, res) => {
    const accountId = getAccountId(req);
    const stats = db.getSmsStats(accountId);
    const settings = db.getSettings(accountId);
    const devices = db.getDevicesForAccount(accountId);

    const activeDevices = devices.filter((d) => d.status === "ACTIVE" && d.lifecycle_state === "ACTIVE");

    res.json({
        success: true,
        devicesCount: devices.length,
        activeDevicesCount: activeDevices.length,
        devices,
        totalSms: stats.total,
        byCategory: stats.byCategory,
        lastSync: stats.lastSync,
        syncState: settings.syncPaused ? "PAUSED" : "ACTIVE",
        syncPaused: settings.syncPaused,
        retentionDays: settings.retentionDays,
        syncEnabled: settings.syncEnabled,
        importRangeDays: settings.importRangeDays,
        scope: settings.scope
    });
});

// 4. Pause / Resume SMS synchronization
app.post("/api/sms/sync/pause", requireUserAuth, (req, res) => {
    const accountId = getAccountId(req);
    const updated = db.updateSettings(accountId, { syncPaused: true });
    res.json({ success: true, syncPaused: true, settings: updated });
});

app.post("/api/sms/sync/resume", requireUserAuth, (req, res) => {
    const accountId = getAccountId(req);
    const updated = db.updateSettings(accountId, { syncPaused: false });
    res.json({ success: true, syncPaused: false, settings: updated });
});

// 5. Delete a specific SMS record
app.delete("/api/sms/:messageId", requireUserAuth, (req, res) => {
    const accountId = getAccountId(req);
    const owner = db.getSmsAccount(req.params.messageId);
    if (owner && owner !== accountId) {
        return res.status(403).json({ error: "Forbidden. You do not own this SMS record." });
    }

    const deleted = db.deleteSmsRecord(req.params.messageId, accountId);
    if (!deleted) {
        return res.status(404).json({ error: "SMS record not found." });
    }
    res.json({ success: true, message: "SMS record deleted successfully." });
});

// 6. Delete all synchronized SMS data for the account
app.delete("/api/sms", requireUserAuth, (req, res) => {
    const accountId = getAccountId(req);
    const deviceId = req.query.deviceId || null;

    if (deviceId) {
        const dev = db.getDeviceById(deviceId);
        if (dev && dev.account_id !== accountId) {
            return res.status(403).json({ error: "Forbidden. Device belongs to another account." });
        }
    }

    const count = db.deleteAllSms(accountId, deviceId);

    db.logActivity(accountId, {
        eventType: "SMS_PURGED",
        category: "SECURITY",
        title: "SMS Records Purged",
        description: `Purged ${count} synchronized SMS records under user privacy action.`,
        severity: "WARNING",
        metadata: { purgedCount: count }
    });

    res.json({ success: true, purgedCount: count, message: `Purged ${count} synchronized SMS records.` });
});

// 7. Get / Update SMS retention and privacy preferences
app.get("/api/sms/settings", requireUserAuth, (req, res) => {
    const accountId = getAccountId(req);
    res.json(db.getSettings(accountId));
});

app.post("/api/sms/settings", requireUserAuth, (req, res) => {
    const accountId = getAccountId(req);
    const { retentionDays, syncPaused, syncEnabled, importRangeDays, scope } = req.body || {};

    const updated = db.updateSettings(accountId, {
        retentionDays,
        syncPaused,
        syncEnabled,
        importRangeDays,
        scope
    });

    db.logActivity(accountId, {
        eventType: "SETTINGS_UPDATED",
        category: "SECURITY",
        title: "SMS Settings Updated",
        description: `Updated SMS synchronization preferences (Retention: ${updated.retentionDays}d, Paused: ${updated.syncPaused}).`,
        severity: "INFO",
        metadata: updated
    });

    res.json({ success: true, settings: updated });
});

// ==================================================
// API: SYSTEM AUDIT ACTIVITY LOG
// ==================================================

app.get("/api/activity", requireUserAuth, (req, res) => {
    const accountId = getAccountId(req);
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 100);
    const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
    const category = req.query.category || null;
    const search = req.query.search || null;

    const result = db.getActivityLog(accountId, { limit, offset, category, search });
    res.json({
        success: true,
        count: result.activities.length,
        total: result.total,
        activities: result.activities
    });
});

// ==================================================
// API: NOTIFICATION CENTER
// ==================================================

app.get("/api/notifications", requireUserAuth, (req, res) => {
    const accountId = getAccountId(req);
    const unreadOnly = req.query.unreadOnly === "true";
    const severity = req.query.severity || null;
    const type = req.query.type || null;
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 200);
    const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);

    const result = db.getNotifications(accountId, { unreadOnly, severity, type, limit, offset });
    res.json({
        success: true,
        unreadCount: result.unreadCount,
        total: result.total,
        count: result.notifications.length,
        notifications: result.notifications
    });
});

app.post("/api/notifications/:id/read", requireUserAuth, (req, res) => {
    const accountId = getAccountId(req);
    const notifOwner = db.getNotificationAccount(req.params.id);
    if (notifOwner && notifOwner !== accountId) {
        return res.status(403).json({ success: false, error: "Forbidden. You do not own this notification." });
    }

    const success = db.markNotificationRead(req.params.id, accountId);
    if (!success) {
        return res.status(404).json({ success: false, error: "Notification not found." });
    }
    const unreadCount = db.getUnreadNotificationCount(accountId);
    res.json({ success: true, unreadCount });
});

app.post("/api/notifications/read-all", requireUserAuth, (req, res) => {
    const accountId = getAccountId(req);
    const markedCount = db.markAllNotificationsRead(accountId);
    res.json({ success: true, markedCount, unreadCount: 0 });
});

app.delete("/api/notifications/:id", requireUserAuth, (req, res) => {
    const accountId = getAccountId(req);
    const notifOwner = db.getNotificationAccount(req.params.id);
    if (notifOwner && notifOwner !== accountId) {
        return res.status(403).json({ success: false, error: "Forbidden. You do not own this notification." });
    }

    const success = db.deleteNotification(req.params.id, accountId);
    if (!success) {
        return res.status(404).json({ success: false, error: "Notification not found." });
    }
    const unreadCount = db.getUnreadNotificationCount(accountId);
    res.json({ success: true, unreadCount });
});

app.get("/api/notifications/unread-count", requireUserAuth, (req, res) => {
    const accountId = getAccountId(req);
    const unreadCount = db.getUnreadNotificationCount(accountId);
    res.json({ success: true, unreadCount });
});

// ==================================================
// API: FULL DIAGNOSTIC HEALTH CHECK
// ==================================================

app.get("/api/health/full", requireUserAuth, async (req, res) => {
    let aiHealth = { status: "offline", service: "Sentinel AI Engine" };
    try {
        const aiRes = await axios.get("http://127.0.0.1:8000/health", { timeout: 2000 });
        if (aiRes.data && (aiRes.data.status === "ok" || aiRes.data.status === "healthy")) {
            aiHealth = { status: "online", ...aiRes.data };
        }
    } catch (err) {
        aiHealth = { status: "offline", error: err.message };
    }

    const accountId = getAccountId(req);
    const oauthData = db.getGmailOAuth(accountId);

    res.json({
        backend: {
            status: "online",
            version: "2.4.0",
            uptime: Math.round(process.uptime()),
            timestamp: new Date().toISOString()
        },
        aiEngine: aiHealth,
        gmail: {
            connected: Boolean(oauthData && oauthData.access_token),
            account: oauthData ? oauthData.email : null
        },
        database: {
            status: "connected",
            driver: "node:sqlite (WAL mode)"
        }
    });
});

// 8. Direct APK Download Endpoint
app.get("/download/sentinel.apk", (req, res) => {
    const apkPath = path.resolve(__dirname, "../android/SentinelCompanion/app/build/outputs/apk/debug/app-debug.apk");
    if (fs.existsSync(apkPath)) {
        res.download(apkPath, "SentinelCompanion.apk");
    } else {
        res.status(404).json({ error: "APK build not found." });
    }
});

// ==================================================
// START SERVER
// ==================================================

const PORT = process.env.PORT || 5000;
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`Backend running on http://localhost:${PORT}`);
    });
}

module.exports = {
    app,
    db,
    getAccountId,
    requireAuth,
    requireUserAuth,
    authenticateDevice,
    fallbackAnalyzeEmail
};