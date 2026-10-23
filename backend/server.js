const path = require("path");
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
app.use(express.json());

// ==================================================
// GOOGLE OAUTH
// ==================================================

const oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI || "http://localhost:5000/auth/google/callback"
);

const SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly"
];

// Temporary token storage
let currentTokens = null;
let connectedEmail = null;

// ==================================================
// BACKEND RULE ENGINE (FALLBACK / LOCAL SCORE)
// ==================================================

function analyzeEmail(email) {
    let score = 0;
    let reasons = [];

    const text = (
        (email.subject || "") + " " +
        (email.from || "") + " " +
        (email.snippet || "")
    ).toLowerCase();

    // Urgent / Threatening words
    const urgentWords = [
        "urgent", "immediately", "act now", "account suspended", "account blocked",
        "verify now", "last warning", "final warning", "expires today"
    ];
    urgentWords.forEach(word => {
        if (text.includes(word)) {
            score += 15;
            reasons.push("Urgent or threatening language");
        }
    });

    // Login / Account words
    const loginWords = [
        "password", "verify your account", "login", "log in", "sign in",
        "confirm your account", "verify identity", "security alert", "confirm access"
    ];
    loginWords.forEach(word => {
        if (text.includes(word)) {
            score += 15;
            reasons.push("Possible account or login request");
        }
    });

    // Financial words
    const moneyWords = [
        "bank", "credit card", "payment", "refund", "upi", "otp", "transaction", "invoice", "money transfer"
    ];
    moneyWords.forEach(word => {
        if (text.includes(word)) {
            score += 10;
            reasons.push("Financial or sensitive information mentioned");
        }
    });

    // Scam / Reward words
    const scamWords = [
        "you won", "winner", "lottery", "free money", "claim your prize", "reward", "congratulations", "cash prize"
    ];
    scamWords.forEach(word => {
        if (text.includes(word)) {
            score += 20;
            reasons.push("Possible prize or reward scam");
        }
    });

    // Links
    if (text.includes("http://") || text.includes("https://") || text.includes("www.")) {
        score += 10;
        reasons.push("Contains a web link");
    }

    score = Math.min(score, 100);

    let risk = "LOW";
    if (score >= 60) {
        risk = "HIGH";
    } else if (score >= 30) {
        risk = "MEDIUM";
    }

    reasons = [...new Set(reasons)];

    return {
        score,
        risk,
        reasons
    };
}

// ==================================================
// HOME & HEALTH ROUTES
// ==================================================

app.get("/", (req, res) => {
    res.send("Personal Security Agent Backend Running");
});

app.get("/api/health", (req, res) => {
    res.json({
        status: "ok",
        uptime: process.uptime(),
        timestamp: new Date().toISOString()
    });
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
                <p>Please create or edit the file <code>backend/.env</code> with your credentials:</p>
                <pre style="background: #222; padding: 15px; border-radius: 5px; color: #50fa7b; overflow-x: auto;">
GOOGLE_CLIENT_ID=your_client_id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your_client_secret
GOOGLE_REDIRECT_URI=http://localhost:5000/auth/google/callback
                </pre>
                <p style="font-size: 13px; color: #aaa;">Get your OAuth credentials from <a href="https://console.cloud.google.com/apis/credentials" target="_blank" style="color: #8be9fd;">Google Cloud Console</a>.</p>
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
        console.log("Gmail connected:", connectedEmail);

        res.redirect("http://localhost:5173");
    } catch (error) {
        console.error("Google OAuth error:", error.message);
        res.status(500).send("Google connection failed: " + error.message);
    }
});

// ==================================================
// API: CONNECTED ACCOUNT STATUS
// ==================================================

app.get("/api/account", (req, res) => {
    if (!currentTokens) {
        return res.json({ connected: false });
    }
    res.json({
        connected: true,
        email: connectedEmail
    });
});

// ==================================================
// API: GET & ANALYZE GMAIL EMAILS
// ==================================================

app.get("/api/emails", async (req, res) => {
    res.set({
        "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
        "Pragma": "no-cache",
        "Expires": "0"
    });

    try {
        if (!currentTokens) {
            return res.status(401).json({ error: "Gmail not connected" });
        }

        oauth2Client.setCredentials(currentTokens);
        const gmail = google.gmail({ version: "v1", auth: oauth2Client });

        const listResponse = await gmail.users.messages.list({
            userId: "me",
            maxResults: 20,
            includeSpamTrash: false
        });

        const messages = listResponse.data.messages || [];

        // 1. Parallel fetch email headers from Gmail API
        const rawEmails = await Promise.all(
            messages.map(async (msg) => {
                try {
                    const emailRes = await gmail.users.messages.get({
                        userId: "me",
                        id: msg.id,
                        format: "metadata",
                        metadataHeaders: ["From", "Subject", "Date"]
                    });

                    const headers = emailRes.data.payload?.headers || [];
                    const from = headers.find(h => h.name === "From")?.value || "Unknown";
                    const subject = headers.find(h => h.name === "Subject")?.value || "No Subject";
                    const date = headers.find(h => h.name === "Date")?.value || "";
                    const snippet = emailRes.data.snippet || "";

                    return { id: msg.id, from, subject, date, snippet };
                } catch (err) {
                    console.error(`Failed to fetch email metadata ${msg.id}:`, err.message);
                    return null;
                }
            })
        );

        const validRawEmails = rawEmails.filter(Boolean);

        // 2. High-speed Batch Request to Python AI Server
        const aiResultsMap = {};
        if (validRawEmails.length > 0) {
            try {
                const batchPayload = {
                    items: validRawEmails.map(e => ({
                        id: e.id,
                        text: `${e.subject} ${e.snippet}`
                    }))
                };
                const aiResponse = await axios.post(
                    "http://127.0.0.1:8000/predict_batch",
                    batchPayload,
                    { timeout: 5000 }
                );
                if (aiResponse.data && Array.isArray(aiResponse.data.results)) {
                    aiResponse.data.results.forEach(resItem => {
                        if (resItem.id) {
                            aiResultsMap[resItem.id] = resItem;
                        }
                    });
                }
            } catch (err) {
                console.log(`[AI Server Batch Offline/Error] ${err.message}`);
            }
        }

        // 3. Process email results with local fallback if needed
        const emails = validRawEmails.map((e) => {
            const security = analyzeEmail({ from: e.from, subject: e.subject, snippet: e.snippet });
            const aiResult = aiResultsMap[e.id] || {};

            const finalRisk = (aiResult && aiResult.final_risk)
                ? aiResult.final_risk.toUpperCase()
                : security.risk;

            const finalScore = (aiResult && aiResult.final_score !== undefined)
                ? Math.round(aiResult.final_score)
                : security.score;

            const mlPrediction = String(
                aiResult.ml_prediction || aiResult.prediction || "safe"
            ).toLowerCase();

            const mlConfidence = Number(
                aiResult.phishing_probability ??
                aiResult.ml_confidence ??
                aiResult.confidence ?? 0
            );

            return {
                id: e.id,
                from: e.from,
                subject: e.subject,
                date: e.date,
                snippet: e.snippet,
                risk: finalRisk,
                score: security.score,
                reasons: security.reasons,
                aiPrediction: mlPrediction,
                aiConfidence: mlConfidence,
                bayesRisk: Number(aiResult.bayes_risk || 0),
                fuzzyScore: Number(aiResult.fuzzy_score || 0),
                fuzzyLevel: aiResult.fuzzy_level || "LOW",
                rulePhishing: aiResult.rule_phishing === true,
                finalScore
            };
        });

        res.json({
            connected: true,
            account: connectedEmail,
            count: emails.length,
            emails
        });
    } catch (error) {
        console.error("Gmail API Error:", error.message);
        res.status(500).json({ error: error.message });
    }
});

// ==================================================
// API: MULTI-MODE MESSAGE & URL ANALYSIS
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

        // Send to Python AI engine
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

app.listen(5000, () => {
    console.log("Backend running on http://localhost:5000");
});