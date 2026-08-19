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
// HOME ROUTE
// ==================================================

app.get("/", (req, res) => {
    res.send("Personal Security Agent Backend Running");
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

        // Parallel processing of emails for high speed
        const emailPromises = messages.map(async (msg) => {
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

                // Local rule engine analysis
                const security = analyzeEmail({ from, subject, snippet });

                // Python AI Server Evaluation
                let aiResult = {
                    prediction: "safe",
                    confidence: 0,
                    ml_prediction: "safe",
                    ml_confidence: 0,
                    phishing_probability: 0,
                    bayes_risk: 0,
                    fuzzy_score: 0,
                    fuzzy_level: "LOW",
                    rule_phishing: false,
                    final_risk: "low",
                    final_score: 0
                };

                try {
                    const aiResponse = await axios.post(
                        "http://127.0.0.1:8000/predict",
                        { text: `${subject} ${snippet}` },
                        { timeout: 4000 }
                    );
                    aiResult = aiResponse.data || {};
                } catch (err) {
                    console.log(`[AI Server Offline] ${err.message}`);
                }

                // Final risk determination prioritizing Python AI decisions
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
                    id: msg.id,
                    from,
                    subject,
                    date,
                    snippet,
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
            } catch (err) {
                console.error(`Failed to process email ${msg.id}:`, err.message);
                return null;
            }
        });

        const results = await Promise.all(emailPromises);
        const emails = results.filter(e => e !== null);

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
// START SERVER
// ==================================================

app.listen(5000, () => {
    console.log("Backend running on http://localhost:5000");
});