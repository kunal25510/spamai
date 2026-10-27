/**
 * Test: Review Corrections & Persistence for SMS and Gmail
 * Validates that correcting classification on one item persists across reloads
 * and does not cross-contaminate or alter any other messages.
 */

const assert = require("assert");
const http = require("http");
const { app } = require("../backend/server");
const db = require("../backend/database");

const PORT = 5096;
const BASE_URL = `http://127.0.0.1:${PORT}`;

function request(method, path, body = null, headers = {}) {
    return new Promise((resolve, reject) => {
        const url = new URL(path, BASE_URL);
        const options = {
            hostname: url.hostname,
            port: url.port,
            path: url.pathname + url.search,
            method,
            headers: {
                "Content-Type": "application/json",
                ...headers
            }
        };

        const req = http.request(options, (res) => {
            let data = "";
            res.on("data", (chunk) => (data += chunk));
            res.on("end", () => {
                let parsed = null;
                try {
                    parsed = JSON.parse(data);
                } catch (_) {
                    parsed = data;
                }
                resolve({ status: res.statusCode, headers: res.headers, body: parsed });
            });
        });

        req.on("error", reject);
        if (body) {
            req.write(typeof body === "string" ? body : JSON.stringify(body));
        }
        req.end();
    });
}

async function runTests() {
    console.log("=== Running Review & Correction Tests ===");

    const server = await new Promise((resolve) => {
        const s = app.listen(PORT, "127.0.0.1", () => resolve(s));
    });

    try {
        const userSession = db.createAnonymousUserSession();
        const accountId = userSession.user.id;
        const cookieHeader = { "x-sentinel-session": userSession.sessionToken, "x-sentinel-account": accountId };

    // 1. Insert 2 sample SMS records under this account
    // Message 1 is in NEEDS REVIEW
    // Message 2 is in NEEDS REVIEW
    const smsBatch = [
        {
            providerId: "prov_101",
            sender: "BankAlert",
            body: "Your account security code is 8849. Please verify unusual activity.",
            timestamp: Date.now() - 60000,
            messageType: 1
        },
        {
            providerId: "prov_102",
            sender: "Mom",
            body: "Are you coming over for dinner tonight?",
            timestamp: Date.now() - 30000,
            messageType: 1
        }
    ];

    // Register a test device
    const device = db.registerDevice(accountId, "Review Test Phone");
    assert(device && device.deviceId, "Device should be registered");

    // Ingest the 2 SMS messages via companion API
    const syncRes = await request("POST", "/api/sms/sync", {
        messages: smsBatch,
        permissionState: "GRANTED"
    }, {
        Authorization: `Bearer ${device.credentialToken}`
    });
    assert.strictEqual(syncRes.status, 200, "Sync should return 200");
    assert.strictEqual(syncRes.body.acceptedCount, 2, "2 messages should be accepted");

    // Get the inserted records
    const allSms = db.getSmsRecords(accountId);
    assert.strictEqual(allSms.length, 2, "Should have 2 SMS records");
    const msg1 = allSms.find(m => m.sender === "BankAlert");
    const msg2 = allSms.find(m => m.sender === "Mom");
    assert(msg1 && msg2, "Both test SMS records should exist");

    // Initially, verify both are unreviewed
    assert.strictEqual(msg1.reviewed, false, "Message 1 should not be reviewed initially");
    assert.strictEqual(msg2.reviewed, false, "Message 2 should not be reviewed initially");

    console.log("[PASS] 1. Initial state verified: both messages unreviewed.");

    // 2. Submit correction on Message 1 ONLY -> Mark as LEGITIMATE
    const feedbackRes1 = await request("POST", "/api/feedback", {
        id: msg1.id,
        source: "SMS",
        feedbackType: "MARK_LEGITIMATE",
        targetCategory: "LEGITIMATE",
        emailSummary: {
            from: msg1.sender,
            subject: msg1.subject,
            category: msg1.category
        }
    }, cookieHeader);

    assert.strictEqual(feedbackRes1.status, 200, "Feedback request should return 200");
    assert.strictEqual(feedbackRes1.body.item.category, "LEGITIMATE", "Message 1 should be reclassified as LEGITIMATE");
    console.log("[PASS] 2. Feedback submitted for Message 1.");

    // 3. Query SMS list again (simulating website refresh)
    const refreshedSms = db.getSmsRecords(accountId);
    const refreshedMsg1 = refreshedSms.find(m => m.id === msg1.id);
    const refreshedMsg2 = refreshedSms.find(m => m.id === msg2.id);

    // Message 1 MUST be LEGITIMATE and reviewed: true
    assert.strictEqual(refreshedMsg1.category, "LEGITIMATE", "Message 1 MUST remain LEGITIMATE after reload");
    assert.strictEqual(refreshedMsg1.reviewed, true, "Message 1 MUST have reviewed: true");
    assert.strictEqual(refreshedMsg1.userFeedback, "MARK_LEGITIMATE", "Message 1 MUST have userFeedback: MARK_LEGITIMATE");

    // Message 2 MUST NOT BE ALTERED! (Must remain unreviewed)
    assert.strictEqual(refreshedMsg2.reviewed, false, "Message 2 MUST NOT be marked reviewed");
    assert.strictEqual(refreshedMsg2.userFeedback, null, "Message 2 userFeedback MUST be null");
    console.log("[PASS] 3. Zero cross-item contamination verified: Message 1 corrected, Message 2 untouched.");

    // 4. Verify byCategory counts in getSmsStats
    const stats = db.getSmsStats(accountId);
    assert.strictEqual(stats.byCategory["LEGITIMATE"] >= 1, true, "byCategory.LEGITIMATE should count Message 1");
    console.log("[PASS] 4. SMS sync status byCategory counts correctly updated in SQLite.");

    // 5. Test Gmail Override Persistence
    const gmailMsgId = "gmail_msg_test_" + Date.now();
    const feedbackGmail = await request("POST", "/api/feedback", {
        id: gmailMsgId,
        source: "GMAIL",
        feedbackType: "MARK_LEGITIMATE",
        targetCategory: "LEGITIMATE",
        emailSummary: {
            from: "alerts@security.test",
            subject: "Suspicious activity notice",
            category: "NEEDS REVIEW"
        }
    }, cookieHeader);

    assert.strictEqual(feedbackGmail.status, 200, "Gmail feedback should succeed");
    assert.strictEqual(feedbackGmail.body.item.category, "LEGITIMATE", "Gmail item should be reclassified as LEGITIMATE");

    // Check classification_overrides directly
    const gmailOverrides = db.getClassificationOverrides(accountId, "GMAIL");
    assert(gmailOverrides[gmailMsgId], "Gmail override must exist in SQLite database");
    assert.strictEqual(gmailOverrides[gmailMsgId].category, "LEGITIMATE", "Gmail override category must be LEGITIMATE");
    assert.strictEqual(gmailOverrides[gmailMsgId].feedbackType, "MARK_LEGITIMATE", "Gmail feedback type must match");
    console.log("[PASS] 5. Gmail persistent override in SQLite verified.");

    // 6. Test reclassifying again (e.g. user changing mind from LEGITIMATE to PHISHING)
    const reclassifyRes = await request("POST", "/api/feedback", {
        id: msg1.id,
        source: "SMS",
        feedbackType: "MARK_PHISHING",
        targetCategory: "PHISHING"
    }, cookieHeader);

    assert.strictEqual(reclassifyRes.status, 200);
    assert.strictEqual(reclassifyRes.body.item.category, "PHISHING");

    const reloadedSms = db.getSmsRecords(accountId);
    const reloadedMsg1 = reloadedSms.find(m => m.id === msg1.id);
    assert.strictEqual(reloadedMsg1.category, "PHISHING", "Message 1 reclassification to PHISHING persisted");
    console.log("[PASS] 6. Reclassification update idempotency verified.");

    // Cleanup test records
    db.deleteAllSms(accountId);
    db.updateDeviceStatus(device.deviceId, accountId, "REVOKED");
    console.log("\nALL REVIEW & CORRECTION TESTS PASSED PERFECTLY!\n");
    } finally {
        if (server) server.close();
    }
}

runTests().catch(err => {
    console.error("Test failed:", err);
    process.exit(1);
});
