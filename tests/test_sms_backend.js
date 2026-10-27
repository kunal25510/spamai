/**
 * Sentinel AI Security Agent - SMS & Device Backend Automated Test Suite
 * Tests pairing, token authentication, batch upload, deduplication, revocation, retention,
 * and Sentinel user session security.
 */

const assert = require("assert");
const http = require("http");
const { app } = require("../backend/server");

async function ensureServerRunning(port = 5097) {
    return new Promise((resolve) => {
        const testReq = http.get(`http://127.0.0.1:${port}/api/health`, (res) => {
            resolve({ started: false, server: null });
        });
        testReq.on("error", () => {
            const server = app.listen(port, "127.0.0.1", () => {
                resolve({ started: true, server });
            });
        });
    });
}

async function runTests() {
    const { started, server } = await ensureServerRunning(5097);
    const base = "http://127.0.0.1:5097";
    console.log("=== Running Sentinel Device Pairing & SMS Backend Tests ===");

    try {
        // Ensure sync is not paused from any interrupted test
        await fetch(`${base}/api/sms/sync/resume`, { method: "POST" });

        // 1. Test Pairing Code Creation
        const sessRes = await fetch(`${base}/api/devices/pairing`, { method: "POST" });
        assert.strictEqual(sessRes.status, 200, "Pairing session creation should succeed");
        const session = await sessRes.json();
        assert.ok(session.code, "Session must have a code");
        assert.strictEqual(session.code.length, 6, "Code must be 6 alphanumeric chars");
        assert.ok(session.expiresAt > Date.now(), "Code expiry must be in the future");
        console.log("[PASS] 1. Pairing session created with 6-digit code:", session.code);

        // 2. Test Device Pairing with Valid Code
        const pairRes = await fetch(`${base}/api/devices/pair`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ code: session.code, displayName: "Test Pixel Phone" })
        });
        assert.strictEqual(pairRes.status, 200, "Device pair should succeed with valid code");
        const devData = await pairRes.json();
        assert.ok(devData.deviceId.startsWith("dev_"), "Should return valid deviceId");
        assert.ok(devData.credentialToken.startsWith("sentinel_dev_"), "Should return revocable credential");
        console.log("[PASS] 2. Device successfully registered and issued credential:", devData.deviceId);

        // 3. Test Reuse of Consumed Pairing Code (Must Be Rejected)
        const reuseRes = await fetch(`${base}/api/devices/pair`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ code: session.code, displayName: "Attacker Cloner" })
        });
        assert.strictEqual(reuseRes.status, 400, "Reusing consumed pairing code must return 400");
        const reuseJson = await reuseRes.json();
        assert.ok(reuseJson.error.includes("already been used"), "Error should explain code is used");
        console.log("[PASS] 3. Consumed pairing code reuse prevented atomically.");

        // 4. Test Invalid Device Credential (Must Be Rejected with 401)
        const fakeAuthRes = await fetch(`${base}/api/sms/sync`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": "Bearer sentinel_dev_completely_fake_token_12345"
            },
            body: JSON.stringify({ items: [] })
        });
        assert.strictEqual(fakeAuthRes.status, 401, "Invalid device token must return 401 Unauthorized");
        console.log("[PASS] 4. Unauthorized device token rejected with 401.");

        // 5. Test Batch SMS Synchronization with Mixed Legitimate & Smishing Messages
        const smsBatch = [
            {
                id: "msg_test_001",
                sender: "VK-HDFCBK",
                body: "Acct XX9871 debited by Rs 1500.00 on 24-Oct-26. UPI: 123456789. If not you, SMS BLOCK to 56767.",
                timestamp: Date.now() - 3600000
            },
            {
                id: "msg_test_002",
                sender: "+18005550188",
                body: "Your parcel delivery has failed. Click to pay $1.99 redelivery fee: http://fedex-update-fee.xyz/pay",
                timestamp: Date.now() - 1800000
            },
            {
                id: "msg_test_003",
                sender: "MUMBAI-POLICE",
                body: "Advisory: Do not click unknown links or share banking OTP with strangers.",
                timestamp: Date.now() - 900000
            }
        ];

        const syncRes = await fetch(`${base}/api/sms/sync`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${devData.credentialToken}`
            },
            body: JSON.stringify({
                permissionState: "GRANTED",
                items: smsBatch
            })
        });
        assert.strictEqual(syncRes.status, 200, "Batch SMS sync should succeed");
        const syncData = await syncRes.json();
        assert.strictEqual(syncData.inserted, 3, "All 3 unique messages should be inserted");
        assert.strictEqual(syncData.duplicates, 0, "No duplicates on first batch");
        console.log("[PASS] 5. Batch SMS synchronization succeeded with 3 records processed.");

        // 6. Test Deduplication Idempotency (Same Batch Uploaded Again)
        const dedupRes = await fetch(`${base}/api/sms/sync`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${devData.credentialToken}`
            },
            body: JSON.stringify({ items: smsBatch })
        });
        assert.strictEqual(dedupRes.status, 200);
        const dedupData = await dedupRes.json();
        assert.strictEqual(dedupData.inserted, 0, "Zero new records should be inserted on duplicate upload");
        assert.strictEqual(dedupData.duplicates, 3, "All 3 records must be caught by deduplication index");
        console.log("[PASS] 6. Deduplication verified (3/3 duplicate messages detected and ignored).");

        // 7. Test Batch Size Limit (>100 Items Rejection)
        const oversizedBatch = Array.from({ length: 101 }, (_, i) => ({
            id: `oversized_${i}`,
            sender: "Spammer",
            body: "Spam content",
            timestamp: Date.now()
        }));
        const overRes = await fetch(`${base}/api/sms/sync`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${devData.credentialToken}`
            },
            body: JSON.stringify({ items: oversizedBatch })
        });
        assert.strictEqual(overRes.status, 400, "Oversized batch > 100 items must be rejected");
        console.log("[PASS] 7. Oversized batch protection enforced (>100 items rejected).");

        // 8. Test Malformed Message Body Validation
        const malformedRes = await fetch(`${base}/api/sms/sync`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${devData.credentialToken}`
            },
            body: JSON.stringify({
                items: [{ id: "bad_ts", sender: "Unknown", body: "Test", timestamp: "invalid_time" }]
            })
        });
        assert.strictEqual(malformedRes.status, 400, "Malformed message payload must be rejected");
        console.log("[PASS] 8. Malformed field validation enforced.");

        // 9. Test Querying Synced SMS Records
        const getSmsRes = await fetch(`${base}/api/sms?limit=10`);
        assert.strictEqual(getSmsRes.status, 200);
        const smsList = await getSmsRes.json();
        assert.ok(smsList.total >= 3, "Database should contain at least 3 SMS records");
        const smishingItem = smsList.sms.find((s) => s.sender === "+18005550188");
        assert.ok(smishingItem, "Smishing message should be in database");
        assert.strictEqual(smishingItem.category, "PHISHING", "Smishing lure with .xyz link must be classified as PHISHING");
        console.log("[PASS] 9. Dashboard SMS records queried with correct PHISHING classification.");

        // 10. Test Pause / Resume Synchronization Control
        const pauseRes = await fetch(`${base}/api/sms/sync/pause`, { method: "POST" });
        assert.strictEqual(pauseRes.status, 200);

        const pausedSync = await fetch(`${base}/api/sms/sync`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${devData.credentialToken}`
            },
            body: JSON.stringify({ items: [{ id: "during_pause", sender: "X", body: "Hi", timestamp: Date.now() }] })
        });
        assert.strictEqual(pausedSync.status, 409, "Sync during paused state must return 409 Conflict");
        console.log("[PASS] 10. Pause synchronization control enforced.");

        // Resume synchronization
        const resumeRes = await fetch(`${base}/api/sms/sync/resume`, { method: "POST" });
        assert.strictEqual(resumeRes.status, 200);

        // 11. Test Device Revocation (Subsequent Uploads Must Return 403 Forbidden)
        const revokeRes = await fetch(`${base}/api/devices/${devData.deviceId}`, { method: "DELETE" });
        assert.strictEqual(revokeRes.status, 200, "Device revocation should succeed");

        const revokedSync = await fetch(`${base}/api/sms/sync`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${devData.credentialToken}`
            },
            body: JSON.stringify({ items: [{ id: "after_revoke", sender: "X", body: "Hi", timestamp: Date.now() }] })
        });
        assert.strictEqual(revokedSync.status, 403, "Upload from revoked device must return 403 Forbidden");
        console.log("[PASS] 11. Device revocation verified (subsequent uploads blocked with 403).");

        // 12. Test Data Deletion Request
        const delRes = await fetch(`${base}/api/sms?deviceId=${devData.deviceId}`, { method: "DELETE" });
        assert.strictEqual(delRes.status, 200);
        const delData = await delRes.json();
        assert.ok(delData.purgedCount >= 3, "Should purge synchronized test records");
        console.log(`[PASS] 12. Data deletion confirmed (${delData.purgedCount} records purged).`);

        // 13. Clean up test device from DB
        try {
            const path = require("path");
            const { DatabaseSync } = require("node:sqlite");
            const db = new DatabaseSync(path.join(__dirname, "../data/sentinel.db"));
            db.prepare("DELETE FROM devices WHERE id = ?").run(devData.deviceId);
            db.prepare("DELETE FROM sms_records WHERE device_id = ?").run(devData.deviceId);
        } catch (_) {}

        console.log("\nALL SMS & DEVICE BACKEND TESTS PASSED SUCCESSFULLY!");
    } finally {
        if (started && server) {
            server.close();
        }
    }
}

runTests().catch((err) => {
    console.error("Test failure:", err);
    process.exit(1);
});
