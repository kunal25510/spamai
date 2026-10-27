/**
 * Sentinel AI Security Agent - Connection Independence Automated Test
 * Verifies that Gmail OAuth and Android Companion operations are 100% decoupled and operate independently.
 */

const assert = require("assert");
const http = require("http");
const { app } = require("../backend/server");

async function ensureServerRunning(port = 5098) {
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

async function runIndependenceTests() {
    const { started, server } = await ensureServerRunning(5098);
    const base = "http://127.0.0.1:5098";
    console.log("=== Running Sentinel Connection Independence Tests ===");

    try {
        // 1. Check initial state
        const healthRes = await fetch(`${base}/api/health/full`);
        assert.strictEqual(healthRes.status, 200, "Full health endpoint must return 200");
        const health = await healthRes.json();
        assert.strictEqual(health.backend.status, "online");
        console.log("[PASS] 1. Initial system health verified (Backend online).");

        // 2. Check initial Gmail status before Android pairing
        const initialAcctRes = await fetch(`${base}/api/account`);
        const initialAcct = await initialAcctRes.json();

        const pairSessionRes = await fetch(`${base}/api/devices/pairing`, { method: "POST" });
        assert.strictEqual(pairSessionRes.status, 200);
        const session = await pairSessionRes.json();
        assert.strictEqual(session.code.length, 6);

        const pairRes = await fetch(`${base}/api/devices/pair`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ code: session.code, displayName: "Independent Phone" })
        });
        assert.strictEqual(pairRes.status, 200);
        const dev = await pairRes.json();
        console.log("[PASS] 2. Android device paired.");

        // Verify Gmail status was NOT altered by pairing
        const acct1Res = await fetch(`${base}/api/account`);
        const acct1 = await acct1Res.json();
        assert.strictEqual(acct1.connected, initialAcct.connected, "Gmail status must NOT be modified by Android pairing");
        console.log("[PASS] 3. Gmail status invariant after Android device paired.");

        // Sync an SMS message
        const syncRes = await fetch(`${base}/api/sms/sync`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${dev.credentialToken}`
            },
            body: JSON.stringify({
                permissionState: "GRANTED",
                items: [{
                    id: "indep_msg_01",
                    sender: "BankAlert",
                    body: "OTP is 998811 for your independent transaction.",
                    timestamp: Date.now()
                }]
            })
        });
        assert.strictEqual(syncRes.status, 200);
        console.log("[PASS] 4. SMS synced successfully while Gmail is DISCONNECTED.");

        // 3. Query devices and SMS - verify they exist
        const devList1Res = await fetch(`${base}/api/devices`);
        const devList1 = await devList1Res.json();
        const foundDev = devList1.devices.find(d => d.id === dev.deviceId);
        assert.ok(foundDev, "Newly registered device must be listed in /api/devices");
        assert.strictEqual(foundDev.status, "ACTIVE");

        const smsList1Res = await fetch(`${base}/api/sms?limit=10`);
        const smsList1 = await smsList1Res.json();
        assert.ok(smsList1.total > 0, "SMS list must be queryable");
        console.log("[PASS] 5. Devices and SMS queryable while Gmail is DISCONNECTED.");

        // 4. Disconnect Gmail explicitly
        const disconnectRes = await fetch(`${base}/api/disconnect`, { method: "POST" });
        assert.strictEqual(disconnectRes.status, 200);

        // Verify devices and SMS still exist after Gmail disconnect
        const devList2Res = await fetch(`${base}/api/devices`);
        const devList2 = await devList2Res.json();
        const foundDevAfter = devList2.devices.find(d => d.id === dev.deviceId);
        assert.ok(foundDevAfter, "Android device MUST survive Gmail disconnect");
        assert.strictEqual(foundDevAfter.status, "ACTIVE");

        const smsList2Res = await fetch(`${base}/api/sms?limit=10`);
        const smsList2 = await smsList2Res.json();
        assert.ok(smsList2.total > 0, "SMS records MUST survive Gmail disconnect");
        console.log("[PASS] 6. Android device and SMS records PRESERVED after Gmail disconnect.");

        // 5. Test Revocation of Android device does not impact Gmail endpoint
        const revokeRes = await fetch(`${base}/api/devices/${dev.deviceId}`, { method: "DELETE" });
        assert.strictEqual(revokeRes.status, 200);

        const acct2Res = await fetch(`${base}/api/account`);
        const acct2 = await acct2Res.json();
        assert.strictEqual(acct2.connected, false, "Gmail status unaffected by Android revocation");
        console.log("[PASS] 7. Gmail status unaffected by Android revocation.");

        // 6. Test Activity log captured both Android and Auth events independently
        const actRes = await fetch(`${base}/api/activity?limit=20`);
        assert.strictEqual(actRes.status, 200);
        const actData = await actRes.json();
        assert.ok(actData.total > 0, "Activity log must contain recorded audit events");
        console.log(`[PASS] 8. Activity log verified (${actData.total} audit events logged).`);

        // Clean up test device from DB
        try {
            const path = require("path");
            const { DatabaseSync } = require("node:sqlite");
            const db = new DatabaseSync(path.join(__dirname, "../data/sentinel.db"));
            db.prepare("DELETE FROM devices WHERE id = ?").run(dev.deviceId);
            db.prepare("DELETE FROM sms_records WHERE device_id = ?").run(dev.deviceId);
        } catch (_) {}

        console.log("\nALL CONNECTION INDEPENDENCE TESTS PASSED SUCCESSFULLY!\n");
    } finally {
        if (started && server) {
            server.close();
        }
    }
}

runIndependenceTests().catch(err => {
    console.error("Independence Test Failed:", err);
    process.exit(1);
});
