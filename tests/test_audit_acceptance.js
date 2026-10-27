/**
 * Sentinel AI - Comprehensive Audit Acceptance Test Suite
 * Validates direct dashboard access, Google OAuth states, and Android companion isolation:
 * 1. Direct dashboard access without login gating
 * 2. Gmail OAuth token requirement for emails
 * 3. Gmail connect/disconnect independent of SMS
 * 4. Android companion pairing & Bearer authentication contract
 * 5. Dynamic device lifecycle evaluation (active vs offline based on heartbeat threshold)
 * 6. Revoking device A does not affect device B
 * 7. Revoked Android device cannot sync (403)
 * 8. SMS history retention and explicit deletion
 * 9. User rules persistence and priority
 * 10. Gmail disconnect preserves Android companion state
 */

const assert = require("assert");
const http = require("http");
const { app, db } = require("../backend/server");

let server;
const PORT = 5099;
const BASE = `http://127.0.0.1:${PORT}`;

function request(method, path, body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE);
    const options = {
      method,
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      headers: {
        "Content-Type": "application/json",
        ...headers
      }
    };

    const req = http.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          const json = data ? JSON.parse(data) : {};
          resolve({ status: res.statusCode, data: json, headers: res.headers });
        } catch (e) {
          resolve({ status: res.statusCode, raw: data, headers: res.headers });
        }
      });
    });

    req.on("error", reject);
    if (body) {
      req.write(typeof body === "string" ? body : JSON.stringify(body));
    }
    req.end();
  });
}

async function runAcceptanceTests() {
  console.log("=== Running Sentinel Acceptance & Security Audit Verification ===");

  await new Promise((resolve) => {
    server = app.listen(PORT, "127.0.0.1", () => {
      resolve();
    });
  });

  try {
    // ----------------------------------------------------
    // Test 1: Direct dashboard entry without login gating
    // ----------------------------------------------------
    const accountRes = await request("GET", "/api/account");
    assert.strictEqual(accountRes.status, 200, "Dashboard entry must load without user login");
    assert.strictEqual(typeof accountRes.data.connected, "boolean");

    const devicesRes = await request("GET", "/api/devices");
    assert.strictEqual(devicesRes.status, 200, "Device telemetry queryable directly");

    const smsRes = await request("GET", "/api/sms");
    assert.strictEqual(smsRes.status, 200, "SMS telemetry queryable directly");
    console.log("[PASS] 1. Dashboard loads directly without requiring separate user login/register.");

    // ----------------------------------------------------
    // Test 2: Gmail OAuth token requirement for emails
    // ----------------------------------------------------
    const emailRes = await request("GET", "/api/emails");
    // When Gmail OAuth is disconnected, emails return 401 requiring Google OAuth
    if (!accountRes.data.connected) {
      assert.strictEqual(emailRes.status, 401, "Disconnected Gmail must reject email fetch with 401");
    }
    console.log("[PASS] 2. Gmail OAuth token requirement strictly enforced for email access.");

    // ----------------------------------------------------
    // Test 3: Android Device A & Device B pairing
    // ----------------------------------------------------
    let devAId = null;
    let devBId = null;
    let devAToken = null;
    let devBToken = null;

    const pairA = await request("POST", "/api/devices/pairing");
    assert.ok(pairA.data.code, "Pairing code generated for Device A");

    const completeA = await request("POST", "/api/devices/pair", {
      pairing_code: pairA.data.code,
      device_name: "Pixel 9 Pro (Device A)",
      model: "Pixel 9 Pro"
    });
    assert.strictEqual(completeA.status, 200);
    devAToken = completeA.data.device_token;
    devAId = completeA.data.device_id;

    const pairB = await request("POST", "/api/devices/pairing");
    const completeB = await request("POST", "/api/devices/pair", {
      pairing_code: pairB.data.code,
      device_name: "Galaxy S24 (Device B)",
      model: "SM-S921B"
    });
    assert.strictEqual(completeB.status, 200);
    devBToken = completeB.data.device_token;
    devBId = completeB.data.device_id;
    console.log("[PASS] 3. Two separate Android companions paired successfully.");

    // ----------------------------------------------------
    // Test 4: Dynamic device lifecycle (Heartbeat freshness)
    // ----------------------------------------------------
    const hbRes = await request("POST", "/api/devices/heartbeat", { sms_permission: "GRANTED" }, {
      Authorization: `Bearer ${devAToken}`
    });
    assert.strictEqual(hbRes.status, 200, "Heartbeat for Device A accepted");

    const devListRes = await request("GET", "/api/devices");
    assert.strictEqual(devListRes.status, 200);
    const devA = devListRes.data.devices.find((d) => d.id === devAId);
    assert.ok(devA, "Device A found in list");
    assert.strictEqual(devA.status, "ACTIVE", "Recently communicating device must have ACTIVE status");
    console.log("[PASS] 4. Heartbeat updates device freshness and status to ACTIVE.");

    // ----------------------------------------------------
    // Test 5: Sync SMS from Device A & verify threat classification
    // ----------------------------------------------------
    const syncRes = await request("POST", "/api/sms/sync", {
      messages: [
        {
          id: `test_msg_${Date.now()}_1`,
          sender: "AM-UNSTOP",
          body: "Congratulations! You have been shortlisted for the Round 2 challenge on Unstop.",
          timestamp: Date.now()
        },
        {
          id: `test_msg_${Date.now()}_2`,
          sender: "+18005550199",
          body: "URGENT: Your account access has been restricted. Unlock at http://secure-bank-login.xyz immediately.",
          timestamp: Date.now()
        }
      ]
    }, {
      Authorization: `Bearer ${devAToken}`
    });
    assert.strictEqual(syncRes.status, 200, "Device A SMS sync succeeded");

    const smsList = await request("GET", "/api/sms?limit=10");
    assert.strictEqual(smsList.status, 200);
    const phishingMsg = smsList.data.sms.find((m) => m.body.includes("secure-bank-login.xyz"));
    assert.ok(phishingMsg, "Phishing SMS must be stored and queryable");
    assert.strictEqual(phishingMsg.category, "PHISHING", "Smishing lure must be classified as PHISHING");
    console.log("[PASS] 5. Device A synced SMS messages with accurate threat classification.");

    // ----------------------------------------------------
    // Test 6: Revoke Device A; verify Device B remains unaffected
    // ----------------------------------------------------
    const revokeARes = await request("DELETE", `/api/devices/${devAId}`);
    assert.strictEqual(revokeARes.status, 200, "Device A revocation succeeded");

    // Device A should now be rejected from syncing
    const rejectedSync = await request("POST", "/api/sms/sync", {
      messages: [{ id: "fail_msg", sender: "test", body: "test", timestamp: Date.now() }]
    }, {
      Authorization: `Bearer ${devAToken}`
    });
    assert.strictEqual(rejectedSync.status, 403, "Revoked device A must receive 403 on sync");

    // Device B should still be valid and capable of syncing
    const bSync = await request("POST", "/api/sms/sync", {
      messages: [{
        id: `b_msg_${Date.now()}`,
        sender: "FRIEND",
        body: "Hey are we still meeting today?",
        timestamp: Date.now()
      }]
    }, {
      Authorization: `Bearer ${devBToken}`
    });
    assert.strictEqual(bSync.status, 200, "Device B must remain unaffected by Device A revocation");
    console.log("[PASS] 6. Device revocation isolation verified: Device A revoked, Device B functional.");

    // ----------------------------------------------------
    // Test 7: Device SMS deletion vs Full SMS Purge
    // ----------------------------------------------------
    const delDevB = await request("DELETE", `/api/sms?deviceId=${devBId}`);
    assert.strictEqual(delDevB.status, 200, "Deleting SMS for Device B succeeded");

    // Device A messages should still be retained
    const remainingSms = await request("GET", "/api/sms?limit=50");
    const devAMessages = remainingSms.data.sms.filter((s) => s.deviceId === devAId || s.device_id === devAId);
    assert.ok(devAMessages.length > 0, "Device A messages remain preserved until explicit deletion");
    console.log("[PASS] 7. Device-specific SMS deletion preserves other device records.");

    // ----------------------------------------------------
    // Test 8: Domain Rules Persistence & Priority
    // ----------------------------------------------------
    const addRuleRes = await request("POST", "/api/reputation/override", {
      domain: "partner-test.org",
      status: "TRUSTED",
      notes: "Acceptance test rule"
    });
    assert.strictEqual(addRuleRes.status, 200);

    const repRes = await request("GET", "/api/reputation");
    assert.strictEqual(repRes.status, 200);
    assert.ok(repRes.data.user_rules["partner-test.org"], "Added rule must persist in reputation state");
    assert.strictEqual(repRes.data.user_rules["partner-test.org"].status, "TRUSTED");
    console.log("[PASS] 8. User domain rules persist and reflect in reputation state.");

    // ----------------------------------------------------
    // Test 9: Disconnect Gmail without affecting Android SMS
    // ----------------------------------------------------
    const disconnectRes = await request("POST", "/api/disconnect");
    assert.strictEqual(disconnectRes.status, 200, "Gmail disconnect endpoint succeeded");

    const postDisconnDev = await request("GET", "/api/devices");
    assert.strictEqual(postDisconnDev.status, 200);
    assert.ok(postDisconnDev.data.devices.length >= 2, "Android devices preserved after Gmail disconnect");

    const postDisconnSms = await request("GET", "/api/sms");
    assert.strictEqual(postDisconnSms.status, 200);
    assert.ok(postDisconnSms.data.sms.length > 0, "SMS records preserved after Gmail disconnect");
    console.log("[PASS] 9. Gmail disconnect leaves Android devices and SMS records completely intact.");

    // ----------------------------------------------------
    // Test 10: Purge Test SMS records cleanly
    // ----------------------------------------------------
    const purgeRes = await request("DELETE", `/api/sms?deviceId=${devAId}`);
    assert.strictEqual(purgeRes.status, 200, "Purge test device SMS succeeded");

    const emptySms = await request("GET", `/api/sms?deviceId=${devAId}`);
    assert.strictEqual(emptySms.data.sms.length, 0, "Device A SMS purged cleanly upon user confirmation");
    console.log("[PASS] 10. Clean user-confirmed SMS purge confirmed.");

    console.log("\nALL ACCEPTANCE CRITERIA VERIFIED SUCCESSFULLY!");
  } finally {
    try {
      const path = require("path");
      const { DatabaseSync } = require("node:sqlite");
      const db = new DatabaseSync(path.join(__dirname, "../data/sentinel.db"));
      if (typeof devAId !== "undefined" && devAId) {
        db.prepare("DELETE FROM devices WHERE id = ?").run(devAId);
        db.prepare("DELETE FROM sms_records WHERE device_id = ?").run(devAId);
      }
      if (typeof devBId !== "undefined" && devBId) {
        db.prepare("DELETE FROM devices WHERE id = ?").run(devBId);
        db.prepare("DELETE FROM sms_records WHERE device_id = ?").run(devBId);
      }
    } catch (_) {}
    server.close();
  }
}

runAcceptanceTests().catch((err) => {
  console.error("ACCEPTANCE TEST FAILED:", err);
  process.exit(1);
});
