/**
 * Sentinel AI — Multi-User Authentication, Dashboard Isolation, Notifications, and Android Device Pairing Test Suite
 *
 * Verifies Scenarios A through I:
 * - Scenario A: New user has 0 devices, disconnected Gmail, 0 notifications
 * - Scenario B: User B with paired device and Gmail shows only their records
 * - Scenario C: Strict cross-user data isolation (User A cannot access User B's devices, SMS, or notifications)
 * - Scenario D: Browser / session isolation
 * - Scenario E: Logout and session switching cleans state
 * - Scenario F: Device pairing idempotency (re-pairing same device updates credentials without creating duplicates)
 * - Scenario G: Notification isolation, deduplication, and read permissions
 * - Scenario H: Disconnection isolation (User A disconnect does not affect User B)
 * - Scenario I: API failures return appropriate errors and cannot be bypassed
 */

const assert = require("assert");
const http = require("http");
const { app } = require("../backend/server");
const db = require("../backend/database");

const PORT = 5097;
const BASE = `http://127.0.0.1:${PORT}`;
let server;

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

async function runMultiUserTests() {
  console.log("=== Running Sentinel Multi-User Isolation & Security Audit Suite ===");

  await new Promise((resolve) => {
    server = app.listen(PORT, "127.0.0.1", () => resolve());
  });

  try {
    // ====================================================
    // Scenario A: New User (Clean State)
    // ====================================================
    console.log("\n--- Scenario A: New User (Clean State) ---");
    const sessionResA = await request("GET", "/api/auth/session");
    assert.strictEqual(sessionResA.status, 200);
    const tokenA = sessionResA.data.sessionToken;
    const userA = sessionResA.data.user;
    assert.ok(tokenA, "User A must receive session token");
    assert.ok(userA.id, "User A must have unique user ID");

    // Check User A's Gmail status -> Not connected
    const acctA = await request("GET", "/api/account", null, { "X-Sentinel-Session": tokenA });
    assert.strictEqual(acctA.status, 200);
    assert.strictEqual(acctA.data.connected, false, "New User A must NOT have Gmail connected");

    // Check User A's devices -> Empty list (0 devices)
    const devListA = await request("GET", "/api/devices", null, { "X-Sentinel-Session": tokenA });
    assert.strictEqual(devListA.status, 200);
    assert.strictEqual(devListA.data.devices.length, 0, "New User A must have 0 paired devices");

    // Check User A's notifications -> Empty list (0 notifications)
    const notifA = await request("GET", "/api/notifications", null, { "X-Sentinel-Session": tokenA });
    assert.strictEqual(notifA.status, 200);
    assert.strictEqual(notifA.data.notifications.length, 0, "New User A must have 0 notifications");
    assert.strictEqual(notifA.data.unreadCount, 0, "New User A unreadCount must be 0");

    // Check User A's SMS records -> 0 records
    const smsA = await request("GET", "/api/sms", null, { "X-Sentinel-Session": tokenA });
    assert.strictEqual(smsA.status, 200);
    assert.strictEqual(smsA.data.sms.length, 0, "New User A must have 0 SMS records");
    console.log("[PASS] Scenario A: New user has 0 devices, disconnected Gmail, 0 notifications, and 0 SMS records.");

    // ====================================================
    // Scenario B: Existing User B with paired device and Gmail
    // ====================================================
    console.log("\n--- Scenario B: Existing User B with Paired Device & Gmail ---");
    const sessionResB = await request("GET", "/api/auth/session");
    assert.strictEqual(sessionResB.status, 200);
    const tokenB = sessionResB.data.sessionToken;
    const userB = sessionResB.data.user;
    assert.notStrictEqual(tokenB, tokenA, "User B must have distinct session token");
    assert.notStrictEqual(userB.id, userA.id, "User B must have distinct user ID");

    // Pair a device for User B
    const pairSessionB = await request("POST", "/api/devices/pairing", null, { "X-Sentinel-Session": tokenB });
    assert.strictEqual(pairSessionB.status, 200);
    const codeB = pairSessionB.data.code;

    const pairDevB = await request("POST", "/api/devices/pair", {
      code: codeB,
      displayName: "Pixel 9 User B",
      hardwareFingerprint: "hw_fingerprint_pixel9_userb"
    });
    assert.strictEqual(pairDevB.status, 200);
    const devBId = pairDevB.data.deviceId;
    const devBToken = pairDevB.data.credentialToken;
    assert.ok(devBId, "User B device ID must be created");

    // Mock Gmail connection for User B in database
    db.saveGmailOAuth(userB.id, {
      access_token: "mock_access_token_user_b",
      refresh_token: "mock_refresh_token_user_b",
      expiry_date: Date.now() + 3600000,
      scope: "https://www.googleapis.com/auth/gmail.readonly",
      token_type: "Bearer"
    }, "userb.security@gmail.com");

    // Verify User B's dashboard shows their Gmail and device
    const acctB = await request("GET", "/api/account", null, { "X-Sentinel-Session": tokenB });
    assert.strictEqual(acctB.status, 200);
    assert.strictEqual(acctB.data.connected, true);
    assert.strictEqual(acctB.data.email, "userb.security@gmail.com");

    const devListB = await request("GET", "/api/devices", null, { "X-Sentinel-Session": tokenB });
    assert.strictEqual(devListB.status, 200);
    assert.strictEqual(devListB.data.devices.length, 1);
    assert.strictEqual(devListB.data.devices[0].id, devBId);
    console.log("[PASS] Scenario B: User B shows only their connected Gmail and their paired device.");

    // ====================================================
    // Scenario C: Cross-Account Data Isolation
    // ====================================================
    console.log("\n--- Scenario C: Cross-Account Data Isolation ---");
    // User A checks Gmail -> Still disconnected
    const acctACheck = await request("GET", "/api/account", null, { "X-Sentinel-Session": tokenA });
    assert.strictEqual(acctACheck.data.connected, false, "User A must not see User B's Gmail connection");

    // User A checks devices -> Still 0 devices
    const devListACheck = await request("GET", "/api/devices", null, { "X-Sentinel-Session": tokenA });
    assert.strictEqual(devListACheck.data.devices.length, 0, "User A must not see User B's device");

    // User A attempts to revoke User B's device -> 404 unauthorized
    const unauthorizedRevoke = await request("DELETE", `/api/devices/${devBId}`, null, { "X-Sentinel-Session": tokenA });
    assert.strictEqual(unauthorizedRevoke.status, 404, "User A cannot revoke User B's device");

    // User B sends SMS
    const syncResB = await request("POST", "/api/sms/sync", {
      messages: [{
        id: "msg_user_b_01",
        sender: "UserBFriend",
        body: "Hey User B, meeting at 3pm today.",
        timestamp: Date.now()
      }]
    }, { Authorization: `Bearer ${devBToken}` });
    assert.strictEqual(syncResB.status, 200);

    // User A queries SMS -> 0 SMS
    const smsACheck = await request("GET", "/api/sms", null, { "X-Sentinel-Session": tokenA });
    assert.strictEqual(smsACheck.data.sms.length, 0, "User A cannot see User B's SMS messages");

    // User B queries SMS -> 1 SMS
    const smsBCheck = await request("GET", "/api/sms", null, { "X-Sentinel-Session": tokenB });
    assert.strictEqual(smsBCheck.data.sms.length, 1, "User B sees their SMS message");
    console.log("[PASS] Scenario C: User A cannot retrieve or modify User B's Gmail, devices, or SMS.");

    // ====================================================
    // Scenario D: Browser / Session Isolation
    // ====================================================
    console.log("\n--- Scenario D: Browser / Session Isolation ---");
    // A fresh browser session (no session token header) requests session
    const freshBrowser = await request("GET", "/api/auth/session");
    const freshToken = freshBrowser.data.sessionToken;
    assert.notStrictEqual(freshToken, tokenA);
    assert.notStrictEqual(freshToken, tokenB);

    const freshDevices = await request("GET", "/api/devices", null, { "X-Sentinel-Session": freshToken });
    assert.strictEqual(freshDevices.data.devices.length, 0, "Fresh browser window starts with 0 devices");

    const freshAccount = await request("GET", "/api/account", null, { "X-Sentinel-Session": freshToken });
    assert.strictEqual(freshAccount.data.connected, false, "Fresh browser window starts with disconnected Gmail");
    console.log("[PASS] Scenario D: New browser sessions produce a clean, isolated dashboard.");

    // ====================================================
    // Scenario E: Logout & Account Switching
    // ====================================================
    console.log("\n--- Scenario E: Logout & Account Switching ---");
    // Register user C
    const uniqueEmailC = `userc_${Date.now()}_${Math.floor(Math.random() * 1000)}@sentinel.test`;
    const regResC = await request("POST", "/api/auth/register", {
      email: uniqueEmailC,
      password: "Password123#Valid!",
      displayName: "User C Isolation"
    });
    assert.strictEqual(regResC.status, 200, `Registration must succeed. Error: ${regResC.data?.error}`);
    const tokenC = regResC.data.sessionToken;

    // Logout User C
    const logoutRes = await request("POST", "/api/auth/logout", null, { "X-Sentinel-Session": tokenC });
    assert.strictEqual(logoutRes.status, 200);

    // Subsequent call with old tokenC returns null user / provisions clean session
    const postLogout = await request("GET", "/api/auth/session", null, { "X-Sentinel-Session": tokenC });
    assert.notStrictEqual(postLogout.data.sessionToken, tokenC, "Post-logout token must be revoked and replaced");
    console.log("[PASS] Scenario E: Logout revokes session and produces clean state.");

    // ====================================================
    // Scenario F: Device Pairing Idempotency
    // ====================================================
    console.log("\n--- Scenario F: Device Pairing Idempotency ---");
    // User B initiates pairing again
    const pairSessionB2 = await request("POST", "/api/devices/pairing", null, { "X-Sentinel-Session": tokenB });
    const codeB2 = pairSessionB2.data.code;

    // Repeat registration with same hardware fingerprint
    const rePairB = await request("POST", "/api/devices/pair", {
      code: codeB2,
      displayName: "Pixel 9 User B",
      hardwareFingerprint: "hw_fingerprint_pixel9_userb"
    });
    assert.strictEqual(rePairB.status, 200);
    assert.strictEqual(rePairB.data.deviceId, devBId, "Re-pairing same hardware must reuse existing device ID");

    // Verify User B still has exactly 1 device, not 2
    const devListB2 = await request("GET", "/api/devices", null, { "X-Sentinel-Session": tokenB });
    assert.strictEqual(devListB2.data.devices.length, 1, "Idempotent pairing must not create duplicate device records");
    console.log("[PASS] Scenario F: Re-pairing same device updates credentials without creating duplicate records.");

    // ====================================================
    // Scenario G: Notifications Isolation & Read Status
    // ====================================================
    console.log("\n--- Scenario G: Notifications Isolation & Deduplication ---");
    // Generate genuine security notification for User B
    const notifResB1 = db.createNotification(userB.id, {
      type: "THREAT_DETECTED",
      severity: "CRITICAL",
      title: "Phishing SMS Detected",
      message: "Suspicious link found in SMS from unknown sender.",
      resourceType: "SMS",
      resourceId: "msg_user_b_01"
    });
    assert.ok(notifResB1.id);

    // Immediate duplicate generation within deduplication window
    const notifResB2 = db.createNotification(userB.id, {
      type: "THREAT_DETECTED",
      severity: "CRITICAL",
      title: "Phishing SMS Detected",
      message: "Suspicious link found in SMS from unknown sender.",
      resourceType: "SMS",
      resourceId: "msg_user_b_01"
    });
    assert.strictEqual(notifResB2.duplicate, true, "Duplicate notification must be suppressed");

    // User A checks notifications -> 0 (User A sees none of User B's notifications)
    const notifListA = await request("GET", "/api/notifications", null, { "X-Sentinel-Session": tokenA });
    assert.strictEqual(notifListA.data.notifications.length, 0, "User A cannot see User B's notifications");

    // User B checks notifications -> exactly 2 (DEVICE_PAIRED from pairing + THREAT_DETECTED from simulated event)
    const notifListB = await request("GET", "/api/notifications", null, { "X-Sentinel-Session": tokenB });
    assert.strictEqual(notifListB.data.notifications.length, 2, "User B sees their device paired and threat notifications");
    assert.strictEqual(notifListB.data.unreadCount, 2);
    const threatNotif = notifListB.data.notifications.find(n => n.type === "THREAT_DETECTED");
    assert.ok(threatNotif, "Threat notification must exist for User B");
    const notifId = threatNotif.id;

    // User A attempts to mark User B's notification as read
    const readByA = await request("POST", `/api/notifications/${notifId}/read`, null, { "X-Sentinel-Session": tokenA });
    assert.strictEqual(readByA.data.success, false, "User A cannot mark User B's notification as read");

    // User B marks as read
    const readByB = await request("POST", `/api/notifications/${notifId}/read`, null, { "X-Sentinel-Session": tokenB });
    assert.strictEqual(readByB.data.success, true);
    assert.strictEqual(readByB.data.unreadCount, 1, "Unread count decrements to 1 after marking one notification read");
    console.log("[PASS] Scenario G: Notification creation, deduplication, and read permissions strictly isolated.");

    // ====================================================
    // Scenario H: Disconnection Isolation
    // ====================================================
    console.log("\n--- Scenario H: Disconnection Isolation ---");
    // Disconnect Gmail for User A (who is not connected)
    const disconnA = await request("POST", "/api/disconnect", null, { "X-Sentinel-Session": tokenA });
    assert.strictEqual(disconnA.status, 200);

    // Verify User B's Gmail remains connected
    const acctBAfter = await request("GET", "/api/account", null, { "X-Sentinel-Session": tokenB });
    assert.strictEqual(acctBAfter.data.connected, true, "User B's Gmail must survive User A disconnect");

    // Disconnect User B's Gmail
    const disconnB = await request("POST", "/api/disconnect", null, { "X-Sentinel-Session": tokenB });
    assert.strictEqual(disconnB.status, 200);

    const acctBFinal = await request("GET", "/api/account", null, { "X-Sentinel-Session": tokenB });
    assert.strictEqual(acctBFinal.data.connected, false);

    // Verify User B's paired device survived Gmail disconnect
    const devBAfterGmail = await request("GET", "/api/devices", null, { "X-Sentinel-Session": tokenB });
    assert.strictEqual(devBAfterGmail.data.devices.length, 1, "User B device survived Gmail disconnect");
    console.log("[PASS] Scenario H: Integration disconnection is strictly isolated per user and per channel.");

    // ====================================================
    // Scenario I: API Failures & Error Handling
    // ====================================================
    console.log("\n--- Scenario I: API Failures & Error Handling ---");
    // Invalid device pairing code
    const invalidPair = await request("POST", "/api/devices/pair", { code: "000000" });
    assert.strictEqual(invalidPair.status, 400);
    assert.ok(invalidPair.data.error, "Invalid pairing code returns clear error");

    // Unauthorized SMS sync without valid device token
    const unauthSms = await request("POST", "/api/sms/sync", { messages: [] }, { Authorization: "Bearer bogus_token" });
    assert.strictEqual(unauthSms.status, 401);
    assert.ok(unauthSms.data.error);

    // Disconnected user fetching emails returns 401
    const unauthEmail = await request("GET", "/api/emails", null, { "X-Sentinel-Session": tokenB });
    assert.strictEqual(unauthEmail.status, 401);

    console.log("[PASS] Scenario I: API failures return explicit error states rather than fake success.");

    console.log("\nALL MULTI-USER ISOLATION SCENARIOS (A-I) PASSED WITH ZERO ERRORS!\n");
  } finally {
    // Clean up test data
    try {
      db.prepare("DELETE FROM devices WHERE display_name LIKE '%User B%'").run();
      db.prepare("DELETE FROM users WHERE email LIKE '%@sentinel.test' OR email LIKE '%@sentinel.local'").run();
      db.prepare("DELETE FROM gmail_oauth WHERE account_id LIKE 'usr_%'").run();
    } catch (_) {}
    server.close();
  }
}

runMultiUserTests().catch((err) => {
  console.error("Multi-User Isolation Suite Failed:", err);
  process.exit(1);
});
