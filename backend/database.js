/**
 * Sentinel AI Security Agent - SQLite Persistent Storage Layer
 * Manages devices, pairing sessions, SMS records, deduplication, and retention policies.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { DatabaseSync } = require("node:sqlite");

const DATA_DIR = path.join(__dirname, "../data");
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_PATH = path.join(DATA_DIR, "sentinel.db");
const db = new DatabaseSync(DB_PATH);

// Enable WAL mode for high performance concurrent reads and writes
db.exec("PRAGMA journal_mode = WAL;");
db.exec("PRAGMA foreign_keys = ON;");

// Initialize Schema
db.exec(`
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    credential_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    permission_state TEXT DEFAULT 'UNKNOWN',
    created_at TEXT NOT NULL,
    last_sync_at TEXT,
    last_active_at TEXT,
    revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_devices_account ON devices(account_id);

CREATE TABLE IF NOT EXISTS pairing_sessions (
    code_hash TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    used INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_pairing_account ON pairing_sessions(account_id);

CREATE TABLE IF NOT EXISTS sms_records (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    dedup_key TEXT UNIQUE NOT NULL,
    sender TEXT NOT NULL,
    body TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    ingested_at TEXT NOT NULL,
    category TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    risk_score REAL NOT NULL,
    reasons_json TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    model_version TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sms_account_time ON sms_records(account_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_sms_dedup ON sms_records(dedup_key);
CREATE INDEX IF NOT EXISTS idx_sms_expires ON sms_records(expires_at);

CREATE TABLE IF NOT EXISTS sms_settings (
    account_id TEXT PRIMARY KEY,
    retention_days INTEGER NOT NULL DEFAULT 7,
    sync_paused INTEGER NOT NULL DEFAULT 0,
    sync_enabled INTEGER NOT NULL DEFAULT 1,
    import_range_days INTEGER NOT NULL DEFAULT 30,
    scope TEXT NOT NULL DEFAULT 'INBOX_ONLY',
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS activity_log (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'INFO',
    metadata_json TEXT,
    timestamp INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_activity_account_time ON activity_log(account_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_activity_category ON activity_log(category);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    created_at TEXT NOT NULL,
    last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS user_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id);
`);

const HEARTBEAT_FRESHNESS_MS = 5 * 60 * 1000; // 5 minutes freshness window

try { db.exec("ALTER TABLE sms_settings ADD COLUMN sync_enabled INTEGER NOT NULL DEFAULT 1"); } catch (_) {}
try { db.exec("ALTER TABLE sms_settings ADD COLUMN import_range_days INTEGER NOT NULL DEFAULT 30"); } catch (_) {}
try { db.exec("ALTER TABLE sms_settings ADD COLUMN scope TEXT NOT NULL DEFAULT 'INBOX_ONLY'"); } catch (_) {}
try { db.exec("ALTER TABLE devices ADD COLUMN hardware_fingerprint TEXT"); } catch (_) {}

// Persistent Notifications Schema
db.exec(`
CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'INFO',
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,
    metadata_json TEXT,
    is_read INTEGER NOT NULL DEFAULT 0,
    is_archived INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notifications_account_time ON notifications(account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(account_id, is_read);

CREATE TABLE IF NOT EXISTS gmail_oauth (
    account_id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    access_token TEXT NOT NULL,
    refresh_token TEXT,
    expiry_date INTEGER,
    scope TEXT,
    token_type TEXT,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_gmail_oauth_account ON gmail_oauth(account_id);

CREATE TABLE IF NOT EXISTS classification_overrides (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    source TEXT NOT NULL,
    message_id TEXT NOT NULL,
    category TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    risk_score REAL NOT NULL,
    feedback_type TEXT NOT NULL,
    notes TEXT,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_overrides_account_msg ON classification_overrides(account_id, message_id);
CREATE INDEX IF NOT EXISTS idx_overrides_account_src ON classification_overrides(account_id, source);

CREATE TABLE IF NOT EXISTS scam_checks (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    check_type TEXT NOT NULL,
    input_preview TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'DIRECT',
    verdict TEXT NOT NULL,
    risk_score REAL NOT NULL,
    category TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scam_checks_account_time ON scam_checks(account_id, created_at DESC);
`);

// Purge test artifacts from primary account & consolidate devices safely
try {
    const deletedTest = db.prepare(`
        DELETE FROM devices 
        WHERE display_name LIKE 'Pixel 9 Pro%' 
           OR display_name LIKE 'Galaxy S24%' 
           OR display_name LIKE 'Independent Phone%' 
           OR display_name LIKE 'Test Pixel Phone%'
           OR display_name LIKE '%User B%'
    `).run();

    const deletedDupes = db.prepare(`
        DELETE FROM devices 
        WHERE account_id = 'sentinel_primary' 
          AND display_name = 'motorola moto g45 5G' 
          AND id != 'dev_4fcfbe943ab8ea4b'
    `).run();

    if (deletedTest.changes > 0 || deletedDupes.changes > 0) {
        console.log(`[Sentinel Database] Cleaned up ${deletedTest.changes} test devices and ${deletedDupes.changes} duplicate entries.`);
    }
} catch (e) {
    console.warn("[Sentinel Database] Device cleanup error:", e.message);
}

console.log("[Sentinel Database] SQLite database initialized at", DB_PATH);

// ==================================================
// HASHING HELPERS
// ==================================================

function hashToken(token, salt) {
    return crypto.createHash("sha256").update(token + salt).digest("hex");
}

function hashCode(code) {
    return crypto.createHash("sha256").update(code.trim().toUpperCase()).digest("hex");
}

function hashPassword(password, salt) {
    return crypto.scryptSync(password, salt, 64).toString("hex");
}

// ==================================================
// SENTINEL USER AUTHENTICATION & SESSIONS
// ==================================================

function initializeDefaultAdmin() {
    try {
        const existing = db.prepare("SELECT COUNT(*) as count FROM users").get();
        if (!existing || existing.count === 0) {
            const id = "usr_" + crypto.randomBytes(8).toString("hex");
            const email = "admin@sentinel.security";
            const password = "SentinelAdmin#2026!";
            const salt = crypto.randomBytes(16).toString("hex");
            const passwordHash = hashPassword(password, salt);
            const now = new Date().toISOString();
            db.prepare(`
                INSERT INTO users (id, email, password_hash, salt, display_name, role, created_at)
                VALUES (?, ?, ?, ?, 'Security Administrator', 'admin', ?)
            `).run(id, email, passwordHash, salt, now);
            console.log(`[Sentinel Auth] Initialized default security administrator: ${email}`);
        }
    } catch (e) {
        console.warn("[Sentinel Auth] Admin initialization notice:", e.message);
    }
}
initializeDefaultAdmin();

const SENTINEL_PRIMARY_ACCOUNT = "sentinel_primary";

function getUserById(id) {
    if (!id) return null;
    try {
        const user = db.prepare("SELECT id, email, display_name, role, created_at, last_login_at FROM users WHERE id = ?").get(id);
        if (!user) return null;
        return {
            id: user.id,
            email: user.email,
            displayName: user.display_name,
            role: user.role,
            createdAt: user.created_at,
            lastLoginAt: user.last_login_at
        };
    } catch (_) {
        return null;
    }
}

function registerUser(email, password, displayName = "Sentinel User") {
    if (!email || !password) {
        throw new Error("Email and password are required.");
    }
    const cleanEmail = email.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
        throw new Error("Invalid email address format.");
    }
    if (password.length < 8) {
        throw new Error("Password must be at least 8 characters.");
    }
    const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(cleanEmail);
    if (existing) {
        throw new Error("An account with this email already exists.");
    }
    const id = "usr_" + crypto.randomBytes(8).toString("hex");
    const salt = crypto.randomBytes(16).toString("hex");
    const passwordHash = hashPassword(password, salt);
    const now = new Date().toISOString();
    const cleanName = displayName.trim() || cleanEmail.split("@")[0];
    db.prepare(`
        INSERT INTO users (id, email, password_hash, salt, display_name, role, created_at)
        VALUES (?, ?, ?, ?, ?, 'admin', ?)
    `).run(id, cleanEmail, passwordHash, salt, cleanName, now);
    return {
        id,
        email: cleanEmail,
        displayName: cleanName,
        role: "admin",
        createdAt: now
    };
}

function verifyUserCredentials(email, password) {
    if (!email || !password) return null;
    const cleanEmail = email.trim().toLowerCase();
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(cleanEmail);
    if (!user) return null;
    try {
        const computedHash = hashPassword(password, user.salt);
        if (crypto.timingSafeEqual(Buffer.from(computedHash, "hex"), Buffer.from(user.password_hash, "hex"))) {
            const now = new Date().toISOString();
            db.prepare("UPDATE users SET last_login_at = ? WHERE id = ?").run(now, user.id);
            return {
                id: user.id,
                email: user.email,
                displayName: user.display_name,
                role: user.role,
                createdAt: user.created_at,
                lastLoginAt: now
            };
        }
    } catch (err) {
        console.error("[Sentinel Auth] Password verification error:", err.message);
    }
    return null;
}

function createUserSession(userId, ttlHours = 24) {
    const rawToken = "sentinel_sess_" + crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
    const expiresAt = Date.now() + ttlHours * 60 * 60 * 1000;
    const now = new Date().toISOString();

    db.prepare(`
        INSERT INTO user_sessions (token_hash, user_id, expires_at, created_at)
        VALUES (?, ?, ?, ?)
    `).run(tokenHash, userId, expiresAt, now);

    return { token: rawToken, expiresAt };
}

function getSessionUser(rawToken) {
    if (!rawToken || typeof rawToken !== "string" || !rawToken.startsWith("sentinel_sess_")) return null;
    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
    const session = db.prepare("SELECT * FROM user_sessions WHERE token_hash = ?").get(tokenHash);
    if (!session) return null;
    if (session.expires_at < Date.now()) {
        db.prepare("DELETE FROM user_sessions WHERE token_hash = ?").run(tokenHash);
        return null;
    }
    const user = db.prepare("SELECT id, email, display_name, role, created_at, last_login_at FROM users WHERE id = ?").get(session.user_id);
    if (!user) return null;
    return {
        id: user.id,
        email: user.email,
        displayName: user.display_name,
        role: user.role,
        createdAt: user.created_at,
        lastLoginAt: user.last_login_at
    };
}

function destroyUserSession(rawToken) {
    if (!rawToken) return false;
    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
    const res = db.prepare("DELETE FROM user_sessions WHERE token_hash = ?").run(tokenHash);
    return res.changes > 0;
}

function initializePrimaryAccount() {
    try {
        const existing = db.prepare("SELECT id FROM users WHERE id = 'sentinel_primary'").get();
        if (!existing) {
            const salt = crypto.randomBytes(16).toString("hex");
            const hash = hashPassword("SentinelPrimary#2026", salt);
            const now = new Date().toISOString();
            db.prepare(`
                INSERT INTO users (id, email, password_hash, salt, display_name, role, created_at)
                VALUES ('sentinel_primary', 'primary@sentinel.local', ?, ?, 'Primary Sentinel User', 'admin', ?)
            `).run(hash, salt, now);
        }
    } catch (_) {}
}
initializePrimaryAccount();

function createAnonymousUserSession(displayName = "Sentinel User") {
    const id = "usr_" + crypto.randomBytes(8).toString("hex");
    const email = `guest_${crypto.randomBytes(6).toString("hex")}@sentinel.local`;
    const salt = crypto.randomBytes(16).toString("hex");
    const dummyPassword = crypto.randomBytes(24).toString("hex");
    const passwordHash = hashPassword(dummyPassword, salt);
    const now = new Date().toISOString();

    db.prepare(`
        INSERT INTO users (id, email, password_hash, salt, display_name, role, created_at)
        VALUES (?, ?, ?, ?, ?, 'user', ?)
    `).run(id, email, passwordHash, salt, displayName, now);

    const session = createUserSession(id, 24 * 7); // 7-day session
    return {
        sessionToken: session.token,
        expiresAt: session.expiresAt,
        user: {
            id,
            email,
            displayName,
            role: "user",
            createdAt: now
        }
    };
}

function getLatestActiveUser() {
    try {
        const userWithDevice = db.prepare(`
            SELECT u.id, u.email, u.display_name, u.role, u.created_at, u.last_login_at
            FROM users u
            JOIN devices d ON d.account_id = u.id
            LEFT JOIN sms_records s ON s.account_id = u.id
            WHERE d.status = 'ACTIVE' 
              AND u.email NOT LIKE '%test%'
              AND u.email NOT LIKE 'userb_%'
              AND u.email NOT LIKE 'usera_%'
              AND d.display_name NOT LIKE '%Test%'
              AND d.display_name NOT LIKE '%Pixel 9 User%'
            GROUP BY u.id
            ORDER BY COUNT(s.id) DESC, d.last_sync_at DESC NULLS LAST, d.last_active_at DESC NULLS LAST, u.created_at DESC
            LIMIT 1
        `).get();
        if (userWithDevice) {
            return {
                id: userWithDevice.id,
                email: userWithDevice.email,
                displayName: userWithDevice.display_name,
                role: userWithDevice.role,
                createdAt: userWithDevice.created_at,
                lastLoginAt: userWithDevice.last_login_at
            };
        }

        const latestUser = db.prepare(`
            SELECT id, email, display_name, role, created_at, last_login_at
            FROM users
            WHERE email NOT LIKE '%test%'
              AND email NOT LIKE 'userb_%'
              AND email NOT LIKE 'usera_%'
            ORDER BY created_at DESC
            LIMIT 1
        `).get();
        if (latestUser) {
            return {
                id: latestUser.id,
                email: latestUser.email,
                displayName: latestUser.display_name,
                role: latestUser.role,
                createdAt: latestUser.created_at,
                lastLoginAt: latestUser.last_login_at
            };
        }
    } catch (_) {}

    return getUserById(SENTINEL_PRIMARY_ACCOUNT);
}

function getOrCreateUserSession(rawToken) {
    if (rawToken) {
        const user = getSessionUser(rawToken);
        if (user) {
            return {
                sessionToken: rawToken,
                user
            };
        }
    }
    return createAnonymousUserSession();
}

// ==================================================
// GMAIL OAUTH STORAGE PER USER ACCOUNT
// ==================================================

function saveGmailOAuth(accountId, tokens, email) {
    if (!accountId || !tokens || !email) return false;
    const now = new Date().toISOString();
    const accessToken = tokens.access_token || "";
    const refreshToken = tokens.refresh_token || null;
    const expiryDate = tokens.expiry_date || null;
    const scope = tokens.scope || "";
    const tokenType = tokens.token_type || "Bearer";

    let finalRefreshToken = refreshToken;
    if (!finalRefreshToken) {
        const existing = getGmailOAuth(accountId);
        if (existing && existing.refresh_token) {
            finalRefreshToken = existing.refresh_token;
        }
    }

    db.prepare(`
        INSERT INTO gmail_oauth (account_id, email, access_token, refresh_token, expiry_date, scope, token_type, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(account_id) DO UPDATE SET
            email = excluded.email,
            access_token = excluded.access_token,
            refresh_token = COALESCE(excluded.refresh_token, gmail_oauth.refresh_token),
            expiry_date = excluded.expiry_date,
            scope = excluded.scope,
            token_type = excluded.token_type,
            updated_at = excluded.updated_at
    `).run(accountId, email, accessToken, finalRefreshToken, expiryDate, scope, tokenType, now);

    return true;
}

function getGmailOAuth(accountId) {
    if (!accountId) return null;
    return db.prepare("SELECT * FROM gmail_oauth WHERE account_id = ?").get(accountId) || null;
}

function deleteGmailOAuth(accountId) {
    if (!accountId) return false;
    const res = db.prepare("DELETE FROM gmail_oauth WHERE account_id = ?").run(accountId);
    return res.changes > 0;
}

// ==================================================
// PAIRING SESSIONS
// ==================================================

function createPairingSession(accountId, ttlMinutes = 5) {
    // Generate clean cryptographically secure 6-digit decimal PIN (e.g. 583921)
    const code = crypto.randomInt(100000, 1000000).toString();
    const codeHash = hashCode(code);
    const expiresAt = Date.now() + ttlMinutes * 60 * 1000;

    // Invalidate existing sessions for this account to maintain a single active code
    const deleteOld = db.prepare("DELETE FROM pairing_sessions WHERE account_id = ?");
    deleteOld.run(accountId);

    const insert = db.prepare(`
        INSERT INTO pairing_sessions (code_hash, account_id, expires_at, attempts, used)
        VALUES (?, ?, ?, 0, 0)
    `);
    insert.run(codeHash, accountId, expiresAt);

    return { code, expiresAt };
}

function consumePairingSession(code) {
    if (!code) return { success: false, error: "Pairing code is required." };
    const codeHash = hashCode(code);
    const now = Date.now();

    const stmt = db.prepare("SELECT * FROM pairing_sessions WHERE code_hash = ?");
    const session = stmt.get(codeHash);

    if (!session) {
        return { success: false, error: "Invalid or unknown pairing code." };
    }

    if (session.used === 1) {
        return { success: false, error: "Pairing code has already been used." };
    }

    if (session.attempts >= 5) {
        db.prepare("DELETE FROM pairing_sessions WHERE code_hash = ?").run(codeHash);
        return { success: false, error: "Too many failed attempts. Code invalidated." };
    }

    if (session.expires_at < now) {
        db.prepare("DELETE FROM pairing_sessions WHERE code_hash = ?").run(codeHash);
        return { success: false, error: "Pairing code has expired. Please generate a new code." };
    }

    // Mark as used atomically
    db.prepare("UPDATE pairing_sessions SET used = 1 WHERE code_hash = ?").run(codeHash);

    return {
        success: true,
        accountId: session.account_id
    };
}

// ==================================================
// DEVICES
// ==================================================

function registerDevice(accountId, displayName = "Android Companion", hardwareFingerprint = null) {
    const now = new Date().toISOString();
    const cleanName = (displayName && typeof displayName === "string")
        ? displayName.slice(0, 50).trim()
        : "Android Companion";

    // 1. Check if a device already exists for this account with the same hardware fingerprint or matching clean name
    let existing = null;
    if (hardwareFingerprint) {
        existing = db.prepare("SELECT * FROM devices WHERE account_id = ? AND hardware_fingerprint = ?").get(accountId, hardwareFingerprint);
    }
    if (!existing) {
        existing = db.prepare("SELECT * FROM devices WHERE account_id = ? AND display_name = ?").get(accountId, cleanName);
    }

    const credentialToken = "sentinel_dev_" + crypto.randomBytes(32).toString("hex");
    const salt = crypto.randomBytes(16).toString("hex");
    const credentialHash = hashToken(credentialToken, salt);

    if (existing) {
        // Idempotent re-pairing: update existing device credentials, reactivate and touch heartbeat
        db.prepare(`
            UPDATE devices
            SET credential_hash = ?, salt = ?, status = 'ACTIVE', revoked_at = null,
                last_active_at = ?, permission_state = 'GRANTED',
                hardware_fingerprint = COALESCE(?, hardware_fingerprint)
            WHERE id = ?
        `).run(credentialHash, salt, now, hardwareFingerprint, existing.id);

        return {
            deviceId: existing.id,
            credentialToken,
            displayName: existing.display_name,
            createdAt: existing.created_at,
            isReused: true
        };
    }

    // New device registration
    const deviceId = "dev_" + crypto.randomBytes(8).toString("hex");
    const insert = db.prepare(`
        INSERT INTO devices (id, account_id, display_name, credential_hash, salt, status, permission_state, created_at, last_active_at, hardware_fingerprint)
        VALUES (?, ?, ?, ?, ?, 'ACTIVE', 'UNKNOWN', ?, ?, ?)
    `);
    insert.run(deviceId, accountId, cleanName, credentialHash, salt, now, now, hardwareFingerprint);

    return {
        deviceId,
        credentialToken,
        displayName: cleanName,
        createdAt: now,
        isReused: false
    };
}

function getDeviceByCredential(token) {
    if (!token) return null;
    // Scan devices and verify hash with constant-time comparison
    const devices = db.prepare("SELECT * FROM devices").all();
    for (const dev of devices) {
        const expectedHash = hashToken(token, dev.salt);
        if (crypto.timingSafeEqual(Buffer.from(dev.credential_hash), Buffer.from(expectedHash))) {
            return dev;
        }
    }
    return null;
}

function getDeviceById(deviceId) {
    return db.prepare("SELECT * FROM devices WHERE id = ?").get(deviceId) || null;
}

function computeDeviceLifecycleState(dev) {
    if (dev.status === "REVOKED") {
        return "REVOKED";
    }
    if (dev.status === "PAUSED") {
        return "PAUSED";
    }
    if (dev.permission_state === "DENIED") {
        return "PERMISSION_UNAVAILABLE";
    }
    const lastActive = dev.last_active_at ? new Date(dev.last_active_at).getTime() : 0;
    const isRecent = (Date.now() - lastActive) <= HEARTBEAT_FRESHNESS_MS;
    if (isRecent) {
        return "ACTIVE";
    }
    return "OFFLINE";
}

function getDevicesForAccount(accountId = "default") {
    const rows = db.prepare(`
        SELECT 
            d.id, 
            d.account_id, 
            d.display_name, 
            d.status, 
            d.permission_state, 
            d.created_at, 
            d.last_sync_at, 
            d.last_active_at, 
            d.revoked_at,
            (SELECT COUNT(*) FROM sms_records s WHERE s.device_id = d.id AND s.account_id = d.account_id) as retained_sms_count
        FROM devices d
        WHERE d.account_id = ?
        ORDER BY d.created_at DESC
    `).all(accountId);

    const now = Date.now();
    return rows.map((dev) => {
        const lifecycleState = computeDeviceLifecycleState(dev);
        const lastActiveTime = dev.last_active_at ? new Date(dev.last_active_at).getTime() : null;
        const secondsSinceHeartbeat = lastActiveTime ? Math.max(0, Math.round((now - lastActiveTime) / 1000)) : null;

        return {
            ...dev,
            lifecycle_state: lifecycleState,
            is_online: lifecycleState === "ACTIVE",
            retained_sms_count: Number(dev.retained_sms_count || 0),
            seconds_since_heartbeat: secondsSinceHeartbeat,
            heartbeat_freshness_threshold_seconds: Math.round(HEARTBEAT_FRESHNESS_MS / 1000)
        };
    });
}

function updateDeviceHeartbeat(deviceId, permissionState = null) {
    const now = new Date().toISOString();
    if (permissionState) {
        db.prepare(`
            UPDATE devices
            SET last_active_at = ?, permission_state = ?
            WHERE id = ?
        `).run(now, permissionState, deviceId);
    } else {
        db.prepare(`
            UPDATE devices
            SET last_active_at = ?
            WHERE id = ?
        `).run(now, deviceId);
    }
}

function updateDeviceSyncSuccess(deviceId, permissionState) {
    const now = new Date().toISOString();
    db.prepare(`
        UPDATE devices
        SET last_sync_at = ?, last_active_at = ?, permission_state = ?
        WHERE id = ?
    `).run(now, now, permissionState || "GRANTED", deviceId);
}

function updateDeviceStatus(deviceId, accountId, status) {
    if (!["ACTIVE", "PAUSED", "REVOKED"].includes(status)) {
        throw new Error("Invalid device status");
    }
    const now = new Date().toISOString();
    const revokedAt = status === "REVOKED" ? now : null;

    const res = db.prepare(`
        UPDATE devices
        SET status = ?, revoked_at = COALESCE(?, revoked_at), last_active_at = ?
        WHERE id = ? AND account_id = ?
    `).run(status, revokedAt, now, deviceId, accountId);

    return res.changes > 0;
}

// ==================================================
// SMS RECORDS & DEDUPLICATION
// ==================================================

function insertSmsBatch(accountId, deviceId, analyzedRecords) {
    let insertedCount = 0;
    let duplicateCount = 0;
    const insertedIds = [];

    const insertStmt = db.prepare(`
        INSERT OR IGNORE INTO sms_records (
            id, account_id, device_id, dedup_key, sender, body,
            timestamp, ingested_at, category, risk_level, risk_score,
            reasons_json, evidence_json, model_version, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    db.exec("BEGIN TRANSACTION;");
    try {
        for (const item of analyzedRecords) {
            const res = insertStmt.run(
                item.id,
                accountId,
                deviceId,
                item.dedupKey,
                item.sender,
                item.body,
                item.timestamp,
                item.ingestedAt,
                item.category,
                item.riskLevel,
                item.riskScore,
                JSON.stringify(item.reasons || []),
                JSON.stringify(item.evidence || []),
                item.modelVersion || "1.0",
                item.expiresAt || (Date.now() + 7 * 24 * 60 * 60 * 1000)
            );

            if (res.changes > 0) {
                insertedCount++;
                insertedIds.push(item.id);
            } else {
                duplicateCount++;
            }
        }

        if (insertedCount > 0) {
            // Enforce strictly at most 50 SMS records retained from mobile per account
            try {
                db.prepare(`
                    DELETE FROM sms_records
                    WHERE account_id = ? AND id NOT IN (
                        SELECT id FROM sms_records
                        WHERE account_id = ?
                        ORDER BY timestamp DESC
                        LIMIT 50
                    )
                `).run(accountId, accountId);
            } catch (_) {}
        }
        db.exec("COMMIT;");
    } catch (err) {
        db.exec("ROLLBACK;");
        throw err;
    }

    return { insertedCount, duplicateCount, insertedIds };
}

function getSmsRecords(accountId = "default", options = {}) {
    const {
        limit = 50,
        offset = 0,
        category = null,
        search = null,
        deviceId = null
    } = options;

    let query = "SELECT * FROM sms_records WHERE account_id = ?";
    const params = [accountId];

    if (category && category !== "ALL") {
        query += " AND category = ?";
        params.push(category.toUpperCase());
    }

    if (deviceId) {
        query += " AND device_id = ?";
        params.push(deviceId);
    }

    if (search) {
        query += " AND (sender LIKE ? OR body LIKE ?)";
        const term = `%${search}%`;
        params.push(term, term);
    }

    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?";
    params.push(limit, offset);

    const rows = db.prepare(query).all(...params);
    const overrides = getClassificationOverrides(accountId, "SMS");

    return rows.map((r) => {
        const ov = overrides[r.id];
        return {
            id: r.id,
            source: "SMS",
            from: r.sender,
            sender: r.sender,
            body: r.body,
            snippet: r.body.length > 120 ? r.body.slice(0, 120) + "..." : r.body,
            subject: "SMS from " + r.sender,
            timestamp: r.timestamp,
            date: new Date(r.timestamp).toISOString(),
            ingestedAt: r.ingested_at,
            category: ov ? ov.category : r.category,
            risk: ov ? ov.riskLevel : r.risk_level,
            score: ov ? Math.round(ov.riskScore) : Math.round(r.risk_score),
            reviewed: Boolean(ov),
            userFeedback: ov ? ov.feedbackType : null,
            reasons: JSON.parse(r.reasons_json || "[]"),
            evidence: JSON.parse(r.evidence_json || "[]"),
            deviceId: r.device_id,
            device_id: r.device_id,
            expiresAt: r.expires_at
        };
    });
}

function getSmsStats(accountId = "default") {
    const totalStmt = db.prepare("SELECT COUNT(*) as count FROM sms_records WHERE account_id = ?");
    const total = totalStmt.get(accountId)?.count || 0;

    const catStmt = db.prepare(`
        SELECT category, COUNT(*) as count
        FROM sms_records
        WHERE account_id = ?
        GROUP BY category
    `);
    const catRows = catStmt.all(accountId);

    const byCategory = {
        LEGITIMATE: 0,
        SPAM: 0,
        "NEEDS REVIEW": 0,
        PHISHING: 0
    };

    catRows.forEach((r) => {
        byCategory[r.category] = r.count;
    });

    const lastSyncStmt = db.prepare(`
        SELECT MAX(last_sync_at) as lastSync
        FROM devices
        WHERE account_id = ? AND status != 'REVOKED'
    `);
    const lastSync = lastSyncStmt.get(accountId)?.lastSync || null;

    return {
        total,
        byCategory,
        lastSync
    };
}

function deleteSmsRecord(messageId, accountId = "default") {
    const res = db.prepare("DELETE FROM sms_records WHERE id = ? AND account_id = ?").run(messageId, accountId);
    try {
        db.prepare("DELETE FROM classification_overrides WHERE message_id = ? AND account_id = ?").run(messageId, accountId);
    } catch (_) {}
    return res.changes > 0;
}

function deleteAllSms(accountId = "default", deviceId = null) {
    let res;
    if (deviceId) {
        res = db.prepare("DELETE FROM sms_records WHERE account_id = ? AND device_id = ?").run(accountId, deviceId);
    } else {
        res = db.prepare("DELETE FROM sms_records WHERE account_id = ?").run(accountId);
        try {
            db.prepare("DELETE FROM classification_overrides WHERE account_id = ? AND source = 'SMS'").run(accountId);
        } catch (_) {}
    }
    return res.changes;
}

function updateSmsClassification(accountId = "default", smsId, update) {
    const { category, riskLevel, riskScore } = update;
    try {
        let stmt = db.prepare(`
            UPDATE sms_records 
            SET category = ?, risk_level = ?, risk_score = ?
            WHERE id = ? AND account_id = ?
        `);
        let res = stmt.run(category.toUpperCase(), riskLevel.toUpperCase(), Number(riskScore), smsId, accountId);
        if (res.changes === 0) {
            const fallbackStmt = db.prepare(`
                UPDATE sms_records 
                SET category = ?, risk_level = ?, risk_score = ?
                WHERE id = ?
            `);
            res = fallbackStmt.run(category.toUpperCase(), riskLevel.toUpperCase(), Number(riskScore), smsId);
        }
        return res.changes > 0;
    } catch (err) {
        console.error("[Sentinel Database] Failed to update SMS classification:", err.message);
        return false;
    }
}

function updateSmsRecordAnalysis(accountId = "default", smsId, update) {
    const { category, riskLevel, riskScore, reasons, evidence } = update;
    try {
        const stmt = db.prepare(`
            UPDATE sms_records 
            SET category = ?, risk_level = ?, risk_score = ?, reasons_json = ?, evidence_json = ?
            WHERE id = ? AND account_id = ?
        `);
        const reasonsJson = JSON.stringify(reasons || []);
        const evidenceJson = JSON.stringify(evidence || []);
        let res = stmt.run(category.toUpperCase(), riskLevel.toUpperCase(), Number(riskScore), reasonsJson, evidenceJson, smsId, accountId);
        if (res.changes === 0) {
            const fallbackStmt = db.prepare(`
                UPDATE sms_records 
                SET category = ?, risk_level = ?, risk_score = ?, reasons_json = ?, evidence_json = ?
                WHERE id = ?
            `);
            res = fallbackStmt.run(category.toUpperCase(), riskLevel.toUpperCase(), Number(riskScore), reasonsJson, evidenceJson, smsId);
        }
        return res.changes > 0;
    } catch (err) {
        console.error("[Sentinel Database] Failed to update SMS analysis:", err.message);
        return false;
    }
}

function getSmsRecordById(accountId = "default", smsId) {
    let row = db.prepare("SELECT * FROM sms_records WHERE id = ? AND account_id = ?").get(smsId, accountId);
    if (!row) {
        row = db.prepare("SELECT * FROM sms_records WHERE id = ?").get(smsId);
    }
    if (!row) return null;

    const overrides = getClassificationOverrides(accountId, "SMS");
    const ov = overrides[row.id];

    return {
        id: row.id,
        source: "SMS",
        from: row.sender,
        sender: row.sender,
        body: row.body,
        snippet: row.body.length > 120 ? row.body.slice(0, 120) + "..." : row.body,
        subject: "SMS from " + row.sender,
        timestamp: row.timestamp,
        date: new Date(row.timestamp).toISOString(),
        ingestedAt: row.ingested_at,
        category: ov ? ov.category : row.category,
        risk: ov ? ov.riskLevel : row.risk_level,
        score: ov ? Math.round(ov.riskScore) : Math.round(row.risk_score),
        reviewed: Boolean(ov),
        userFeedback: ov ? ov.feedbackType : null,
        reasons: JSON.parse(row.reasons_json || "[]"),
        evidence: JSON.parse(row.evidence_json || "[]"),
        deviceId: row.device_id,
        device_id: row.device_id,
        expiresAt: row.expires_at
    };
}

function saveClassificationOverride(accountId = "default", override) {
    const { source, messageId, category, riskLevel, riskScore, feedbackType, notes } = override;
    const id = `ovr_${(source || "ITEM").toLowerCase()}_${messageId}`;
    const now = new Date().toISOString();
    try {
        const stmt = db.prepare(`
            INSERT INTO classification_overrides (
                id, account_id, source, message_id, category, risk_level, risk_score, feedback_type, notes, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                account_id = excluded.account_id,
                category = excluded.category,
                risk_level = excluded.risk_level,
                risk_score = excluded.risk_score,
                feedback_type = excluded.feedback_type,
                notes = excluded.notes,
                updated_at = excluded.updated_at
        `);
        stmt.run(
            id,
            accountId,
            (source || "ITEM").toUpperCase(),
            messageId,
            category.toUpperCase(),
            riskLevel.toUpperCase(),
            Number(riskScore),
            feedbackType,
            notes || "",
            now
        );
        return true;
    } catch (err) {
        console.error("[Sentinel Database] Failed to save classification override:", err.message);
        return false;
    }
}

function getClassificationOverrides(accountId = "default", source = null) {
    try {
        let query = "SELECT * FROM classification_overrides WHERE account_id = ?";
        const params = [accountId];
        if (source) {
            query += " AND source = ?";
            params.push(source.toUpperCase());
        }
        const rows = db.prepare(query).all(...params);
        const map = {};
        for (const r of rows) {
            map[r.message_id] = {
                id: r.id,
                source: r.source,
                messageId: r.message_id,
                category: r.category,
                riskLevel: r.risk_level,
                riskScore: r.risk_score,
                feedbackType: r.feedback_type,
                notes: r.notes,
                updatedAt: r.updated_at
            };
        }
        return map;
    } catch (err) {
        console.error("[Sentinel Database] Failed to get classification overrides:", err.message);
        return {};
    }
}

function isSmsRecord(accountId = "default", messageId) {
    if (!messageId) return false;
    try {
        const row = db.prepare("SELECT id, account_id FROM sms_records WHERE id = ?").get(messageId);
        if (row) {
            return row.account_id || true;
        }
    } catch (_) {}
    return false;
}

// ==================================================
// RETENTION & SETTINGS
// ==================================================

function getSettings(accountId = "default") {
    const row = db.prepare("SELECT * FROM sms_settings WHERE account_id = ?").get(accountId);
    if (!row) {
        const now = new Date().toISOString();
        db.prepare(`
            INSERT INTO sms_settings (account_id, retention_days, sync_paused, sync_enabled, import_range_days, scope, updated_at)
            VALUES (?, 7, 0, 1, 30, 'INBOX_ONLY', ?)
        `).run(accountId, now);
        return {
            retentionDays: 7,
            syncPaused: false,
            syncEnabled: true,
            importRangeDays: 30,
            scope: "INBOX_ONLY"
        };
    }
    return {
        retentionDays: row.retention_days || 7,
        syncPaused: Boolean(row.sync_paused),
        syncEnabled: row.sync_enabled !== undefined ? Boolean(row.sync_enabled) : true,
        importRangeDays: row.import_range_days || 30,
        scope: row.scope || "INBOX_ONLY"
    };
}

function updateSettings(accountId = "default", { retentionDays, syncPaused, syncEnabled, importRangeDays, scope }) {
    const current = getSettings(accountId);
    const updatedRetention = retentionDays !== undefined ? Number(retentionDays) : current.retentionDays;
    const updatedPaused = syncPaused !== undefined ? Boolean(syncPaused) : current.syncPaused;
    const updatedEnabled = syncEnabled !== undefined ? Boolean(syncEnabled) : current.syncEnabled;
    const updatedRange = importRangeDays !== undefined ? Number(importRangeDays) : current.importRangeDays;
    const updatedScope = scope !== undefined ? String(scope) : current.scope;
    const now = new Date().toISOString();

    db.prepare(`
        INSERT INTO sms_settings (account_id, retention_days, sync_paused, sync_enabled, import_range_days, scope, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(account_id) DO UPDATE SET
            retention_days = excluded.retention_days,
            sync_paused = excluded.sync_paused,
            sync_enabled = excluded.sync_enabled,
            import_range_days = excluded.import_range_days,
            scope = excluded.scope,
            updated_at = excluded.updated_at
    `).run(
        accountId,
        updatedRetention,
        updatedPaused ? 1 : 0,
        updatedEnabled ? 1 : 0,
        updatedRange,
        updatedScope,
        now
    );

    return {
        retentionDays: updatedRetention,
        syncPaused: updatedPaused,
        syncEnabled: updatedEnabled,
        importRangeDays: updatedRange,
        scope: updatedScope
    };
}

function enforceRetention(accountId = null) {
    const now = Date.now();
    let res;
    if (accountId) {
        res = db.prepare("DELETE FROM sms_records WHERE account_id = ? AND expires_at < ?").run(accountId, now);
    } else {
        res = db.prepare("DELETE FROM sms_records WHERE expires_at < ?").run(now);
    }
    return res.changes;
}

// Run retention check every hour
const retentionInterval = setInterval(() => {
    try {
        const purged = enforceRetention();
        if (purged > 0) {
            console.log(`[Sentinel Retention] Purged ${purged} expired SMS records.`);
        }
    } catch (err) {
        console.error("[Sentinel Retention Error]", err.message);
    }
}, 60 * 60 * 1000);
retentionInterval.unref();

function logActivity(accountId = "sentinel_primary", { eventType, category = "SECURITY", title, description, severity = "INFO", metadata = null }) {
    const id = "act_" + crypto.randomBytes(8).toString("hex");
    const now = Date.now();
    const createdAt = new Date(now).toISOString();

    const insert = db.prepare(`
        INSERT INTO activity_log (id, account_id, event_type, category, title, description, severity, metadata_json, timestamp, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insert.run(
        id,
        accountId,
        eventType,
        category,
        title,
        description,
        severity,
        metadata ? JSON.stringify(metadata) : null,
        now,
        createdAt
    );

    return { id, eventType, category, title, description, severity, createdAt, timestamp: now };
}

function getActivityLog(accountId = "sentinel_primary", options = {}) {
    const {
        limit = 50,
        offset = 0,
        category = null,
        search = null
    } = options;

    let query = "SELECT * FROM activity_log WHERE account_id = ?";
    const params = [accountId];

    if (category && category !== "ALL") {
        query += " AND category = ?";
        params.push(category.toUpperCase());
    }

    if (search) {
        query += " AND (title LIKE ? OR description LIKE ?)";
        const term = `%${search}%`;
        params.push(term, term);
    }

    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?";
    params.push(limit, offset);

    const rows = db.prepare(query).all(...params);

    const countStmt = db.prepare("SELECT COUNT(*) as total FROM activity_log WHERE account_id = ?");
    const total = countStmt.get(accountId)?.total || 0;

    return {
        total,
        activities: rows.map(r => ({
            id: r.id,
            eventType: r.event_type,
            category: r.category,
            title: r.title,
            description: r.description,
            severity: r.severity,
            metadata: r.metadata_json ? JSON.parse(r.metadata_json) : null,
            timestamp: r.timestamp,
            createdAt: r.created_at
        }))
    };
}

// ==================================================
// NOTIFICATIONS
// ==================================================

function createNotification(accountId = "sentinel_primary", {
    type = "SECURITY_ALERT",
    severity = "INFO",
    title,
    message,
    resourceType = null,
    resourceId = null,
    metadata = null
}) {
    if (!title || !message) return null;

    // Deduplicate repeated alerts within 1 hour for the same resource & type
    const oneHourAgo = new Date(Date.now() - 3600 * 1000).toISOString();
    const existing = db.prepare(`
        SELECT id FROM notifications 
        WHERE account_id = ? AND type = ? AND title = ? AND created_at > ?
        LIMIT 1
    `).get(accountId, type, title, oneHourAgo);

    if (existing) {
        return { id: existing.id, duplicate: true };
    }

    const id = "notif_" + crypto.randomBytes(8).toString("hex");
    const now = new Date().toISOString();
    db.prepare(`
        INSERT INTO notifications (id, account_id, type, severity, title, message, resource_type, resource_id, metadata_json, is_read, is_archived, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?)
    `).run(id, accountId, type, severity, title, message, resourceType, resourceId, metadata ? JSON.stringify(metadata) : null, now);

    return { id, success: true };
}

function getNotifications(accountId = "sentinel_primary", options = {}) {
    const {
        unreadOnly = false,
        severity = null,
        type = null,
        limit = 50,
        offset = 0
    } = options;

    let query = "SELECT * FROM notifications WHERE account_id = ? AND is_archived = 0";
    const params = [accountId];

    if (unreadOnly) {
        query += " AND is_read = 0";
    }
    if (severity && severity !== "ALL") {
        query += " AND severity = ?";
        params.push(severity);
    }
    if (type && type !== "ALL") {
        query += " AND type = ?";
        params.push(type);
    }

    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?";
    params.push(limit, offset);

    const rows = db.prepare(query).all(...params);
    const unreadCount = db.prepare("SELECT COUNT(*) as count FROM notifications WHERE account_id = ? AND is_read = 0 AND is_archived = 0").get(accountId).count;
    const totalCount = db.prepare("SELECT COUNT(*) as count FROM notifications WHERE account_id = ? AND is_archived = 0").get(accountId).count;

    return {
        notifications: rows.map(r => ({
            id: r.id,
            type: r.type,
            severity: r.severity,
            title: r.title,
            message: r.message,
            resourceType: r.resource_type,
            resourceId: r.resource_id,
            metadata: r.metadata_json ? JSON.parse(r.metadata_json) : null,
            isRead: r.is_read === 1,
            createdAt: r.created_at
        })),
        unreadCount,
        total: totalCount
    };
}

function markNotificationRead(id, accountId = "sentinel_primary") {
    const res = db.prepare("UPDATE notifications SET is_read = 1 WHERE id = ? AND account_id = ?").run(id, accountId);
    return res.changes > 0;
}

function markAllNotificationsRead(accountId = "sentinel_primary") {
    const res = db.prepare("UPDATE notifications SET is_read = 1 WHERE account_id = ? AND is_read = 0").run(accountId);
    return res.changes;
}

function deleteNotification(id, accountId = "sentinel_primary") {
    const res = db.prepare("UPDATE notifications SET is_archived = 1 WHERE id = ? AND account_id = ?").run(id, accountId);
    return res.changes > 0;
}

function getUnreadNotificationCount(accountId = "sentinel_primary") {
    const row = db.prepare("SELECT COUNT(*) as count FROM notifications WHERE account_id = ? AND is_read = 0 AND is_archived = 0").get(accountId);
    return row ? row.count : 0;
}

// ==================================================
// SCAM CHECKER PERSISTENT STORAGE
// ==================================================

function insertScamCheck(accountId, { checkType, inputPreview, source = "DIRECT", verdict, riskScore, category, resultJson }) {
    const id = "chk_" + crypto.randomBytes(12).toString("hex");
    const createdAt = new Date().toISOString();
    db.prepare(`
        INSERT INTO scam_checks (id, account_id, check_type, input_preview, source, verdict, risk_score, category, result_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
        id,
        accountId || "sentinel_primary",
        checkType,
        inputPreview ? String(inputPreview).slice(0, 300) : "",
        source || "DIRECT",
        verdict,
        Number(riskScore) || 0,
        category || "UNKNOWN",
        typeof resultJson === "string" ? resultJson : JSON.stringify(resultJson || {}),
        createdAt
    );
    return { id, createdAt };
}

function getScamChecks(accountId, limit = 50) {
    const rows = db.prepare(`
        SELECT id, account_id, check_type, input_preview, source, verdict, risk_score, category, result_json, created_at
        FROM scam_checks
        WHERE account_id = ?
        ORDER BY created_at DESC
        LIMIT ?
    `).all(accountId || "sentinel_primary", limit);

    return rows.map(r => ({
        id: r.id,
        accountId: r.account_id,
        checkType: r.check_type,
        inputPreview: r.input_preview,
        source: r.source,
        verdict: r.verdict,
        riskScore: r.risk_score,
        category: r.category,
        result: JSON.parse(r.result_json || "{}"),
        createdAt: r.created_at
    }));
}

function getScamCheckById(id, accountId) {
    const r = db.prepare(`
        SELECT id, account_id, check_type, input_preview, source, verdict, risk_score, category, result_json, created_at
        FROM scam_checks
        WHERE id = ? AND account_id = ?
    `).get(id, accountId || "sentinel_primary");

    if (!r) return null;
    return {
        id: r.id,
        accountId: r.account_id,
        checkType: r.check_type,
        inputPreview: r.input_preview,
        source: r.source,
        verdict: r.verdict,
        riskScore: r.risk_score,
        category: r.category,
        result: JSON.parse(r.result_json || "{}"),
        createdAt: r.created_at
    };
}

function deleteScamCheck(id, accountId) {
    const res = db.prepare("DELETE FROM scam_checks WHERE id = ? AND account_id = ?").run(id, accountId || "sentinel_primary");
    return res.changes > 0;
}

function clearScamChecks(accountId) {
    const res = db.prepare("DELETE FROM scam_checks WHERE account_id = ?").run(accountId || "sentinel_primary");
    return res.changes;
}

function getSmsAccount(messageId) {
    if (!messageId) return null;
    try {
        const row = db.prepare("SELECT account_id FROM sms_records WHERE id = ? LIMIT 1").get(messageId);
        return row ? row.account_id : null;
    } catch (_) {
        return null;
    }
}

function getNotificationAccount(id) {
    if (!id) return null;
    try {
        const row = db.prepare("SELECT account_id FROM notifications WHERE id = ? LIMIT 1").get(id);
        return row ? row.account_id : null;
    } catch (_) {
        return null;
    }
}

function getNotificationAccount(id) {
    if (!id) return null;
    try {
        const row = db.prepare("SELECT account_id FROM notifications WHERE id = ? LIMIT 1").get(id);
        return row ? row.account_id : null;
    } catch (_) {
        return null;
    }
}

function getScamCheckAccount(id) {
    if (!id) return null;
    try {
        const row = db.prepare("SELECT account_id FROM scam_checks WHERE id = ? LIMIT 1").get(id);
        return row ? row.account_id : null;
    } catch (_) {
        return null;
    }
}

module.exports = {
    HEARTBEAT_FRESHNESS_MS,
    registerUser,
    verifyUserCredentials,
    createUserSession,
    getSessionUser,
    destroyUserSession,
    initializeDefaultAdmin,
    initializePrimaryAccount,
    createAnonymousUserSession,
    getOrCreateUserSession,
    getLatestActiveUser,
    getUserById,
    saveGmailOAuth,
    getGmailOAuth,
    deleteGmailOAuth,
    createPairingSession,
    consumePairingSession,
    registerDevice,
    getDeviceByCredential,
    getDeviceById,
    getDevicesForAccount,
    updateDeviceHeartbeat,
    updateDeviceSyncSuccess,
    updateDeviceStatus,
    insertSmsBatch,
    getSmsRecords,
    getSmsStats,
    deleteSmsRecord,
    deleteAllSms,
    getSettings,
    updateSettings,
    enforceRetention,
    logActivity,
    getActivityLog,
    createNotification,
    getNotifications,
    markNotificationRead,
    markAllNotificationsRead,
    deleteNotification,
    getUnreadNotificationCount,
    getNotificationAccount,
    saveClassificationOverride,
    getClassificationOverrides,
    updateSmsClassification,
    updateSmsRecordAnalysis,
    getSmsRecordById,
    getSmsAccount,
    isSmsRecord,
    insertScamCheck,
    getScamChecks,
    getScamCheckById,
    getScamCheckAccount,
    deleteScamCheck,
    clearScamChecks
};
