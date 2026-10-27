/**
 * Sentinel AI Security Agent - Centralized API Client
 * Connects directly to local Sentinel backend for Google OAuth, Android companion telemetry,
 * and AI threat intelligence. No artificial user login tokens required.
 */

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:5000";

let currentSessionToken = null;
try {
  currentSessionToken = sessionStorage.getItem("sentinel_session_token") || localStorage.getItem("sentinel_session_token") || null;
} catch (_) {}

async function request(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;

  let token = api.getSessionToken();
  if (!token && !endpoint.startsWith("/api/auth/")) {
    try {
      const s = await api.initSession();
      if (s && s.sessionToken) {
        token = s.sessionToken;
      }
    } catch (_) {}
  }

  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {})
  };

  if (token && !headers["X-Sentinel-Session"]) {
    headers["X-Sentinel-Session"] = token;
  }

  const config = {
    ...options,
    headers
  };

  try {
    const res = await fetch(url, config);

    // If Gmail is disconnected, /api/emails responds with 401. Return empty list gracefully.
    if (res.status === 401 && endpoint.includes("/api/emails")) {
      return { emails: [], connected: false };
    }

    // Auto-recover on 401 for other endpoints by refreshing session once
    if (res.status === 401 && !options._retried && !endpoint.startsWith("/api/auth/")) {
      try {
        const s = await api.initSession();
        if (s && s.sessionToken) {
          return await request(endpoint, { ...options, _retried: true });
        }
      } catch (_) {}
    }

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.error || `Server returned error status ${res.status}`);
    }

    return await res.json();
  } catch (err) {
    if (err.name === "TypeError" && err.message.includes("fetch")) {
      throw new Error("Unable to reach Sentinel Backend server. Please ensure it is running on port 5000.");
    }
    throw err;
  }
}

export const api = {
  baseUrl: API_BASE,

  // ==========================================
  // AUTHENTICATION & USER SESSION LIFECYCLE
  // ==========================================
  getSessionToken() {
    if (currentSessionToken) return currentSessionToken;
    try {
      currentSessionToken = sessionStorage.getItem("sentinel_session_token") || localStorage.getItem("sentinel_session_token") || null;
    } catch (_) {}
    return currentSessionToken;
  },

  setSessionToken(token) {
    currentSessionToken = token || null;
    try {
      if (token) {
        sessionStorage.setItem("sentinel_session_token", token);
        localStorage.setItem("sentinel_session_token", token);
      } else {
        sessionStorage.removeItem("sentinel_session_token");
        localStorage.removeItem("sentinel_session_token");
      }
    } catch (_) {}
  },

  async initSession() {
    const data = await request("/api/auth/session");
    if (data && data.sessionToken) {
      this.setSessionToken(data.sessionToken);
      return data;
    }
    return null;
  },

  async login(email, password) {
    const data = await request("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password })
    });
    if (data && data.sessionToken) {
      this.setSessionToken(data.sessionToken);
    }
    return data;
  },

  async register(email, password, displayName) {
    const data = await request("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({ email, password, displayName })
    });
    if (data && data.sessionToken) {
      this.setSessionToken(data.sessionToken);
    }
    return data;
  },

  async logout() {
    try {
      await request("/api/auth/logout", { method: "POST" });
    } catch (_) {}
    this.setSessionToken(null);
  },

  // ==========================================
  // GMAIL OAUTH INTEGRATION
  // ==========================================
  getGoogleAuthUrl() {
    const token = this.getSessionToken();
    const url = new URL(`${API_BASE}/auth/google`);
    if (token) {
      url.searchParams.set("sessionToken", token);
    }
    return url.toString();
  },

  async getGmailAccount() {
    return await request(`/api/account?_t=${Date.now()}`);
  },

  async disconnectGmail() {
    return await request("/api/disconnect", { method: "POST" });
  },

  async getEmails(maxResults = 50, refresh = false) {
    return await request(`/api/emails?maxResults=${maxResults}&refresh=${refresh ? "true" : "false"}&_t=${Date.now()}`);
  },

  async clearEmailCache() {
    return await request("/api/cache/clear", { method: "POST" });
  },

  async rescanMessage(id, source = "EMAIL") {
    return await request("/api/messages/rescan", {
      method: "POST",
      body: JSON.stringify({ id, source })
    });
  },

  // ==========================================
  // ANDROID COMPANION & SMS INTEGRATION
  // ==========================================
  async createPairingSession() {
    return await request("/api/devices/pairing", { method: "POST" });
  },

  async getDevices() {
    return await request(`/api/devices?_t=${Date.now()}`);
  },

  async revokeDevice(deviceId) {
    return await request(`/api/devices/${encodeURIComponent(deviceId)}`, { method: "DELETE" });
  },

  async getSmsSyncStatus() {
    return await request(`/api/sms/sync-status?_t=${Date.now()}`);
  },

  async getSmsRecords(limit = 100, category = null, search = null, deviceId = null) {
    const params = new URLSearchParams({ limit: String(limit), _t: String(Date.now()) });
    if (category && category !== "ALL") params.set("category", category);
    if (search) params.set("search", search);
    if (deviceId) params.set("deviceId", deviceId);
    return await request(`/api/sms?${params.toString()}`);
  },

  async pauseSmsSync() {
    return await request("/api/sms/sync/pause", { method: "POST" });
  },

  async resumeSmsSync() {
    return await request("/api/sms/sync/resume", { method: "POST" });
  },

  async deleteDeviceSms(deviceId) {
    return await request(`/api/sms?deviceId=${encodeURIComponent(deviceId)}`, { method: "DELETE" });
  },

  async deleteAllSms() {
    return await request("/api/sms", { method: "DELETE" });
  },

  async getSmsSettings() {
    return await request("/api/sms/settings");
  },

  async updateSmsSettings(settings) {
    return await request("/api/sms/settings", {
      method: "POST",
      body: JSON.stringify(settings)
    });
  },

  // ==========================================
  // DOMAIN REPUTATION & RULES
  // ==========================================
  async getReputation() {
    return await request("/api/reputation");
  },

  async overrideReputation(domain, status, notes = "") {
    return await request("/api/reputation/override", {
      method: "POST",
      body: JSON.stringify({ domain, status, notes })
    });
  },

  // ==========================================
  // USER CLASSIFICATION FEEDBACK
  // ==========================================
  async submitFeedback(payload) {
    return await request("/api/feedback", {
      method: "POST",
      body: JSON.stringify(payload)
    });
  },

  // ==========================================
  // SECURITY AUDIT ACTIVITY LOG
  // ==========================================
  async getActivityLog(limit = 50, category = null, search = null) {
    const params = new URLSearchParams({ limit: String(limit), _t: String(Date.now()) });
    if (category && category !== "ALL") params.set("category", category);
    if (search) params.set("search", search);
    return await request(`/api/activity?${params.toString()}`);
  },

  // ==========================================
  // SYSTEM HEALTH DIAGNOSTICS
  // ==========================================
  async getHealthFull() {
    return await request("/api/health/full");
  },

  // ==========================================
  // NOTIFICATION CENTER
  // ==========================================
  async getNotifications(options = {}) {
    const { unreadOnly = false, severity = null, type = null, limit = 50, offset = 0 } = options;
    const params = new URLSearchParams({
      limit: String(limit),
      offset: String(offset),
      _t: String(Date.now())
    });
    if (unreadOnly) params.set("unreadOnly", "true");
    if (severity && severity !== "ALL") params.set("severity", severity);
    if (type && type !== "ALL") params.set("type", type);
    return await request(`/api/notifications?${params.toString()}`);
  },

  async markNotificationRead(id) {
    return await request(`/api/notifications/${encodeURIComponent(id)}/read`, { method: "POST" });
  },

  async markAllNotificationsRead() {
    return await request("/api/notifications/read-all", { method: "POST" });
  },

  async deleteNotification(id) {
    return await request(`/api/notifications/${encodeURIComponent(id)}`, { method: "DELETE" });
  },

  async getUnreadNotificationCount() {
    return await request(`/api/notifications/unread-count?_t=${Date.now()}`);
  },

  // ==========================================
  // SCAM CHECKER API
  // ==========================================
  async analyzeScamMessage(message, source = "OTHER", saveToHistory = true) {
    return await request("/api/scam-checker/analyze-message", {
      method: "POST",
      body: JSON.stringify({ message, source, saveToHistory })
    });
  },

  async checkScamUrl(url, saveToHistory = true) {
    return await request("/api/scam-checker/check-url", {
      method: "POST",
      body: JSON.stringify({ url, saveToHistory })
    });
  },

  async getScamCheckerHistory(limit = 50) {
    return await request(`/api/scam-checker/history?limit=${limit}&_t=${Date.now()}`);
  },

  async deleteScamCheckerHistoryItem(id) {
    return await request(`/api/scam-checker/history/${encodeURIComponent(id)}`, {
      method: "DELETE"
    });
  },

  async clearScamCheckerHistory() {
    return await request("/api/scam-checker/history", {
      method: "DELETE"
    });
  }
};

export { api as client };
export default api;


