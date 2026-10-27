import React, { useState, useEffect } from "react";
import {
  User,
  LogIn,
  UserPlus,
  LogOut,
  X,
  Shield,
  Lock,
  Mail,
  Eye,
  EyeOff,
  Copy,
  Check,
  AlertCircle,
  CheckCircle2,
  ArrowRight
} from "lucide-react";
import { api } from "../api/client";

export function AccountModal({
  isOpen = false,
  onClose,
  currentUser = null,
  onSessionChanged,
  showToast
}) {
  const isGuest =
    !currentUser ||
    !currentUser.email ||
    currentUser.email.startsWith("guest_") ||
    currentUser.email === "guest@sentinel.local";

  const [mode, setMode] = useState(isGuest ? "login" : "info"); // "login", "register", "info"
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [copiedId, setCopiedId] = useState(false);

  // Sync mode when modal opens
  useEffect(() => {
    if (isOpen) {
      setMode(isGuest ? "login" : "info");
      setError(null);
      setPassword("");
    }
  }, [isOpen, isGuest]);

  if (!isOpen) return null;

  async function handleLogin(e) {
    e.preventDefault();
    if (!email || !password) {
      setError("Please fill in both email and password.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await api.login(email.trim(), password);
      if (res && res.user) {
        if (showToast) showToast(`Signed in as ${res.user.email}`);
        if (onSessionChanged) onSessionChanged(res.user);
        onClose();
      } else {
        setError(res?.message || "Invalid credentials.");
      }
    } catch (err) {
      setError(err.message || "Failed to log in.");
    } finally {
      setLoading(false);
    }
  }

  async function handleRegister(e) {
    e.preventDefault();
    if (!email || !password) {
      setError("Please fill in email and password.");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters long.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await api.register(email.trim(), password, displayName.trim());
      if (res && res.user) {
        if (showToast) showToast(`Account created for ${res.user.email}`);
        if (onSessionChanged) onSessionChanged(res.user);
        onClose();
      } else {
        setError(res?.message || "Registration failed.");
      }
    } catch (err) {
      setError(err.message || "Failed to create account.");
    } finally {
      setLoading(false);
    }
  }

  async function handleLogout() {
    setLoading(true);
    try {
      await api.logout();
      const fresh = await api.initSession();
      if (showToast) showToast("Switched to clean isolated session.");
      if (onSessionChanged) onSessionChanged(fresh?.user || null);
      onClose();
    } catch (err) {
      setError(err.message || "Failed to reset session.");
    } finally {
      setLoading(false);
    }
  }

  function copyAccountId() {
    if (currentUser?.id) {
      navigator.clipboard.writeText(currentUser.id);
      setCopiedId(true);
      setTimeout(() => setCopiedId(false), 2000);
    }
  }

  const userInitial = (currentUser?.displayName || currentUser?.email || "U")
    .trim()[0]
    .toUpperCase();

  return (
    <div className="modal-backdrop" onClick={onClose} role="dialog" aria-modal="true">
      <div className="modal-card modal-auth" onClick={(e) => e.stopPropagation()}>
        {/* Top Gradient Accent Bar */}
        <div className="auth-accent-bar" />

        {/* Modal Header */}
        <div className="auth-header">
          <div className="auth-header-main">
            <div className="auth-icon-badge" aria-hidden="true">
              {mode === "register" ? (
                <UserPlus size={22} />
              ) : mode === "info" ? (
                <Shield size={22} />
              ) : (
                <LogIn size={22} />
              )}
            </div>
            <div>
              <h2 className="auth-title">
                {mode === "login"
                  ? "Sign In to Sentinel"
                  : mode === "register"
                  ? "Create Sentinel Account"
                  : "Active Session & Identity"}
              </h2>
              <p className="auth-subtitle">
                {mode === "login"
                  ? "Access your isolated email and SMS threat workspace"
                  : mode === "register"
                  ? "Join Sentinel AI with your dedicated security posture"
                  : "Authoritative workspace scoping security telemetry"}
              </p>
            </div>
          </div>
          <button
            type="button"
            className="auth-close-btn"
            onClick={onClose}
            aria-label="Close modal"
          >
            <X size={18} />
          </button>
        </div>

        {/* Segmented Mode Switcher */}
        <div className="auth-tabs-wrap">
          <div className="auth-segmented-control" role="tablist">
            <button
              type="button"
              role="tab"
              aria-selected={mode === "login"}
              className={`auth-tab-pill ${mode === "login" ? "active" : ""}`}
              onClick={() => {
                setMode("login");
                setError(null);
              }}
            >
              <LogIn size={13} />
              <span>Sign In</span>
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={mode === "register"}
              className={`auth-tab-pill ${mode === "register" ? "active" : ""}`}
              onClick={() => {
                setMode("register");
                setError(null);
              }}
            >
              <UserPlus size={13} />
              <span>Register</span>
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={mode === "info"}
              className={`auth-tab-pill ${mode === "info" ? "active" : ""}`}
              onClick={() => {
                setMode("info");
                setError(null);
              }}
            >
              <User size={13} />
              <span>Profile</span>
              {!isGuest && <span className="auth-tab-badge-dot" />}
            </button>
          </div>
        </div>

        {/* Modal Body */}
        <div className="auth-body">
          {/* Error Notice */}
          {error && (
            <div
              className="alert-box alert-danger"
              style={{
                display: "flex",
                alignItems: "center",
                gap: "10px",
                marginBottom: "16px",
                padding: "10px 14px",
                borderRadius: "10px",
                background: "rgba(239, 68, 68, 0.08)",
                border: "1px solid rgba(239, 68, 68, 0.25)",
                color: "var(--status-danger-text)",
                fontSize: "13px"
              }}
            >
              <AlertCircle size={16} style={{ flexShrink: 0 }} />
              <span style={{ lineHeight: 1.4 }}>{error}</span>
            </div>
          )}

          {/* MODE: SIGN IN */}
          {mode === "login" && (
            <form onSubmit={handleLogin} className="auth-form">
              <div className="auth-field-group">
                <label className="auth-field-label">
                  <span>Email Address</span>
                </label>
                <div className="auth-input-wrapper">
                  <Mail size={16} className="auth-input-icon" />
                  <input
                    type="email"
                    required
                    autoFocus
                    autoComplete="email"
                    placeholder="admin@sentinel.security"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="auth-input"
                  />
                </div>
              </div>

              <div className="auth-field-group">
                <label className="auth-field-label">
                  <span>Password</span>
                </label>
                <div className="auth-input-wrapper">
                  <Lock size={16} className="auth-input-icon" />
                  <input
                    type={showPassword ? "text" : "password"}
                    required
                    autoComplete="current-password"
                    placeholder="Enter password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="auth-input"
                  />
                  <button
                    type="button"
                    className="auth-pwd-toggle"
                    onClick={() => setShowPassword(!showPassword)}
                    aria-label={showPassword ? "Hide password" : "Show password"}
                  >
                    {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>

              <button
                type="submit"
                className="auth-submit-btn"
                disabled={loading}
              >
                {loading ? (
                  <span>Authenticating...</span>
                ) : (
                  <>
                    <span>Sign In</span>
                    <ArrowRight size={15} />
                  </>
                )}
              </button>

              <div className="auth-switch-prompt">
                Don't have an account?{" "}
                <button
                  type="button"
                  className="auth-switch-link"
                  onClick={() => {
                    setMode("register");
                    setError(null);
                  }}
                >
                  Create one now
                </button>
              </div>
            </form>
          )}

          {/* MODE: REGISTER */}
          {mode === "register" && (
            <form onSubmit={handleRegister} className="auth-form">
              <div className="auth-field-group">
                <label className="auth-field-label">
                  <span>Full Name / Display Name</span>
                </label>
                <div className="auth-input-wrapper">
                  <User size={16} className="auth-input-icon" />
                  <input
                    type="text"
                    autoFocus
                    autoComplete="name"
                    placeholder="Security Analyst"
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                    className="auth-input"
                  />
                </div>
              </div>

              <div className="auth-field-group">
                <label className="auth-field-label">
                  <span>Work Email</span>
                </label>
                <div className="auth-input-wrapper">
                  <Mail size={16} className="auth-input-icon" />
                  <input
                    type="email"
                    required
                    autoComplete="email"
                    placeholder="analyst@enterprise.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="auth-input"
                  />
                </div>
              </div>

              <div className="auth-field-group">
                <label className="auth-field-label">
                  <span>Password</span>
                  <span
                    style={{
                      fontSize: "11px",
                      color:
                        password.length >= 8
                          ? "var(--status-success-text)"
                          : "var(--text-muted)"
                    }}
                  >
                    {password.length >= 8 ? "✓ Minimum 8 chars" : "Min. 8 characters"}
                  </span>
                </label>
                <div className="auth-input-wrapper">
                  <Lock size={16} className="auth-input-icon" />
                  <input
                    type={showPassword ? "text" : "password"}
                    required
                    autoComplete="new-password"
                    placeholder="At least 8 characters"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="auth-input"
                  />
                  <button
                    type="button"
                    className="auth-pwd-toggle"
                    onClick={() => setShowPassword(!showPassword)}
                    aria-label={showPassword ? "Hide password" : "Show password"}
                  >
                    {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>

              <button
                type="submit"
                className="auth-submit-btn"
                disabled={loading}
              >
                {loading ? (
                  <span>Creating Account...</span>
                ) : (
                  <>
                    <span>Create Account</span>
                    <ArrowRight size={15} />
                  </>
                )}
              </button>

              <div className="auth-switch-prompt">
                Already registered?{" "}
                <button
                  type="button"
                  className="auth-switch-link"
                  onClick={() => {
                    setMode("login");
                    setError(null);
                  }}
                >
                  Sign in here
                </button>
              </div>
            </form>
          )}

          {/* MODE: CURRENT PROFILE / INFO */}
          {mode === "info" && (
            <div className="auth-profile-card">
              <div className="auth-profile-header">
                <div className="auth-avatar-circle">{userInitial}</div>
                <div className="auth-profile-names">
                  <div className="auth-profile-name">
                    {currentUser?.displayName || (isGuest ? "Guest User" : "Sentinel User")}
                  </div>
                  <div className="auth-profile-email">
                    {currentUser?.email || "guest@sentinel.local"}
                  </div>
                </div>
                <span className="auth-status-pill">
                  <span className="status-dot dot-online" style={{ width: 6, height: 6 }} />
                  <span>{isGuest ? "Isolated" : "Verified"}</span>
                </span>
              </div>

              <div className="auth-meta-list">
                <div className="auth-meta-item">
                  <span className="auth-meta-key">Account ID</span>
                  <div className="auth-meta-val">
                    <span>{currentUser?.id || "sentinel_primary"}</span>
                    <button
                      type="button"
                      onClick={copyAccountId}
                      title="Copy Account ID"
                      style={{
                        background: "transparent",
                        border: "none",
                        cursor: "pointer",
                        color: copiedId ? "var(--status-success-text)" : "var(--text-muted)",
                        padding: "2px"
                      }}
                    >
                      {copiedId ? <Check size={13} /> : <Copy size={13} />}
                    </button>
                  </div>
                </div>

                <div className="auth-meta-item">
                  <span className="auth-meta-key">Access Role</span>
                  <span className="auth-meta-val" style={{ textTransform: "uppercase", fontSize: "11px" }}>
                    {currentUser?.role || "analyst"}
                  </span>
                </div>

                <div className="auth-meta-item">
                  <span className="auth-meta-key">Telemetry Scope</span>
                  <span className="auth-meta-val" style={{ color: "var(--accent-blue)" }}>
                    Dedicated Sandbox
                  </span>
                </div>
              </div>

              <div className="auth-profile-actions">
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  style={{ width: "100%", justifyContent: "center" }}
                  onClick={() => {
                    setMode("login");
                    setError(null);
                  }}
                >
                  <LogIn size={14} />
                  <span>Switch to Another Account</span>
                </button>

                <button
                  type="button"
                  className="btn btn-ghost btn-sm text-danger"
                  style={{ width: "100%", justifyContent: "center" }}
                  onClick={handleLogout}
                  disabled={loading}
                >
                  <LogOut size={14} />
                  <span>End Session / Reset to Guest</span>
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
