import React, { useState, useEffect } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  Globe,
  MessageSquare,
  Search,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  ExternalLink,
  Trash2,
  Clock,
  ArrowRight,
  RefreshCw,
  Info,
  Server,
  Lock,
  Link2,
  Copy,
  Check,
  Sparkles
} from "lucide-react";
import { VerdictBadge } from "../components/StatusBadge";
import { client } from "../api/client";

const SOURCE_OPTIONS = [
  { value: "WHATSAPP", label: "WhatsApp" },
  { value: "INSTAGRAM", label: "Instagram" },
  { value: "TELEGRAM", label: "Telegram" },
  { value: "MESSENGER", label: "Facebook Messenger" },
  { value: "LINKEDIN", label: "LinkedIn" },
  { value: "SMS", label: "SMS" },
  { value: "EMAIL", label: "Email" },
  { value: "OTHER", label: "Other" }
];

const SAMPLE_MESSAGES = [
  {
    label: "KYC Suspension Scam",
    source: "SMS",
    text: "URGENT: Your HDFC Bank account is temporarily blocked due to unverified KYC. Click http://hdfc-kyc-reactivate.xyz to verify your password and identity within 24 hours to avoid closure."
  },
  {
    label: "UPI Refund Fraud",
    source: "WHATSAPP",
    text: "Dear Customer, you received a cashback refund of Rs. 4,999 from PhonePe. To receive the money directly in your bank account, please click here and enter your UPI PIN: http://phonepe-cashback-claim.vip"
  },
  {
    label: "Safe Bank Alert",
    source: "SMS",
    text: "Your account XX9871 was debited by Rs 1500.00 on 24-Oct-26 via UPI 123456789. If not you, SMS BLOCK to 56767 or call 1800-258-3838."
  }
];

const SAMPLE_URLS = [
  { label: "Lookalike Domain", url: "http://paypa1-security-verify.com/login" },
  { label: "Suspicious TLD", url: "http://netflix-billing-update.xyz/account" },
  { label: "Authentic Website", url: "https://www.google.com" }
];

export function ScamCheckerPage({ onNavigateOverview }) {
  const [activeTab, setActiveTab] = useState("message"); // "message" | "url" | "history"

  // Message Checker State
  const [messageInput, setMessageInput] = useState("");
  const [messageSource, setMessageSource] = useState("WHATSAPP");
  const [messageLoading, setMessageLoading] = useState(false);
  const [messageError, setMessageError] = useState("");
  const [messageResult, setMessageResult] = useState(null);

  // URL Checker State
  const [urlInput, setUrlInput] = useState("");
  const [urlLoading, setUrlLoading] = useState(false);
  const [urlError, setUrlError] = useState("");
  const [urlResult, setUrlResult] = useState(null);

  // History State
  const [history, setHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState("");
  const [selectedHistoryItem, setSelectedHistoryItem] = useState(null);

  // Copy helper
  const [copied, setCopied] = useState(false);

  // Load history on mount or tab change
  const loadHistory = async () => {
    setHistoryLoading(true);
    setHistoryError("");
    try {
      const res = await client.getScamCheckerHistory(50);
      if (res && res.history) {
        setHistory(res.history);
      }
    } catch (err) {
      setHistoryError(err.message || "Failed to load recent check history.");
    } finally {
      setHistoryLoading(false);
    }
  };

  useEffect(() => {
    loadHistory();
  }, []);

  // Handle Message Check
  const handleAnalyzeMessage = async (e) => {
    if (e) e.preventDefault();
    const trimmed = messageInput.trim();
    if (!trimmed) {
      setMessageError("Please paste a suspicious message to analyze.");
      return;
    }
    if (trimmed.length > 15000) {
      setMessageError("Message exceeds maximum permitted length of 15,000 characters.");
      return;
    }

    setMessageLoading(true);
    setMessageError("");
    setMessageResult(null);

    try {
      const result = await client.analyzeScamMessage(trimmed, messageSource, true);
      setMessageResult(result);
      loadHistory();
    } catch (err) {
      setMessageError(err.message || "Analysis failed. Please check backend connection.");
    } finally {
      setMessageLoading(false);
    }
  };

  // Handle URL Check
  const handleCheckUrl = async (e) => {
    if (e) e.preventDefault();
    const trimmed = urlInput.trim();
    if (!trimmed) {
      setUrlError("Please enter a web URL to check.");
      return;
    }

    setUrlLoading(true);
    setUrlError("");
    setUrlResult(null);

    try {
      const result = await client.checkScamUrl(trimmed, true);
      setUrlResult(result);
      loadHistory();
    } catch (err) {
      setUrlError(err.message || "URL analysis failed. Please verify syntax.");
    } finally {
      setUrlLoading(false);
    }
  };

  // Handle Delete Single History Item
  const handleDeleteHistory = async (id, e) => {
    if (e) e.stopPropagation();
    try {
      await client.deleteScamCheckerHistoryItem(id);
      setHistory((prev) => prev.filter((item) => item.id !== id));
      if (selectedHistoryItem?.id === id) {
        setSelectedHistoryItem(null);
      }
    } catch (err) {
      console.error("Failed to delete history item:", err);
    }
  };

  // Handle Clear All History
  const handleClearHistory = async () => {
    if (!window.confirm("Are you sure you want to clear your entire check history?")) {
      return;
    }
    try {
      await client.clearScamCheckerHistory();
      setHistory([]);
      setSelectedHistoryItem(null);
    } catch (err) {
      console.error("Failed to clear history:", err);
    }
  };

  // Copy snippet
  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Calibrated score theme helper that adapts to light/dark tokens
  const getScoreTheme = (score) => {
    if (score >= 70) {
      return {
        color: "var(--status-danger-text, #dc2626)",
        bg: "var(--status-danger-bg, #fef2f2)",
        border: "var(--status-danger-border, #fecaca)",
        badgeClass: "badge-danger",
        label: "High Risk"
      };
    }
    if (score >= 40) {
      return {
        color: "var(--status-orange-text, #ea580c)",
        bg: "var(--status-orange-bg, #fff7ed)",
        border: "var(--status-orange-border, #fed7aa)",
        badgeClass: "badge-amber",
        label: "Suspicious"
      };
    }
    if (score >= 20) {
      return {
        color: "var(--status-amber-text, #d97706)",
        bg: "var(--status-amber-bg, #fffbeb)",
        border: "var(--status-amber-border, #fef08a)",
        badgeClass: "badge-amber",
        label: "Guarded"
      };
    }
    return {
      color: "var(--status-success-text, #059669)",
      bg: "var(--status-success-bg, #ecfdf5)",
      border: "var(--status-success-border, #a7f3d0)",
      badgeClass: "badge-success",
      label: "Likely Safe"
    };
  };

  return (
    <div className="page-container scam-checker-page" style={{ maxWidth: "1280px", margin: "0 auto", paddingBottom: "40px" }}>
      {/* Top Banner Header */}
      <div className="page-header" style={{ marginBottom: "20px" }}>
        <div className="page-header-content">
          <div className="page-title-row" style={{ display: "flex", alignItems: "center", gap: "14px" }}>
            <div style={{
              width: "44px",
              height: "44px",
              borderRadius: "12px",
              background: "var(--status-danger-bg, #fef2f2)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              border: "1px solid var(--status-danger-border, #fecaca)",
              flexShrink: 0
            }}>
              <ShieldAlert size={22} style={{ color: "var(--status-danger, #ef4444)" }} />
            </div>
            <div>
              <h1 className="page-title" style={{ fontSize: "22px", fontWeight: "700", margin: 0, color: "var(--text-primary, #0f172a)" }}>
                Scam Checker
              </h1>
              <p className="page-subtitle" style={{ color: "var(--text-muted, #64748b)", fontSize: "13.5px", marginTop: "3px", margin: "3px 0 0 0" }}>
                Check suspicious messages and links before you trust them.
              </p>
            </div>
          </div>
        </div>

        {/* Tab Controls Bar */}
        <div style={{
          display: "flex",
          alignItems: "center",
          gap: "8px",
          marginTop: "18px",
          borderBottom: "1px solid var(--border-subtle, #e2e8f0)",
          paddingBottom: "12px",
          flexWrap: "wrap"
        }}>
          <button
            type="button"
            className={`btn-tab ${activeTab === "message" ? "active" : ""}`}
            onClick={() => setActiveTab("message")}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              padding: "9px 18px",
              borderRadius: "8px",
              fontSize: "13.5px",
              fontWeight: "600",
              cursor: "pointer",
              background: activeTab === "message" ? "var(--accent-blue, #2563eb)" : "var(--bg-card, #ffffff)",
              color: activeTab === "message" ? "#ffffff" : "var(--text-secondary, #334155)",
              border: "1px solid " + (activeTab === "message" ? "var(--accent-blue, #2563eb)" : "var(--border-card, #e2e8f0)"),
              boxShadow: activeTab === "message" ? "0 2px 4px rgba(37, 99, 235, 0.2)" : "none",
              transition: "all 0.15s ease"
            }}
          >
            <MessageSquare size={16} />
            Message Checker
          </button>

          <button
            type="button"
            className={`btn-tab ${activeTab === "url" ? "active" : ""}`}
            onClick={() => setActiveTab("url")}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              padding: "9px 18px",
              borderRadius: "8px",
              fontSize: "13.5px",
              fontWeight: "600",
              cursor: "pointer",
              background: activeTab === "url" ? "var(--accent-blue, #2563eb)" : "var(--bg-card, #ffffff)",
              color: activeTab === "url" ? "#ffffff" : "var(--text-secondary, #334155)",
              border: "1px solid " + (activeTab === "url" ? "var(--accent-blue, #2563eb)" : "var(--border-card, #e2e8f0)"),
              boxShadow: activeTab === "url" ? "0 2px 4px rgba(37, 99, 235, 0.2)" : "none",
              transition: "all 0.15s ease"
            }}
          >
            <Globe size={16} />
            URL Checker
          </button>

          <button
            type="button"
            className={`btn-tab ${activeTab === "history" ? "active" : ""}`}
            onClick={() => { setActiveTab("history"); loadHistory(); }}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              padding: "9px 18px",
              borderRadius: "8px",
              fontSize: "13.5px",
              fontWeight: "600",
              cursor: "pointer",
              background: activeTab === "history" ? "var(--accent-blue, #2563eb)" : "var(--bg-card, #ffffff)",
              color: activeTab === "history" ? "#ffffff" : "var(--text-secondary, #334155)",
              border: "1px solid " + (activeTab === "history" ? "var(--accent-blue, #2563eb)" : "var(--border-card, #e2e8f0)"),
              boxShadow: activeTab === "history" ? "0 2px 4px rgba(37, 99, 235, 0.2)" : "none",
              transition: "all 0.15s ease",
              marginLeft: "auto"
            }}
          >
            <Clock size={16} />
            Recent Checks ({history.length})
          </button>
        </div>
      </div>

      {/* ======================================================== */}
      {/* TAB 1: MESSAGE CHECKER */}
      {/* ======================================================== */}
      {activeTab === "message" && (
        <div className="tab-pane-message" style={{
          display: "grid",
          gridTemplateColumns: messageResult ? "1.05fr 1fr" : "1fr",
          gap: "24px",
          alignItems: "start"
        }}>
          {/* Main Input Card */}
          <div className="card" style={{
            background: "var(--bg-card, #ffffff)",
            borderRadius: "14px",
            border: "1px solid var(--border-card, #e2e8f0)",
            padding: "24px",
            boxShadow: "var(--shadow-card, 0 1px 3px 0 rgba(0, 0, 0, 0.05))"
          }}>
            <h2 style={{
              fontSize: "16px",
              fontWeight: "600",
              marginBottom: "16px",
              display: "flex",
              alignItems: "center",
              gap: "8px",
              color: "var(--text-primary, #0f172a)"
            }}>
              <MessageSquare size={18} style={{ color: "var(--accent-blue, #2563eb)" }} />
              Paste Suspicious Message
            </h2>

            {/* Quick Test Samples */}
            <div style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              marginBottom: "16px",
              flexWrap: "wrap",
              background: "var(--bg-subtle, #f8fafc)",
              padding: "10px 14px",
              borderRadius: "8px",
              border: "1px solid var(--border-subtle, #e2e8f0)"
            }}>
              <span style={{ fontSize: "12px", fontWeight: "600", color: "var(--text-muted, #64748b)" }}>
                Quick Test:
              </span>
              {SAMPLE_MESSAGES.map((s, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => {
                    setMessageInput(s.text);
                    setMessageSource(s.source);
                    setMessageError("");
                  }}
                  style={{
                    padding: "4px 10px",
                    borderRadius: "6px",
                    fontSize: "12px",
                    fontWeight: "500",
                    background: "var(--bg-card, #ffffff)",
                    color: "var(--text-secondary, #334155)",
                    border: "1px solid var(--border-card, #cbd5e1)",
                    cursor: "pointer",
                    transition: "all 0.15s ease"
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.borderColor = "var(--accent-blue, #2563eb)";
                    e.currentTarget.style.color = "var(--accent-blue, #2563eb)";
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.borderColor = "var(--border-card, #cbd5e1)";
                    e.currentTarget.style.color = "var(--text-secondary, #334155)";
                  }}
                >
                  {s.label}
                </button>
              ))}
            </div>

            <form onSubmit={handleAnalyzeMessage}>
              {/* Platform chips */}
              <div style={{ marginBottom: "16px" }}>
                <label style={{ display: "block", fontSize: "13px", fontWeight: "600", marginBottom: "8px", color: "var(--text-secondary, #334155)" }}>
                  Contextual Platform / Source
                </label>
                <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
                  {SOURCE_OPTIONS.map((opt) => {
                    const isSelected = messageSource === opt.value;
                    return (
                      <button
                        key={opt.value}
                        type="button"
                        onClick={() => setMessageSource(opt.value)}
                        style={{
                          padding: "6px 14px",
                          borderRadius: "7px",
                          fontSize: "12.5px",
                          fontWeight: isSelected ? "600" : "500",
                          cursor: "pointer",
                          background: isSelected ? "var(--accent-blue-light, #eff6ff)" : "var(--bg-subtle, #f1f5f9)",
                          color: isSelected ? "var(--accent-blue, #2563eb)" : "var(--text-secondary, #334155)",
                          border: "1px solid " + (isSelected ? "var(--accent-blue-border, #bfdbfe)" : "var(--border-subtle, #e2e8f0)"),
                          boxShadow: isSelected ? "0 1px 2px rgba(37, 99, 235, 0.1)" : "none",
                          transition: "all 0.15s ease"
                        }}
                      >
                        {opt.label}
                      </button>
                    );
                  })}
                </div>
                <p style={{ fontSize: "11.5px", color: "var(--text-muted, #64748b)", marginTop: "6px", lineHeight: "1.4" }}>
                  Contextual indicator only — Sentinel AI never connects to external messaging accounts without explicit authorization.
                </p>
              </div>

              {/* Message Content Textarea */}
              <div style={{ marginBottom: "18px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                  <label htmlFor="message-textarea" style={{ fontSize: "13px", fontWeight: "600", color: "var(--text-secondary, #334155)" }}>
                    Message Content
                  </label>
                  <span style={{ fontSize: "12px", color: messageInput.length > 14000 ? "var(--status-danger, #ef4444)" : "var(--text-muted, #64748b)" }}>
                    {messageInput.length.toLocaleString()} / 15,000
                  </span>
                </div>
                <textarea
                  id="message-textarea"
                  rows={8}
                  value={messageInput}
                  onChange={(e) => { setMessageInput(e.target.value); setMessageError(""); }}
                  placeholder="Paste the message you received on WhatsApp, Instagram, SMS, email, Telegram, or another platform..."
                  style={{
                    width: "100%",
                    padding: "14px",
                    borderRadius: "10px",
                    background: "var(--bg-input, var(--bg-subtle, #f8fafc))",
                    border: "1px solid " + (messageError ? "var(--status-danger, #ef4444)" : "var(--border-card, #cbd5e1)"),
                    color: "var(--text-primary, #0f172a)",
                    fontSize: "14px",
                    fontFamily: "inherit",
                    resize: "vertical",
                    outline: "none",
                    lineHeight: "1.5",
                    boxSizing: "border-box",
                    transition: "border-color 0.15s ease"
                  }}
                  onFocus={(e) => e.target.style.borderColor = "var(--accent-blue, #2563eb)"}
                  onBlur={(e) => e.target.style.borderColor = messageError ? "var(--status-danger, #ef4444)" : "var(--border-card, #cbd5e1)"}
                />
                {messageError && (
                  <p style={{ color: "var(--status-danger, #ef4444)", fontSize: "12.5px", marginTop: "6px", display: "flex", alignItems: "center", gap: "6px" }}>
                    <AlertTriangle size={14} /> {messageError}
                  </p>
                )}
              </div>

              {/* Action Buttons */}
              <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
                <button
                  type="submit"
                  disabled={messageLoading || !messageInput.trim()}
                  className="btn btn-primary"
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "8px",
                    padding: "10px 22px",
                    borderRadius: "8px",
                    fontSize: "14px",
                    fontWeight: "600",
                    cursor: messageLoading || !messageInput.trim() ? "not-allowed" : "pointer",
                    opacity: messageLoading || !messageInput.trim() ? 0.6 : 1,
                    background: "var(--accent-blue, #2563eb)",
                    color: "#ffffff",
                    border: "none",
                    boxShadow: "0 2px 4px rgba(37, 99, 235, 0.25)"
                  }}
                >
                  {messageLoading ? (
                    <>
                      <RefreshCw size={16} className="animate-spin" />
                      Analyzing Message...
                    </>
                  ) : (
                    <>
                      <Search size={16} />
                      Analyze Message
                    </>
                  )}
                </button>

                <button
                  type="button"
                  onClick={() => { setMessageInput(""); setMessageResult(null); setMessageError(""); }}
                  disabled={!messageInput && !messageResult}
                  style={{
                    padding: "10px 18px",
                    borderRadius: "8px",
                    fontSize: "14px",
                    fontWeight: "500",
                    cursor: !messageInput && !messageResult ? "not-allowed" : "pointer",
                    background: "transparent",
                    color: "var(--text-secondary, #334155)",
                    border: "1px solid var(--border-card, #cbd5e1)",
                    opacity: !messageInput && !messageResult ? 0.5 : 1
                  }}
                >
                  Clear
                </button>
              </div>
            </form>
          </div>

          {/* Result Card for Message */}
          {messageResult && (
            <MessageResultCard
              result={messageResult}
              source={messageSource}
              getScoreTheme={getScoreTheme}
            />
          )}
        </div>
      )}

      {/* ======================================================== */}
      {/* TAB 2: URL CHECKER */}
      {/* ======================================================== */}
      {activeTab === "url" && (
        <div className="tab-pane-url" style={{
          display: "grid",
          gridTemplateColumns: urlResult ? "1.05fr 1fr" : "1fr",
          gap: "24px",
          alignItems: "start"
        }}>
          {/* Input Card */}
          <div className="card" style={{
            background: "var(--bg-card, #ffffff)",
            borderRadius: "14px",
            border: "1px solid var(--border-card, #e2e8f0)",
            padding: "24px",
            boxShadow: "var(--shadow-card, 0 1px 3px 0 rgba(0, 0, 0, 0.05))"
          }}>
            <h2 style={{
              fontSize: "16px",
              fontWeight: "600",
              marginBottom: "16px",
              display: "flex",
              alignItems: "center",
              gap: "8px",
              color: "var(--text-primary, #0f172a)"
            }}>
              <Globe size={18} style={{ color: "var(--accent-blue, #2563eb)" }} />
              Enter URL to Check
            </h2>

            {/* Quick URL Samples */}
            <div style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              marginBottom: "16px",
              flexWrap: "wrap",
              background: "var(--bg-subtle, #f8fafc)",
              padding: "10px 14px",
              borderRadius: "8px",
              border: "1px solid var(--border-subtle, #e2e8f0)"
            }}>
              <span style={{ fontSize: "12px", fontWeight: "600", color: "var(--text-muted, #64748b)" }}>
                Quick Test:
              </span>
              {SAMPLE_URLS.map((s, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => {
                    setUrlInput(s.url);
                    setUrlError("");
                  }}
                  style={{
                    padding: "4px 10px",
                    borderRadius: "6px",
                    fontSize: "12px",
                    fontWeight: "500",
                    background: "var(--bg-card, #ffffff)",
                    color: "var(--text-secondary, #334155)",
                    border: "1px solid var(--border-card, #cbd5e1)",
                    cursor: "pointer",
                    transition: "all 0.15s ease"
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.borderColor = "var(--accent-blue, #2563eb)";
                    e.currentTarget.style.color = "var(--accent-blue, #2563eb)";
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.borderColor = "var(--border-card, #cbd5e1)";
                    e.currentTarget.style.color = "var(--text-secondary, #334155)";
                  }}
                >
                  {s.label}
                </button>
              ))}
            </div>

            <form onSubmit={handleCheckUrl}>
              <div style={{ marginBottom: "18px" }}>
                <label htmlFor="url-input" style={{ display: "block", fontSize: "13px", fontWeight: "600", marginBottom: "8px", color: "var(--text-secondary, #334155)" }}>
                  Web Link (HTTP or HTTPS)
                </label>
                <div style={{ position: "relative" }}>
                  <Link2 size={16} style={{ position: "absolute", left: "14px", top: "14px", color: "var(--text-muted, #64748b)" }} />
                  <input
                    id="url-input"
                    type="text"
                    value={urlInput}
                    onChange={(e) => { setUrlInput(e.target.value); setUrlError(""); }}
                    placeholder="https://example.com or any web link to inspect..."
                    style={{
                      width: "100%",
                      padding: "12px 14px 12px 42px",
                      borderRadius: "10px",
                      background: "var(--bg-input, var(--bg-subtle, #f8fafc))",
                      border: "1px solid " + (urlError ? "var(--status-danger, #ef4444)" : "var(--border-card, #cbd5e1)"),
                      color: "var(--text-primary, #0f172a)",
                      fontSize: "14px",
                      fontFamily: "inherit",
                      outline: "none",
                      boxSizing: "border-box",
                      transition: "border-color 0.15s ease"
                    }}
                    onFocus={(e) => e.target.style.borderColor = "var(--accent-blue, #2563eb)"}
                    onBlur={(e) => e.target.style.borderColor = urlError ? "var(--status-danger, #ef4444)" : "var(--border-card, #cbd5e1)"}
                  />
                </div>
                {urlError && (
                  <p style={{ color: "var(--status-danger, #ef4444)", fontSize: "12.5px", marginTop: "6px", display: "flex", alignItems: "center", gap: "6px" }}>
                    <AlertTriangle size={14} /> {urlError}
                  </p>
                )}
                <p style={{ fontSize: "12px", color: "var(--text-muted, #64748b)", marginTop: "8px", lineHeight: "1.4" }}>
                  Links are inspected safely via public-suffix structural parsing, lookalike detection, and server-side DNS lookups.
                  Target web servers are never fetched or visited in your browser.
                </p>
              </div>

              <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
                <button
                  type="submit"
                  disabled={urlLoading || !urlInput.trim()}
                  className="btn btn-primary"
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "8px",
                    padding: "10px 22px",
                    borderRadius: "8px",
                    fontSize: "14px",
                    fontWeight: "600",
                    cursor: urlLoading || !urlInput.trim() ? "not-allowed" : "pointer",
                    opacity: urlLoading || !urlInput.trim() ? 0.6 : 1,
                    background: "var(--accent-blue, #2563eb)",
                    color: "#ffffff",
                    border: "none",
                    boxShadow: "0 2px 4px rgba(37, 99, 235, 0.25)"
                  }}
                >
                  {urlLoading ? (
                    <>
                      <RefreshCw size={16} className="animate-spin" />
                      Checking URL...
                    </>
                  ) : (
                    <>
                      <Search size={16} />
                      Check URL
                    </>
                  )}
                </button>

                <button
                  type="button"
                  onClick={() => { setUrlInput(""); setUrlResult(null); setUrlError(""); }}
                  disabled={!urlInput && !urlResult}
                  style={{
                    padding: "10px 18px",
                    borderRadius: "8px",
                    fontSize: "14px",
                    fontWeight: "500",
                    cursor: !urlInput && !urlResult ? "not-allowed" : "pointer",
                    background: "transparent",
                    color: "var(--text-secondary, #334155)",
                    border: "1px solid var(--border-card, #cbd5e1)",
                    opacity: !urlInput && !urlResult ? 0.5 : 1
                  }}
                >
                  Clear
                </button>
              </div>
            </form>
          </div>

          {/* Result Card for URL */}
          {urlResult && (
            <UrlResultCard
              result={urlResult}
              getScoreTheme={getScoreTheme}
            />
          )}
        </div>
      )}

      {/* ======================================================== */}
      {/* TAB 3: RECENT CHECKS HISTORY */}
      {/* ======================================================== */}
      {activeTab === "history" && (
        <div className="tab-pane-history">
          <div className="card" style={{
            background: "var(--bg-card, #ffffff)",
            borderRadius: "14px",
            border: "1px solid var(--border-card, #e2e8f0)",
            padding: "24px",
            boxShadow: "var(--shadow-card, 0 1px 3px 0 rgba(0, 0, 0, 0.05))"
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "18px", flexWrap: "wrap", gap: "10px" }}>
              <div>
                <h2 style={{ fontSize: "16px", fontWeight: "600", margin: 0, display: "flex", alignItems: "center", gap: "8px", color: "var(--text-primary, #0f172a)" }}>
                  <Clock size={18} style={{ color: "var(--accent-blue, #2563eb)" }} />
                  Recent Check History
                </h2>
                <p style={{ color: "var(--text-muted, #64748b)", fontSize: "13px", marginTop: "4px", margin: "4px 0 0 0" }}>
                  Private, user-isolated log of previously analyzed messages and links.
                </p>
              </div>

              {history.length > 0 && (
                <button
                  type="button"
                  onClick={handleClearHistory}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "6px",
                    padding: "6px 14px",
                    borderRadius: "6px",
                    fontSize: "12.5px",
                    fontWeight: "600",
                    background: "var(--status-danger-bg, #fef2f2)",
                    color: "var(--status-danger, #ef4444)",
                    border: "1px solid var(--status-danger-border, #fecaca)",
                    cursor: "pointer",
                    transition: "all 0.15s ease"
                  }}
                >
                  <Trash2 size={13} />
                  Clear All History
                </button>
              )}
            </div>

            {historyLoading && (
              <div style={{ textAlign: "center", padding: "40px", color: "var(--text-muted, #64748b)" }}>
                <RefreshCw size={24} className="animate-spin" style={{ margin: "0 auto 8px" }} />
                <p style={{ margin: 0, fontSize: "13.5px" }}>Loading check history...</p>
              </div>
            )}

            {!historyLoading && history.length === 0 && (
              <div style={{ textAlign: "center", padding: "60px 20px", color: "var(--text-muted, #64748b)" }}>
                <ShieldCheck size={40} style={{ opacity: 0.35, margin: "0 auto 12px" }} />
                <h3 style={{ fontSize: "16px", fontWeight: "600", color: "var(--text-primary, #0f172a)", marginBottom: "6px" }}>
                  No checks performed yet
                </h3>
                <p style={{ fontSize: "13px", maxWidth: "420px", margin: "0 auto", color: "var(--text-muted, #64748b)" }}>
                  Paste a suspicious WhatsApp, Instagram, or email message in the Message Checker or enter a link to review real threat indicators.
                </p>
              </div>
            )}

            {!historyLoading && history.length > 0 && (
              <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                {history.map((item) => {
                  const scoreTheme = getScoreTheme(item.riskScore);
                  return (
                    <div
                      key={item.id}
                      onClick={() => setSelectedHistoryItem(item)}
                      style={{
                        padding: "14px 18px",
                        borderRadius: "10px",
                        background: "var(--bg-subtle, #f8fafc)",
                        border: "1px solid var(--border-card, #e2e8f0)",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        cursor: "pointer",
                        transition: "all 0.15s ease"
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.borderColor = "var(--accent-blue, #2563eb)";
                        e.currentTarget.style.background = "var(--bg-card-hover, #f1f5f9)";
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.borderColor = "var(--border-card, #e2e8f0)";
                        e.currentTarget.style.background = "var(--bg-subtle, #f8fafc)";
                      }}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: "12px", minWidth: 0 }}>
                        <div style={{
                          padding: "8px",
                          borderRadius: "8px",
                          background: item.checkType === "URL" ? "var(--accent-blue-light, #eff6ff)" : "rgba(168, 85, 247, 0.12)",
                          color: item.checkType === "URL" ? "var(--accent-blue, #2563eb)" : "#9333ea",
                          border: "1px solid " + (item.checkType === "URL" ? "var(--accent-blue-border, #bfdbfe)" : "rgba(168, 85, 247, 0.25)")
                        }}>
                          {item.checkType === "URL" ? <Globe size={18} /> : <MessageSquare size={18} />}
                        </div>

                        <div style={{ minWidth: 0 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                            <span style={{ fontSize: "11px", fontWeight: "700", textTransform: "uppercase", letterSpacing: "0.5px", color: "var(--text-muted, #64748b)" }}>
                              {item.checkType} ({item.source || "DIRECT"})
                            </span>
                            <span style={{ fontSize: "11.5px", color: "var(--text-disabled, #94a3b8)" }}>
                              {new Date(item.createdAt).toLocaleString()}
                            </span>
                          </div>
                          <p style={{
                            margin: "4px 0 0 0",
                            fontSize: "13px",
                            fontWeight: "500",
                            color: "var(--text-primary, #0f172a)",
                            whiteSpace: "nowrap",
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            maxWidth: "480px"
                          }}>
                            {item.inputPreview}
                          </p>
                        </div>
                      </div>

                      <div style={{ display: "flex", alignItems: "center", gap: "14px", flexShrink: 0 }}>
                        <VerdictBadge verdict={item.verdict} />

                        <div style={{
                          padding: "4px 10px",
                          borderRadius: "6px",
                          background: scoreTheme.bg,
                          color: scoreTheme.color,
                          border: `1px solid ${scoreTheme.border}`,
                          fontWeight: "700",
                          fontSize: "12px"
                        }}>
                          {Math.round(item.riskScore)}/100
                        </div>

                        <button
                          type="button"
                          onClick={(e) => handleDeleteHistory(item.id, e)}
                          title="Delete check"
                          style={{
                            background: "transparent",
                            border: "none",
                            color: "var(--text-muted, #64748b)",
                            cursor: "pointer",
                            padding: "4px"
                          }}
                          onMouseEnter={(e) => e.currentTarget.style.color = "var(--status-danger, #ef4444)"}
                          onMouseLeave={(e) => e.currentTarget.style.color = "var(--text-muted, #64748b)"}
                        >
                          <Trash2 size={16} />
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* History Detail Inspector Modal */}
          {selectedHistoryItem && (
            <div style={{ marginTop: "24px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                <h3 style={{ fontSize: "16px", fontWeight: "600", margin: 0, color: "var(--text-primary, #0f172a)" }}>
                  Inspection Report Details
                </h3>
                <button
                  type="button"
                  onClick={() => setSelectedHistoryItem(null)}
                  style={{
                    background: "var(--bg-subtle, #f1f5f9)",
                    border: "1px solid var(--border-card, #e2e8f0)",
                    color: "var(--text-secondary, #334155)",
                    fontSize: "12.5px",
                    fontWeight: "600",
                    padding: "4px 12px",
                    borderRadius: "6px",
                    cursor: "pointer"
                  }}
                >
                  Close Detail
                </button>
              </div>

              {selectedHistoryItem.checkType === "URL" ? (
                <UrlResultCard
                  result={selectedHistoryItem.result}
                  getScoreTheme={getScoreTheme}
                />
              ) : (
                <MessageResultCard
                  result={selectedHistoryItem.result}
                  source={selectedHistoryItem.source}
                  getScoreTheme={getScoreTheme}
                />
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ========================================================
// SUBCOMPONENT: MESSAGE RESULT CARD
// ========================================================
function MessageResultCard({ result, source, getScoreTheme }) {
  const scoreTheme = getScoreTheme(result.riskScore || 0);

  return (
    <div className="card" style={{
      background: "var(--bg-card, #ffffff)",
      borderRadius: "14px",
      border: `1.5px solid ${scoreTheme.border}`,
      padding: "24px",
      boxShadow: "var(--shadow-card, 0 1px 3px 0 rgba(0, 0, 0, 0.05))"
    }}>
      {/* Header Banner */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "18px" }}>
        <div>
          <span style={{ fontSize: "11px", fontWeight: "700", textTransform: "uppercase", letterSpacing: "0.5px", color: "var(--text-muted, #64748b)" }}>
            Analysis Verdict • {source}
          </span>
          <div style={{ marginTop: "6px" }}>
            <VerdictBadge verdict={result.verdict} />
          </div>
        </div>

        <div style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "flex-end"
        }}>
          <div style={{
            fontSize: "24px",
            fontWeight: "800",
            color: scoreTheme.color
          }}>
            {Math.round(result.riskScore || 0)}
            <span style={{ fontSize: "14px", fontWeight: "500", color: "var(--text-muted, #64748b)" }}> / 100</span>
          </div>
          <span style={{
            fontSize: "11px",
            fontWeight: "700",
            textTransform: "uppercase",
            color: scoreTheme.color,
            marginTop: "2px"
          }}>
            {scoreTheme.label}
          </span>
        </div>
      </div>

      {/* Summary Box */}
      <div style={{
        padding: "14px 16px",
        borderRadius: "10px",
        background: "var(--bg-subtle, #f8fafc)",
        border: "1px solid var(--border-subtle, #e2e8f0)",
        marginBottom: "18px"
      }}>
        <h4 style={{ fontSize: "12px", fontWeight: "700", textTransform: "uppercase", letterSpacing: "0.5px", margin: "0 0 6px 0", color: "var(--text-muted, #64748b)" }}>
          Analysis Explanation
        </h4>
        <p style={{ margin: 0, fontSize: "13.5px", lineHeight: "1.5", color: "var(--text-primary, #0f172a)" }}>
          {result.summary}
        </p>
        {result.fallbackUsed && (
          <div style={{ marginTop: "10px", padding: "6px 10px", borderRadius: "6px", background: "var(--status-amber-bg, #fffbeb)", border: "1px solid var(--status-amber-border, #fef08a)", display: "flex", alignItems: "center", gap: "8px" }}>
            <span style={{ fontSize: "10px", fontWeight: "700", padding: "1px 6px", borderRadius: "4px", background: "var(--status-amber-border, #fef08a)", color: "var(--status-amber-text, #d97706)" }}>
              FALLBACK ENGINE
            </span>
            <span style={{ fontSize: "12px", color: "var(--text-secondary, #334155)" }}>
              Analysis generated using local detection rules (Python AI service offline).
            </span>
          </div>
        )}
        {result.analysisLimitations && result.analysisLimitations.length > 0 && (
          <div style={{ marginTop: "8px", fontSize: "11.5px", color: "var(--text-muted, #64748b)", fontStyle: "italic" }}>
            Limitations: {result.analysisLimitations.join(" • ")}
          </div>
        )}
      </div>

      {/* Extracted Identifiers (UPI, Phones) */}
      {result.detectedIdentifiers && result.detectedIdentifiers.length > 0 && (
        <div style={{ marginBottom: "18px" }}>
          <h4 style={{ fontSize: "12px", fontWeight: "700", textTransform: "uppercase", letterSpacing: "0.5px", margin: "0 0 8px 0", color: "var(--text-muted, #64748b)" }}>
            Detected Contact & Payment Identifiers
          </h4>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
            {result.detectedIdentifiers.map((item, idx) => (
              <span
                key={idx}
                style={{
                  padding: "4px 10px",
                  borderRadius: "6px",
                  background: "var(--accent-blue-light, #eff6ff)",
                  color: "var(--accent-blue, #2563eb)",
                  fontSize: "12px",
                  fontWeight: "600",
                  border: "1px solid var(--accent-blue-border, #bfdbfe)"
                }}
              >
                {item.type}: {item.value}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Extracted URLs breakdown */}
      {result.extractedUrls && result.extractedUrls.length > 0 && (
        <div style={{ marginBottom: "18px" }}>
          <h4 style={{ fontSize: "12px", fontWeight: "700", textTransform: "uppercase", letterSpacing: "0.5px", margin: "0 0 8px 0", color: "var(--text-muted, #64748b)" }}>
            Extracted Links ({result.extractedUrls.length})
          </h4>
          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            {result.extractedUrls.map((u, idx) => {
              const uTheme = getScoreTheme(u.riskScore || 0);
              return (
                <div
                  key={idx}
                  style={{
                    padding: "10px 14px",
                    borderRadius: "8px",
                    background: "var(--bg-subtle, #f8fafc)",
                    border: "1px solid var(--border-subtle, #e2e8f0)",
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    gap: "12px"
                  }}
                >
                  <div style={{ minWidth: 0, paddingRight: "10px" }}>
                    <p style={{ margin: 0, fontSize: "13px", fontWeight: "600", color: "var(--text-primary, #0f172a)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                      {u.url}
                    </p>
                    <span style={{ fontSize: "11px", color: "var(--text-muted, #64748b)" }}>
                      Host: {u.host || "N/A"} • Root: {u.rootDomain || "N/A"}
                    </span>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", flexShrink: 0 }}>
                    <VerdictBadge verdict={u.verdict} />
                    <span style={{
                      fontSize: "12px",
                      fontWeight: "700",
                      color: uTheme.color,
                      padding: "2px 8px",
                      borderRadius: "6px",
                      background: uTheme.bg,
                      border: `1px solid ${uTheme.border}`
                    }}>
                      {Math.round(u.riskScore || 0)}/100
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Evidence & Findings */}
      <div style={{ marginBottom: "18px" }}>
        <h4 style={{ fontSize: "12px", fontWeight: "700", textTransform: "uppercase", letterSpacing: "0.5px", margin: "0 0 8px 0", color: "var(--text-muted, #64748b)" }}>
          Why Was This Flagged? ({result.findings?.length || 0})
        </h4>
        {(!result.findings || result.findings.length === 0) ? (
          <p style={{ fontSize: "13px", color: "var(--text-muted, #64748b)", margin: 0 }}>No structural or behavioral anomalies detected.</p>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            {result.findings.map((f, idx) => (
              <div
                key={idx}
                style={{
                  padding: "11px 14px",
                  borderRadius: "8px",
                  background: "var(--bg-subtle, #f8fafc)",
                  border: "1px solid var(--border-subtle, #e2e8f0)",
                  borderLeft: `3px solid ${f.severity === "CRITICAL" ? "var(--status-danger, #ef4444)" : f.severity === "HIGH" ? "var(--status-orange, #f97316)" : "var(--status-amber, #f59e0b)"}`
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                  <span style={{ fontSize: "13px", fontWeight: "600", color: "var(--text-primary, #0f172a)" }}>
                    {f.title}
                  </span>
                  <span style={{
                    fontSize: "10.5px",
                    fontWeight: "700",
                    padding: "2px 7px",
                    borderRadius: "4px",
                    background: f.severity === "CRITICAL" ? "var(--status-danger-bg, #fef2f2)" : f.severity === "HIGH" ? "var(--status-orange-bg, #fff7ed)" : "var(--accent-blue-light, #eff6ff)",
                    color: f.severity === "CRITICAL" ? "var(--status-danger, #ef4444)" : f.severity === "HIGH" ? "var(--status-orange, #ea580c)" : "var(--accent-blue, #2563eb)",
                    border: `1px solid ${f.severity === "CRITICAL" ? "var(--status-danger-border, #fecaca)" : f.severity === "HIGH" ? "var(--status-orange-border, #fed7aa)" : "var(--accent-blue-border, #bfdbfe)"}`
                  }}>
                    {f.severity}
                  </span>
                </div>
                <p style={{ margin: 0, fontSize: "12.5px", color: "var(--text-secondary, #334155)", lineHeight: "1.45" }}>
                  {f.explanation}
                </p>
                {f.evidence && (
                  <p style={{ margin: "5px 0 0 0", fontSize: "11.5px", color: "var(--text-muted, #64748b)", fontFamily: "var(--font-mono, monospace)" }}>
                    Evidence: {String(f.evidence)}
                  </p>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Recommended Actions */}
      {result.recommendedActions && result.recommendedActions.length > 0 && (
        <div style={{ marginBottom: "18px" }}>
          <h4 style={{ fontSize: "12px", fontWeight: "700", textTransform: "uppercase", letterSpacing: "0.5px", margin: "0 0 8px 0", color: "var(--status-success-text, #059669)" }}>
            Recommended Next Steps
          </h4>
          <ul style={{ margin: 0, paddingLeft: "20px", fontSize: "13px", color: "var(--text-primary, #0f172a)", lineHeight: "1.6" }}>
            {result.recommendedActions.map((action, idx) => (
              <li key={idx}>{action}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Limitations / Disclosures */}
      {result.analysisLimitations && result.analysisLimitations.length > 0 && (
        <div style={{ borderTop: "1px solid var(--border-subtle, #e2e8f0)", paddingTop: "12px" }}>
          <span style={{ fontSize: "11.5px", fontWeight: "600", color: "var(--text-muted, #64748b)" }}>
            Security Scope & Disclosures:
          </span>
          <ul style={{ margin: "4px 0 0 0", paddingLeft: "16px", fontSize: "11px", color: "var(--text-muted, #64748b)" }}>
            {result.analysisLimitations.map((lim, idx) => (
              <li key={idx}>{lim}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

// ========================================================
// SUBCOMPONENT: URL RESULT CARD
// ========================================================
function UrlResultCard({ result, getScoreTheme }) {
  const scoreTheme = getScoreTheme(result.riskScore || 0);

  return (
    <div className="card" style={{
      background: "var(--bg-card, #ffffff)",
      borderRadius: "14px",
      border: `1.5px solid ${scoreTheme.border}`,
      padding: "24px",
      boxShadow: "var(--shadow-card, 0 1px 3px 0 rgba(0, 0, 0, 0.05))"
    }}>
      {/* Header Banner */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "18px" }}>
        <div>
          <span style={{ fontSize: "11px", fontWeight: "700", textTransform: "uppercase", letterSpacing: "0.5px", color: "var(--text-muted, #64748b)" }}>
            URL Safety Verdict
          </span>
          <div style={{ marginTop: "6px" }}>
            <VerdictBadge verdict={result.verdict} />
          </div>
        </div>

        <div style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "flex-end"
        }}>
          <div style={{
            fontSize: "24px",
            fontWeight: "800",
            color: scoreTheme.color
          }}>
            {Math.round(result.riskScore || 0)}
            <span style={{ fontSize: "14px", fontWeight: "500", color: "var(--text-muted, #64748b)" }}> / 100</span>
          </div>
          <span style={{ fontSize: "11px", fontWeight: "700", textTransform: "uppercase", color: scoreTheme.color, marginTop: "2px" }}>
            {scoreTheme.label}
          </span>
        </div>
      </div>

      {/* Analyzed Destination Hostname */}
      <div style={{
        padding: "12px 16px",
        borderRadius: "10px",
        background: "var(--bg-subtle, #f8fafc)",
        border: "1px solid var(--border-subtle, #e2e8f0)",
        marginBottom: "18px"
      }}>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "4px" }}>
          <span style={{ fontSize: "11px", fontWeight: "700", textTransform: "uppercase", color: "var(--text-muted, #64748b)" }}>
            Normalized Hostname & Domain
          </span>
          <span style={{ fontSize: "11.5px", color: "var(--text-muted, #64748b)" }}>
            {result.urlStructure?.protocol || "http:"}
          </span>
        </div>
        <p style={{ margin: 0, fontSize: "14px", fontWeight: "600", color: "var(--text-primary, #0f172a)", wordBreak: "break-all" }}>
          {result.host || result.url}
        </p>
        <div style={{ display: "flex", gap: "16px", marginTop: "8px", fontSize: "12px", color: "var(--text-muted, #64748b)" }}>
          <span>Registered Root: <strong style={{ color: "var(--text-primary, #0f172a)" }}>{result.rootDomain || "N/A"}</strong></span>
          {result.domainInfo?.ip && (
            <span>Resolved IP: <strong style={{ color: "var(--text-primary, #0f172a)" }}>{result.domainInfo.ip}</strong></span>
          )}
        </div>
      </div>

      {/* Summary Box */}
      <div style={{ marginBottom: "18px" }}>
        <h4 style={{ fontSize: "12px", fontWeight: "700", textTransform: "uppercase", letterSpacing: "0.5px", margin: "0 0 6px 0", color: "var(--text-muted, #64748b)" }}>
          Security Summary
        </h4>
        <p style={{ margin: 0, fontSize: "13.5px", lineHeight: "1.5", color: "var(--text-primary, #0f172a)" }}>
          {result.summary}
        </p>
        {result.fallbackUsed && (
          <div style={{ marginTop: "10px", padding: "6px 10px", borderRadius: "6px", background: "var(--status-amber-bg, #fffbeb)", border: "1px solid var(--status-amber-border, #fef08a)", display: "flex", alignItems: "center", gap: "8px" }}>
            <span style={{ fontSize: "10px", fontWeight: "700", padding: "1px 6px", borderRadius: "4px", background: "var(--status-amber-border, #fef08a)", color: "var(--status-amber-text, #d97706)" }}>
              FALLBACK ENGINE
            </span>
            <span style={{ fontSize: "12px", color: "var(--text-secondary, #334155)" }}>
              Analysis generated using local inspection rules (Python AI service offline).
            </span>
          </div>
        )}
        {result.analysisLimitations && result.analysisLimitations.length > 0 && (
          <div style={{ marginTop: "8px", fontSize: "11.5px", color: "var(--text-muted, #64748b)", fontStyle: "italic" }}>
            Limitations: {result.analysisLimitations.join(" • ")}
          </div>
        )}
      </div>

      {/* Threat Intelligence Box */}
      <div style={{
        padding: "12px 14px",
        borderRadius: "8px",
        background: result.threatIntelligence?.isMalicious ? "var(--status-danger-bg, #fef2f2)" : "var(--bg-subtle, #f8fafc)",
        border: "1px solid " + (result.threatIntelligence?.isMalicious ? "var(--status-danger-border, #fecaca)" : "var(--border-subtle, #e2e8f0)"),
        marginBottom: "18px"
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
          <Server size={14} style={{ color: result.threatIntelligence?.isMalicious ? "var(--status-danger, #ef4444)" : "var(--accent-blue, #2563eb)" }} />
          <span style={{ fontSize: "12.5px", fontWeight: "700", color: "var(--text-primary, #0f172a)" }}>
            Threat Intelligence ({result.threatIntelligence?.provider || "Local Inspection"})
          </span>
        </div>
        <p style={{ margin: 0, fontSize: "12px", color: "var(--text-secondary, #334155)" }}>
          {result.threatIntelligence?.details || "Status: Checked."}
        </p>
      </div>

      {/* Findings */}
      <div style={{ marginBottom: "18px" }}>
        <h4 style={{ fontSize: "12px", fontWeight: "700", textTransform: "uppercase", letterSpacing: "0.5px", margin: "0 0 8px 0", color: "var(--text-muted, #64748b)" }}>
          Why Was This Flagged? ({result.findings?.length || 0})
        </h4>
        {(!result.findings || result.findings.length === 0) ? (
          <p style={{ fontSize: "13px", color: "var(--text-muted, #64748b)", margin: 0 }}>No structural or behavioral anomalies detected.</p>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            {result.findings.map((f, idx) => (
              <div
                key={idx}
                style={{
                  padding: "11px 14px",
                  borderRadius: "8px",
                  background: "var(--bg-subtle, #f8fafc)",
                  border: "1px solid var(--border-subtle, #e2e8f0)",
                  borderLeft: `3px solid ${f.severity === "CRITICAL" ? "var(--status-danger, #ef4444)" : f.severity === "HIGH" ? "var(--status-orange, #f97316)" : "var(--status-amber, #f59e0b)"}`
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                  <span style={{ fontSize: "13px", fontWeight: "600", color: "var(--text-primary, #0f172a)" }}>
                    {f.title}
                  </span>
                  <span style={{
                    fontSize: "10.5px",
                    fontWeight: "700",
                    padding: "2px 7px",
                    borderRadius: "4px",
                    background: f.severity === "CRITICAL" ? "var(--status-danger-bg, #fef2f2)" : f.severity === "HIGH" ? "var(--status-orange-bg, #fff7ed)" : "var(--accent-blue-light, #eff6ff)",
                    color: f.severity === "CRITICAL" ? "var(--status-danger, #ef4444)" : f.severity === "HIGH" ? "var(--status-orange, #ea580c)" : "var(--accent-blue, #2563eb)",
                    border: `1px solid ${f.severity === "CRITICAL" ? "var(--status-danger-border, #fecaca)" : f.severity === "HIGH" ? "var(--status-orange-border, #fed7aa)" : "var(--accent-blue-border, #bfdbfe)"}`
                  }}>
                    {f.severity}
                  </span>
                </div>
                <p style={{ margin: 0, fontSize: "12.5px", color: "var(--text-secondary, #334155)", lineHeight: "1.45" }}>
                  {f.explanation}
                </p>
                {f.evidence && (
                  <p style={{ margin: "5px 0 0 0", fontSize: "11.5px", color: "var(--text-muted, #64748b)", fontFamily: "var(--font-mono, monospace)" }}>
                    Evidence: {String(f.evidence)}
                  </p>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Recommended Actions */}
      {result.recommendedActions && result.recommendedActions.length > 0 && (
        <div style={{ marginBottom: "18px" }}>
          <h4 style={{ fontSize: "12px", fontWeight: "700", textTransform: "uppercase", letterSpacing: "0.5px", margin: "0 0 8px 0", color: "var(--status-success-text, #059669)" }}>
            Recommended Next Steps
          </h4>
          <ul style={{ margin: 0, paddingLeft: "20px", fontSize: "13px", color: "var(--text-primary, #0f172a)", lineHeight: "1.6" }}>
            {result.recommendedActions.map((action, idx) => (
              <li key={idx}>{action}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Limitations / Disclosures */}
      {result.analysisLimitations && result.analysisLimitations.length > 0 && (
        <div style={{ borderTop: "1px solid var(--border-subtle, #e2e8f0)", paddingTop: "12px" }}>
          <span style={{ fontSize: "11.5px", fontWeight: "600", color: "var(--text-muted, #64748b)" }}>
            Security Scope & Disclosures:
          </span>
          <ul style={{ margin: "4px 0 0 0", paddingLeft: "16px", fontSize: "11px", color: "var(--text-muted, #64748b)" }}>
            {result.analysisLimitations.map((lim, idx) => (
              <li key={idx}>{lim}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
