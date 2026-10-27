import React, { useState, useEffect } from "react";
import {
  X,
  AlertTriangle,
  AlertOctagon,
  ExternalLink,
  Flag,
  UserCheck,
  Ban,
  Link,
  CheckCircle2,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Globe,
  Lock,
  Clock,
  Info,
  Check,
  XCircle,
  HelpCircle
} from "lucide-react";
import { SourceBadge, CategoryBadge, RiskScoreBadge, VerdictBadge } from "./StatusBadge";
import { api } from "../api/client";

export function MessageDetailDrawer({
  item,
  isOpen,
  onClose,
  onFeedbackSubmitted
}) {
  const [feedbackLoading, setFeedbackLoading] = useState(false);
  const [feedbackSent, setFeedbackSent] = useState(null);
  const [rescanLoading, setRescanLoading] = useState(false);
  const [rescanError, setRescanError] = useState(null);

  const [activeItem, setActiveItem] = useState(item);
  const [currentCategory, setCurrentCategory] = useState(item?.category || "LEGITIMATE");
  const [currentRisk, setCurrentRisk] = useState(item?.risk || item?.riskLevel || "LOW");
  const [currentScore, setCurrentScore] = useState(item?.riskScore ?? item?.score ?? 15);
  const [currentVerdict, setCurrentVerdict] = useState(item?.verdict || "Likely safe");

  useEffect(() => {
    if (item) {
      setActiveItem(item);
      setCurrentCategory(item.category || "LEGITIMATE");
      setCurrentRisk(item.risk || item.riskLevel || "LOW");
      const score = item.riskScore ?? item.score ?? 15;
      setCurrentScore(score);
      setCurrentVerdict(
        item.verdict ||
        (score >= 70 ? "High risk" : score >= 40 ? "Suspicious" : score >= 20 ? "Needs caution" : "Likely safe")
      );
      setFeedbackSent(item.reviewed ? (item.userFeedback || item.category) : null);
      setFeedbackLoading(false);
      setRescanError(null);
    } else {
      setFeedbackSent(null);
      setFeedbackLoading(false);
      setRescanError(null);
    }
  }, [item?.id, item?.category, item?.risk, item?.riskLevel, item?.score, item?.riskScore, item?.verdict, item?.reviewed, item?.userFeedback]);

  if (!isOpen || !activeItem) return null;

  const isSms = activeItem.source === "SMS";
  const dateFormatted = activeItem.timestamp
    ? new Date(activeItem.timestamp).toLocaleString()
    : activeItem.date || "Unknown";

  const scannedAtFormatted = activeItem.scannedAt
    ? new Date(activeItem.scannedAt).toLocaleString()
    : "Recently scanned";

  const urls = activeItem.urls || [];
  const findings = activeItem.findings || [];
  const reasons = activeItem.reasons || [];
  const evidence = activeItem.evidence || [];
  const recommendations = activeItem.recommendedActions || [];
  const urlAnalysis = activeItem.urlAnalysis || [];
  const auth = activeItem.auth || {};
  const limitations = activeItem.analysisLimitations || [];

  const isReviewItem =
    currentCategory === "NEEDS REVIEW" ||
    currentCategory === "SUSPICIOUS" ||
    activeItem.category === "NEEDS REVIEW" ||
    activeItem.category === "SUSPICIOUS";

  async function handleRescan() {
    setRescanLoading(true);
    setRescanError(null);
    try {
      const res = await api.rescanMessage(activeItem.id, activeItem.source);
      if (res && res.item) {
        const updated = res.item;
        setActiveItem(updated);
        setCurrentCategory(updated.category);
        setCurrentRisk(updated.risk || updated.riskLevel);
        const score = updated.riskScore ?? updated.score ?? 15;
        setCurrentScore(score);
        setCurrentVerdict(
          updated.verdict ||
          (score >= 70 ? "High risk" : score >= 40 ? "Suspicious" : score >= 20 ? "Needs caution" : "Likely safe")
        );
        if (onFeedbackSubmitted) {
          onFeedbackSubmitted(activeItem.id, "RESCAN", updated);
        }
      }
    } catch (err) {
      console.error("[Sentinel Rescan Error]", err);
      setRescanError(err.message || "Failed to rescan message from source.");
    } finally {
      setRescanLoading(false);
    }
  }

  async function sendFeedback(actionType, targetCat) {
    setFeedbackLoading(true);
    try {
      const res = await api.submitFeedback({
        id: activeItem.id,
        emailId: activeItem.id,
        source: activeItem.source,
        feedbackType: actionType,
        targetCategory: targetCat,
        notes: `Classified as ${targetCat || actionType} by security review`,
        emailSummary: {
          from: activeItem.from || activeItem.sender,
          subject: activeItem.subject,
          category: targetCat || activeItem.category,
          source: activeItem.source
        }
      });

      const updatedCat =
        res?.item?.category ||
        targetCat ||
        (actionType === "MARK_LEGITIMATE" || actionType === "FALSE_POSITIVE" || actionType === "CORRECT"
          ? "LEGITIMATE"
          : actionType === "MARK_PHISHING" || actionType === "MISSED_PHISHING"
          ? "PHISHING"
          : actionType === "MARK_SPAM"
          ? "SPAM"
          : "NEEDS REVIEW");

      const updatedScore =
        res?.item?.score !== undefined
          ? res.item.score
          : updatedCat === "PHISHING"
          ? 90
          : updatedCat === "SPAM"
          ? 35
          : updatedCat === "NEEDS REVIEW"
          ? 55
          : 10;

      const updatedVerdict =
        updatedScore >= 70 ? "High risk" : updatedScore >= 40 ? "Suspicious" : updatedScore >= 20 ? "Needs caution" : "Likely safe";

      const updatedRisk =
        updatedScore >= 70 ? "CRITICAL" : updatedScore >= 40 ? "HIGH" : updatedScore >= 20 ? "MEDIUM" : "LOW";

      setCurrentCategory(updatedCat);
      setCurrentRisk(updatedRisk);
      setCurrentScore(updatedScore);
      setCurrentVerdict(updatedVerdict);
      setFeedbackSent(actionType);

      const updatedItem = {
        ...activeItem,
        category: updatedCat,
        risk: updatedRisk,
        riskLevel: updatedRisk,
        score: updatedScore,
        riskScore: updatedScore,
        verdict: updatedVerdict,
        reviewed: true,
        userFeedback: actionType
      };

      setActiveItem(updatedItem);

      if (onFeedbackSubmitted) {
        onFeedbackSubmitted(activeItem.id, actionType, updatedItem);
      }
    } catch (e) {
      console.error("[Sentinel Review Error]", e);
    } finally {
      setFeedbackLoading(false);
    }
  }

  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <div
        className="drawer-panel"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-label="Message Detail Inspection"
      >
        {/* Drawer Header */}
        <div className="drawer-header">
          <div className="drawer-header-left">
            <SourceBadge source={activeItem.source} />
            <VerdictBadge verdict={currentVerdict} score={currentScore} />
            <RiskScoreBadge score={currentScore} />
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={handleRescan}
              disabled={rescanLoading}
              title="Rescan directly against real source data"
            >
              <RefreshCw size={13} className={rescanLoading ? "spin" : ""} style={{ marginRight: "4px" }} />
              <span>{rescanLoading ? "Rescanning..." : "Rescan"}</span>
            </button>
            <button className="icon-btn-ghost" onClick={onClose} aria-label="Close drawer">
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Rescan Error Alert */}
        {rescanError && (
          <div className="alert-banner alert-danger" style={{ margin: "12px 20px 0" }}>
            <AlertTriangle size={14} />
            <span>{rescanError}</span>
          </div>
        )}

        {/* Drawer Content */}
        <div className="drawer-body">
          {/* Metadata Card */}
          <div className="drawer-section meta-card">
            <div className="meta-row">
              <span className="meta-label">Sender</span>
              <span className="meta-value font-mono">{activeItem.from || activeItem.sender || "Unknown"}</span>
            </div>
            {!isSms && (
              <div className="meta-row">
                <span className="meta-label">Subject</span>
                <span className="meta-value font-semibold">{activeItem.subject || "(No Subject)"}</span>
              </div>
            )}
            <div className="meta-row">
              <span className="meta-label">Received</span>
              <span className="meta-value text-muted">{dateFormatted}</span>
            </div>
            <div className="meta-row">
              <span className="meta-label">Last Analyzed</span>
              <span className="meta-value text-muted font-mono">{scannedAtFormatted}</span>
            </div>
            {isSms && activeItem.deviceId && (
              <div className="meta-row">
                <span className="meta-label">Source Device</span>
                <span className="meta-value text-muted font-mono">{activeItem.deviceId}</span>
              </div>
            )}
          </div>

          {/* Explainable Verdict & Summary */}
          <div className="drawer-section">
            <h4 className="section-title">Verdict & Posture Summary</h4>
            <div className="risk-overview-card">
              <div className="risk-header" style={{ marginBottom: "10px" }}>
                <div>
                  <span className="risk-title">Calibrated Threat Exposure</span>
                  <div className="risk-score-display">
                    <span className="score-number">{currentScore}</span>
                    <span className="score-max">/ 100</span>
                    <span className={`risk-tag tag-${(currentRisk || "low").toLowerCase()}`}>
                      {currentVerdict.toUpperCase()}
                    </span>
                  </div>
                </div>
              </div>

              {activeItem.summary && (
                <p className="text-sm" style={{ color: "var(--text-secondary)", lineHeight: "1.5", margin: 0 }}>
                  {activeItem.summary}
                </p>
              )}
            </div>
          </div>

          {/* Section: Why Was This Flagged? (Structured Findings) */}
          <div className="drawer-section">
            <h4 className="section-title">Why was this flagged?</h4>
            {findings.length > 0 ? (
              <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                {findings.map((f, i) => {
                  const isCrit = f.severity === "CRITICAL";
                  const isHigh = f.severity === "HIGH";
                  const isMed = f.severity === "MEDIUM";
                  const badgeClass = isCrit || isHigh ? "badge-danger" : isMed ? "badge-amber" : "badge-muted";

                  return (
                    <div
                      key={f.id || i}
                      style={{
                        padding: "10px 12px",
                        background: isCrit || isHigh ? "rgba(239, 68, 68, 0.05)" : "var(--bg-subtle)",
                        border: `1px solid ${isCrit || isHigh ? "rgba(239, 68, 68, 0.25)" : "var(--border-subtle)"}`,
                        borderRadius: "var(--radius-sm)"
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                        <strong style={{ fontSize: "13px", color: "var(--text-primary)" }}>{f.title}</strong>
                        <span className={`badge-pill ${badgeClass}`} style={{ fontSize: "11px", padding: "2px 6px" }}>
                          {f.severity}
                        </span>
                      </div>
                      <p style={{ fontSize: "12px", color: "var(--text-secondary)", margin: "0 0 6px 0", lineHeight: "1.4" }}>
                        {f.explanation}
                      </p>
                      {f.evidence && (
                        <div style={{ fontSize: "11.5px", fontFamily: "var(--font-mono)", background: "rgba(0,0,0,0.04)", padding: "4px 8px", borderRadius: "4px", color: "var(--text-muted)", wordBreak: "break-all" }}>
                          <span style={{ fontWeight: 600 }}>Evidence: </span>{typeof f.evidence === "object" ? JSON.stringify(f.evidence) : String(f.evidence)}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <div style={{ padding: "12px", background: "rgba(16, 185, 129, 0.06)", border: "1px solid rgba(16, 185, 129, 0.2)", borderRadius: "var(--radius-sm)", display: "flex", gap: "8px", alignItems: "center" }}>
                <CheckCircle2 size={16} className="text-success" />
                <span style={{ fontSize: "12.5px", color: "var(--text-secondary)" }}>
                  No malicious links, credential lures, or urgent social-engineering tactics detected. Communication aligns with authentic patterns.
                </span>
              </div>
            )}
          </div>

          {/* Section: Actionable Recommendations (What should I do?) */}
          <div className="drawer-section">
            <h4 className="section-title">What should I do?</h4>
            <div style={{ background: "var(--bg-subtle)", border: "1px solid var(--border-subtle)", borderRadius: "var(--radius-sm)", padding: "12px" }}>
              {recommendations.length > 0 ? (
                <ul style={{ margin: 0, paddingLeft: "18px", display: "flex", flexDirection: "column", gap: "6px" }}>
                  {recommendations.map((action, i) => (
                    <li key={i} style={{ fontSize: "12.5px", color: "var(--text-primary)", lineHeight: "1.4" }}>
                      {action}
                    </li>
                  ))}
                </ul>
              ) : (
                <div style={{ fontSize: "12.5px", color: "var(--text-secondary)" }}>
                  No defensive actions required. Message is verified benign.
                </div>
              )}
            </div>
          </div>

          {/* Section: Sender Authentication Analysis (Emails only) */}
          {!isSms && (
            <div className="drawer-section">
              <h4 className="section-title">Sender Cryptographic Authentication</h4>
              <div style={{ background: "var(--bg-subtle)", border: "1px solid var(--border-subtle)", borderRadius: "var(--radius-sm)", padding: "12px" }}>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "8px", marginBottom: "8px" }}>
                  <div style={{ textAlign: "center", padding: "6px", background: "var(--bg-card)", borderRadius: "4px", border: "1px solid var(--border-subtle)" }}>
                    <div style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: 600 }}>SPF</div>
                    <div style={{ fontSize: "12px", fontWeight: 700, color: auth.spf === "pass" ? "#10b981" : auth.spf === "fail" ? "#ef4444" : "var(--text-muted)" }}>
                      {(auth.spf || "NONE").toUpperCase()}
                    </div>
                  </div>
                  <div style={{ textAlign: "center", padding: "6px", background: "var(--bg-card)", borderRadius: "4px", border: "1px solid var(--border-subtle)" }}>
                    <div style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: 600 }}>DKIM</div>
                    <div style={{ fontSize: "12px", fontWeight: 700, color: auth.dkim === "pass" ? "#10b981" : auth.dkim === "fail" ? "#ef4444" : "var(--text-muted)" }}>
                      {(auth.dkim || "NONE").toUpperCase()}
                    </div>
                  </div>
                  <div style={{ textAlign: "center", padding: "6px", background: "var(--bg-card)", borderRadius: "4px", border: "1px solid var(--border-subtle)" }}>
                    <div style={{ fontSize: "11px", color: "var(--text-muted)", fontWeight: 600 }}>DMARC</div>
                    <div style={{ fontSize: "12px", fontWeight: 700, color: auth.dmarc === "pass" ? "#10b981" : auth.dmarc === "fail" ? "#ef4444" : "var(--text-muted)" }}>
                      {(auth.dmarc || "NONE").toUpperCase()}
                    </div>
                  </div>
                </div>
                {limitations.length > 0 && (
                  <div style={{ fontSize: "11.5px", color: "var(--text-muted)", fontStyle: "italic", marginTop: "4px" }}>
                    {limitations.join(" ")}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Section: Detected URLs & Domains Inspection */}
          {urls.length > 0 && (
            <div className="drawer-section">
              <h4 className="section-title">Detected Links ({urls.length})</h4>
              <div className="urls-list">
                {urls.map((u, i) => {
                  const href = typeof u === "string" ? u : u.href || u.url;
                  const inspection = urlAnalysis.find(a => a.href === href);
                  const isDeceptive = inspection?.flags?.length > 0;

                  return (
                    <div key={i} className="url-item" style={{ flexDirection: "column", alignItems: "flex-start", gap: "4px" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "6px", width: "100%" }}>
                        <Link size={14} className="url-icon" />
                        <span className="url-text font-mono" title={href} style={{ flex: 1, wordBreak: "break-all" }}>{href}</span>
                        <a
                          href={href}
                          target="_blank"
                          rel="noreferrer noopener"
                          className="url-ext"
                          title="External preview (Click with caution)"
                        >
                          <ExternalLink size={12} />
                        </a>
                      </div>
                      {inspection && (
                        <div style={{ fontSize: "11.5px", color: "var(--text-muted)", paddingLeft: "20px" }}>
                          <span>Host: <strong>{inspection.host}</strong> ({inspection.rootDomain})</span>
                          {inspection.flags?.length > 0 && (
                            <span style={{ color: "#ef4444", marginLeft: "6px", fontWeight: 600 }}>
                              [{inspection.flags.join(", ")}]
                            </span>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Message Body Content (Strictly escaped plain-text rendering) */}
          <div className="drawer-section">
            <h4 className="section-title">Message Body Content</h4>
            <div className="message-body-box">
              <pre className="message-body-text">{activeItem.body || activeItem.bodyText || activeItem.snippet || "(Empty body)"}</pre>
            </div>
          </div>

          {/* User Feedback & Actions */}
          <div className="drawer-section feedback-section">
            <div className="feedback-section-header">
              <h4 className="section-title">Security Review & Corrections</h4>
              {isReviewItem && (
                <span className="review-needed-badge">
                  <AlertTriangle size={12} />
                  Needs Review
                </span>
              )}
            </div>
            <p className="feedback-desc">
              {isReviewItem
                ? "This message requires security verification. Choose a resolution to update classification rules and remove it from Needs Review:"
                : "Correct or verify classification to update Sentinel's detection models and adjust threat intelligence."}
            </p>

            {feedbackSent ? (
              <div className="feedback-confirmed-card">
                <div className="feedback-confirmed-body">
                  <CheckCircle2 size={18} className="icon-success" />
                  <div className="feedback-confirmed-text">
                    <span className="feedback-confirmed-title">
                      Classification Saved: {currentCategory} ({currentVerdict})
                    </span>
                    <span className="feedback-confirmed-subtitle">
                      Persisted to SQLite security database for {isSms ? "Android SMS" : "Gmail"} message.
                    </span>
                  </div>
                </div>
                <button
                  type="button"
                  className="btn-reclassify"
                  onClick={() => setFeedbackSent(null)}
                  title="Change classification"
                >
                  <RefreshCw size={12} style={{ marginRight: 4, display: "inline" }} />
                  Change
                </button>
              </div>
            ) : (
              <div className="feedback-action-container">
                <div className="feedback-buttons-grid">
                  <button
                    type="button"
                    className={`btn-action-legit ${currentCategory === "LEGITIMATE" ? "active-choice" : ""}`}
                    onClick={() => sendFeedback("MARK_LEGITIMATE", "LEGITIMATE")}
                    disabled={feedbackLoading}
                    title="Mark as Legitimate and Safe"
                  >
                    <UserCheck size={14} />
                    <span>Likely Safe</span>
                  </button>

                  <button
                    type="button"
                    className={`btn-action-phish ${currentCategory === "PHISHING" ? "active-choice" : ""}`}
                    onClick={() => sendFeedback("MARK_PHISHING", "PHISHING")}
                    disabled={feedbackLoading}
                    title="Confirm message as Phishing threat"
                  >
                    <AlertOctagon size={14} />
                    <span>High Risk</span>
                  </button>

                  <button
                    type="button"
                    className={`btn-action-spam ${currentCategory === "SPAM" ? "active-choice" : ""}`}
                    onClick={() => sendFeedback("MARK_SPAM", "SPAM")}
                    disabled={feedbackLoading}
                    title="Mark message as Spam / Caution"
                  >
                    <Ban size={14} />
                    <span>Needs Caution</span>
                  </button>

                  <button
                    type="button"
                    className={`btn-action-review ${currentCategory === "NEEDS REVIEW" || currentCategory === "SUSPICIOUS" ? "active-choice" : ""}`}
                    onClick={() => sendFeedback("REQUEST_REVIEW", "NEEDS REVIEW")}
                    disabled={feedbackLoading}
                    title="Flag for security team inspection"
                  >
                    <Flag size={14} />
                    <span>Suspicious</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Drawer Footer */}
        <div className="drawer-footer">
          <button className="btn btn-ghost" onClick={onClose}>
            Close Inspection
          </button>
        </div>
      </div>
    </div>
  );
}
