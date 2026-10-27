import React, { useState, useMemo } from "react";
import {
  ShieldCheck,
  AlertTriangle,
  AlertCircle,
  Smartphone,
  Mail,
  RefreshCw,
  Clock,
  ChevronRight,
  Shield,
  Layers,
  CheckCircle2,
  HelpCircle,
  X,
  ExternalLink
} from "lucide-react";
import {
  CategoryBadge,
  RiskScoreBadge
} from "../components/StatusBadge";
import {
  calculateChannelScore,
  calculateOverallScore,
  getScoreStatus
} from "../utils/securityScore";

// =========================================================================
// HELPER: FORMAT TIME
// =========================================================================
function formatTimeRelative(isoOrTimestamp) {
  if (!isoOrTimestamp) return "Just now";
  try {
    const d = new Date(isoOrTimestamp);
    if (isNaN(d.getTime())) return "Just now";
    const now = new Date();
    const diffSec = Math.floor((now - d) / 1000);
    if (diffSec < 60) return "Just now";
    if (diffSec < 3600) {
      const mins = Math.floor(diffSec / 60);
      return `${mins} min${mins > 1 ? "s" : ""} ago`;
    }
    const isToday = d.toDateString() === now.toDateString();
    if (isToday) {
      return `Today ${d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
    }
    return (
      d.toLocaleDateString([], { month: "short", day: "numeric" }) +
      ` ${d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`
    );
  } catch (e) {
    return "Recent";
  }
}

// =========================================================================
// SCORE CALCULATION MODAL
// =========================================================================
function ScoreCalculationModal({ isOpen, onClose, overallScore, scoreStatus, gmailScore, smsScore }) {
  if (!isOpen) return null;

  return (
    <div className="modal-backdrop" onClick={onClose} role="presentation">
      <div
        className="modal-box modal-calc-explanation"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-labelledby="calc-modal-title"
        aria-modal="true"
      >
        <div className="modal-header">
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <ShieldCheck size={22} className="text-primary" />
            <h3 id="calc-modal-title" className="modal-title">Threat Exposure Methodology</h3>
          </div>
          <button type="button" className="modal-close-btn" onClick={onClose} aria-label="Close modal">
            <X size={18} />
          </button>
        </div>

        <div className="modal-body" style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
          <p style={{ fontSize: "13px", color: "var(--text-secondary)", lineHeight: 1.5 }}>
            Sentinel AI evaluates continuous telemetry across verified communication channels on a <strong>0–100 threat exposure scale</strong>, where lower indicates cleaner communications and higher indicates elevated risk.
          </p>

          <div className="calc-breakdown-box">
            <h4 style={{ fontSize: "12px", textTransform: "uppercase", letterSpacing: "0.05em", color: "var(--text-muted)", marginBottom: "8px" }}>
              Active Channel Posture
            </h4>
            <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: "12.5px" }}>
                <span style={{ fontWeight: 600 }}>Gmail Stream:</span>
                <span className="font-mono">{gmailScore !== null ? `${gmailScore}/100` : "Not connected (excluded)"}</span>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: "12.5px" }}>
                <span style={{ fontWeight: 600 }}>Android SMS Stream:</span>
                <span className="font-mono">{smsScore !== null ? `${smsScore}/100` : "Not paired (excluded)"}</span>
              </div>
            </div>
          </div>

          <div className="calc-status-box">
            <h4 style={{ fontSize: "12px", textTransform: "uppercase", letterSpacing: "0.05em", color: "var(--text-muted)", marginBottom: "8px" }}>
              Risk Threshold Bands
            </h4>
            <ul style={{ fontSize: "12.5px", color: "var(--text-secondary)", listStyle: "none", display: "flex", flexDirection: "column", gap: "8px", padding: 0, margin: 0 }}>
              <li><strong>0–19 (Likely Safe):</strong> Normal authentic communications with zero critical threat indicators.</li>
              <li><strong>20–39 (Needs Caution):</strong> Guarded posture; bulk commercial promotions or marketing detected.</li>
              <li><strong>40–69 (Suspicious):</strong> Suspicious links, credential requests, or spoofed sender headers requiring review.</li>
              <li><strong>70–100 (High Risk):</strong> Confirmed phishing, extortion blackmail, credential harvesting, or malicious payloads.</li>
            </ul>
          </div>
        </div>

        <div className="modal-footer">
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

// =========================================================================
// MAIN MINIMAL OVERVIEW PAGE
// =========================================================================
export function OverviewPage({
  currentUser = null,
  emails = [],
  smsMessages = [],
  allMessages = [],
  loading = false,
  onRefresh,
  onSelectMessage,
  selectedMessageId,
  gmailConnected = false,
  gmailAccount = "",
  onConnectGmail,
  onDisconnectGmail,
  androidDevices = [],
  activeDevicesCount = 0,
  smsSyncStatus = {},
  onOpenPairModal,
  onNavigateToDevices,
  onNavigateToFeed,
  lastSuccessfulScanTime = null
}) {
  const [calcModalOpen, setCalcModalOpen] = useState(false);
  const [sourceFilter, setSourceFilter] = useState("ALL");
  const [categoryFilter, setCategoryFilter] = useState("ALL");

  // Telemetry Counts
  const totalEmails = emails.length;
  const totalSms = smsSyncStatus.totalSms ?? smsMessages.length;
  const totalScanned = totalEmails + totalSms;

  // Unified sorted message stream
  const rawAllMessages = useMemo(() => {
    const combined = [...emails, ...smsMessages];
    if (combined.length === 0 && allMessages && allMessages.length > 0) {
      return [...allMessages];
    }
    const map = new Map();
    for (const m of combined) {
      if (!map.has(m.id)) map.set(m.id, m);
    }
    const list = Array.from(map.values());
    const getTs = (m) => {
      let t = Number(m.timestamp);
      if (!t && m.date) {
        const p = new Date(m.date).getTime();
        if (!isNaN(p)) t = p;
      }
      return t || 0;
    };
    list.sort((a, b) => getTs(b) - getTs(a));
    return list;
  }, [emails, smsMessages, allMessages]);

  // Classification Metrics
  const phishingCount = useMemo(() => {
    return rawAllMessages.filter((m) => {
      const cat = (m.category || "").toUpperCase();
      const sc = Number(m.riskScore ?? m.score ?? 0);
      return cat === "PHISHING" || sc >= 70;
    }).length;
  }, [rawAllMessages]);

  const reviewCount = useMemo(() => {
    return rawAllMessages.filter((m) => {
      const cat = (m.category || "").toUpperCase();
      const sc = Number(m.riskScore ?? m.score ?? 0);
      if (cat === "PHISHING" || sc >= 70) return false;
      return cat === "NEEDS REVIEW" || cat === "SUSPICIOUS" || (sc >= 40 && sc < 70);
    }).length;
  }, [rawAllMessages]);

  const legitimateCount = useMemo(() => {
    return rawAllMessages.filter((m) => {
      const cat = (m.category || "").toUpperCase();
      const sc = Number(m.riskScore ?? m.score ?? 0);
      return cat === "LEGITIMATE" && sc < 20;
    }).length;
  }, [rawAllMessages]);

  // Channel Risk Calculations
  const gmailPhishing = useMemo(() => emails.filter((m) => (m.category || "").toUpperCase() === "PHISHING" || Number(m.riskScore ?? 0) >= 70).length, [emails]);
  const gmailReview = useMemo(() => emails.filter((m) => (m.category || "").toUpperCase() === "NEEDS REVIEW" || (Number(m.riskScore ?? 0) >= 40 && Number(m.riskScore ?? 0) < 70)).length, [emails]);
  const gmailSpam = useMemo(() => emails.filter((m) => (m.category || "").toUpperCase() === "SPAM" || (Number(m.riskScore ?? 0) >= 20 && Number(m.riskScore ?? 0) < 40)).length, [emails]);

  const smsPhishing = useMemo(() => smsMessages.filter((m) => (m.category || "").toUpperCase() === "PHISHING" || Number(m.riskScore ?? 0) >= 70).length, [smsMessages]);
  const smsReview = useMemo(() => smsMessages.filter((m) => (m.category || "").toUpperCase() === "NEEDS REVIEW" || (Number(m.riskScore ?? 0) >= 40 && Number(m.riskScore ?? 0) < 70)).length, [smsMessages]);
  const smsSpam = useMemo(() => smsMessages.filter((m) => (m.category || "").toUpperCase() === "SPAM" || (Number(m.riskScore ?? 0) >= 20 && Number(m.riskScore ?? 0) < 40)).length, [smsMessages]);

  const gmailScore = useMemo(() => {
    return calculateChannelScore({
      total: totalEmails,
      phishing: gmailPhishing,
      review: gmailReview,
      spam: gmailSpam,
      isConnected: gmailConnected
    });
  }, [totalEmails, gmailPhishing, gmailReview, gmailSpam, gmailConnected]);

  const smsScore = useMemo(() => {
    return calculateChannelScore({
      total: totalSms,
      phishing: smsPhishing,
      review: smsReview,
      spam: smsSpam,
      isConnected: androidDevices.length > 0
    });
  }, [totalSms, smsPhishing, smsReview, smsSpam, androidDevices.length]);

  const overallScore = useMemo(() => {
    return calculateOverallScore({
      gmailScore,
      smsScore,
      totalEmails,
      totalSms
    });
  }, [gmailScore, smsScore, totalEmails, totalSms]);

  const scoreStatus = useMemo(() => {
    return getScoreStatus({
      score: overallScore,
      phishingCount,
      reviewCount
    });
  }, [overallScore, phishingCount, reviewCount]);

  // Filtered Detections List
  const filteredMessages = useMemo(() => {
    let list = [...rawAllMessages];

    if (sourceFilter === "GMAIL") {
      list = list.filter((m) => m.source !== "SMS");
    } else if (sourceFilter === "SMS") {
      list = list.filter((m) => m.source === "SMS");
    }

    if (categoryFilter !== "ALL") {
      list = list.filter((m) => {
        const cat = (m.category || "").toUpperCase();
        const sc = Number(m.riskScore ?? m.score ?? 0);
        if (categoryFilter === "PHISHING") return cat === "PHISHING" || sc >= 70;
        if (categoryFilter === "REVIEW") return cat === "NEEDS REVIEW" || cat === "SUSPICIOUS" || (sc >= 40 && sc < 70);
        if (categoryFilter === "SPAM") return cat === "SPAM" || (sc >= 20 && sc < 40);
        if (categoryFilter === "SAFE") return cat === "LEGITIMATE" && sc < 20;
        return true;
      });
    }

    return list.slice(0, 10);
  }, [rawAllMessages, sourceFilter, categoryFilter]);

  // SVG Gauge geometry
  const radius = 34;
  const circumference = 2 * Math.PI * radius;
  const gaugePercent = overallScore !== null ? Math.min(100, Math.max(0, overallScore)) : 0;
  const strokeDashoffset = circumference - (gaugePercent / 100) * circumference;

  let gaugeColor = "#10b981";
  if (overallScore >= 70 || phishingCount > 0) gaugeColor = "#ef4444";
  else if (overallScore >= 40 || reviewCount > 0) gaugeColor = "#f59e0b";
  else if (overallScore >= 20) gaugeColor = "#3b82f6";

  const userName = currentUser?.displayName || currentUser?.email?.split("@")[0] || "Sentinel User";

  return (
    <div className="overview-page-wrapper">
      {/* ================================================================= */}
      {/* 1. MINIMAL HEADER                                                 */}
      {/* ================================================================= */}
      <div className="overview-header-panel">
        <div className="overview-header-left">
          <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
            <span className="pulse-dot green" />
            <span style={{ fontSize: "12px", fontWeight: "600", color: "var(--status-success-text, #10b981)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
              Active Threat Protection
            </span>
          </div>
          <h1 className="overview-greeting">
            Welcome back, {userName}
          </h1>
          <p className="overview-header-desc">
            Universal threat defense across your verified communication channels.
          </p>
        </div>

        <div className="overview-header-actions">
          <div className="last-sync-tag">
            <Clock size={13} className="text-muted" />
            <span>Last scan: {formatTimeRelative(lastSuccessfulScanTime)}</span>
          </div>

          <button
            type="button"
            className={`btn btn-secondary btn-sm ${loading ? "is-loading" : ""}`}
            onClick={onRefresh}
            disabled={loading}
          >
            <RefreshCw size={13} className={loading ? "spin" : ""} />
            <span>Scan Now</span>
          </button>
        </div>
      </div>

      {/* ================================================================= */}
      {/* 2. UNIFIED SECURITY POSTURE & CHANNELS ROW                        */}
      {/* ================================================================= */}
      <div className="posture-summary-grid">
        {/* Left: Overall Threat Exposure Card */}
        <div className="card posture-main-card">
          <div className="posture-gauge-block">
            <div className="compact-gauge-wrap">
              <svg width="84" height="84" viewBox="0 0 82 82" className="gauge-svg" aria-hidden="true">
                <circle
                  cx="41"
                  cy="41"
                  r={radius}
                  fill="none"
                  stroke="var(--bg-subtle, #f1f5f9)"
                  strokeWidth="7"
                />
                <circle
                  cx="41"
                  cy="41"
                  r={radius}
                  fill="none"
                  stroke={gaugeColor}
                  strokeWidth="7"
                  strokeDasharray={circumference}
                  strokeDashoffset={overallScore !== null ? strokeDashoffset : circumference}
                  strokeLinecap="round"
                  style={{ transition: "stroke-dashoffset 0.6s ease" }}
                />
              </svg>
              <div className="compact-gauge-center">
                <span className="compact-gauge-number font-mono">
                  {overallScore !== null ? overallScore : "—"}
                </span>
                <span className="compact-gauge-unit">/100</span>
              </div>
            </div>

            <div className="posture-text-block">
              <div className="posture-title-row">
                <span className="card-section-label">Overall Threat Exposure</span>
                <span className={`status-pill-small ${overallScore !== null ? scoreStatus.variant : "status-disconnected"}`}>
                  {overallScore !== null ? scoreStatus.label : "Insufficient Data"}
                </span>
              </div>
              <p className="posture-explanation-text">
                {overallScore !== null
                  ? scoreStatus.explanation
                  : "No verified communication telemetry available yet. Connect a channel to begin scanning."}
              </p>
              <div className="posture-scale-legend">
                <span>Risk Scale: 0 to 100 (Higher is more dangerous).</span>
                <button
                  type="button"
                  className="link-btn-text"
                  onClick={() => setCalcModalOpen(true)}
                >
                  View Methodology
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Right: Channels Grid (Gmail + Android SMS) */}
        <div className="channel-scores-container">
          {/* Gmail Channel Card */}
          <div className="card channel-score-card">
            <div className="channel-card-header">
              <div className="channel-icon-title">
                <Mail size={16} className="text-primary" />
                <span className="channel-name">Google Mail</span>
              </div>
              <span className={`status-pill-small ${gmailConnected ? "status-connected" : "status-disconnected"}`}>
                {gmailConnected ? "Connected" : "Disconnected"}
              </span>
            </div>
            <div className="channel-score-body">
              <div className="channel-score-metric">
                <span className="channel-number">
                  {gmailScore !== null ? gmailScore : "—"}
                </span>
                {gmailScore !== null && <span className="channel-unit">/100 risk</span>}
              </div>
              <p className="channel-subtext">
                {gmailConnected
                  ? `${gmailAccount || "Account connected"} • ${totalEmails} scanned`
                  : "Read-only OAuth integration required."}
              </p>
            </div>
            <div style={{ marginTop: "auto", paddingTop: "8px", borderTop: "1px solid var(--border-subtle, rgba(255,255,255,0.06))", display: "flex", justifyContent: "flex-end" }}>
              {gmailConnected ? (
                <button
                  type="button"
                  className="btn-tiny-action text-danger"
                  onClick={onDisconnectGmail}
                  style={{ fontSize: "12px", background: "none", border: "none", cursor: "pointer", padding: "2px 0" }}
                >
                  Disconnect
                </button>
              ) : (
                <button
                  type="button"
                  className="btn btn-primary btn-sm"
                  onClick={onConnectGmail}
                  style={{ height: "26px", fontSize: "11.5px", padding: "0 10px" }}
                >
                  Connect Gmail
                </button>
              )}
            </div>
          </div>

          {/* Android SMS Channel Card */}
          <div className="card channel-score-card">
            <div className="channel-card-header">
              <div className="channel-icon-title">
                <Smartphone size={16} className="text-primary" />
                <span className="channel-name">Android SMS</span>
              </div>
              <span className={`status-pill-small ${activeDevicesCount > 0 ? "status-connected" : "status-disconnected"}`}>
                {activeDevicesCount > 0 ? "Active" : "Disconnected"}
              </span>
            </div>
            <div className="channel-score-body">
              <div className="channel-score-metric">
                <span className="channel-number">
                  {smsScore !== null ? smsScore : "—"}
                </span>
                {smsScore !== null && <span className="channel-unit">/100 risk</span>}
              </div>
              <p className="channel-subtext">
                {androidDevices.length > 0
                  ? `${androidDevices.length} device${androidDevices.length > 1 ? "s" : ""} paired • ${totalSms} SMS synced`
                  : "Pair phone with 6-digit code to sync SMS."}
              </p>
            </div>
            <div style={{ marginTop: "auto", paddingTop: "8px", borderTop: "1px solid var(--border-subtle, rgba(255,255,255,0.06))", display: "flex", justifyContent: "flex-end" }}>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={onOpenPairModal}
                style={{ height: "26px", fontSize: "11.5px", padding: "0 10px" }}
              >
                Pair Phone
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* ================================================================= */}
      {/* 3. FOUR MINIMAL METRIC CARDS                                      */}
      {/* ================================================================= */}
      <div className="metric-cards-row">
        {/* Metric 1: Total Scanned */}
        <div
          className="card compact-metric-item item-accent-blue"
          onClick={onNavigateToFeed}
          role="button"
          tabIndex={0}
          style={{ cursor: "pointer" }}
          title="Click to view full message telemetry feed"
        >
          <div className="metric-header-mini">
            <span className="metric-label-mini">Total Scanned</span>
            <Layers size={16} className="text-muted" />
          </div>
          <span className="metric-num-mini font-mono">{totalScanned}</span>
          <span className="metric-sub-mini">{totalEmails} emails + {totalSms} SMS</span>
        </div>

        {/* Metric 2: High Risk Threats */}
        <div
          className="card compact-metric-item item-accent-danger"
          onClick={onNavigateToFeed}
          role="button"
          tabIndex={0}
          style={{ cursor: "pointer" }}
          title="Click to inspect high-risk threats"
        >
          <div className="metric-header-mini">
            <span className="metric-label-mini">High Risk Threats</span>
            <AlertCircle size={16} className="text-danger" />
          </div>
          <span className="metric-num-mini font-mono text-danger">{phishingCount}</span>
          <span className="metric-sub-mini">
            {phishingCount > 0 ? `${phishingCount} critical threats detected` : "Zero critical threats"}
          </span>
        </div>

        {/* Metric 3: Needs Review */}
        <div
          className="card compact-metric-item item-accent-amber"
          onClick={onNavigateToFeed}
          role="button"
          tabIndex={0}
          style={{ cursor: "pointer" }}
          title="Click to inspect items needing review"
        >
          <div className="metric-header-mini">
            <span className="metric-label-mini">Needs Review</span>
            <AlertTriangle size={16} className="text-amber" />
          </div>
          <span className="metric-num-mini font-mono text-amber">{reviewCount}</span>
          <span className="metric-sub-mini">
            {reviewCount > 0 ? `${reviewCount} anomalies requiring review` : "Zero anomalies detected"}
          </span>
        </div>

        {/* Metric 4: Verified Safe */}
        <div
          className="card compact-metric-item item-accent-success"
          onClick={onNavigateToFeed}
          role="button"
          tabIndex={0}
          style={{ cursor: "pointer" }}
          title="Click to view legitimate communications"
        >
          <div className="metric-header-mini">
            <span className="metric-label-mini">Verified Safe</span>
            <CheckCircle2 size={16} className="text-success" />
          </div>
          <span className="metric-num-mini font-mono text-success">{legitimateCount}</span>
          <span className="metric-sub-mini">Authentic communications</span>
        </div>
      </div>

      {/* ================================================================= */}
      {/* 4. FULL-WIDTH RECENT SECURITY DETECTIONS                          */}
      {/* ================================================================= */}
      <div className="card" style={{ padding: "20px 24px" }}>
        <div className="panel-header-toolbar" style={{ marginBottom: "16px" }}>
          <div className="toolbar-title-wrap">
            <h3 className="card-section-label" style={{ margin: 0, fontSize: "15px" }}>Recent Security Detections</h3>
            <span style={{ fontSize: "12.5px", color: "var(--text-muted)" }}>
              Real-time threat assessments across email and SMS
            </span>
          </div>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={onNavigateToFeed}
            style={{ fontSize: "12px", gap: "4px" }}
          >
            <span>View Full Feed</span>
            <ChevronRight size={13} />
          </button>
        </div>

        {/* Filter Bar */}
        <div className="table-filter-bar" style={{ marginBottom: "16px" }}>
          <div className="source-filter-group">
            <button
              type="button"
              className={`filter-btn ${sourceFilter === "ALL" ? "filter-active" : ""}`}
              onClick={() => setSourceFilter("ALL")}
            >
              All Sources
            </button>
            <button
              type="button"
              className={`filter-btn ${sourceFilter === "GMAIL" ? "filter-active" : ""}`}
              onClick={() => setSourceFilter("GMAIL")}
            >
              Gmail
            </button>
            <button
              type="button"
              className={`filter-btn ${sourceFilter === "SMS" ? "filter-active" : ""}`}
              onClick={() => setSourceFilter("SMS")}
            >
              Android SMS
            </button>
          </div>

          <select
            className="category-filter-select"
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            aria-label="Filter detections by category"
          >
            <option value="ALL">All Categories</option>
            <option value="PHISHING">High Risk (Phishing)</option>
            <option value="REVIEW">Needs Review</option>
            <option value="SPAM">Commercial Spam</option>
            <option value="SAFE">Likely Safe</option>
          </select>
        </div>

        {/* Table Content or Empty State */}
        {filteredMessages.length === 0 ? (
          <div className="overview-empty-detections">
            <div className="overview-empty-icon">
              <Shield size={24} />
            </div>
            <h4 style={{ fontSize: "14px", fontWeight: 700, margin: 0, color: "var(--text-primary)" }}>
              No Communications Scanned Yet
            </h4>
            <p style={{ fontSize: "12px", color: "var(--text-muted)", maxWidth: "380px", margin: "2px 0 10px" }}>
              Connect your Gmail account or pair an Android companion to begin streaming real-time security telemetry.
            </p>
            {!gmailConnected && (
              <button
                type="button"
                className="btn btn-primary btn-sm"
                onClick={onConnectGmail}
              >
                Connect Gmail
              </button>
            )}
          </div>
        ) : (
          <div className="ref-table-responsive">
            <table className="enterprise-table" aria-label="Recent Detections Table">
              <thead>
                <tr>
                  <th style={{ width: "90px" }}>Source</th>
                  <th>Sender / Message Preview</th>
                  <th style={{ width: "135px" }}>Classification</th>
                  <th style={{ width: "100px" }}>Risk Score</th>
                  <th style={{ width: "120px" }}>Time</th>
                  <th style={{ width: "60px", textAlign: "right" }}></th>
                </tr>
              </thead>
              <tbody>
                {filteredMessages.map((m) => {
                  const isSelected = selectedMessageId === m.id;
                  const sender = m.from || m.sender || "Unknown Sender";
                  const subject = m.subject || m.snippet || m.body || "(No message preview)";
                  const sc = Number(m.riskScore ?? m.score ?? 10);
                  const isSms = m.source === "SMS";

                  return (
                    <tr
                      key={m.id}
                      className={`clickable-row ${isSelected ? "row-selected" : ""}`}
                      onClick={() => onSelectMessage && onSelectMessage(m)}
                      tabIndex={0}
                      role="button"
                      aria-label={`View detection details for ${subject}`}
                    >
                      <td>
                        <span className={`source-tag ${isSms ? "tag-sms" : "tag-gmail"}`}>
                          {isSms ? "SMS" : "Gmail"}
                        </span>
                      </td>
                      <td>
                        <div className="message-cell-content">
                          <span className="message-sender" title={sender}>{sender}</span>
                          <span className="message-preview" title={subject}>{subject}</span>
                        </div>
                      </td>
                      <td>
                        <CategoryBadge category={m.category} />
                      </td>
                      <td>
                        <RiskScoreBadge score={sc} />
                      </td>
                      <td className="timestamp-cell">
                        {formatTimeRelative(m.timestamp)}
                      </td>
                      <td style={{ textAlign: "right" }}>
                        <button
                          type="button"
                          className="btn-details-link"
                          onClick={(e) => {
                            e.stopPropagation();
                            if (onSelectMessage) onSelectMessage(m);
                          }}
                        >
                          View
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Score Methodology Modal */}
      <ScoreCalculationModal
        isOpen={calcModalOpen}
        onClose={() => setCalcModalOpen(false)}
        overallScore={overallScore}
        scoreStatus={scoreStatus}
        gmailScore={gmailScore}
        smsScore={smsScore}
      />
    </div>
  );
}
