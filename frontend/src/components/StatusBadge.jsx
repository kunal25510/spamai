import React from "react";
import {
  Mail,
  Smartphone,
  ShieldCheck,
  AlertTriangle,
  AlertOctagon,
  HelpCircle,
  CheckCircle2,
  XCircle,
  Clock,
  Radio
} from "lucide-react";

export function SourceBadge({ source }) {
  const isSms = String(source).toUpperCase() === "SMS";
  return (
    <span className={`badge-pill badge-source ${isSms ? "badge-sms" : "badge-gmail"}`}>
      {isSms ? <Smartphone size={12} /> : <Mail size={12} />}
      <span>{isSms ? "SMS" : "Gmail"}</span>
    </span>
  );
}

export function CategoryBadge({ category }) {
  const cat = String(category || "LEGITIMATE").toUpperCase();

  switch (cat) {
    case "PHISHING":
      return (
        <span className="badge-pill badge-danger">
          <AlertOctagon size={12} />
          <span>Phishing</span>
        </span>
      );
    case "SPAM":
      return (
        <span className="badge-pill badge-warning">
          <AlertTriangle size={12} />
          <span>Spam</span>
        </span>
      );
    case "NEEDS REVIEW":
    case "SUSPICIOUS":
      return (
        <span className="badge-pill badge-amber">
          <HelpCircle size={12} />
          <span>Needs Review</span>
        </span>
      );
    case "LEGITIMATE":
    default:
      return (
        <span className="badge-pill badge-success">
          <ShieldCheck size={12} />
          <span>Legitimate</span>
        </span>
      );
  }
}

export function VerdictBadge({ verdict, score }) {
  const v = String(verdict || "").trim().toLowerCase();
  const num = Number(score ?? 0);

  if (v === "high risk" || (!v && num >= 70)) {
    return (
      <span className="badge-pill badge-danger" title="High risk detected">
        <AlertOctagon size={12} />
        <span>High risk</span>
      </span>
    );
  }
  if (v === "suspicious" || (!v && num >= 40)) {
    return (
      <span className="badge-pill badge-danger" style={{ background: "rgba(239, 68, 68, 0.15)", color: "#f87171" }} title="Suspicious message requiring review">
        <AlertTriangle size={12} />
        <span>Suspicious</span>
      </span>
    );
  }
  if (v === "needs caution" || (!v && num >= 20)) {
    return (
      <span className="badge-pill badge-amber" title="Needs caution">
        <HelpCircle size={12} />
        <span>Needs caution</span>
      </span>
    );
  }
  return (
    <span className="badge-pill badge-success" title="Likely safe">
      <ShieldCheck size={12} />
      <span>Likely safe</span>
    </span>
  );
}

export function RiskScoreBadge({ score }) {
  const val = Number(score ?? 0);
  let variant = "risk-low";
  if (val >= 70) variant = "risk-high";
  else if (val >= 40) variant = "risk-suspicious";
  else if (val >= 20) variant = "risk-med";

  return (
    <div className={`risk-badge ${variant}`} title={`Risk score: ${val}/100`}>
      <span className="risk-num">{val}</span>
      <span className="risk-scale">/100</span>
    </div>
  );
}


export function DeviceStatusBadge({ status }) {
  const st = String(status || "ACTIVE").toUpperCase();

  if (st === "REVOKED") {
    return (
      <span className="badge-pill badge-danger">
        <XCircle size={12} />
        <span>Revoked</span>
      </span>
    );
  }
  if (st === "OFFLINE") {
    return (
      <span className="badge-pill badge-muted">
        <span className="status-dot dot-offline" />
        <span>Offline</span>
      </span>
    );
  }
  if (st === "PAUSED") {
    return (
      <span className="badge-pill badge-amber">
        <Clock size={12} />
        <span>Paused</span>
      </span>
    );
  }
  if (st === "PERMISSION_UNAVAILABLE") {
    return (
      <span className="badge-pill badge-amber">
        <AlertTriangle size={12} />
        <span>No Permission</span>
      </span>
    );
  }

  return (
    <span className="badge-pill badge-success">
      <span className="status-dot dot-online" />
      <span>Active</span>
    </span>
  );
}

export function PermissionBadge({ state }) {
  const s = String(state || "UNKNOWN").toUpperCase();
  if (s === "GRANTED") {
    return (
      <span className="badge-pill badge-success">
        <CheckCircle2 size={12} />
        <span>Granted</span>
      </span>
    );
  }
  if (s === "DENIED") {
    return (
      <span className="badge-pill badge-danger">
        <XCircle size={12} />
        <span>Denied</span>
      </span>
    );
  }
  return (
    <span className="badge-pill badge-muted">
      <HelpCircle size={12} />
      <span>Not Granted</span>
    </span>
  );
}
