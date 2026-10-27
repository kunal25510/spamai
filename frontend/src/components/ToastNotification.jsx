import React from "react";
import { CheckCircle2, AlertTriangle, AlertOctagon, Info, X } from "lucide-react";

export function ToastNotification({
  message,
  type = "info", // 'info' | 'success' | 'warning' | 'error'
  onClose
}) {
  if (!message) return null;

  function renderIcon() {
    switch (type) {
      case "success":
        return <CheckCircle2 size={16} className="toast-icon text-success" />;
      case "error":
        return <AlertOctagon size={16} className="toast-icon text-danger" />;
      case "warning":
        return <AlertTriangle size={16} className="toast-icon text-amber" />;
      case "info":
      default:
        return <Info size={16} className="toast-icon text-blue" />;
    }
  }

  return (
    <div
      className={`toast-alert-box toast-${type}`}
      role="status"
      aria-live="polite"
    >
      <div className="toast-content-wrapper">
        {renderIcon()}
        <span className="toast-text-body">{message}</span>
      </div>
      {onClose && (
        <button
          type="button"
          className="toast-dismiss-btn"
          onClick={onClose}
          aria-label="Dismiss notification"
        >
          <X size={14} />
        </button>
      )}
    </div>
  );
}
