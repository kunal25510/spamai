import React, { useEffect } from "react";
import { AlertTriangle, Info, X } from "lucide-react";

export function ConfirmDialog({
  isOpen,
  title,
  message,
  confirmText = "Confirm",
  confirmVariant = "danger", // 'danger' | 'primary'
  onConfirm,
  onCancel,
  loading = false
}) {
  useEffect(() => {
    function handleKeyDown(e) {
      if (e.key === "Escape" && isOpen && !loading) {
        onCancel();
      }
    }
    if (isOpen) {
      window.addEventListener("keydown", handleKeyDown);
    }
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, loading, onCancel]);

  if (!isOpen) return null;

  return (
    <div className="modal-backdrop" onClick={loading ? undefined : onCancel} role="presentation">
      <div
        className="modal-card modal-confirm"
        onClick={(e) => e.stopPropagation()}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-dialog-title"
        aria-describedby="confirm-dialog-desc"
      >
        <div className="modal-header">
          <div className="modal-title-wrap">
            <div className={`modal-icon ${confirmVariant === "danger" ? "danger-icon" : "info-icon"}`}>
              {confirmVariant === "danger" ? <AlertTriangle size={20} /> : <Info size={20} />}
            </div>
            <h3 id="confirm-dialog-title">{title}</h3>
          </div>
          <button
            type="button"
            className="icon-btn-ghost"
            onClick={onCancel}
            aria-label="Close dialog"
            disabled={loading}
          >
            <X size={18} />
          </button>
        </div>

        <div className="modal-body">
          <p id="confirm-dialog-desc" className="confirm-message">{message}</p>
        </div>

        <div className="modal-footer">
          <button
            type="button"
            className="btn btn-ghost"
            onClick={onCancel}
            disabled={loading}
          >
            Cancel
          </button>
          <button
            type="button"
            className={`btn ${confirmVariant === "danger" ? "btn-danger" : "btn-primary"}`}
            onClick={onConfirm}
            disabled={loading}
          >
            {loading ? "Processing..." : confirmText}
          </button>
        </div>
      </div>
    </div>
  );
}
