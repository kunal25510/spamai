import React from "react";
import { Shield, Smartphone, Mail, AlertCircle, FileSearch } from "lucide-react";

export function EmptyState({ icon: Icon = FileSearch, title, description, actionText, onAction, secondaryText, onSecondary }) {
  return (
    <div className="empty-state-box">
      <div className="empty-icon-wrap">
        <Icon size={32} />
      </div>
      <h3 className="empty-title">{title}</h3>
      <p className="empty-desc">{description}</p>
      {(actionText || secondaryText) && (
        <div className="empty-actions">
          {actionText && (
            <button className="btn btn-primary" onClick={onAction}>
              {actionText}
            </button>
          )}
          {secondaryText && (
            <button className="btn btn-ghost" onClick={onSecondary}>
              {secondaryText}
            </button>
          )}
        </div>
      )}
    </div>
  );
}
