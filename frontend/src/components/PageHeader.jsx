import React from "react";
import { ChevronRight, RefreshCw, Clock } from "lucide-react";

export function PageHeader({
  breadcrumbs = ["Sentinel AI", "Overview"],
  onBreadcrumbClick,
  title,
  description,
  actions,
  lastUpdated,
  onRefresh,
  loading = false,
  badge
}) {
  return (
    <header className="page-header-banner" aria-label="Page Title & Navigation">
      <div className="page-header-content">
        {/* Breadcrumbs */}
        {breadcrumbs && breadcrumbs.length > 0 && (
          <nav className="header-breadcrumbs" aria-label="Breadcrumbs">
            <ol className="breadcrumb-list">
              {breadcrumbs.map((crumb, idx) => {
                const isLast = idx === breadcrumbs.length - 1;
                return (
                  <li key={idx} className="breadcrumb-item">
                    {idx > 0 && <ChevronRight size={12} className="breadcrumb-separator" />}
                    {isLast ? (
                      <span className="breadcrumb-current" aria-current="page">
                        {crumb}
                      </span>
                    ) : (
                      <button
                        type="button"
                        className="breadcrumb-link"
                        onClick={() => onBreadcrumbClick && onBreadcrumbClick(crumb, idx)}
                      >
                        {crumb}
                      </button>
                    )}
                  </li>
                );
              })}
            </ol>
          </nav>
        )}

        {/* Heading & Badge */}
        <div className="page-header-title-row">
          <h1 className="page-header-title">{title}</h1>
          {badge && <div className="page-header-badge">{badge}</div>}
        </div>

        {/* Subtitle / Description */}
        {description && <p className="page-header-desc">{description}</p>}
      </div>

      {/* Actions and Timestamp */}
      <div className="page-header-actions">
        {lastUpdated && (
          <div className="header-last-updated" title="Last successful scan synchronization">
            <Clock size={13} className="text-muted" />
            <span>Last updated {lastUpdated}</span>
          </div>
        )}

        {onRefresh && (
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={onRefresh}
            disabled={loading}
            aria-label="Refresh page telemetry"
          >
            <RefreshCw size={14} className={loading ? "spin" : ""} />
            <span>Refresh</span>
          </button>
        )}

        {actions}
      </div>
    </header>
  );
}
