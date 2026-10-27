import React from "react";

export function MetricCard({
  title,
  label,
  value,
  subtitle,
  subtext = "Last 7 days",
  trend,
  trendVariant = "neutral",
  variant = "default", // 'default' | 'danger' | 'warning' | 'amber' | 'success'
  hasDot = false,
  dotColor,
  icon: Icon,
  iconComponent,
  iconBoxClass,
  onClick
}) {
  const displayTitle = title || label;
  const displaySubtitle = subtitle || subtext;

  // Variant color mapping for icon badge and subtle accent borders
  const variantClass = variant || "default";

  return (
    <div
      className={`metric-card-ref metric-card-${variantClass} ${onClick ? "metric-card-clickable" : ""}`}
      onClick={onClick}
    >
      <div className="metric-header-row">
        <div className={`metric-icon-box metric-icon-${variantClass} ${iconBoxClass || ""}`}>
          {iconComponent ? iconComponent : Icon ? <Icon size={18} /> : null}
        </div>
        <span className="metric-card-label">{displayTitle}</span>
      </div>

      <div className="metric-value-row">
        <span className="metric-bold-value">{value}</span>
      </div>

      <div className="metric-footer-row">
        {hasDot && (
          <span
            className="metric-status-dot"
            style={{ backgroundColor: dotColor || (variantClass === "danger" ? "#ef4444" : "#10b981") }}
          />
        )}
        <span className="metric-period-subtext">{displaySubtitle}</span>
        {trend && (
          <span className={`metric-trend-pill trend-${trendVariant}`}>
            {trend}
          </span>
        )}
      </div>
    </div>
  );
}
