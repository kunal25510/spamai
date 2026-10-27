import React from "react";
import {
  ShieldCheck,
  Mail,
  Smartphone,
  Shield,
  ShieldAlert,
  Activity,
  Settings,
  Bell,
  Menu,
  X,
  Activity as PulseIcon
} from "lucide-react";

export function Sidebar({
  activeRoute = "Overview",
  onRouteChange,
  systemHealth = {},
  threatCount = 0,
  deviceCount = 0,
  unreadNotificationsCount = 0,
  collapsed = false,
  onToggleCollapse,
  isMobileOpen = false,
  onCloseMobile
}) {
  const routes = [
    { id: "Overview", label: "Overview", icon: ShieldCheck },
    { id: "Feed", label: "Mail & SMS Feed", icon: Mail, badge: threatCount > 0 ? threatCount : null, badgeVariant: "danger" },
    { id: "Devices", label: "Connected Devices", icon: Smartphone, badge: deviceCount > 0 ? deviceCount : null, badgeVariant: "blue" },
    { id: "ScamChecker", label: "Scam Checker", icon: ShieldAlert },
    { id: "Activity", label: "Activity", icon: Activity },
    { id: "Notifications", label: "Notifications", icon: Bell, badge: unreadNotificationsCount > 0 ? unreadNotificationsCount : null, badgeVariant: "danger" },
    { id: "Settings", label: "Settings", icon: Settings },
  ];


  const aiOnline = systemHealth?.aiEngine?.status === "ok" || systemHealth?.aiEngine?.status === "online";
  const backendOnline = systemHealth?.backend?.status === "online";

  return (
    <>
      {/* Mobile Backdrop */}
      {isMobileOpen && (
        <div
          className="sidebar-mobile-backdrop"
          onClick={onCloseMobile}
          role="presentation"
          aria-hidden="true"
        />
      )}

      <aside
        className={`app-sidebar ${collapsed ? "sidebar-collapsed" : ""} ${isMobileOpen ? "sidebar-mobile-open" : ""}`}
        aria-label="Application Main Navigation"
      >
        {/* Brand Header */}
        <div className="sidebar-brand">
          <div className="brand-logo-wrap" aria-hidden="true">
            <ShieldCheck size={22} className="brand-logo-icon" />
          </div>
          {!collapsed && (
            <div className="brand-text-wrap">
              <span className="brand-name">SENTINEL AI</span>
              <span className="brand-sub">SECURITY AGENT</span>
            </div>
          )}

          {isMobileOpen && (
            <button
              type="button"
              className="sidebar-mobile-close-btn"
              onClick={onCloseMobile}
              aria-label="Close navigation"
            >
              <X size={18} />
            </button>
          )}
        </div>

        {/* Navigation Destinations */}
        <nav className="sidebar-nav" aria-label="Sidebar Sections">
          {routes.map((route) => {
            const Icon = route.icon;
            const isActive = activeRoute === route.id;

            return (
              <button
                key={route.id}
                type="button"
                className={`nav-item ${isActive ? "nav-item-active" : ""}`}
                onClick={() => {
                  onRouteChange(route.id);
                  if (onCloseMobile) onCloseMobile();
                }}
                title={collapsed ? route.label : ""}
                aria-current={isActive ? "page" : undefined}
              >
                <div className="nav-item-content">
                  <Icon size={18} className="nav-item-icon" aria-hidden="true" />
                  {!collapsed && <span className="nav-item-label">{route.label}</span>}
                </div>
                {!collapsed && route.badge && (
                  <span className={`nav-badge nav-badge-${route.badgeVariant || "default"}`}>
                    {route.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        {/* Bottom Health Section & Collapse Toggle */}
        <div className="sidebar-bottom">
          {!collapsed && (
            <div className="system-health-panel" role="status" aria-label="System service health">
              <div className="health-row">
                <span className={`status-indicator ${backendOnline ? "status-online" : "status-offline"}`} aria-hidden="true" />
                <span className="health-label">Backend v2.4.0</span>
                <span className="health-state">{backendOnline ? "Online" : "Offline"}</span>
              </div>
              <div className="health-row">
                <span className={`status-indicator ${aiOnline ? "status-online" : "status-warning"}`} aria-hidden="true" />
                <span className="health-label">AI Engine</span>
                <span className="health-state">{aiOnline ? "Online" : "Offline"}</span>
              </div>
              <div className="health-row health-footer-row">
                <PulseIcon size={13} className="text-muted" aria-hidden="true" />
                <span className="health-healthy-text">
                  {backendOnline && aiOnline ? "All services active" : "Core operational"}
                </span>
              </div>
            </div>
          )}

          <button
            type="button"
            className="collapse-toggle-btn"
            onClick={onToggleCollapse}
            title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            {collapsed ? <Menu size={16} /> : <X size={16} />}
            {!collapsed && <span>Collapse Sidebar</span>}
          </button>
        </div>
      </aside>
    </>
  );
}
