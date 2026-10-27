import React, { useRef, useEffect } from "react";
import {
  Search,
  Bell,
  Sun,
  Moon,
  Mail,
  Menu,
  RefreshCw,
  Settings,
  ShieldCheck,
  User
} from "lucide-react";

export function TopBar({
  title = "Overview",
  subtitle = "",
  showSearch = false,
  globalSearch = "",
  onGlobalSearchChange,
  onRefresh,
  loading = false,
  currentUser = null,
  onOpenAccountModal,
  gmailAccount = "",
  gmailConnected = false,
  activeDevicesCount = 0,
  unreadNotificationsCount = 0,
  theme = "light",
  onThemeChange,
  onConnectGmail,
  onDisconnectGmail,
  onNavigateSettings,
  onNavigateNotifications,
  onToggleSidebar
}) {
  const searchInputRef = useRef(null);

  // Global Ctrl+K shortcut listener
  useEffect(() => {
    if (!showSearch) return;
    function handleKeyDown(e) {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        if (searchInputRef.current) {
          searchInputRef.current.focus();
          searchInputRef.current.select();
        }
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [showSearch]);

  return (
    <header className="app-topbar" role="banner">
      {/* Left: Mobile Nav Toggle & Page Title */}
      <div className="topbar-left-section">
        {onToggleSidebar && (
          <button
            type="button"
            className="mobile-nav-toggle-btn"
            onClick={onToggleSidebar}
            aria-label="Toggle navigation menu"
          >
            <Menu size={20} />
          </button>
        )}
        <div className="topbar-page-titles">
          <h1 className="topbar-page-title">{title}</h1>
          {subtitle && <p className="topbar-page-subtitle">{subtitle}</p>}
        </div>
      </div>

      {/* Middle: Minimal Clean Search Bar */}
      {showSearch && (
        <div className="topbar-search-container">
          <Search size={15} className="topbar-search-icon" aria-hidden="true" />
          <input
            ref={searchInputRef}
            type="text"
            placeholder="Search sender, subject, domain, keywords..."
            value={globalSearch}
            onChange={(e) => onGlobalSearchChange && onGlobalSearchChange(e.target.value)}
            className="topbar-search-field"
            aria-label="Search security telemetry"
          />
          <span className="search-shortcut-badge" title="Press Ctrl+K to search">⌘K</span>
        </div>
      )}

      {/* Right: Essential Quick Controls */}
      <div className="topbar-controls-right">
        {/* Global Scan/Refresh */}
        {onRefresh && (
          <button
            type="button"
            className={`btn-icon-round ${loading ? "is-loading" : ""}`}
            onClick={onRefresh}
            disabled={loading}
            title="Scan & refresh all security telemetry"
            aria-label="Refresh telemetry"
          >
            <RefreshCw size={15} className={loading ? "animate-spin" : ""} />
          </button>
        )}

        {/* Theme Switcher */}
        <button
          type="button"
          className="btn-icon-round"
          onClick={() => onThemeChange && onThemeChange(theme === "light" ? "dark" : "light")}
          title={`Switch to ${theme === "light" ? "Dark" : "Light"} mode`}
          aria-label="Toggle theme"
        >
          {theme === "light" ? <Moon size={15} /> : <Sun size={15} />}
        </button>

        {/* Notifications Icon with Badge */}
        <div className="notification-bell-wrap">
          <button
            type="button"
            className="btn-icon-round"
            onClick={onNavigateNotifications}
            title={unreadNotificationsCount > 0 ? `${unreadNotificationsCount} unread alerts` : "Notification Center"}
            aria-label="Notifications"
          >
            <Bell size={15} />
          </button>
          {unreadNotificationsCount > 0 && (
            <span className="bell-badge-count">
              {unreadNotificationsCount > 9 ? "9+" : unreadNotificationsCount}
            </span>
          )}
        </div>

        {/* User Session Pill */}
        {onOpenAccountModal && (
          <button
            type="button"
            className="topbar-user-pill"
            onClick={onOpenAccountModal}
            title={currentUser ? `Session: ${currentUser.email}` : "Manage Session"}
          >
            <div className="user-avatar-circle">
              <User size={13} />
            </div>
            <span className="user-pill-name">
              {currentUser?.email ? (currentUser.email.startsWith("guest_") ? "Guest User" : currentUser.email.split("@")[0]) : "User"}
            </span>
          </button>
        )}
      </div>
    </header>
  );
}
