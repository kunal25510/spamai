import React, { useState, useEffect } from "react";
import {
  Bell,
  CheckCircle2,
  AlertTriangle,
  AlertOctagon,
  Info,
  Search,
  Filter,
  CheckCheck,
  Trash2,
  ExternalLink,
  Smartphone,
  Mail,
  Shield,
  Clock
} from "lucide-react";
import { PageHeader } from "../components/PageHeader";
import { EmptyState } from "../components/EmptyState";
import { LoadingSkeleton } from "../components/LoadingSkeleton";
import { api } from "../api/client";

export function NotificationsPage({
  onNavigateOverview,
  onNavigateFeed,
  onNavigateDevices,
  onNavigateSettings,
  onSelectMessageById,
  onNotificationCountChange
}) {
  const [notifications, setNotifications] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);

  // Filters
  const [tabFilter, setTabFilter] = useState("ALL"); // ALL, UNREAD, THREATS, SYSTEM
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [searchQuery, setSearchQuery] = useState("");

  async function fetchNotifications() {
    setLoading(true);
    try {
      const unreadOnly = tabFilter === "UNREAD";
      let type = null;
      if (tabFilter === "THREATS") type = "THREAT_DETECTED";

      const data = await api.getNotifications({
        unreadOnly,
        severity: severityFilter,
        type,
        limit: 100
      });

      setNotifications(data.notifications || []);
      setUnreadCount(data.unreadCount || 0);
      setTotal(data.total || 0);

      if (onNotificationCountChange) {
        onNotificationCountChange(data.unreadCount || 0);
      }
    } catch (err) {
      console.error("Failed to fetch notifications:", err);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchNotifications();
  }, [tabFilter, severityFilter]);

  async function handleMarkRead(id, e) {
    if (e) e.stopPropagation();
    try {
      await api.markNotificationRead(id);
      setNotifications((prev) =>
        prev.map((n) => (n.id === id ? { ...n, isRead: 1 } : n))
      );
      setUnreadCount((prev) => Math.max(0, prev - 1));
      if (onNotificationCountChange) {
        onNotificationCountChange(Math.max(0, unreadCount - 1));
      }
    } catch (err) {
      console.error("Failed to mark notification read:", err);
    }
  }

  async function handleMarkAllRead() {
    try {
      await api.markAllNotificationsRead();
      setNotifications((prev) => prev.map((n) => ({ ...n, isRead: 1 })));
      setUnreadCount(0);
      if (onNotificationCountChange) {
        onNotificationCountChange(0);
      }
    } catch (err) {
      console.error("Failed to mark all read:", err);
    }
  }

  async function handleDelete(id, e) {
    if (e) e.stopPropagation();
    try {
      await api.deleteNotification(id);
      const target = notifications.find((n) => n.id === id);
      setNotifications((prev) => prev.filter((n) => n.id !== id));
      if (target && !target.isRead) {
        setUnreadCount((prev) => Math.max(0, prev - 1));
        if (onNotificationCountChange) {
          onNotificationCountChange(Math.max(0, unreadCount - 1));
        }
      }
    } catch (err) {
      console.error("Failed to delete notification:", err);
    }
  }

  function handleActionClick(item) {
    if (!item.isRead) {
      handleMarkRead(item.id);
    }

    if (item.resourceType === "SMS" || item.resourceType === "EMAIL") {
      if (onSelectMessageById && item.resourceId) {
        onSelectMessageById(item.resourceId, item.resourceType);
      } else if (onNavigateFeed) {
        onNavigateFeed();
      }
    } else if (item.resourceType === "DEVICE") {
      if (onNavigateDevices) onNavigateDevices();
    } else if (item.resourceType === "GMAIL") {
      if (onNavigateSettings) onNavigateSettings();
    }
  }

  function getSeverityBadge(sev) {
    switch (String(sev).toUpperCase()) {
      case "CRITICAL":
        return (
          <span className="badge-pill badge-danger">
            <AlertOctagon size={12} />
            <span>Critical</span>
          </span>
        );
      case "WARNING":
        return (
          <span className="badge-pill badge-amber">
            <AlertTriangle size={12} />
            <span>Warning</span>
          </span>
        );
      case "SUCCESS":
        return (
          <span className="badge-pill badge-success">
            <CheckCircle2 size={12} />
            <span>Success</span>
          </span>
        );
      case "INFO":
      default:
        return (
          <span className="badge-pill badge-indigo">
            <Info size={12} />
            <span>Info</span>
          </span>
        );
    }
  }

  function getResourceIcon(type) {
    switch (String(type).toUpperCase()) {
      case "SMS":
      case "DEVICE":
        return <Smartphone size={14} className="text-indigo" />;
      case "EMAIL":
      case "GMAIL":
        return <Mail size={14} className="text-amber" />;
      default:
        return <Shield size={14} className="text-muted" />;
    }
  }

  // Client-side text filter on the retrieved items
  const filteredNotifications = notifications.filter((n) => {
    if (tabFilter === "SYSTEM") {
      if (n.type === "THREAT_DETECTED") return false;
    }
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    const title = (n.title || "").toLowerCase();
    const message = (n.message || "").toLowerCase();
    return title.includes(q) || message.includes(q);
  });

  return (
    <div className="page-container notifications-page">
      <PageHeader
        breadcrumbs={["Sentinel AI", "Notification Center"]}
        onBreadcrumbClick={() => onNavigateOverview && onNavigateOverview()}
        title="Notification Center"
        description="Persistent security intelligence alerts, pairing lifecycle notices, threat warnings, and synchronization telemetry."
        onRefresh={fetchNotifications}
        loading={loading}
      />

      <div className="card-panel">
        {/* Navigation Tabs and Quick Actions */}
        <div className="notifications-header-bar">
          <div className="filter-tabs" role="tablist">
            <button
              type="button"
              role="tab"
              aria-selected={tabFilter === "ALL"}
              className={`filter-tab ${tabFilter === "ALL" ? "filter-tab-active" : ""}`}
              onClick={() => setTabFilter("ALL")}
            >
              All Alerts
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={tabFilter === "UNREAD"}
              className={`filter-tab ${tabFilter === "UNREAD" ? "filter-tab-active" : ""}`}
              onClick={() => setTabFilter("UNREAD")}
            >
              Unread {unreadCount > 0 && <span className="tab-counter-badge">{unreadCount}</span>}
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={tabFilter === "THREATS"}
              className={`filter-tab ${tabFilter === "THREATS" ? "filter-tab-active" : ""}`}
              onClick={() => setTabFilter("THREATS")}
            >
              Security Threats
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={tabFilter === "SYSTEM"}
              className={`filter-tab ${tabFilter === "SYSTEM" ? "filter-tab-active" : ""}`}
              onClick={() => setTabFilter("SYSTEM")}
            >
              System & Devices
            </button>
          </div>

          <div className="notifications-actions-bar">
            {unreadCount > 0 && (
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={handleMarkAllRead}
                title="Mark all notifications as read"
              >
                <CheckCheck size={14} />
                <span>Mark All Read</span>
              </button>
            )}
          </div>
        </div>

        {/* Toolbar: Severity Filter & Search */}
        <div className="table-toolbar" style={{ borderTop: "1px solid var(--border-subtle)" }}>
          <div className="toolbar-left">
            <div className="select-wrap">
              <select
                className="custom-select"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                aria-label="Filter by severity"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical Alerts</option>
                <option value="WARNING">Warnings</option>
                <option value="INFO">Informational</option>
              </select>
            </div>
          </div>

          <div className="toolbar-right">
            <div className="search-input-wrap">
              <Search size={14} className="search-icon" aria-hidden="true" />
              <input
                type="text"
                placeholder="Search alerts by title or description..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="search-input"
                aria-label="Search notifications"
              />
            </div>
          </div>
        </div>

        {/* List Content */}
        {loading ? (
          <LoadingSkeleton rows={5} />
        ) : filteredNotifications.length === 0 ? (
          <EmptyState
            icon={Bell}
            title={
              tabFilter === "UNREAD"
                ? "No unread notifications"
                : searchQuery
                ? "No notifications matching search"
                : "No notifications"
            }
            description={
              tabFilter === "UNREAD"
                ? "You have acknowledged all system and threat notifications."
                : "Real-time security alerts and integration lifecycle events will appear here as they occur."
            }
          />
        ) : (
          <div className="notifications-list" role="list">
            {filteredNotifications.map((notif) => {
              const isUnread = !notif.isRead;
              return (
                <div
                  key={notif.id}
                  className={`notification-item ${isUnread ? "notification-unread" : ""}`}
                  onClick={() => handleActionClick(notif)}
                  role="listitem"
                  tabIndex={0}
                >
                  <div className="notification-status-col">
                    <span
                      className={`notif-unread-dot ${isUnread ? "is-active" : ""}`}
                      title={isUnread ? "Unread alert" : "Read alert"}
                    />
                  </div>

                  <div className="notification-icon-col">
                    {getResourceIcon(notif.resourceType || notif.type)}
                  </div>

                  <div className="notification-content-col">
                    <div className="notification-title-row">
                      <span className="notification-title">{notif.title}</span>
                      {getSeverityBadge(notif.severity)}
                      {notif.resourceType && (
                        <span className="notif-resource-tag">
                          {notif.resourceType}
                        </span>
                      )}
                    </div>
                    <p className="notification-message">{notif.message}</p>
                    <div className="notification-meta-row">
                      <Clock size={12} className="text-muted" />
                      <span className="notification-time">
                        {notif.createdAt
                          ? new Date(notif.createdAt).toLocaleString(undefined, {
                              month: "short",
                              day: "numeric",
                              hour: "2-digit",
                              minute: "2-digit"
                            })
                          : "Recently"}
                      </span>
                    </div>
                  </div>

                  <div className="notification-actions-col">
                    {notif.resourceType && (
                      <button
                        type="button"
                        className="btn-icon-subtle"
                        title={`View ${notif.resourceType}`}
                        onClick={(e) => {
                          e.stopPropagation();
                          handleActionClick(notif);
                        }}
                        aria-label={`View ${notif.resourceType}`}
                      >
                        <ExternalLink size={15} />
                      </button>
                    )}

                    {isUnread && (
                      <button
                        type="button"
                        className="btn-icon-subtle"
                        title="Mark as read"
                        onClick={(e) => handleMarkRead(notif.id, e)}
                        aria-label="Mark as read"
                      >
                        <CheckCircle2 size={15} />
                      </button>
                    )}

                    <button
                      type="button"
                      className="btn-icon-subtle text-danger-hover"
                      title="Dismiss alert"
                      onClick={(e) => handleDelete(notif.id, e)}
                      aria-label="Dismiss alert"
                    >
                      <Trash2 size={15} />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
