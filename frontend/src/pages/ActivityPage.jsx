import React, { useState, useEffect } from "react";
import {
  Activity,
  Filter,
  Search,
  RefreshCw,
  Clock,
  Shield,
  Smartphone,
  Mail,
  Lock,
  CheckCircle2,
  AlertTriangle,
  AlertOctagon,
  Info
} from "lucide-react";
import { PageHeader } from "../components/PageHeader";
import { EmptyState } from "../components/EmptyState";
import { LoadingSkeleton } from "../components/LoadingSkeleton";
import { api } from "../api/client";

export function ActivityPage({ onNavigateOverview }) {
  const [activities, setActivities] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [categoryFilter, setCategoryFilter] = useState("ALL");
  const [search, setSearch] = useState("");

  async function fetchActivity() {
    setLoading(true);
    try {
      const data = await api.getActivityLog(100, categoryFilter, search);
      setActivities(data.activities || []);
      setTotal(data.total || 0);
    } catch (e) {
      console.error("Failed to load activity log:", e);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchActivity();
  }, [categoryFilter]);

  function getSeverityBadge(sev) {
    switch (String(sev).toUpperCase()) {
      case "CRITICAL":
        return <span className="badge-pill badge-danger"><AlertOctagon size={12} /><span>Critical</span></span>;
      case "WARNING":
        return <span className="badge-pill badge-amber"><AlertTriangle size={12} /><span>Warning</span></span>;
      case "SUCCESS":
        return <span className="badge-pill badge-success"><CheckCircle2 size={12} /><span>Success</span></span>;
      case "INFO":
      default:
        return <span className="badge-pill badge-indigo"><Info size={12} /><span>Info</span></span>;
    }
  }

  function getCategoryIcon(cat) {
    switch (String(cat).toUpperCase()) {
      case "AUTH":
        return <Lock size={15} className="text-amber" aria-label="Authentication event" />;
      case "DEVICE":
        return <Smartphone size={15} className="text-indigo" aria-label="Device event" />;
      case "SYNC":
        return <Activity size={15} className="text-success" aria-label="Sync event" />;
      case "SECURITY":
      default:
        return <Shield size={15} className="text-muted" aria-label="Security event" />;
    }
  }

  return (
    <div className="page-container activity-page">
      {/* Enterprise Page Header */}
      <PageHeader
        breadcrumbs={["Sentinel AI", "Security Activity"]}
        onBreadcrumbClick={() => onNavigateOverview && onNavigateOverview()}
        title="Security Audit Trail"
        description="Immutable, timestamped audit log of all OAuth sessions, companion pairings, synchronization batches, and security corrections."
        onRefresh={fetchActivity}
        loading={loading}
      />

      {/* Toolbar & Audit Stream */}
      <div className="card-panel">
        <div className="table-toolbar">
          <div className="toolbar-left">
            <div className="select-wrap">
              <select
                className="custom-select"
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                aria-label="Filter events by category"
              >
                <option value="ALL">All Event Categories</option>
                <option value="AUTH">Authentication (OAuth)</option>
                <option value="DEVICE">Device Pairing & State</option>
                <option value="SYNC">SMS Telemetry & Batch Sync</option>
                <option value="SECURITY">Security & User Actions</option>
              </select>
            </div>
          </div>
          <div className="toolbar-right">
            <div className="search-input-wrap">
              <Search size={14} className="search-icon" aria-hidden="true" />
              <input
                type="text"
                placeholder="Search audit descriptions..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && fetchActivity()}
                className="table-search-input"
                aria-label="Search audit trail"
              />
            </div>
          </div>
        </div>

        {/* Activity Stream Table */}
        <div className="table-responsive">
          <table className="dense-table" aria-label="Audit trail table">
            <thead>
              <tr>
                <th scope="col" style={{ width: "40px" }} aria-label="Category icon"></th>
                <th scope="col" style={{ width: "140px" }}>Event Type</th>
                <th scope="col" style={{ width: "100px" }}>Severity</th>
                <th scope="col">Event Description</th>
                <th scope="col" style={{ width: "180px" }}>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {loading && activities.length === 0 ? (
                <LoadingSkeleton type="table-row" rows={6} />
              ) : activities.length === 0 ? (
                <tr>
                  <td colSpan={5} className="table-empty-cell">
                    <EmptyState
                      icon={Activity}
                      title="No Audit Events Recorded"
                      description="Audit events will automatically appear here as you authenticate accounts, pair devices, sync communications, or adjust security policies."
                    />
                  </td>
                </tr>
              ) : (
                activities.map((act) => (
                  <tr key={act.id} className="dense-row">
                    <td>{getCategoryIcon(act.category)}</td>
                    <td className="font-mono text-xs font-semibold">{act.eventType}</td>
                    <td>{getSeverityBadge(act.severity)}</td>
                    <td>
                      <div className="activity-title font-medium">{act.title}</div>
                      <div className="activity-desc text-muted text-sm">{act.description}</div>
                    </td>
                    <td className="font-mono text-xs text-muted">
                      {new Date(act.timestamp).toLocaleString()}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
