import React, { useState } from "react";
import {
  Smartphone,
  Plus,
  Play,
  Pause,
  Trash2,
  XCircle,
  Radio,
  RefreshCw,
  Clock,
  ShieldCheck,
  AlertTriangle,
  Lock,
  Search,
  MessageSquare,
  ShieldAlert,
  ChevronDown,
  Info
} from "lucide-react";
import { PageHeader } from "../components/PageHeader";
import { DeviceStatusBadge, PermissionBadge } from "../components/StatusBadge";
import { EmptyState } from "../components/EmptyState";
import { LoadingSkeleton } from "../components/LoadingSkeleton";
import { api } from "../api/client";

export function DevicesPage({
  devices = [],
  loading = false,
  onRefresh,
  onOpenPairModal,
  onRevokeDevice,
  onDeleteDeviceSms,
  onDeleteAllSms,
  onToggleSyncPause,
  syncPaused = false,
  totalSms = 0,
  onNavigateOverview
}) {
  const [searchFilter, setSearchFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [expandedDevice, setExpandedDevice] = useState(null);

  // Counts based on dynamic lifecycle states from backend
  const activeCount = devices.filter((d) => d.lifecycle_state === "ACTIVE").length;
  const offlineCount = devices.filter((d) => d.lifecycle_state === "OFFLINE").length;
  const revokedCount = devices.filter((d) => d.lifecycle_state === "REVOKED").length;

  const filteredDevices = devices.filter((d) => {
    if (statusFilter !== "ALL" && d.lifecycle_state !== statusFilter) {
      return false;
    }
    if (searchFilter.trim()) {
      const q = searchFilter.toLowerCase();
      const name = (d.display_name || "").toLowerCase();
      const id = (d.id || "").toLowerCase();
      return name.includes(q) || id.includes(q);
    }
    return true;
  });

  return (
    <div className="page-container devices-page">
      {/* Enterprise Page Header */}
      <PageHeader
        breadcrumbs={["Sentinel AI", "Connected Devices"]}
        onBreadcrumbClick={() => onNavigateOverview && onNavigateOverview()}
        title="Authorized Android Companions"
        description="Hardware endpoints streaming real-time mobile SMS telemetry to Sentinel AI. Online status is verified via authenticated heartbeats."
        onRefresh={onRefresh}
        loading={loading}
        actions={
          <div className="header-actions-group">
            <button
              type="button"
              className="btn btn-primary btn-sm"
              onClick={onOpenPairModal}
            >
              <Plus size={15} />
              <span>Pair Android Device</span>
            </button>
          </div>
        }
      />

      {/* Device Stat Pills & Status Bar */}
      <div className="device-status-summary-bar">
        <div className="status-pills-row">
          <div className="stat-counter-pill">
            <span className="counter-label">Total Paired</span>
            <span className="counter-number">{devices.length}</span>
          </div>
          <div className="stat-counter-pill counter-active">
            <span className="counter-label">Active (Online)</span>
            <span className="counter-number">{activeCount}</span>
          </div>
          <div className="stat-counter-pill counter-offline">
            <span className="counter-label">Temporarily Offline</span>
            <span className="counter-number">{offlineCount}</span>
          </div>
          <div className="stat-counter-pill counter-revoked">
            <span className="counter-label">Revoked</span>
            <span className="counter-number">{revokedCount}</span>
          </div>
          <div className="stat-counter-pill">
            <span className="counter-label">Total SMS Stored</span>
            <span className="counter-number">{totalSms}</span>
          </div>
        </div>

        <div className="device-controls-right">
          <button
            type="button"
            className={`btn btn-sm ${syncPaused ? "btn-primary" : "btn-secondary"}`}
            onClick={onToggleSyncPause}
          >
            {syncPaused ? <Play size={14} /> : <Pause size={14} />}
            <span>{syncPaused ? "Resume Global Sync" : "Pause Global Sync"}</span>
          </button>
          {totalSms > 0 && onDeleteAllSms && (
            <button
              type="button"
              className="btn btn-ghost btn-sm text-danger"
              onClick={onDeleteAllSms}
              title="Purge all synchronized mobile SMS records"
            >
              <Trash2 size={14} />
              <span>Purge All SMS</span>
            </button>
          )}
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="card-panel table-toolbar-panel mb-4">
        <div className="table-toolbar">
          <div className="toolbar-search-box">
            <Search size={15} className="text-muted" />
            <input
              type="text"
              placeholder="Filter by device name or ID..."
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              className="search-input-field"
            />
          </div>

          <div className="select-wrap">
            <select
              className="custom-select"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              aria-label="Filter devices by state"
            >
              <option value="ALL">All Lifecycle States</option>
              <option value="ACTIVE">Active (Online) Only</option>
              <option value="OFFLINE">Temporarily Offline Only</option>
              <option value="PAUSED">Paused Only</option>
              <option value="REVOKED">Revoked Only</option>
            </select>
          </div>
        </div>
      </div>

      {/* Loading Skeletons */}
      {loading && devices.length === 0 ? (
        <div className="devices-grid">
          <LoadingSkeleton type="card" rows={1} />
          <LoadingSkeleton type="card" rows={1} />
        </div>
      ) : filteredDevices.length === 0 ? (
        /* Empty State */
        <div className="card-panel empty-card-panel">
          <EmptyState
            icon={Smartphone}
            title={devices.length === 0 ? "No Android Devices Paired" : "No devices match filter"}
            description={
              devices.length === 0
                ? "Install the Sentinel Companion APK on an Android device and enter a 6-digit PIN or scan the pairing QR code to establish telemetry."
                : "No paired hardware matches the active search query or lifecycle filter."
            }
            actionText={devices.length === 0 ? "Pair Android Device" : "Clear Filters"}
            onAction={devices.length === 0 ? onOpenPairModal : () => { setSearchFilter(""); setStatusFilter("ALL"); }}
          />
        </div>
      ) : (
        /* Devices Grid */
        <div className="devices-grid">
          {filteredDevices.map((device) => {
            const isRevoked = device.lifecycle_state === "REVOKED";
            const isOnline = device.lifecycle_state === "ACTIVE";
            const lastActive = device.last_active_at
              ? new Date(device.last_active_at).toLocaleString()
              : "No heartbeat yet";
            const lastSync = device.last_sync_at
              ? new Date(device.last_sync_at).toLocaleString()
              : "No synchronization yet";
            const isExpanded = expandedDevice === device.id;

            let lifecycleBadgeClass = "badge-muted";
            let lifecycleLabel = device.lifecycle_state || "UNKNOWN";
            if (isOnline) {
              lifecycleBadgeClass = "badge-success";
              lifecycleLabel = "Active (Online)";
            } else if (device.lifecycle_state === "OFFLINE") {
              lifecycleBadgeClass = "badge-muted";
              lifecycleLabel = "Temporarily Offline";
            } else if (device.lifecycle_state === "REVOKED") {
              lifecycleBadgeClass = "badge-danger";
              lifecycleLabel = "Revoked";
            } else if (device.lifecycle_state === "PAUSED") {
              lifecycleBadgeClass = "badge-blue";
              lifecycleLabel = "Paused";
            } else if (device.lifecycle_state === "PERMISSION_UNAVAILABLE") {
              lifecycleBadgeClass = "badge-amber";
              lifecycleLabel = "Permission Required";
            }

            return (
              <div
                key={device.id}
                className={`card-panel device-card-panel ${isRevoked ? "device-card-revoked" : ""} ${isOnline ? "device-card-online" : ""}`}
              >
                {/* Device Card Header */}
                <div className="device-card-header">
                  <div className="device-title-wrap">
                    <div className={`device-icon-box ${isOnline ? "icon-online" : ""}`} aria-hidden="true">
                      <Smartphone size={20} />
                    </div>
                    <div>
                      <h3 className="device-name">{device.display_name}</h3>
                      <span className="device-id font-mono text-xs">{device.id}</span>
                    </div>
                  </div>
                  <span className={`badge-pill ${lifecycleBadgeClass}`}>
                    {lifecycleLabel}
                  </span>
                </div>

                {/* Device Telemetry Metrics */}
                <div className="device-meta-grid">
                  <div className="meta-box">
                    <span className="meta-label">SMS Permission</span>
                    <PermissionBadge state={device.permission_state} />
                  </div>
                  <div className="meta-box">
                    <span className="meta-label">Retained Messages</span>
                    <span className="meta-val font-mono">{device.retained_sms_count ?? 0}</span>
                  </div>
                  <div className="meta-box">
                    <span className="meta-label">Last Active Heartbeat</span>
                    <span className="meta-val">{lastActive}</span>
                  </div>
                  <div className="meta-box">
                    <span className="meta-label">Last Successful Sync</span>
                    <span className="meta-val">{lastSync}</span>
                  </div>
                </div>

                {/* Freshness Subtext */}
                <div className="heartbeat-info-row">
                  <Clock size={12} className="text-muted" />
                  <span className="text-xs text-muted">
                    Heartbeat Freshness Threshold: 5 minutes.
                    {device.seconds_since_heartbeat !== null && (
                      <> Last seen: {Math.round(device.seconds_since_heartbeat / 60)} min ago.</>
                    )}
                  </span>
                </div>

                {/* Device Actions */}
                <div className="device-card-actions">
                  <div className="actions-left">
                    {device.retained_sms_count > 0 && onDeleteDeviceSms && (
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm text-muted hover-danger"
                        onClick={() => onDeleteDeviceSms(device)}
                        title="Delete retained SMS uploaded by this device only"
                      >
                        <Trash2 size={14} />
                        <span>Delete Device SMS</span>
                      </button>
                    )}
                  </div>
                  <div className="actions-right">
                    {!isRevoked ? (
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm text-danger"
                        onClick={() => onRevokeDevice(device)}
                        title="Revoke device authorization immediately"
                      >
                        <XCircle size={14} />
                        <span>Revoke Access</span>
                      </button>
                    ) : (
                      <button
                        type="button"
                        className="btn btn-secondary btn-sm"
                        onClick={onOpenPairModal}
                        title="Generate a new pairing PIN to re-pair this device"
                      >
                        <RefreshCw size={14} />
                        <span>Re-pair Device</span>
                      </button>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
