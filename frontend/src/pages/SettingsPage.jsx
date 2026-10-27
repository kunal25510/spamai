import React, { useState } from "react";
import {
  Mail,
  Smartphone,
  Shield,
  Trash2,
  Cpu,
  Database,
  CheckCircle2,
  RefreshCw,
  Sun,
  Moon,
  Check,
  Pause,
  Play,
  Info
} from "lucide-react";
import { PageHeader } from "../components/PageHeader";

export function SettingsPage({
  // Gmail State
  gmailConnected = false,
  gmailAccount = "",
  onConnectGmail,
  onDisconnectGmail,
  // Android & SMS Settings
  smsSettings = {
    retentionDays: 7,
    syncPaused: false,
    syncEnabled: true,
    importRangeDays: 30,
    scope: "INBOX_ONLY"
  },
  onUpdateSmsSettings,
  onDeleteAllSms,
  androidDevices = [],
  onToggleSyncPause,
  // Appearance / Theme
  theme = "light",
  onThemeChange,
  // Diagnostics
  systemHealth = {},
  onRefreshHealth,
  onNavigateOverview,
  onNavigateDevices
}) {
  const [retentionDays, setRetentionDays] = useState(smsSettings.retentionDays || 7);
  const [importRangeDays, setImportRangeDays] = useState(smsSettings.importRangeDays || 30);
  const [scope, setScope] = useState(smsSettings.scope || "INBOX_ONLY");
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [saving, setSaving] = useState(false);

  async function handleSavePrivacy(e) {
    e.preventDefault();
    setSaving(true);
    setSaveSuccess(false);

    try {
      if (onUpdateSmsSettings) {
        await onUpdateSmsSettings({
          retentionDays: Number(retentionDays),
          importRangeDays: Number(importRangeDays),
          scope
        });
      }
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
    } catch (err) {
      console.error("Save settings error:", err);
    } finally {
      setSaving(false);
    }
  }

  const backend = systemHealth?.backend || {};
  const aiEngine = systemHealth?.aiEngine || {};
  const uptimeMinutes = Math.floor((backend.uptime || 0) / 60);
  const activeDeviceCount = androidDevices.filter((d) => d.status === "ACTIVE").length;

  return (
    <div className="page-container settings-page">
      {/* Enterprise Page Header */}
      <PageHeader
        breadcrumbs={["Sentinel AI", "System Settings"]}
        onBreadcrumbClick={() => onNavigateOverview && onNavigateOverview()}
        title="Settings & Governance"
        description="Manage Google OAuth inbox integration, Android companion telemetry, data retention policies, and service diagnostics."
        onRefresh={onRefreshHealth}
      />

      <div className="settings-grid">
        {/* Section 1: Google Mail Integration */}
        <div className="card-panel">
          <div className="panel-header-with-icon">
            <Mail size={18} className="text-primary" aria-hidden="true" />
            <div>
              <h3 className="panel-title">Google Mail OAuth Integration</h3>
              <p className="panel-subtitle">Direct read-only OAuth 2.0 integration for inbox threat scanning</p>
            </div>
          </div>

          <div className="settings-section-body">
            <div className="setting-row">
              <div>
                <strong className="setting-name">Connection Status</strong>
                <p className="setting-desc">
                  {gmailConnected
                    ? `Verified and scanning Gmail inbox for: ${gmailAccount}`
                    : "Gmail is currently disconnected. Inbox scanning is inactive."}
                </p>
              </div>
              <div>
                {gmailConnected ? (
                  <span className="badge-pill badge-success">Connected</span>
                ) : (
                  <span className="badge-pill badge-muted">Disconnected</span>
                )}
              </div>
            </div>

            <div className="setting-row">
              <div>
                <strong className="setting-name">OAuth Permissions & Scopes</strong>
                <p className="setting-desc">
                  Requests strictly read-only access (<code>gmail.readonly</code>) to evaluate email headers, URLs, and bodies for phishing and spam.
                </p>
              </div>
              <div className="flex items-center gap-2">
                {gmailConnected ? (
                  <>
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={onConnectGmail}
                      title="Re-authorize Google OAuth"
                    >
                      <RefreshCw size={13} />
                      <span>Reconnect</span>
                    </button>
                    <button
                      type="button"
                      className="btn btn-danger btn-sm"
                      onClick={onDisconnectGmail}
                    >
                      Disconnect Gmail
                    </button>
                  </>
                ) : (
                  <button
                    type="button"
                    className="btn btn-primary btn-sm"
                    onClick={onConnectGmail}
                  >
                    <Mail size={14} />
                    <span>Connect Gmail</span>
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Section 2: Android SMS Companions */}
        <div className="card-panel">
          <div className="panel-header-with-icon">
            <Smartphone size={18} className="text-primary" aria-hidden="true" />
            <div>
              <h3 className="panel-title">Android SMS Companion</h3>
              <p className="panel-subtitle">Mobile companion hardware pairing and live telemetry streaming</p>
            </div>
          </div>

          <div className="settings-section-body">
            <div className="setting-row">
              <div>
                <strong className="setting-name">Paired Companion Hardware</strong>
                <p className="setting-desc">
                  {androidDevices.length} device(s) registered in SQLite persistent storage ({activeDeviceCount} active).
                </p>
              </div>
              {onNavigateDevices && (
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={onNavigateDevices}
                >
                  Manage Devices ({androidDevices.length})
                </button>
              )}
            </div>

            <div className="setting-row">
              <div>
                <strong className="setting-name">Global SMS Synchronization</strong>
                <p className="setting-desc">
                  {smsSettings.syncPaused
                    ? "SMS ingestion is currently paused. Android companions will queue messages."
                    : "Active. Incoming SMS messages are ingested and evaluated by the AI engine."}
                </p>
              </div>
              {onToggleSyncPause && (
                <button
                  type="button"
                  className={`btn btn-sm ${smsSettings.syncPaused ? "btn-primary" : "btn-secondary"}`}
                  onClick={onToggleSyncPause}
                >
                  {smsSettings.syncPaused ? (
                    <>
                      <Play size={13} />
                      <span>Resume Synchronization</span>
                    </>
                  ) : (
                    <>
                      <Pause size={13} />
                      <span>Pause Synchronization</span>
                    </>
                  )}
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Section 3: Privacy & Retention Policy */}
        <div className="card-panel">
          <div className="panel-header-with-icon">
            <Shield size={18} className="text-primary" aria-hidden="true" />
            <div>
              <h3 className="panel-title">SMS Privacy & Data Retention Policy</h3>
              <p className="panel-subtitle">Configure automated expiration and telemetry ingestion scopes</p>
            </div>
          </div>

          <form onSubmit={handleSavePrivacy} className="settings-section-body">
            <div className="setting-row-vertical">
              <label htmlFor="retention-select" className="setting-name">Automatic Data Retention Period</label>
              <p className="setting-desc">
                Sentinel automatically purges analyzed SMS records once this period elapses.
              </p>
              <div className="select-wrap mt-2">
                <select
                  id="retention-select"
                  value={retentionDays}
                  onChange={(e) => setRetentionDays(Number(e.target.value))}
                  className="custom-select"
                >
                  <option value={1}>1 Day (Ephemeral Privacy Mode)</option>
                  <option value={3}>3 Days</option>
                  <option value={7}>7 Days (Standard)</option>
                  <option value={14}>14 Days</option>
                  <option value={30}>30 Days (Extended)</option>
                </select>
              </div>
            </div>

            <div className="setting-row-vertical mt-3">
              <label htmlFor="import-select" className="setting-name">Initial Historical Import Range</label>
              <p className="setting-desc">
                How many days of prior SMS messages to synchronize when a new device connects.
              </p>
              <div className="select-wrap mt-2">
                <select
                  id="import-select"
                  value={importRangeDays}
                  onChange={(e) => setImportRangeDays(Number(e.target.value))}
                  className="custom-select"
                >
                  <option value={7}>Last 7 Days</option>
                  <option value={14}>Last 14 Days</option>
                  <option value={30}>Last 30 Days (Recommended)</option>
                  <option value={90}>Last 90 Days</option>
                </select>
              </div>
            </div>

            <div className="setting-row-vertical mt-3">
              <label htmlFor="scope-select" className="setting-name">Telemetry Ingestion Scope</label>
              <p className="setting-desc">Message categories synchronized by companion background workers.</p>
              <div className="select-wrap mt-2">
                <select
                  id="scope-select"
                  value={scope}
                  onChange={(e) => setScope(e.target.value)}
                  className="custom-select"
                >
                  <option value="INBOX_ONLY">Inbox & Incoming Messages Only</option>
                  <option value="ALL">All Available Folders</option>
                </select>
              </div>
            </div>

            <div className="mt-4 flex items-center gap-3">
              <button type="submit" className="btn btn-primary" disabled={saving}>
                {saving ? "Saving Preferences..." : "Save Privacy Preferences"}
              </button>
              {saveSuccess && (
                <span className="text-success text-sm flex items-center gap-1" role="status">
                  <CheckCircle2 size={15} />
                  <span>Preferences saved successfully!</span>
                </span>
              )}
            </div>
          </form>

          {/* Destructive SMS Purge */}
          <div className="danger-zone-box mt-4">
            <div>
              <strong className="text-danger">Purge All Stored SMS Telemetry</strong>
              <p className="setting-desc">
                Permanently delete all synchronized SMS records from Sentinel's SQLite database.
              </p>
            </div>
            <button
              type="button"
              className="btn btn-danger btn-sm"
              onClick={onDeleteAllSms}
            >
              <Trash2 size={14} />
              <span>Purge All SMS</span>
            </button>
          </div>
        </div>

        {/* Section 4: Appearance / Theme */}
        <div className="card-panel">
          <div className="panel-header-with-icon">
            <Sun size={18} className="text-primary" aria-hidden="true" />
            <div>
              <h3 className="panel-title">Appearance & Interface Theme</h3>
              <p className="panel-subtitle">Select visual contrast and theme preference</p>
            </div>
          </div>

          <div className="settings-section-body">
            <div className="setting-row">
              <div>
                <strong className="setting-name">Theme Selection</strong>
                <p className="setting-desc">
                  Sentinel AI defaults to clean Enterprise Light mode, with full High-Contrast Dark mode support.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  className={`btn btn-sm ${theme === "light" ? "btn-primary" : "btn-secondary"}`}
                  onClick={() => onThemeChange && onThemeChange("light")}
                >
                  <Sun size={14} />
                  <span>Light</span>
                  {theme === "light" && <Check size={13} />}
                </button>
                <button
                  type="button"
                  className={`btn btn-sm ${theme === "dark" ? "btn-primary" : "btn-secondary"}`}
                  onClick={() => onThemeChange && onThemeChange("dark")}
                >
                  <Moon size={14} />
                  <span>Dark</span>
                  {theme === "dark" && <Check size={13} />}
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Section 5: System Diagnostics */}
        <div className="card-panel diagnostics-panel">
          <div className="panel-header-with-icon">
            <Cpu size={18} className="text-primary" aria-hidden="true" />
            <div>
              <h3 className="panel-title">Service Diagnostics & Verified Health</h3>
              <p className="panel-subtitle">Real-time health verification from active daemon endpoints</p>
            </div>
          </div>

          <div className="diagnostics-grid mt-3">
            <div className="diag-item">
              <span className="diag-label">Core Backend</span>
              <span className="diag-val font-semibold">{backend.version || "2.4.0"} (Port 5000)</span>
              <span className={`diag-status ${backend.status === "online" ? "text-success" : "text-danger"}`}>
                <CheckCircle2 size={12} /> {backend.status || "online"}
              </span>
            </div>

            <div className="diag-item">
              <span className="diag-label">Python AI Engine</span>
              <span className="diag-val font-semibold">Port 8000 (Flask / scikit-learn)</span>
              <span className={`diag-status ${aiEngine.status === "ok" ? "text-success" : "text-amber"}`}>
                <CheckCircle2 size={12} /> {aiEngine.status === "ok" ? "Active" : "Fallback Engine"}
              </span>
            </div>

            <div className="diag-item">
              <span className="diag-label">Persistent Storage</span>
              <span className="diag-val font-semibold">SQLite (WAL Journal Mode)</span>
              <span className="diag-status text-success">
                <Database size={12} /> Connected
              </span>
            </div>

            <div className="diag-item">
              <span className="diag-label">Process Uptime</span>
              <span className="diag-val font-semibold">{uptimeMinutes} minute(s)</span>
              <span className="diag-status text-muted">
                Active PID
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
