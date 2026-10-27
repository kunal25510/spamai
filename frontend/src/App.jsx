import React, { useState, useEffect, useMemo, useRef } from "react";
import { Sidebar } from "./components/Sidebar";
import { TopBar } from "./components/TopBar";
import { MessageDetailDrawer } from "./components/MessageDetailDrawer";
import { PairDeviceModal } from "./components/PairDeviceModal";
import { ConfirmDialog } from "./components/ConfirmDialog";
import { ToastNotification } from "./components/ToastNotification";
import { AccountModal } from "./components/AccountModal";

// Pages
import { OverviewPage } from "./pages/OverviewPage";
import { FeedPage } from "./pages/FeedPage";
import { DevicesPage } from "./pages/DevicesPage";
import { ScamCheckerPage } from "./pages/ScamCheckerPage";
import { ActivityPage } from "./pages/ActivityPage";
import { NotificationsPage } from "./pages/NotificationsPage";
import { SettingsPage } from "./pages/SettingsPage";

import { api } from "./api/client";
import "./App.css";

export default function App() {
  // Navigation & View State
  const [activeRoute, setActiveRoute] = useState("Overview");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [theme, setTheme] = useState(() => {
    try {
      return localStorage.getItem("sentinel_theme") || "light";
    } catch (e) {
      return "light";
    }
  });

  // Sync theme to root DOM and localStorage
  useEffect(() => {
    try {
      localStorage.setItem("sentinel_theme", theme);
    } catch (e) {}
    document.documentElement.setAttribute("data-theme", theme);
    document.documentElement.className = `theme-${theme}`;
  }, [theme]);

  // Modals, Drawers & Dialogs
  const [selectedMessage, setSelectedMessage] = useState(null);
  const [pairModalOpen, setPairModalOpen] = useState(false);
  const [accountModalOpen, setAccountModalOpen] = useState(false);
  const [confirmDialog, setConfirmDialog] = useState(null);
  const [toastMessage, setToastMessage] = useState(null);

  // Authenticated User Identity
  const [currentUser, setCurrentUser] = useState(null);

  // Toast Notification Helper
  function showToast(msg) {
    setToastMessage(msg);
    setTimeout(() => {
      setToastMessage((prev) => (prev === msg ? null : prev));
    }, 4000);
  }

  // ==================================================
  // INDEPENDENT GMAIL STATE
  // ==================================================
  const [gmailConnected, setGmailConnected] = useState(false);
  const [gmailAccount, setGmailAccount] = useState("");
  const [gmailEmails, setGmailEmails] = useState([]);
  const [gmailLoading, setGmailLoading] = useState(false);

  // ==================================================
  // INDEPENDENT ANDROID SMS STATE
  // ==================================================
  const [androidDevices, setAndroidDevices] = useState([]);
  const [smsMessages, setSmsMessages] = useState([]);
  const [smsLoading, setSmsLoading] = useState(false);
  const [smsSyncStatus, setSmsSyncStatus] = useState({
    activeDevicesCount: 0,
    totalSms: 0,
    devices: [],
    lastSync: null,
    syncPaused: false,
    retentionDays: 7,
    syncEnabled: true,
    importRangeDays: 30,
    scope: "INBOX_ONLY"
  });

  // Notifications State
  const [unreadNotificationsCount, setUnreadNotificationsCount] = useState(0);

  async function checkNotifications() {
    try {
      const data = await api.getUnreadNotificationCount();
      if (typeof data.unreadCount === "number") {
        setUnreadNotificationsCount(data.unreadCount);
      }
    } catch (_) {}
  }

  // System Health & Reputation
  const [systemHealth, setSystemHealth] = useState({
    backend: { status: "online", version: "2.4.0" },
    aiEngine: { status: "ok" }
  });
  const [reputationData, setReputationData] = useState({ domains: {}, user_rules: {} });
  const [lastSuccessfulScanTime, setLastSuccessfulScanTime] = useState(null);

  // Filters & Search
  const [sourceFilter, setSourceFilter] = useState("ALL");
  const [categoryFilter, setCategoryFilter] = useState("ALL");
  const [searchQuery, setSearchQuery] = useState("");

  const scanningRef = useRef(false);

  // ==================================================
  // GMAIL DATA INGESTION
  // ==================================================
  async function checkGmail(silent = false) {
    if (!silent) setGmailLoading(true);

    try {
      const data = await api.getGmailAccount();
      if (data && data.connected) {
        setGmailConnected(true);
        setGmailAccount(data.email || "");
        await loadGmailEmails(silent);
      } else {
        setGmailConnected(false);
        setGmailAccount("");
        setGmailEmails([]);
      }
    } catch (err) {
      setGmailConnected(false);
      setGmailAccount("");
      setGmailEmails([]);
    } finally {
      if (!silent) setGmailLoading(false);
    }
  }

  async function loadGmailEmails(silent = false) {
    if (scanningRef.current) return;
    scanningRef.current = true;

    try {
      const data = await api.getEmails(50);
      const formatted = (data.emails || []).map((e) => {
        let ts = Number(e.timestamp);
        if (!ts && e.date) {
          const parsed = new Date(e.date).getTime();
          if (!isNaN(parsed)) ts = parsed;
        }
        if (!ts && e.scannedAt) {
          const parsed = new Date(e.scannedAt).getTime();
          if (!isNaN(parsed)) ts = parsed;
        }
        return {
          ...e,
          timestamp: ts || Date.now(),
          source: "GMAIL"
        };
      });
      setGmailEmails(formatted);
      setLastSuccessfulScanTime(new Date().toISOString());
    } catch (err) {
      console.warn("[Gmail Load Error]", err.message);
    } finally {
      scanningRef.current = false;
    }
  }

  function handleConnectGmail() {
    window.location.href = api.getGoogleAuthUrl();
  }

  function handleDisconnectGmail() {
    setConfirmDialog({
      title: "Disconnect Google Mail Integration?",
      message: `Are you sure you want to disconnect Gmail (${gmailAccount})? Stored OAuth tokens will be revoked. Android SMS protection and paired devices will NOT be affected.`,
      confirmText: "Disconnect Gmail",
      confirmVariant: "danger",
      onConfirm: async () => {
        setConfirmDialog(null);
        try {
          await api.disconnectGmail();
          setGmailConnected(false);
          setGmailAccount("");
          setGmailEmails([]);
          showToast("Gmail integration disconnected successfully.");
        } catch (e) {
          showToast("Failed to disconnect Gmail: " + e.message);
        }
      }
    });
  }

  // ==================================================
  // ANDROID SMS INGESTION & DEVICE LIFECYCLE
  // ==================================================
  async function loadAndroidState(silent = false) {
    if (!silent) setSmsLoading(true);

    try {
      // 1. Fetch SMS Sync Status & Settings
      const statusData = await api.getSmsSyncStatus().catch(() => null);
      if (statusData) {
        setSmsSyncStatus(statusData);
      }

      // 2. Fetch Devices List
      const devData = await api.getDevices().catch(() => ({ devices: [] }));
      setAndroidDevices(devData.devices || []);

      // 3. Fetch SMS Records (full retained volume)
      const smsData = await api.getSmsRecords(500).catch(() => ({ sms: [] }));
      const formatted = (smsData.sms || []).map((s) => ({
        ...s,
        source: "SMS"
      }));
      setSmsMessages(formatted);
      setLastSuccessfulScanTime(new Date().toISOString());
    } catch (err) {
      console.warn("[Android State Error]", err.message);
    } finally {
      if (!silent) setSmsLoading(false);
    }
  }

  function handleRevokeDevice(device) {
    setConfirmDialog({
      title: `Revoke Device "${device.display_name}"?`,
      message: `This will immediately invalidate the authorization credential for device ${device.id}. The companion will no longer be able to synchronize SMS. Gmail and other devices will NOT be affected.`,
      confirmText: "Revoke Device",
      confirmVariant: "danger",
      onConfirm: async () => {
        setConfirmDialog(null);
        try {
          await api.revokeDevice(device.id);
          await loadAndroidState(true);
          showToast(`Device "${device.display_name}" access revoked.`);
        } catch (e) {
          showToast("Failed to revoke device: " + e.message);
        }
      }
    });
  }

  function handleDeleteAllSms() {
    setConfirmDialog({
      title: "Purge All Synchronized SMS Records?",
      message: "Are you sure you want to permanently delete all synchronized SMS records from local SQLite storage? This action cannot be undone.",
      confirmText: "Purge All SMS",
      confirmVariant: "danger",
      onConfirm: async () => {
        setConfirmDialog(null);
        try {
          await api.deleteAllSms();
          await loadAndroidState(true);
          showToast("All synchronized SMS records purged successfully.");
        } catch (e) {
          showToast("Failed to purge SMS records: " + e.message);
        }
      }
    });
  }

  function handleDeleteDeviceSms(device) {
    setConfirmDialog({
      title: `Delete SMS from "${device.display_name}"?`,
      message: `Permanently delete all SMS records uploaded by device ${device.id}?`,
      confirmText: "Delete Records",
      confirmVariant: "danger",
      onConfirm: async () => {
        setConfirmDialog(null);
        try {
          await api.deleteDeviceSms(device.id);
          await loadAndroidState(true);
          showToast(`SMS records for "${device.display_name}" deleted.`);
        } catch (e) {
          showToast("Failed to delete device SMS records: " + e.message);
        }
      }
    });
  }

  async function handleToggleSyncPause() {
    const isPaused = smsSyncStatus.syncPaused;
    try {
      if (isPaused) {
        await api.resumeSmsSync();
        showToast("SMS synchronization resumed.");
      } else {
        await api.pauseSmsSync();
        showToast("SMS synchronization paused.");
      }
      await loadAndroidState(true);
    } catch (e) {
      showToast("Failed to toggle synchronization state: " + e.message);
    }
  }

  async function handleUpdateSmsSettings(newSettings) {
    await api.updateSmsSettings(newSettings);
    await loadAndroidState(true);
  }

  // ==================================================
  // SYSTEM HEALTH & REPUTATION
  // ==================================================
  async function checkHealth() {
    try {
      const data = await api.getHealthFull();
      setSystemHealth(data);
    } catch (_) {}
  }

  async function fetchReputation() {
    try {
      const data = await api.getReputation();
      setReputationData(data);
    } catch (_) {}
  }

  async function handleAddRule(domain, status, notes) {
    try {
      await api.overrideReputation(domain, status, notes);
      await fetchReputation();
      showToast(`Rule added: ${domain} -> ${status}`);
    } catch (e) {
      showToast("Failed to add domain rule: " + e.message);
    }
  }

  async function handleRemoveRule(domain) {
    try {
      await api.overrideReputation(domain, "NONE");
      await fetchReputation();
      showToast(`Rule removed for ${domain}`);
    } catch (e) {
      showToast("Failed to remove domain rule: " + e.message);
    }
  }

  // Periodic Polling & URL Query Parameter Handling
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("connected") === "gmail") {
      showToast("Google Mail connected successfully!");
      window.history.replaceState({}, document.title, window.location.pathname);
    } else if (params.get("oauth_error")) {
      showToast("Google connection was not completed: " + params.get("oauth_error"));
      window.history.replaceState({}, document.title, window.location.pathname);
    }

    async function init() {
      try {
        const sessionData = await api.initSession();
        if (sessionData && sessionData.user) {
          setCurrentUser(sessionData.user);
        }
      } catch (e) {
        console.warn("[Sentinel] Session init fallback:", e.message);
      }
      checkGmail();
      loadAndroidState();
      checkHealth();
      fetchReputation();
      checkNotifications();
    }

    init();

    const interval = setInterval(() => {
      checkGmail(true);
      loadAndroidState(true);
      checkHealth();
      checkNotifications();
    }, 15000);

    return () => clearInterval(interval);
  }, []);

  // Handle switching or logging out user account
  async function handleSessionChanged(newUser) {
    setCurrentUser(newUser);
    setGmailConnected(false);
    setGmailAccount("");
    setGmailEmails([]);
    setAndroidDevices([]);
    setSmsMessages([]);
    setSmsSyncStatus({
      activeDevicesCount: 0,
      totalSms: 0,
      devices: [],
      lastSync: null,
      syncPaused: false,
      retentionDays: 7,
      syncEnabled: true,
      importRangeDays: 30,
      scope: "INBOX_ONLY"
    });
    setUnreadNotificationsCount(0);
    await Promise.all([
      checkGmail(false),
      loadAndroidState(false),
      checkHealth(),
      fetchReputation(),
      checkNotifications()
    ]);
  }

  // Global Refresh Action
  async function handleGlobalRefresh() {
    await Promise.all([
      checkGmail(false),
      loadAndroidState(false),
      checkHealth(),
      fetchReputation(),
      checkNotifications()
    ]);
    setLastSuccessfulScanTime(new Date().toISOString());
    showToast("Synchronized all telemetry endpoints and channels.");
  }

  // ==================================================
  // UNIFIED MESSAGE STREAM WITH FILTERING
  // ==================================================
  const allMessages = useMemo(() => {
    let list = [];
    if (sourceFilter === "ALL" || sourceFilter === "GMAIL") {
      list.push(...gmailEmails);
    }
    if (sourceFilter === "ALL" || sourceFilter === "SMS") {
      list.push(...smsMessages);
    }

    if (categoryFilter !== "ALL") {
      list = list.filter((m) => {
        const cat = (m.category || "").toUpperCase();
        if (categoryFilter === "NEEDS REVIEW") {
          return cat === "NEEDS REVIEW" || cat === "SUSPICIOUS";
        }
        return cat === categoryFilter;
      });
    }

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter((m) => {
        const from = (m.from || m.sender || "").toLowerCase();
        const subj = (m.subject || "").toLowerCase();
        const snippet = (m.snippet || "").toLowerCase();
        const body = (m.body || m.bodyText || "").toLowerCase();
        return from.includes(q) || subj.includes(q) || snippet.includes(q) || body.includes(q);
      });
    }

    list.sort((a, b) => {
      const tA = a.timestamp || 0;
      const tB = b.timestamp || 0;
      return tB - tA;
    });

    return list;
  }, [gmailEmails, smsMessages, sourceFilter, categoryFilter, searchQuery]);

  const threatCount = allMessages.filter((m) => m.category === "PHISHING").length;
  const activeDevicesCount = androidDevices.filter((d) => d.status === "ACTIVE" && d.lifecycle_state === "ACTIVE").length;

  function handleSelectMessageById(id, type) {
    const found = allMessages.find((m) => m.id === id);
    if (found) {
      setSelectedMessage(found);
    } else {
      setActiveRoute("Feed");
    }
  }

  function handleMessageFeedback(id, type, updatedItem) {
    if (updatedItem) {
      setSelectedMessage((prev) => (prev && prev.id === id ? { ...prev, ...updatedItem } : prev));
      if (updatedItem.source === "GMAIL") {
        setGmailEmails((prev) => prev.map((m) => (m.id === id ? { ...m, ...updatedItem } : m)));
      } else {
        setSmsMessages((prev) => prev.map((m) => (m.id === id ? { ...m, ...updatedItem } : m)));
        api.getSmsSyncStatus().then((st) => st && setSmsSyncStatus(st)).catch(() => {});
      }
      showToast(`Item reclassified as ${updatedItem.category}.`);
    } else {
      showToast(`Feedback recorded for ${id}: ${type}`);
    }
  }

  return (
    <div className={`app-root theme-${theme}`} data-theme={theme}>
      {/* Enterprise Sidebar Navigation */}
      <Sidebar
        activeRoute={activeRoute}
        onRouteChange={(route) => {
          setActiveRoute(route);
          setMobileNavOpen(false);
          window.scrollTo({ top: 0, behavior: "smooth" });
        }}
        systemHealth={systemHealth}
        threatCount={threatCount}
        deviceCount={activeDevicesCount}
        unreadNotificationsCount={unreadNotificationsCount}
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed(!sidebarCollapsed)}
        isMobileOpen={mobileNavOpen}
        onCloseMobile={() => setMobileNavOpen(false)}
      />

      {/* Main Content Area */}
      <div className={`app-main ${sidebarCollapsed ? "main-expanded" : ""}`}>
        {/* Top Header */}
        <TopBar
          title={
            activeRoute === "Overview" ? "Security Overview" :
            activeRoute === "Feed" ? "Mail & SMS Feed" :
            activeRoute === "Devices" ? "Connected Devices" :
            activeRoute === "ScamChecker" ? "Scam Checker" :
            activeRoute === "Activity" ? "Security Activity" :
            activeRoute === "Notifications" ? "Notification Center" :
            "System Settings"
          }
          subtitle={
            activeRoute === "Overview" ? "Universal threat posture and telemetry across email and mobile channels" :
            activeRoute === "Feed" ? "Chronological security classifications from Gmail OAuth and Android companion" :
            activeRoute === "Devices" ? "Authorized companion hardware streaming real-time SMS messages" :
            activeRoute === "ScamChecker" ? "Check suspicious messages and links before you trust them." :
            activeRoute === "Activity" ? "Cryptographic audit trail of OAuth states, pairing, and sync events" :
            activeRoute === "Notifications" ? "Persistent security intelligence alerts, pairing lifecycle notices, and warnings" :
            "Retention policies, ephemeral privacy, and backend service diagnostics"
          }
          showSearch={activeRoute === "Feed"}
          globalSearch={searchQuery}
          onGlobalSearchChange={setSearchQuery}
          onRefresh={handleGlobalRefresh}
          loading={gmailLoading || smsLoading}
          currentUser={currentUser}
          onOpenAccountModal={() => setAccountModalOpen(true)}
          gmailAccount={gmailAccount}
          gmailConnected={gmailConnected}
          activeDevicesCount={activeDevicesCount}
          threatCount={threatCount}
          unreadNotificationsCount={unreadNotificationsCount}
          theme={theme}
          onThemeChange={setTheme}
          onConnectGmail={handleConnectGmail}
          onDisconnectGmail={handleDisconnectGmail}
          onNavigateSettings={() => setActiveRoute("Settings")}
          onNavigateNotifications={() => setActiveRoute("Notifications")}
          onToggleSidebar={() => setMobileNavOpen((prev) => !prev)}
        />

        {/* Dynamic Route View */}
        <main className="app-body">
          {activeRoute === "Overview" && (
            <OverviewPage
              currentUser={currentUser}
              emails={gmailEmails}
              smsMessages={smsMessages}
              allMessages={allMessages}
              loading={gmailLoading || smsLoading}
              onRefresh={handleGlobalRefresh}
              sourceFilter={sourceFilter}
              setSourceFilter={setSourceFilter}
              categoryFilter={categoryFilter}
              setCategoryFilter={setCategoryFilter}
              searchQuery={searchQuery}
              setSearchQuery={setSearchQuery}
              onSelectMessage={setSelectedMessage}
              selectedMessageId={selectedMessage?.id}
              gmailConnected={gmailConnected}
              gmailAccount={gmailAccount}
              onConnectGmail={handleConnectGmail}
              onDisconnectGmail={handleDisconnectGmail}
              androidDevices={androidDevices}
              activeDevicesCount={activeDevicesCount}
              smsSyncStatus={smsSyncStatus}
              onOpenPairModal={() => setPairModalOpen(true)}
              onToggleSyncPause={handleToggleSyncPause}
              onRevokeDevice={handleRevokeDevice}
              onNavigateToDevices={() => setActiveRoute("Devices")}
              onNavigateToFeed={() => setActiveRoute("Feed")}
              onNavigateToScamChecker={() => setActiveRoute("ScamChecker")}
              onNavigateToActivity={() => setActiveRoute("Activity")}
              reputationData={reputationData}
              systemHealth={systemHealth}
              lastSuccessfulScanTime={lastSuccessfulScanTime}
            />
          )}

          {activeRoute === "Feed" && (
            <FeedPage
              allMessages={allMessages}
              loading={gmailLoading || smsLoading}
              onRefresh={handleGlobalRefresh}
              sourceFilter={sourceFilter}
              setSourceFilter={setSourceFilter}
              categoryFilter={categoryFilter}
              setCategoryFilter={setCategoryFilter}
              searchQuery={searchQuery}
              setSearchQuery={setSearchQuery}
              onSelectMessage={setSelectedMessage}
              selectedMessageId={selectedMessage?.id}
              onNavigateOverview={() => setActiveRoute("Overview")}
            />
          )}

          {activeRoute === "Devices" && (
            <DevicesPage
              devices={androidDevices}
              loading={smsLoading}
              onRefresh={() => loadAndroidState(false)}
              onOpenPairModal={() => setPairModalOpen(true)}
              onRevokeDevice={handleRevokeDevice}
              onDeleteDeviceSms={handleDeleteDeviceSms}
              onToggleSyncPause={handleToggleSyncPause}
              syncPaused={smsSyncStatus.syncPaused}
              totalSms={smsSyncStatus.totalSms}
              onNavigateOverview={() => setActiveRoute("Overview")}
            />
          )}

          {activeRoute === "ScamChecker" && (
            <ScamCheckerPage
              onNavigateOverview={() => setActiveRoute("Overview")}
            />
          )}

          {activeRoute === "Activity" && (
            <ActivityPage
              onNavigateOverview={() => setActiveRoute("Overview")}
            />
          )}

          {activeRoute === "Notifications" && (
            <NotificationsPage
              onNavigateOverview={() => setActiveRoute("Overview")}
              onNavigateFeed={() => setActiveRoute("Feed")}
              onNavigateDevices={() => setActiveRoute("Devices")}
              onNavigateSettings={() => setActiveRoute("Settings")}
              onSelectMessageById={handleSelectMessageById}
              onNotificationCountChange={setUnreadNotificationsCount}
            />
          )}

          {activeRoute === "Settings" && (
            <SettingsPage
              gmailConnected={gmailConnected}
              gmailAccount={gmailAccount}
              onConnectGmail={handleConnectGmail}
              onDisconnectGmail={handleDisconnectGmail}
              smsSettings={smsSyncStatus}
              onUpdateSmsSettings={handleUpdateSmsSettings}
              onDeleteAllSms={handleDeleteAllSms}
              androidDevices={androidDevices}
              onToggleSyncPause={handleToggleSyncPause}
              theme={theme}
              onThemeChange={setTheme}
              systemHealth={systemHealth}
              onRefreshHealth={checkHealth}
              onNavigateOverview={() => setActiveRoute("Overview")}
              onNavigateDevices={() => setActiveRoute("Devices")}
            />
          )}
        </main>
      </div>

      {/* Slide-Over Message Detail Drawer */}
      <MessageDetailDrawer
        key={selectedMessage ? `${selectedMessage.source || "MSG"}-${selectedMessage.id}` : "none"}
        item={selectedMessage}
        isOpen={Boolean(selectedMessage)}
        onClose={() => setSelectedMessage(null)}
        onFeedbackSubmitted={handleMessageFeedback}
      />

      {/* Pair Android Companion Modal */}
      <PairDeviceModal
        isOpen={pairModalOpen}
        onClose={() => setPairModalOpen(false)}
        onDevicePaired={() => {
          loadAndroidState(true);
          showToast("Android Companion paired and verified successfully!");
        }}
      />

      {/* Confirmation Dialog */}
      {confirmDialog && (
        <ConfirmDialog
          isOpen={Boolean(confirmDialog)}
          title={confirmDialog.title}
          message={confirmDialog.message}
          confirmText={confirmDialog.confirmText}
          confirmVariant={confirmDialog.confirmVariant}
          onConfirm={confirmDialog.onConfirm}
          onCancel={() => setConfirmDialog(null)}
        />
      )}

      {/* Account & Session Management Modal */}
      <AccountModal
        isOpen={accountModalOpen}
        onClose={() => setAccountModalOpen(false)}
        currentUser={currentUser}
        onSessionChanged={handleSessionChanged}
        showToast={showToast}
      />

      {/* Accessible Toast Notification */}
      {toastMessage && (
        <ToastNotification
          message={toastMessage}
          onClose={() => setToastMessage(null)}
        />
      )}
    </div>
  );
}