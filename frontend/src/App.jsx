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
  ExternalLink
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

function App() {
  const [active, setActive] = useState("Overview");
  const [connected, setConnected] = useState(false);
  const [account, setAccount] = useState("");
  const [emails, setEmails] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");

  const scanningRef = useRef(false);

  // =================================================
  // INITIAL CHECK + BACKGROUND SCANNING
  // =================================================

  useEffect(() => {
    // First load
    checkAccount();

    // Background scan every 5 seconds
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
  // CHECK GMAIL CONNECTION
  // =================================================

  async function checkAccount(silent = false) {
    try {
      if (!silent) {
        setLoading(true);
        setError("");
      }

      const response = await fetch(
        `${API}/api/account?_t=${Date.now()}`,
        {
          cache: "no-store"
        }
      );

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
      if (!silent) {
        setError("Cannot connect to security backend.");
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

      const response = await fetch(
        `${API}/api/emails?_t=${Date.now()}`,
        {
          method: "GET",
          cache: "no-store",
          headers: {
            "Cache-Control": "no-cache",
            "Pragma": "no-cache"
          }
        }
      );

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

  const highRisk = emails.filter(email => email.risk === "HIGH").length;
  const mediumRisk = emails.filter(email => email.risk === "MEDIUM").length;
  const threats = highRisk + mediumRisk;

  const securityScore = emails.length === 0
    ? 100
    : Math.max(0, 100 - (highRisk * 15) - (mediumRisk * 5));

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
            <span>SYSTEM ACTIVE</span>
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
            <div className="avatar">K</div>
          </div>
        </header>

        {/* LOADING */}
        {loading && (
          <div className="empty-state">
            <div className="empty-icon">
              <RefreshCw size={25} className="spin" />
            </div>
            <p className="section-label">SECURITY NODE</p>
            <h2>Scanning accounts...</h2>
            <p>Connecting to your security services.</p>
          </div>
        )}

        {/* ERROR */}
        {!loading && error && (
          <div className="empty-state">
            <div className="empty-icon">
              <AlertTriangle size={25} />
            </div>
            <p className="section-label">CONNECTION ERROR</p>
            <h2>Security backend unavailable</h2>
            <p>{error}</p>
            <button className="text-button" onClick={() => checkAccount(false)}>
              <RefreshCw size={15} />
              Retry
            </button>
          </div>
        )}

        {/* NOT CONNECTED */}
        {!loading && !error && !connected && (
          <div className="empty-state">
            <div className="empty-icon">
              <Mail size={25} />
            </div>
            <p className="section-label">GMAIL SECURITY</p>
            <h2>Connect your Gmail</h2>
            <p>
              Sentinel needs read-only access to scan your emails for phishing and suspicious activity.
            </p>
            <button className="connect-button" onClick={connectGmail}>
              <Mail size={17} />
              Connect Gmail
              <ExternalLink size={15} />
            </button>
            <small style={{ marginTop: "12px", color: "#555" }}>
              Read-only access · Your password is never shared
            </small>
          </div>
        )}

        {/* CONNECTED DASHBOARD */}
        {!loading && !error && connected && (
          <>
            {active === "Overview" && (
              <>
                {/* HERO */}
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

                {/* METRICS */}
                <section className="metrics">
                  <Metric
                    label="EMAILS SCANNED"
                    value={emails.length}
                    change="Gmail"
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
                    value="ON"
                    change="ML + rules"
                  />
                </section>

                {/* CONTENT GRID */}
                <section className="content-grid">
                  {/* ACTIVITY / THREAT TABLE */}
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
                          No emails found.
                        </div>
                      ) : (
                        filteredEmails.slice(0, 8).map((email) => (
                          <div key={email.id} className="activity-row">
                            <div className={`activity-icon ${email.risk === "HIGH" ? "danger" : "safe"}`}>
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
                            <span className={`risk ${email.risk === "HIGH" ? "high" : "low"}`}>
                              {email.risk}
                            </span>
                          </div>
                        ))
                      )}
                    </div>
                  </div>

                  {/* ACCOUNTS PANEL */}
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
                          <span className="connected">Connected & Protected</span>
                        </div>
                        <ChevronRight size={15} color="#4d575f" />
                      </div>
                    </div>
                  </div>
                </section>
              </>
            )}

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
                      <span className="time">{email.date ? email.date.slice(0, 16) : "Recent"}</span>
                      <span className={`risk ${email.risk === "HIGH" ? "high" : "low"}`}>
                        {email.risk} ({email.finalScore || email.score}%)
                      </span>
                    </div>
                  ))}
                </div>
              </section>
            )}
          </>
        )}
      </main>
    </div>
  );
}

export default App;