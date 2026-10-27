import React, { useEffect, useState } from "react";
import QRCode from "qrcode";
import {
  Smartphone,
  X,
  Copy,
  Check,
  RefreshCw,
  Clock,
  QrCode,
  ShieldCheck,
  AlertCircle
} from "lucide-react";
import { api } from "../api/client";

export function PairDeviceModal({
  isOpen,
  onClose,
  onDevicePaired
}) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [sessionData, setSessionData] = useState(null);
  const [timeLeft, setTimeLeft] = useState(300);
  const [qrUrl, setQrUrl] = useState(null);
  const [copied, setCopied] = useState(false);
  const [copiedServer, setCopiedServer] = useState(false);
  const [copiedUsb, setCopiedUsb] = useState(false);
  const [pairedSuccess, setPairedSuccess] = useState(false);
  const [connectionMode, setConnectionMode] = useState("wifi"); // "wifi" | "usb"

  async function generateQr(targetUrl, code, expiresAt) {
    try {
      const qrPayload = JSON.stringify({
        sentinel_pair: true,
        code,
        server: targetUrl,
        api: targetUrl,
        expiresAt
      });

      const dataUrl = await QRCode.toDataURL(qrPayload, {
        width: 180,
        margin: 1,
        color: {
          dark: "#ffffff",
          light: "#0f172a"
        }
      });
      setQrUrl(dataUrl);
    } catch (e) {
      console.error("[QR Error]", e);
    }
  }

  // Fetch or generate new pairing session from backend
  async function generatePairingSession() {
    setLoading(true);
    setError(null);
    setCopied(false);
    setPairedSuccess(false);

    try {
      const data = await api.createPairingSession();
      setSessionData(data);

      const secondsRemaining = Math.max(
        Math.floor((data.expiresAt - Date.now()) / 1000),
        0
      );
      setTimeLeft(secondsRemaining > 0 ? secondsRemaining : 300);

      const wifiTarget = data.serverUrl || "http://10.139.80.176:5000";
      const usbTarget = data.usbUrl || "http://localhost:5000";
      const activeTarget = connectionMode === "usb" ? usbTarget : wifiTarget;

      await generateQr(activeTarget, data.code, data.expiresAt);
    } catch (err) {
      console.error("[Pairing Error]", err);
      setError(err.message || "Failed to initialize pairing session.");
    } finally {
      setLoading(false);
    }
  }

  function handleSwitchMode(mode) {
    setConnectionMode(mode);
    if (sessionData) {
      const target = mode === "usb"
        ? (sessionData.usbUrl || "http://localhost:5000")
        : (sessionData.serverUrl || "http://10.139.80.176:5000");
      generateQr(target, sessionData.code, sessionData.expiresAt);
    }
  }

  // Load session on open
  useEffect(() => {
    if (isOpen) {
      generatePairingSession();
    } else {
      setSessionData(null);
      setQrUrl(null);
      setPairedSuccess(false);
      setError(null);
    }
  }, [isOpen]);

  // Countdown timer
  useEffect(() => {
    if (!isOpen || !sessionData || timeLeft <= 0 || pairedSuccess) return;

    const timer = setInterval(() => {
      setTimeLeft((prev) => {
        if (prev <= 1) {
          clearInterval(timer);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [isOpen, sessionData, timeLeft, pairedSuccess]);

  // Auto-detect when device consumes code
  useEffect(() => {
    if (!isOpen || !sessionData || timeLeft <= 0 || pairedSuccess) return;

    const poller = setInterval(async () => {
      try {
        const res = await fetch(`http://localhost:5000/api/devices?_t=${Date.now()}`);
        if (res.ok) {
          const data = await res.json();
          // Check if a new active device appeared
          const hasActive = (data.devices || []).some(
            (d) => d.status === "ACTIVE" && new Date(d.created_at).getTime() > sessionData.expiresAt - 300000
          );
          if (hasActive) {
            setPairedSuccess(true);
            if (onDevicePaired) onDevicePaired();
            setTimeout(() => {
              onClose();
            }, 2000);
          }
        }
      } catch (_) {}
    }, 2500);

    return () => clearInterval(poller);
  }, [isOpen, sessionData, timeLeft, pairedSuccess, onClose, onDevicePaired]);

  if (!isOpen) return null;

  const minutes = Math.floor(timeLeft / 60);
  const seconds = timeLeft % 60;
  const isExpired = timeLeft <= 0;

  function copyCode() {
    if (!sessionData?.code) return;
    navigator.clipboard.writeText(sessionData.code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function copyServer() {
    const url = sessionData?.serverUrl || "http://10.139.80.176:5000";
    navigator.clipboard.writeText(url);
    setCopiedServer(true);
    setTimeout(() => setCopiedServer(false), 2000);
  }

  function copyUsb() {
    const url = sessionData?.usbUrl || "http://localhost:5000";
    navigator.clipboard.writeText(url);
    setCopiedUsb(true);
    setTimeout(() => setCopiedUsb(false), 2000);
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        className="modal-card modal-pair"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
      >
        <div className="modal-header">
          <div className="modal-title-wrap">
            <div className="modal-icon info-icon">
              <Smartphone size={20} />
            </div>
            <div>
              <h3>Pair Android Device</h3>
              <p className="modal-subtitle">
                Connect your mobile companion for real-time SMS threat monitoring
              </p>
            </div>
          </div>
          <button className="icon-btn-ghost" onClick={onClose} aria-label="Close">
            <X size={18} />
          </button>
        </div>

        <div className="modal-body">
          {loading && (
            <div className="modal-state-center">
              <RefreshCw className="spin" size={32} />
              <p>Requesting secure pairing code from Sentinel...</p>
            </div>
          )}

          {error && (
            <div className="modal-state-center text-danger">
              <AlertCircle size={32} />
              <p className="error-title">Pairing Session Error</p>
              <p className="error-desc">{error}</p>
              <button className="btn btn-primary mt-3" onClick={generatePairingSession}>
                Try Again
              </button>
            </div>
          )}

          {pairedSuccess && (
            <div className="modal-state-center text-success">
              <ShieldCheck size={48} />
              <h4 className="mt-2">Pairing Successful!</h4>
              <p>Android Companion is now connected and synchronizing security telemetry.</p>
            </div>
          )}

          {!loading && !error && !pairedSuccess && sessionData && (
            <div className="pair-content-grid">
              {/* Left Column: Code & QR */}
              <div className="pair-code-column">
                <div className="code-display-card">
                  <span className="code-label">6-Digit Pairing PIN</span>
                  {isExpired ? (
                    <div className="code-expired-notice">
                      <span>EXPIRED</span>
                    </div>
                  ) : (
                    <div className="code-digits">
                      {sessionData.code.split("").map((digit, i) => (
                        <span key={i} className="digit-box">{digit}</span>
                      ))}
                    </div>
                  )}

                  {!isExpired && (
                    <div className="code-actions">
                      <button className="btn btn-ghost btn-sm" onClick={copyCode}>
                        {copied ? <Check size={14} /> : <Copy size={14} />}
                        <span>{copied ? "Copied" : "Copy Code"}</span>
                      </button>
                      <div className="countdown-pill">
                        <Clock size={13} />
                        <span>{minutes}:{seconds < 10 ? `0${seconds}` : seconds}</span>
                      </div>
                    </div>
                  )}

                  {/* Connection Mode Selector */}
                  {!isExpired && (
                    <div style={{
                      display: "flex",
                      gap: "6px",
                      marginTop: "12px",
                      background: "rgba(15, 23, 42, 0.4)",
                      padding: "3px",
                      borderRadius: "8px",
                      border: "1px solid rgba(255, 255, 255, 0.08)"
                    }}>
                      <button
                        type="button"
                        onClick={() => handleSwitchMode("wifi")}
                        style={{
                          flex: 1,
                          padding: "6px 8px",
                          fontSize: "11px",
                          fontWeight: 600,
                          borderRadius: "6px",
                          border: "none",
                          cursor: "pointer",
                          background: connectionMode === "wifi" ? "#3b82f6" : "transparent",
                          color: connectionMode === "wifi" ? "#ffffff" : "#94a3b8",
                          transition: "all 0.15s ease"
                        }}
                      >
                        📶 Wi-Fi Wireless
                      </button>
                      <button
                        type="button"
                        onClick={() => handleSwitchMode("usb")}
                        style={{
                          flex: 1,
                          padding: "6px 8px",
                          fontSize: "11px",
                          fontWeight: 600,
                          borderRadius: "6px",
                          border: "none",
                          cursor: "pointer",
                          background: connectionMode === "usb" ? "#3b82f6" : "transparent",
                          color: connectionMode === "usb" ? "#ffffff" : "#94a3b8",
                          transition: "all 0.15s ease"
                        }}
                      >
                        🔌 USB Cable (ADB)
                      </button>
                    </div>
                  )}

                  {!isExpired && (
                    <div style={{
                      marginTop: "8px",
                      padding: "8px 10px",
                      background: "rgba(15, 23, 42, 0.6)",
                      border: "1px solid rgba(255, 255, 255, 0.08)",
                      borderRadius: "8px",
                      fontSize: "11px",
                      display: "flex",
                      flexDirection: "column",
                      gap: "4px"
                    }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ color: "#94a3b8" }}>
                          {connectionMode === "usb" ? "USB Target Address:" : "Wi-Fi Server Address:"}
                        </span>
                        <button
                          type="button"
                          onClick={connectionMode === "usb" ? copyUsb : copyServer}
                          style={{
                            background: "transparent",
                            border: "none",
                            color: (connectionMode === "usb" ? copiedUsb : copiedServer) ? "#10b981" : "#818cf8",
                            cursor: "pointer",
                            fontSize: "11px",
                            display: "flex",
                            alignItems: "center",
                            gap: "3px",
                            padding: 0
                          }}
                        >
                          {(connectionMode === "usb" ? copiedUsb : copiedServer) ? <Check size={11} /> : <Copy size={11} />}
                          <span>{(connectionMode === "usb" ? copiedUsb : copiedServer) ? "Copied" : "Copy"}</span>
                        </button>
                      </div>
                      <code style={{
                        fontFamily: "monospace",
                        color: "#38bdf8",
                        background: "rgba(0, 0, 0, 0.2)",
                        padding: "2px 6px",
                        borderRadius: "4px",
                        fontSize: "11px"
                      }}>
                        {connectionMode === "usb"
                          ? (sessionData?.usbUrl || "http://localhost:5000")
                          : (sessionData?.serverUrl || "http://10.139.80.176:5000")}
                      </code>
                      <span style={{ fontSize: "10px", color: "#64748b", marginTop: "2px" }}>
                        {connectionMode === "usb"
                          ? "Run: adb reverse tcp:5000 tcp:5000 to tunnel phone USB to PC"
                          : "Phone and PC must be connected to the same Wi-Fi network"}
                      </span>
                    </div>
                  )}

                  {isExpired && (
                    <button className="btn btn-primary btn-sm mt-2" onClick={generatePairingSession}>
                      <RefreshCw size={14} />
                      <span>Generate New Code</span>
                    </button>
                  )}
                </div>

                {qrUrl && !isExpired && (
                  <div className="qr-card">
                    <img src={qrUrl} alt="Pairing QR Code" className="qr-image" />
                    <span className="qr-caption">Scan with Companion Camera</span>
                  </div>
                )}
              </div>

              {/* Right Column: Instructions */}
              <div className="pair-instructions-column">
                <h4 className="instructions-title">How to Connect</h4>
                <ol className="instructions-list">
                  <li>
                    <span className="step-num">1</span>
                    <div>
                      <strong>Open Sentinel Companion</strong>
                      <p>Launch the Sentinel app installed on your Android device.</p>
                    </div>
                  </li>
                  <li>
                    <span className="step-num">2</span>
                    <div>
                      <strong>Scan QR or Enter PIN</strong>
                      <p>Tap <em>"Scan QR Code to Pair"</em> or enter the 6-digit decimal PIN shown on the left.</p>
                    </div>
                  </li>
                  <li>
                    <span className="step-num">3</span>
                    <div>
                      <strong>Grant SMS Permission</strong>
                      <p>Allow SMS read access so the companion can stream incoming and inbox messages for AI phishing analysis.</p>
                    </div>
                  </li>
                  <li>
                    <span className="step-num">4</span>
                    <div>
                      <strong>Secure Synchronization</strong>
                      <p>Sentinel authenticates your device and securely synchronizes messages. Gmail is NOT required.</p>
                    </div>
                  </li>
                </ol>

                <div className="companion-download-hint">
                  <p>Need the companion app? Download directly:</p>
                  <a
                    href={`${sessionData?.serverUrl || "http://10.139.80.176:5000"}/download/sentinel.apk`}
                    className="btn btn-ghost btn-sm"
                    download="SentinelCompanion.apk"
                  >
                    Download SentinelCompanion.apk
                  </a>
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="modal-footer">
          <button className="btn btn-ghost" onClick={onClose}>
            Close
          </button>
          {!loading && !error && !pairedSuccess && (
            <button className="btn btn-primary" onClick={generatePairingSession}>
              <RefreshCw size={14} />
              <span>Refresh Code</span>
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
