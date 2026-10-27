import React from "react";

export function LoadingSkeleton({
  type = "text", // 'text' | 'card' | 'table-row' | 'stat' | 'avatar'
  rows = 1,
  className = "",
  style = {}
}) {
  if (type === "table-row") {
    return (
      <>
        {Array.from({ length: rows }).map((_, idx) => (
          <tr key={idx} className="skeleton-row" aria-hidden="true">
            <td style={{ width: "95px" }}>
              <div className="skeleton-box skeleton-pill" />
            </td>
            <td style={{ width: "160px" }}>
              <div className="skeleton-box skeleton-text" style={{ width: "85%" }} />
            </td>
            <td>
              <div className="skeleton-box skeleton-text" style={{ width: "95%" }} />
              <div className="skeleton-box skeleton-text-sm" style={{ width: "65%", marginTop: "4px" }} />
            </td>
            <td style={{ width: "135px" }}>
              <div className="skeleton-box skeleton-pill" style={{ width: "80px" }} />
            </td>
            <td style={{ width: "90px" }}>
              <div className="skeleton-box skeleton-pill" style={{ width: "50px" }} />
            </td>
            <td style={{ width: "125px" }}>
              <div className="skeleton-box skeleton-text-sm" style={{ width: "70px" }} />
            </td>
            <td style={{ width: "40px" }}>
              <div className="skeleton-box skeleton-circle" style={{ width: "18px", height: "18px" }} />
            </td>
          </tr>
        ))}
      </>
    );
  }

  if (type === "card") {
    return (
      <div className={`skeleton-card-wrap ${className}`} style={style} aria-hidden="true">
        <div className="skeleton-box skeleton-text" style={{ width: "40%", height: "18px", marginBottom: "12px" }} />
        <div className="skeleton-box skeleton-text-sm" style={{ width: "80%", marginBottom: "16px" }} />
        <div className="skeleton-box" style={{ width: "100%", height: "120px", borderRadius: "8px" }} />
      </div>
    );
  }

  if (type === "stat") {
    return (
      <div className={`skeleton-stat-card ${className}`} style={style} aria-hidden="true">
        <div className="skeleton-box skeleton-icon" />
        <div style={{ flex: 1 }}>
          <div className="skeleton-box skeleton-text-sm" style={{ width: "60%", marginBottom: "8px" }} />
          <div className="skeleton-box skeleton-text" style={{ width: "45%", height: "24px" }} />
        </div>
      </div>
    );
  }

  return (
    <div className={`skeleton-container ${className}`} style={style} aria-hidden="true">
      {Array.from({ length: rows }).map((_, idx) => (
        <div
          key={idx}
          className="skeleton-box skeleton-text"
          style={{
            width: idx === rows - 1 && rows > 1 ? "60%" : "100%",
            marginBottom: idx < rows - 1 ? "8px" : "0"
          }}
        />
      ))}
    </div>
  );
}
