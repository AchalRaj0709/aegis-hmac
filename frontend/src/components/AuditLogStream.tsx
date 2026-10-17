import React, { useState, useEffect } from "react";
import { Activity, RefreshCw, ShieldCheck, ShieldAlert, Zap } from "lucide-react";
import { AuditLog } from "../types";
import { fetchAuditLogs } from "../services/api";

export const AuditLogStream: React.FC = () => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  const loadLogs = async () => {
    try {
      setLoading(true);
      const data = await fetchAuditLogs(50);
      setLogs(data);
    } catch (err) {
      console.error("Failed to load audit logs:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadLogs();
    const interval = setInterval(loadLogs, 8000); // Polling every 8 seconds
    return () => clearInterval(interval);
  }, []);

  // Compute telemetry metrics
  const total = logs.length;
  const successes = logs.filter((l) => l.verdict === "SUCCESS").length;
  const failures = logs.filter((l) => l.verdict === "FAILED").length;
  const successRate = total > 0 ? Math.round((successes / total) * 100) : 100;
  const avgLatency =
    total > 0
      ? (logs.reduce((acc, curr) => acc + (curr.latency_ms || 0), 0) / total).toFixed(2)
      : "0.00";

  return (
    <div style={{ maxWidth: "1280px", margin: "0 auto", padding: "0 24px 40px" }}>
      {/* Header bar */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "24px" }}>
        <div>
          <h1 style={{ fontSize: "1.5rem", fontWeight: 700 }}>Security Telemetry & Audit Stream</h1>
          <p style={{ color: "var(--text-secondary)", fontSize: "0.875rem", marginTop: "4px" }}>
            Real-time forensic logs for all authentication attempts. In compliance with FR8, zero keys or signatures are logged.
          </p>
        </div>
        <button className="btn btn-secondary" onClick={loadLogs}>
          <RefreshCw size={14} />
          <span>Refresh Logs</span>
        </button>
      </div>

      {/* Metrics Bar */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "16px", marginBottom: "24px" }}>
        <div className="glass-panel" style={{ padding: "16px 20px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: "0.75rem", fontWeight: 600, color: "var(--text-secondary)", textTransform: "uppercase" }}>
              Total Verified Calls
            </span>
            <Activity size={18} color="var(--accent-primary)" />
          </div>
          <div style={{ fontSize: "1.75rem", fontWeight: 700, marginTop: "8px" }}>{total}</div>
        </div>

        <div className="glass-panel" style={{ padding: "16px 20px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: "0.75rem", fontWeight: 600, color: "var(--text-secondary)", textTransform: "uppercase" }}>
              Auth Success Rate
            </span>
            <ShieldCheck size={18} color="var(--accent-green)" />
          </div>
          <div style={{ fontSize: "1.75rem", fontWeight: 700, marginTop: "8px", color: successRate >= 90 ? "#34d399" : "#fbbf24" }}>
            {successRate}%
          </div>
        </div>

        <div className="glass-panel" style={{ padding: "16px 20px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: "0.75rem", fontWeight: 600, color: "var(--text-secondary)", textTransform: "uppercase" }}>
              Blocked Attempts
            </span>
            <ShieldAlert size={18} color="var(--accent-red)" />
          </div>
          <div style={{ fontSize: "1.75rem", fontWeight: 700, marginTop: "8px", color: "#f87171" }}>
            {failures}
          </div>
        </div>

        <div className="glass-panel" style={{ padding: "16px 20px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: "0.75rem", fontWeight: 600, color: "var(--text-secondary)", textTransform: "uppercase" }}>
              Average Verification Latency
            </span>
            <Zap size={18} color="var(--accent-cyan)" />
          </div>
          <div style={{ fontSize: "1.75rem", fontWeight: 700, marginTop: "8px" }}>
            {avgLatency} <span style={{ fontSize: "1rem", color: "var(--text-muted)" }}>ms</span>
          </div>
        </div>
      </div>

      {/* Logs Table */}
      <div className="glass-panel" style={{ overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left", fontSize: "0.8125rem" }}>
          <thead>
            <tr style={{ background: "rgba(255, 255, 255, 0.03)", borderBottom: "1px solid var(--border-color)", color: "var(--text-secondary)" }}>
              <th style={{ padding: "14px 18px", fontWeight: 600 }}>Verdict</th>
              <th style={{ padding: "14px 18px", fontWeight: 600 }}>Endpoint</th>
              <th style={{ padding: "14px 18px", fontWeight: 600 }}>Client ID</th>
              <th style={{ padding: "14px 18px", fontWeight: 600 }}>Failure Reason / Details</th>
              <th style={{ padding: "14px 18px", fontWeight: 600 }}>Latency</th>
              <th style={{ padding: "14px 18px", fontWeight: 600, textAlign: "right" }}>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {loading && logs.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ padding: "32px", textAlign: "center", color: "var(--text-muted)" }}>
                  Connecting to live audit log stream...
                </td>
              </tr>
            ) : logs.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ padding: "40px", textAlign: "center", color: "var(--text-muted)" }}>
                  No authentication logs recorded yet. Send requests from the HMAC Sandbox to observe live telemetry.
                </td>
              </tr>
            ) : (
              logs.map((log, idx) => (
                <tr
                  key={`${log.request_id}-${idx}`}
                  style={{ borderBottom: "1px solid var(--border-color)", transition: "background 0.15s ease" }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(255, 255, 255, 0.02)")}
                  onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                >
                  <td style={{ padding: "12px 18px" }}>
                    {log.verdict === "SUCCESS" ? (
                      <span className="badge badge-green">200 OK</span>
                    ) : log.status_code === 408 ? (
                      <span className="badge badge-amber">408 Stale</span>
                    ) : (
                      <span className="badge badge-red">{log.status_code} Blocked</span>
                    )}
                  </td>
                  <td style={{ padding: "12px 18px" }}>
                    <span className="mono" style={{ fontWeight: 600, color: log.method === "POST" ? "#818cf8" : "#34d399" }}>
                      {log.method}
                    </span>{" "}
                    <span className="mono" style={{ color: "var(--text-primary)" }}>
                      {log.path}
                    </span>
                  </td>
                  <td style={{ padding: "12px 18px" }}>
                    <span className="mono" style={{ color: "var(--accent-cyan)" }}>
                      {log.client_id || "anonymous"}
                    </span>
                  </td>
                  <td style={{ padding: "12px 18px" }}>
                    {log.failure_reason ? (
                      <span style={{ color: "#f87171" }}>{log.failure_reason}</span>
                    ) : (
                      <span style={{ color: "var(--text-muted)" }}>Constant-time signature verified</span>
                    )}
                  </td>
                  <td style={{ padding: "12px 18px" }}>
                    <span className="mono" style={{ color: "var(--accent-cyan)" }}>
                      {log.latency_ms}ms
                    </span>
                  </td>
                  <td style={{ padding: "12px 18px", textAlign: "right", color: "var(--text-muted)" }}>
                    {new Date(log.timestamp).toLocaleTimeString()}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
