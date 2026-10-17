import React from "react";
import { Shield, KeyRound, PlayCircle, Activity } from "lucide-react";
import { HealthStatus } from "../types";

interface NavbarProps {
  activeTab: "keys" | "playground" | "audit";
  setActiveTab: (tab: "keys" | "playground" | "audit") => void;
  health: HealthStatus | null;
}

export const Navbar: React.FC<NavbarProps> = ({ activeTab, setActiveTab, health }) => {
  return (
    <header className="glass-panel" style={{ margin: "16px 24px", padding: "12px 24px" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "16px" }}>
        {/* Brand */}
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <div
            style={{
              background: "linear-gradient(135deg, #6366f1 0%, #4338ca 100%)",
              padding: "8px",
              borderRadius: "10px",
              display: "flex",
              alignItems: "center",
              boxShadow: "0 0 15px rgba(99, 102, 241, 0.4)",
            }}
          >
            <Shield size={24} color="#ffffff" />
          </div>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <span style={{ fontSize: "1.25rem", fontWeight: 700, letterSpacing: "-0.02em" }}>AegisHMAC</span>
              <span className="badge badge-purple" style={{ fontSize: "0.6875rem" }}>v1.0.0</span>
            </div>
            <p style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
              Enterprise API Authentication & Integrity Gateway
            </p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav style={{ display: "flex", gap: "6px", background: "rgba(10, 14, 23, 0.5)", padding: "4px", borderRadius: "10px", border: "1px solid var(--border-color)" }}>
          <button
            id="tab-keys"
            className={`btn ${activeTab === "keys" ? "btn-primary" : "btn-secondary"}`}
            onClick={() => setActiveTab("keys")}
            style={{ border: "none", fontSize: "0.8125rem", padding: "6px 14px" }}
          >
            <KeyRound size={16} />
            <span>Key Vault</span>
          </button>
          <button
            id="tab-playground"
            className={`btn ${activeTab === "playground" ? "btn-primary" : "btn-secondary"}`}
            onClick={() => setActiveTab("playground")}
            style={{ border: "none", fontSize: "0.8125rem", padding: "6px 14px" }}
          >
            <PlayCircle size={16} />
            <span>HMAC Sandbox</span>
          </button>
          <button
            id="tab-audit"
            className={`btn ${activeTab === "audit" ? "btn-primary" : "btn-secondary"}`}
            onClick={() => setActiveTab("audit")}
            style={{ border: "none", fontSize: "0.8125rem", padding: "6px 14px" }}
          >
            <Activity size={16} />
            <span>Audit Stream</span>
          </button>
        </nav>

        {/* System Health Status */}
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          {health ? (
            <div className="badge badge-green" style={{ textTransform: "none", padding: "6px 12px" }}>
              <span className="status-dot status-dot-green"></span>
              <span>Gateway Online</span>
            </div>
          ) : (
            <div className="badge badge-red" style={{ textTransform: "none", padding: "6px 12px" }}>
              <span className="status-dot status-dot-red"></span>
              <span>Gateway Offline</span>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
