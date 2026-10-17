import React, { useState, useEffect } from "react";
import { Navbar } from "./components/Navbar";
import { KeyManager } from "./components/KeyManager";
import { HmacPlayground } from "./components/HmacPlayground";
import { AuditLogStream } from "./components/AuditLogStream";
import { HealthStatus } from "./types";
import { fetchHealth } from "./services/api";

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<"keys" | "playground" | "audit">("playground");
  const [health, setHealth] = useState<HealthStatus | null>(null);

  useEffect(() => {
    fetchHealth()
      .then(setHealth)
      .catch(() => setHealth(null));

    const interval = setInterval(() => {
      fetchHealth()
        .then(setHealth)
        .catch(() => setHealth(null));
    }, 10000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} health={health} />

      <main style={{ flex: 1, paddingTop: "8px" }}>
        {activeTab === "keys" && <KeyManager />}
        {activeTab === "playground" && <HmacPlayground />}
        {activeTab === "audit" && <AuditLogStream />}
      </main>

      <footer style={{ borderTop: "1px solid var(--border-color)", padding: "16px 24px", textAlign: "center", fontSize: "0.75rem", color: "var(--text-muted)" }}>
        <div style={{ display: "flex", justifyContent: "center", gap: "16px", flexWrap: "wrap", alignItems: "center" }}>
          <span>AegisHMAC Security Gateway &bull; RFC 2104 / FIPS 198</span>
          <span>&bull;</span>
          <span>MongoDB TTL Replay Defense</span>
          <span>&bull;</span>
          <span>Constant-Time Verification</span>
          <span>&bull;</span>
          <span>AES-256-GCM Envelope Encryption</span>
        </div>
      </footer>
    </div>
  );
};

export default App;
