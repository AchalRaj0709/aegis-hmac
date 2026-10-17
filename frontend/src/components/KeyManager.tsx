import React, { useState, useEffect } from "react";
import { Plus, RefreshCw, Trash2, Copy, Check, Key, AlertTriangle } from "lucide-react";
import { ClientSummary, ClientCreateResponse, KeyRotateResponse } from "../types";
import { fetchClients, createClient, rotateClient, revokeClient } from "../services/api";

export const KeyManager: React.FC = () => {
  const [clients, setClients] = useState<ClientSummary[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [newClientName, setNewClientName] = useState<string>("");
  const [isCreating, setIsCreating] = useState<boolean>(false);

  // Modals
  const [createdData, setCreatedData] = useState<ClientCreateResponse | null>(null);
  const [rotatedData, setRotatedData] = useState<KeyRotateResponse | null>(null);
  const [copied, setCopied] = useState<boolean>(false);

  const loadClients = async () => {
    try {
      setLoading(true);
      const data = await fetchClients();
      setClients(data);
    } catch (err) {
      console.error("Failed to load clients:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadClients();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newClientName.trim()) return;

    try {
      const res = await createClient(newClientName.trim());
      setCreatedData(res);
      setNewClientName("");
      setIsCreating(false);
      loadClients();
    } catch (err: any) {
      alert(`Error creating client: ${err.message}`);
    }
  };

  const handleRotate = async (clientId: string) => {
    if (!confirm(`Are you sure you want to rotate keys for ${clientId}? The previous key will remain valid for 24 hours.`)) {
      return;
    }
    try {
      const res = await rotateClient(clientId);
      setRotatedData(res);
      loadClients();
    } catch (err: any) {
      alert(`Error rotating key: ${err.message}`);
    }
  };

  const handleRevoke = async (clientId: string) => {
    if (!confirm(`CAUTION: Permanently revoke all credentials for ${clientId}? All subsequent API requests will be blocked immediately.`)) {
      return;
    }
    try {
      await revokeClient(clientId);
      loadClients();
    } catch (err: any) {
      alert(`Error revoking key: ${err.message}`);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div style={{ maxWidth: "1200px", margin: "0 auto", padding: "0 24px 40px" }}>
      {/* Header bar */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "24px" }}>
        <div>
          <h1 style={{ fontSize: "1.5rem", fontWeight: 700 }}>Client Identities & Symmetric Key Vault</h1>
          <p style={{ color: "var(--text-secondary)", fontSize: "0.875rem", marginTop: "4px" }}>
            All symmetric keys are encrypted at rest using AES-256-GCM envelope encryption with a master HSM vault key.
          </p>
        </div>
        <button
          id="btn-register-client"
          className="btn btn-primary"
          onClick={() => setIsCreating(true)}
        >
          <Plus size={16} />
          <span>Register New Client</span>
        </button>
      </div>

      {/* Client Table */}
      <div className="glass-panel" style={{ overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left", fontSize: "0.875rem" }}>
          <thead>
            <tr style={{ background: "rgba(255, 255, 255, 0.03)", borderBottom: "1px solid var(--border-color)", color: "var(--text-secondary)" }}>
              <th style={{ padding: "14px 20px", fontWeight: 600 }}>Client ID</th>
              <th style={{ padding: "14px 20px", fontWeight: 600 }}>Client Name</th>
              <th style={{ padding: "14px 20px", fontWeight: 600 }}>Status</th>
              <th style={{ padding: "14px 20px", fontWeight: 600 }}>Active Key Version</th>
              <th style={{ padding: "14px 20px", fontWeight: 600 }}>Created Date</th>
              <th style={{ padding: "14px 20px", fontWeight: 600, textAlign: "right" }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={6} style={{ padding: "32px", textAlign: "center", color: "var(--text-muted)" }}>
                  Loading client directory...
                </td>
              </tr>
            ) : clients.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ padding: "40px", textAlign: "center", color: "var(--text-muted)" }}>
                  No clients registered yet. Click "Register New Client" to provision your first HMAC credentials.
                </td>
              </tr>
            ) : (
              clients.map((c) => (
                <tr
                  key={c.client_id}
                  style={{ borderBottom: "1px solid var(--border-color)", transition: "background 0.15s ease" }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(255, 255, 255, 0.02)")}
                  onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                >
                  <td style={{ padding: "14px 20px" }}>
                    <span className="mono" style={{ color: "var(--accent-cyan)", fontWeight: 500 }}>
                      {c.client_id}
                    </span>
                  </td>
                  <td style={{ padding: "14px 20px", fontWeight: 500 }}>{c.client_name}</td>
                  <td style={{ padding: "14px 20px" }}>
                    {c.status === "ACTIVE" && <span className="badge badge-green">Active</span>}
                    {c.status === "SUSPENDED" && <span className="badge badge-amber">Suspended</span>}
                    {c.status === "REVOKED" && <span className="badge badge-red">Revoked</span>}
                  </td>
                  <td style={{ padding: "14px 20px" }}>
                    <span className="badge badge-blue">v{c.active_key_version}</span>
                  </td>
                  <td style={{ padding: "14px 20px", color: "var(--text-muted)" }}>
                    {new Date(c.created_at).toLocaleDateString()}
                  </td>
                  <td style={{ padding: "14px 20px", textAlign: "right" }}>
                    {c.status !== "REVOKED" ? (
                      <div style={{ display: "inline-flex", gap: "8px" }}>
                        <button
                          className="btn btn-secondary"
                          style={{ padding: "4px 10px", fontSize: "0.75rem" }}
                          onClick={() => handleRotate(c.client_id)}
                          title="Rotate key with 24h grace window"
                        >
                          <RefreshCw size={13} />
                          <span>Rotate</span>
                        </button>
                        <button
                          className="btn btn-danger"
                          style={{ padding: "4px 10px", fontSize: "0.75rem" }}
                          onClick={() => handleRevoke(c.client_id)}
                          title="Revoke key immediately"
                        >
                          <Trash2 size={13} />
                          <span>Revoke</span>
                        </button>
                      </div>
                    ) : (
                      <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Decommissioned</span>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Modal: Create Client */}
      {isCreating && (
        <div className="modal-overlay">
          <div className="modal-content">
            <h2 style={{ fontSize: "1.25rem", fontWeight: 700, marginBottom: "8px" }}>Register New Client</h2>
            <p style={{ color: "var(--text-secondary)", fontSize: "0.875rem", marginBottom: "20px" }}>
              Provision a unique Client ID and cryptographically secure 256-bit symmetric secret key.
            </p>
            <form onSubmit={handleCreate}>
              <div style={{ marginBottom: "20px" }}>
                <label style={{ display: "block", fontSize: "0.8125rem", fontWeight: 600, marginBottom: "6px" }}>
                  Application / Service Name
                </label>
                <input
                  id="input-client-name"
                  type="text"
                  className="input-control"
                  placeholder="e.g. Payments Microservice"
                  value={newClientName}
                  onChange={(e) => setNewClientName(e.target.value)}
                  autoFocus
                  required
                />
              </div>
              <div style={{ display: "flex", justifyContent: "flex-end", gap: "10px" }}>
                <button type="button" className="btn btn-secondary" onClick={() => setIsCreating(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  Generate Credentials
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Reveal Secret Once */}
      {createdData && (
        <div className="modal-overlay">
          <div className="modal-content" style={{ maxWidth: "580px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "16px" }}>
              <div style={{ background: "rgba(16, 185, 129, 0.15)", padding: "10px", borderRadius: "10px" }}>
                <Key size={24} color="#10b981" />
              </div>
              <div>
                <h2 style={{ fontSize: "1.25rem", fontWeight: 700 }}>Client Registered Successfully</h2>
                <p style={{ color: "var(--text-muted)", fontSize: "0.8125rem" }}>
                  Save your credentials securely. The secret key will never be shown again!
                </p>
              </div>
            </div>

            <div style={{ background: "rgba(0,0,0,0.3)", borderRadius: "10px", padding: "16px", marginBottom: "16px" }}>
              <div style={{ marginBottom: "12px" }}>
                <span style={{ fontSize: "0.75rem", color: "var(--text-secondary)", textTransform: "uppercase", fontWeight: 600 }}>
                  Client ID
                </span>
                <p className="mono" style={{ color: "var(--accent-cyan)", fontWeight: 600, fontSize: "0.9375rem" }}>
                  {createdData.client_id}
                </p>
              </div>

              <div>
                <span style={{ fontSize: "0.75rem", color: "var(--text-secondary)", textTransform: "uppercase", fontWeight: 600 }}>
                  Symmetric Secret Key (256-Bit)
                </span>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginTop: "4px" }}>
                  <code className="code-preview" style={{ flex: 1, padding: "8px 12px", color: "#34d399" }}>
                    {createdData.secret_key}
                  </code>
                  <button
                    className="btn btn-secondary"
                    onClick={() => copyToClipboard(createdData.secret_key)}
                    style={{ padding: "8px 12px" }}
                  >
                    {copied ? <Check size={16} color="#34d399" /> : <Copy size={16} />}
                  </button>
                </div>
              </div>
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: "8px", background: "rgba(245, 158, 11, 0.08)", border: "1px solid rgba(245, 158, 11, 0.2)", borderRadius: "8px", padding: "10px 14px", marginBottom: "20px" }}>
              <AlertTriangle size={18} color="#fbbf24" style={{ flexShrink: 0 }} />
              <p style={{ fontSize: "0.75rem", color: "#fef3c7" }}>
                This symmetric key is stored encrypted at rest using AES-256-GCM. It cannot be recovered if lost.
              </p>
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end" }}>
              <button className="btn btn-primary" onClick={() => setCreatedData(null)}>
                I Have Safely Saved My Key
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Rotation Confirmation */}
      {rotatedData && (
        <div className="modal-overlay">
          <div className="modal-content" style={{ maxWidth: "580px" }}>
            <h2 style={{ fontSize: "1.25rem", fontWeight: 700, marginBottom: "8px" }}>Key Rotated (Version {rotatedData.new_key_version})</h2>
            <p style={{ color: "var(--text-secondary)", fontSize: "0.875rem", marginBottom: "16px" }}>
              {rotatedData.message}
            </p>

            <div style={{ background: "rgba(0,0,0,0.3)", borderRadius: "10px", padding: "16px", marginBottom: "16px" }}>
              <span style={{ fontSize: "0.75rem", color: "var(--text-secondary)", textTransform: "uppercase", fontWeight: 600 }}>
                New Symmetric Key
              </span>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", marginTop: "4px" }}>
                <code className="code-preview" style={{ flex: 1, padding: "8px 12px", color: "#34d399" }}>
                  {rotatedData.new_secret_key}
                </code>
                <button className="btn btn-secondary" onClick={() => copyToClipboard(rotatedData.new_secret_key)}>
                  {copied ? <Check size={16} color="#34d399" /> : <Copy size={16} />}
                </button>
              </div>
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end" }}>
              <button className="btn btn-primary" onClick={() => setRotatedData(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
