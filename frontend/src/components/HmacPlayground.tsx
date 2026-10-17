import React, { useState, useEffect } from "react";
import { Send, Eye, EyeOff, ShieldCheck, ShieldX, Terminal, Sparkles, Flame, Clock, RefreshCw } from "lucide-react";
import { ClientSummary } from "../types";
import { fetchClients, dispatchCustomRequest } from "../services/api";
import { hashPayload, computeHmacSha256, generateRandomNonce, formatCompactUtc } from "../utils/browserCrypto";

export const HmacPlayground: React.FC = () => {
  const [clients, setClients] = useState<ClientSummary[]>([]);
  const [selectedClientId, setSelectedClientId] = useState<string>("");
  const [secretKey, setSecretKey] = useState<string>("");
  const [showSecret, setShowSecret] = useState<boolean>(false);

  // Request parameters
  const [method, setMethod] = useState<string>("POST");
  const [endpoint, setEndpoint] = useState<string>("/api/v1/payments/transfer");
  const [queryString, setQueryString] = useState<string>("");
  const [body, setBody] = useState<string>(
    JSON.stringify({ recipient_id: "client_vendor_88", amount: 250.0, currency: "USD" }, null, 2)
  );

  // Attack simulators
  const [tamperPayload, setTamperPayload] = useState<boolean>(false);
  const [expiredTimestamp, setExpiredTimestamp] = useState<boolean>(false);
  const [staleNonce, setStaleNonce] = useState<string>("");

  // Live Cryptographic state
  const [canonicalString, setCanonicalString] = useState<string>("");
  const [payloadHash, setPayloadHash] = useState<string>("");
  const [signature, setSignature] = useState<string>("");
  const [authHeader, setAuthHeader] = useState<string>("");
  const [timestamp, setTimestamp] = useState<string>("");
  const [nonce, setNonce] = useState<string>("");

  // Server response state
  const [isSending, setIsSending] = useState<boolean>(false);
  const [responseStatus, setResponseStatus] = useState<number | null>(null);
  const [responseData, setResponseData] = useState<any>(null);
  const [duration, setDuration] = useState<number | null>(null);

  // Load registered clients on mount
  useEffect(() => {
    fetchClients().then((data) => {
      setClients(data);
      if (data.length > 0) {
        setSelectedClientId(data[0].client_id);
      }
    });
  }, []);

  // Update dynamic cryptographic calculations in real-time
  const recalculateCrypto = async () => {
    let currentTs = formatCompactUtc();
    if (expiredTimestamp) {
      // 10 minutes in the past
      const past = new Date(Date.now() - 10 * 60 * 1000);
      currentTs = formatCompactUtc(past);
    }
    setTimestamp(currentTs);

    const currentNonce = staleNonce || generateRandomNonce(16);
    setNonce(currentNonce);

    // Compute payload hash
    const pHash = await hashPayload(method === "GET" ? "" : body);
    setPayloadHash(pHash);

    // Build headers
    const headers: Record<string, string> = {
      "content-type": "application/json",
      "x-nonce": currentNonce,
      "x-timestamp": currentTs,
    };

    const signedHeaders = "content-type;x-nonce;x-timestamp";
    const canonicalHeaders = `content-type:${headers["content-type"]}\nx-nonce:${headers["x-nonce"]}\nx-timestamp:${headers["x-timestamp"]}`;

    // Clean URI & Query
    const cleanUri = endpoint.startsWith("/") ? endpoint : `/${endpoint}`;
    const cleanQs = queryString.replace(/^\?/, "");

    // Assemble canonical string
    const canonStr = [
      method.toUpperCase(),
      cleanUri,
      cleanQs,
      canonicalHeaders,
      signedHeaders,
      pHash,
      currentTs,
      currentNonce,
    ].join("\n");

    setCanonicalString(canonStr);

    // Compute HMAC
    if (secretKey.trim()) {
      const sig = await computeHmacSha256(secretKey.trim(), canonStr);
      setSignature(sig);
      setAuthHeader(`HMAC-SHA256 Credential=${selectedClientId || "client_custom"}, SignedHeaders=${signedHeaders}, Signature=${sig}`);
    } else {
      setSignature("Enter secret key to compute HMAC-SHA256 signature");
      setAuthHeader("");
    }
  };

  useEffect(() => {
    recalculateCrypto();
  }, [selectedClientId, secretKey, method, endpoint, queryString, body, expiredTimestamp, staleNonce]);

  const handleDispatch = async () => {
    if (!secretKey.trim()) {
      alert("Please enter the client's symmetric secret key to sign the request.");
      return;
    }

    setIsSending(true);
    setResponseStatus(null);
    setResponseData(null);
    const start = performance.now();

    try {
      const requestHeaders: Record<string, string> = {
        authorization: authHeader,
        "x-timestamp": timestamp,
        "x-nonce": nonce,
        "content-type": "application/json",
      };

      // If tamperPayload is checked, alter the body AFTER computing the signature!
      let bodyToSend = method === "GET" ? undefined : body;
      if (tamperPayload && method !== "GET") {
        bodyToSend = body.replace(/amount":\s*(\d+)/, 'amount": 999999');
        if (bodyToSend === body) {
          bodyToSend = body + " /*TAMPERED*/";
        }
      }

      const res = await dispatchCustomRequest(
        method,
        endpoint + (queryString ? `?${queryString}` : ""),
        requestHeaders,
        bodyToSend
      );

      const elapsed = Math.round(performance.now() - start);
      setDuration(elapsed);
      setResponseStatus(res.status);
      setResponseData(res.data);
    } catch (err: any) {
      setResponseStatus(500);
      setResponseData({ error: err.message });
    } finally {
      setIsSending(false);
    }
  };

  const handleSimulateReplay = () => {
    setStaleNonce(nonce);
    alert(`Nonce locked to "${nonce}". Clicking "Send Signed Request" again will simulate an attacker replaying this exact request!`);
  };

  return (
    <div style={{ maxWidth: "1280px", margin: "0 auto", padding: "0 24px 40px" }}>
      {/* Title */}
      <div style={{ marginBottom: "20px" }}>
        <h1 style={{ fontSize: "1.5rem", fontWeight: 700, display: "flex", alignItems: "center", gap: "10px" }}>
          <span>Interactive HMAC Signing Sandbox</span>
          <span className="badge badge-blue">Live Verification</span>
        </h1>
        <p style={{ color: "var(--text-secondary)", fontSize: "0.875rem", marginTop: "4px" }}>
          Inspect step-by-step canonical request generation, SHA-256 payload digests, and test live signatures against the FastAPI gateway.
        </p>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "24px" }}>
        {/* Left Column: Request Form & Attack Simulator */}
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
          {/* Credentials Card */}
          <div className="glass-panel" style={{ padding: "20px" }}>
            <h3 style={{ fontSize: "1rem", fontWeight: 600, marginBottom: "16px", display: "flex", alignItems: "center", gap: "8px" }}>
              <Terminal size={18} color="var(--accent-primary)" />
              <span>1. Authentication Credentials</span>
            </h3>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "14px", marginBottom: "14px" }}>
              <div>
                <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 600, color: "var(--text-secondary)", marginBottom: "4px" }}>
                  Select Registered Client
                </label>
                <select
                  className="input-control"
                  value={selectedClientId}
                  onChange={(e) => setSelectedClientId(e.target.value)}
                >
                  {clients.map((c) => (
                    <option key={c.client_id} value={c.client_id}>
                      {c.client_name} ({c.client_id})
                    </option>
                  ))}
                  <option value="custom">-- Custom Client ID --</option>
                </select>
              </div>

              <div>
                <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 600, color: "var(--text-secondary)", marginBottom: "4px" }}>
                  Client ID
                </label>
                <input
                  type="text"
                  className="input-control mono"
                  value={selectedClientId}
                  onChange={(e) => setSelectedClientId(e.target.value)}
                  placeholder="client_..."
                />
              </div>
            </div>

            <div>
              <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 600, color: "var(--text-secondary)", marginBottom: "4px" }}>
                Client Secret Key (256-Bit Hex)
              </label>
              <div style={{ position: "relative" }}>
                <input
                  type={showSecret ? "text" : "password"}
                  className="input-control mono"
                  value={secretKey}
                  onChange={(e) => setSecretKey(e.target.value)}
                  placeholder="Paste the 256-bit secret key obtained from Key Vault"
                  style={{ paddingRight: "40px" }}
                />
                <button
                  type="button"
                  onClick={() => setShowSecret(!showSecret)}
                  style={{ position: "absolute", right: "10px", top: "50%", transform: "translateY(-50%)", background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer" }}
                >
                  {showSecret ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>
          </div>

          {/* Request Builder Card */}
          <div className="glass-panel" style={{ padding: "20px" }}>
            <h3 style={{ fontSize: "1rem", fontWeight: 600, marginBottom: "16px", display: "flex", alignItems: "center", gap: "8px" }}>
              <Sparkles size={18} color="var(--accent-cyan)" />
              <span>2. HTTP Request Parameters</span>
            </h3>

            <div style={{ display: "grid", gridTemplateColumns: "120px 1fr", gap: "12px", marginBottom: "14px" }}>
              <div>
                <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 600, color: "var(--text-secondary)", marginBottom: "4px" }}>
                  Method
                </label>
                <select className="input-control" value={method} onChange={(e) => setMethod(e.target.value)}>
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                </select>
              </div>

              <div>
                <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 600, color: "var(--text-secondary)", marginBottom: "4px" }}>
                  Endpoint Preset
                </label>
                <select
                  className="input-control"
                  value={endpoint}
                  onChange={(e) => {
                    const ep = e.target.value;
                    setEndpoint(ep);
                    if (ep === "/api/v1/user/profile") {
                      setMethod("GET");
                    } else if (ep === "/graphql") {
                      setMethod("POST");
                      setBody(JSON.stringify({ query: "{ getAccount(accountId: \"acc_sandbox\") { balance currency } }" }, null, 2));
                    } else if (ep === "/api/v1/payments/transfer") {
                      setMethod("POST");
                      setBody(JSON.stringify({ recipient_id: "vendor_99", amount: 250.0, currency: "USD" }, null, 2));
                    }
                  }}
                >
                  <option value="/api/v1/payments/transfer">POST /api/v1/payments/transfer (Financial Transfer)</option>
                  <option value="/api/v1/user/profile">GET /api/v1/user/profile (Caller Profile)</option>
                  <option value="/api/v1/webhooks/deliver">POST /api/v1/webhooks/deliver (Webhook Ingress)</option>
                  <option value="/graphql">POST /graphql (Strawberry GraphQL Query)</option>
                  <option value="/api/v1/test/echo">POST /api/v1/test/echo (Payload Echo)</option>
                </select>
              </div>
            </div>

            <div style={{ marginBottom: "14px" }}>
              <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 600, color: "var(--text-secondary)", marginBottom: "4px" }}>
                Query Parameters (e.g. currency=USD&sort=desc)
              </label>
              <input
                type="text"
                className="input-control mono"
                placeholder="key=value&sort=asc"
                value={queryString}
                onChange={(e) => setQueryString(e.target.value)}
              />
            </div>

            {method !== "GET" && (
              <div style={{ marginBottom: "14px" }}>
                <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 600, color: "var(--text-secondary)", marginBottom: "4px" }}>
                  JSON Request Body
                </label>
                <textarea
                  className="input-control mono"
                  rows={5}
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                  style={{ resize: "vertical" }}
                />
              </div>
            )}

            {/* Attack Simulation Controls */}
            <div style={{ background: "rgba(239, 68, 68, 0.05)", border: "1px solid rgba(239, 68, 68, 0.2)", borderRadius: "8px", padding: "12px", marginTop: "16px" }}>
              <span style={{ fontSize: "0.75rem", fontWeight: 700, color: "#f87171", display: "flex", alignItems: "center", gap: "6px", marginBottom: "8px" }}>
                <Flame size={14} />
                Attack & Tampering Simulator
              </span>

              <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                <label style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "0.8125rem", cursor: "pointer" }}>
                  <input
                    type="checkbox"
                    checked={tamperPayload}
                    onChange={(e) => setTamperPayload(e.target.checked)}
                  />
                  <span>
                    <strong>Tamper Payload in Transit</strong> (Alters amount in body after signing &rarr; demonstrates <span style={{ color: "#f87171" }}>401 Signature Mismatch</span>)
                  </span>
                </label>

                <label style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "0.8125rem", cursor: "pointer" }}>
                  <input
                    type="checkbox"
                    checked={expiredTimestamp}
                    onChange={(e) => setExpiredTimestamp(e.target.checked)}
                  />
                  <span>
                    <strong>Simulate Stale Timestamp</strong> (Sets time 10 min in past &rarr; demonstrates <span style={{ color: "#fbbf24" }}>408 Clock Skew Exceeded</span>)
                  </span>
                </label>
              </div>

              <div style={{ marginTop: "10px", display: "flex", alignItems: "center", gap: "10px" }}>
                <button
                  type="button"
                  className="btn btn-secondary"
                  style={{ padding: "4px 10px", fontSize: "0.75rem" }}
                  onClick={handleSimulateReplay}
                >
                  <RefreshCw size={12} />
                  <span>Lock Nonce for Replay Attack</span>
                </button>
                {staleNonce && (
                  <span className="badge badge-purple" style={{ fontSize: "0.6875rem" }}>
                    Nonce Locked: {staleNonce.slice(0, 8)}...
                  </span>
                )}
              </div>
            </div>

            {/* Dispatch Button */}
            <button
              id="btn-dispatch-request"
              className="btn btn-primary"
              style={{ width: "100%", marginTop: "18px", padding: "12px" }}
              onClick={handleDispatch}
              disabled={isSending}
            >
              <Send size={16} />
              <span>{isSending ? "Verifying Signature on Server..." : "Dispatch Signed Request"}</span>
            </button>
          </div>
        </div>

        {/* Right Column: Live Cryptographic Visualizer & Server Response */}
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
          {/* Live Crypto Inspector Card */}
          <div className="glass-panel" style={{ padding: "20px" }}>
            <h3 style={{ fontSize: "1rem", fontWeight: 600, marginBottom: "14px", display: "flex", alignItems: "center", gap: "8px" }}>
              <ShieldCheck size={18} color="var(--accent-green)" />
              <span>3. Live Cryptographic Visualizer</span>
            </h3>

            {/* Step 1: Canonical String */}
            <div style={{ marginBottom: "14px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "4px" }}>
                <span style={{ fontSize: "0.75rem", fontWeight: 600, color: "var(--accent-cyan)", textTransform: "uppercase" }}>
                  Step 1: Canonical Request String (AWS SigV4 Format)
                </span>
              </div>
              <pre className="code-preview" style={{ maxHeight: "150px", fontSize: "0.75rem" }}>
                {canonicalString}
              </pre>
            </div>

            {/* Step 2: Body Hash */}
            <div style={{ marginBottom: "14px" }}>
              <span style={{ fontSize: "0.75rem", fontWeight: 600, color: "var(--accent-cyan)", textTransform: "uppercase", display: "block", marginBottom: "4px" }}>
                Step 2: SHA-256 Payload Hash
              </span>
              <code className="code-preview" style={{ display: "block", color: "#a5b4fc" }}>
                {payloadHash}
              </code>
            </div>

            {/* Step 3: Signature */}
            <div>
              <span style={{ fontSize: "0.75rem", fontWeight: 600, color: "var(--accent-cyan)", textTransform: "uppercase", display: "block", marginBottom: "4px" }}>
                Step 3: Computed HMAC-SHA256 Signature
              </span>
              <code className="code-preview" style={{ display: "block", color: "#34d399" }}>
                {signature}
              </code>
            </div>
          </div>

          {/* Live Server Response Verdict */}
          <div className="glass-panel" style={{ padding: "20px", flex: 1 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px" }}>
              <h3 style={{ fontSize: "1rem", fontWeight: 600, display: "flex", alignItems: "center", gap: "8px" }}>
                <Clock size={18} color="var(--accent-primary)" />
                <span>4. Gateway Verification Response</span>
              </h3>
              {duration !== null && (
                <span className="badge badge-blue">
                  {duration}ms Latency
                </span>
              )}
            </div>

            {responseStatus !== null ? (
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "14px" }}>
                  {responseStatus === 200 && (
                    <div className="badge badge-green" style={{ fontSize: "0.875rem", padding: "6px 14px" }}>
                      <ShieldCheck size={16} />
                      <span>200 OK — Signature Verified & Request Authenticated</span>
                    </div>
                  )}
                  {responseStatus === 401 && (
                    <div className="badge badge-red" style={{ fontSize: "0.875rem", padding: "6px 14px" }}>
                      <ShieldX size={16} />
                      <span>401 Unauthorized — {responseData?.error || "Signature Mismatch"}</span>
                    </div>
                  )}
                  {responseStatus === 408 && (
                    <div className="badge badge-amber" style={{ fontSize: "0.875rem", padding: "6px 14px" }}>
                      <Clock size={16} />
                      <span>408 Request Timeout — Clock Skew Exceeded (&plusmn;300s window)</span>
                    </div>
                  )}
                </div>

                <span style={{ fontSize: "0.75rem", fontWeight: 600, color: "var(--text-secondary)", textTransform: "uppercase", display: "block", marginBottom: "6px" }}>
                  Server JSON Response Payload:
                </span>
                <pre className="code-preview" style={{ maxHeight: "220px", color: responseStatus === 200 ? "#34d399" : "#f87171" }}>
                  {JSON.stringify(responseData, null, 2)}
                </pre>
              </div>
            ) : (
              <div style={{ padding: "40px", textAlign: "center", color: "var(--text-muted)" }}>
                Click <strong>"Dispatch Signed Request"</strong> to send the cryptographic headers to the FastAPI gateway.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
