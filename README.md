# 🛡️ AegisHMAC

> **Production-Grade HMAC-SHA256 API Authentication & Integrity Defense System**  
> *Modeled after AWS Signature Version 4 (SigV4) & GitHub Webhook Architecture*

---

## 🌟 Overview

**AegisHMAC** is an enterprise-grade cryptographic authentication middleware, client SDK suite, and management gateway designed to secure machine-to-machine, microservice, and webhook communications without ever exposing secret keys in transit.

Traditional API keys are vulnerable to man-in-the-middle sniffing, request tampering, and replay attacks. **AegisHMAC** solves this by establishing a zero-trust message integrity protocol:
1. **Origin Authenticity**: Cryptographically validates the sender's identity using 256-bit symmetric keys.
2. **Tamper-Proof Integrity**: Digitally signs the full HTTP request (Method, Path, Query Parameters, Headers, and Payload). Altering even 1 byte in transit invalidates the signature.
3. **Replay Attack Defense**: Employs a $\pm 5$-minute sliding temporal window paired with atomic nonce tracking and automatic MongoDB TTL expiration.
4. **Side-Channel Immunity**: Enforces constant-time byte comparisons to eliminate timing attack vectors.

---

## 🏗️ System Architecture

```
[ Client Consumer / Microservice ]
   │
   ├──> Python Client SDK (httpx / requests)
   └──> TypeScript Client SDK (Axios / Fetch)
             │
             │ HTTP Signed Request:
             │ - Authorization: HMAC-SHA256 Credential=..., Signature=...
             │ - X-Timestamp: 20261017T143000Z
             │ - X-Nonce: <unique-uuid>
             ▼
┌────────────────────────────────────────────────────────┐
│             AEGISHMAC API GATEWAY / MIDDLEWARE         │
├────────────────────────────────────────────────────────┤
│ 1. Header Extraction & Schema Validation               │
│ 2. Clock Skew Check (|T_client - T_server| <= 300s)    │
│ 3. Atomic Nonce Replay Check (MongoDB TTL Cache)       │
│ 4. Key Resolution & AES-256-GCM Envelope Decryption    │
│ 5. Canonical Request String Reconstruction             │
│ 6. Constant-Time Signature Comparison (compare_digest) │
│ 7. Asynchronous Audit Logging & Telemetry              │
└────────────────────────────┬───────────────────────────┘
                             │ (Forward If Valid)
                             ▼
┌────────────────────────────────────────────────────────┐
│             PROTECTED APPLICATION ENDPOINTS            │
├────────────────────────────┬───────────────────────────┤
│ REST APIs                  │ GraphQL API               │
│ - /api/v1/transfers        │ - Query: getAccount       │
│ - /api/v1/profile          │ - Mutation: transferFunds │
│ - /api/v1/webhooks         │                           │
└────────────────────────────┴───────────────────────────┘
```

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Backend Framework** | **Python (FastAPI + Uvicorn)** | High-performance ASGI engine, clean async middleware, and auto-generated OpenAPI documentation. |
| **Database & Nonce Store** | **MongoDB (Motor Driver)** | Client credentials store, audit logging, and **300-second TTL index** for automatic nonce expiration. |
| **Cryptographic Engine** | **Standard `hmac`, `hashlib`, `cryptography`** | RFC 2104 / FIPS 198 compliant HMAC, SHA-256 body hashing, and AES-256-GCM envelope encryption. |
| **Protocols Supported** | **REST (JSON) + GraphQL (Strawberry)** | Complete cryptographic protection for both REST and GraphQL over HTTP. |
| **Client SDKs** | **Python & TypeScript** | Plug-and-play client libraries for Python (`httpx`/`requests`) and Node/Browser (`Axios`/`Fetch`). |
| **Developer Dashboard** | **React 18 + TypeScript (Vite)** | Key lifecycle management, live security audit stream, and interactive **HMAC Signing Sandbox**. |

---

## 🚀 Key Features

* **Strict Canonicalization**: AWS SigV4-compliant normalization of HTTP methods, paths, alphabetically sorted query parameters, lowercased headers, and hashed payloads.
* **Dual-Key Graceful Rotation**: Supports overlapping "Active" and "Rotating" key versions, allowing zero-downtime key rotation across distributed clients.
* **Replay Attack Blocker**: Automatic rejection of stale timestamps outside the $\pm 300$-second window and duplicate nonces.
* **Zero Plaintext Secrets at Rest**: Client symmetric secrets stored in MongoDB are encrypted using AES-256-GCM envelope encryption with a master vault key.
* **Interactive Signing Sandbox**: A visual developer UI where engineers can inspect step-by-step canonical string formation and test live signatures.
* **RFC 4231 Test Vector Suite**: Rigorous automated test suite verifying mathematical precision against all 7 official RFC 4231 test vectors.

---

## 📋 Project Roadmap

- [x] Architecture & Threat Modeling Specification
- [ ] **Phase 1**: Core Cryptographic Engine & Canonicalizer
- [ ] **Phase 2**: MongoDB Models & Replay Nonce TTL Store
- [ ] **Phase 3**: FastAPI HMAC Authentication Middleware Pipeline
- [ ] **Phase 4**: Protected REST & Strawberry GraphQL Endpoints
- [ ] **Phase 5**: Python & TypeScript Client SDKs
- [ ] **Phase 6**: Security & Attack Simulation Test Suite (Replay, Tamper, Clock Skew, Timing)
- [ ] **Phase 7**: React + TypeScript Developer Dashboard & HMAC Sandbox

---

## 📄 License

MIT License. Designed and built for secure, enterprise-grade distributed API architectures.
