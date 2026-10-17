# 🛡️ AegisHMAC

> **Enterprise-Grade HMAC-SHA256 API Authentication & Integrity Defense System**  
> *Modeled after AWS Signature Version 4 (SigV4) & GitHub Webhook Standards*

[![Python](https://img.shields.io/badge/Python-3.12%2B-blue?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.4%2B-3178C6?logo=typescript)](https://www.typescriptlang.org)
[![MongoDB](https://img.shields.io/badge/MongoDB-TTL%20Index%20Active-47A248?logo=mongodb)](https://mongodb.com)
[![GraphQL](https://img.shields.io/badge/GraphQL-Strawberry-E10098?logo=graphql)](https://strawberry.rocks)
[![Tests](https://img.shields.io/badge/Tests-47%20Passed-10b981?logo=pytest)](https://docs.pytest.org)
[![License](https://img.shields.io/badge/License-MIT-purple)](#license)

---

## 🌟 Executive Summary

**AegisHMAC** is a production-grade cryptographic authentication middleware, client SDK suite, and management gateway designed to secure microservice communications, webhooks, and REST/GraphQL APIs **without ever exposing symmetric keys in transit**.

Traditional API keys sent over HTTP headers are vulnerable to packet sniffing, payload tampering, and replay attacks. **AegisHMAC** establishes a zero-trust message integrity protocol where:
1. **The Secret Key is Never Sent**: Symmetric keys are stored securely on both ends and used strictly as mathematical signing inputs.
2. **Payload Tamper-Proofing**: The full request (Method, Path, Sorted Query Parameters, Normalized Headers, and SHA-256 Payload Hash) is cryptographically signed. Altering even 1 character in transit invalidates the signature.
3. **Replay Attack Defense**: Nonces are atomically tracked and automatically purged by a **300-second MongoDB TTL index**, paired with a $\pm 5$-minute sliding temporal window.
4. **Side-Channel Timing Immunity**: Enforces constant-time byte comparisons (`hmac.compare_digest`) to eliminate nanosecond timing attack vectors.
5. **Zero Plaintext Secrets at Rest**: Client keys stored in MongoDB are encrypted using **AES-256-GCM envelope encryption** with a master vault key.

---

## 🏗️ Architecture Overview

```text
[ Client Application / Microservice ]
   │
   ├──> Python Client SDK (httpx / requests)
   └──> TypeScript Client SDK (Axios / Fetch)
             │
             │ HTTP Request + Signed Headers:
             │ - Authorization: HMAC-SHA256 Credential=..., SignedHeaders=..., Signature=...
             │ - X-Timestamp: 20261017T200000Z
             │ - X-Nonce: <32-hex-uuid>
             ▼
┌────────────────────────────────────────────────────────┐
│             AEGISHMAC FASTAPI GATEWAY                  │
├────────────────────────────────────────────────────────┤
│ 1. Header Extraction & Schema Validation               │
│ 2. Clock Skew Check (|T_client - T_server| <= 300s)    │
│ 3. Atomic Nonce Replay Check (MongoDB TTL Cache)       │
│ 4. Key Resolution & AES-256-GCM Envelope Decryption    │
│ 5. AWS SigV4 Canonical Request Reconstruction          │
│ 6. Constant-Time Signature Verification (compare_digest│
│ 7. Asynchronous Security Audit Logging & Telemetry     │
└────────────────────────────┬───────────────────────────┘
                             │ (Forward If Valid)
                             ▼
┌────────────────────────────────────────────────────────┐
│             PROTECTED APPLICATION ENDPOINTS            │
├────────────────────────────┬───────────────────────────┤
│ Protected REST Endpoints   │ Protected GraphQL Engine  │
│ - /api/v1/payments/transfer│ - Query: getAccount       │
│ - /api/v1/user/profile     │ - Mutation: executeTransfer
│ - /api/v1/webhooks/deliver │                           │
└────────────────────────────┴───────────────────────────┘
```

---

## 🛡️ Threat Model & Cryptographic Mitigations

| Threat Vector | Attack Mechanism | AegisHMAC Mitigation |
| :--- | :--- | :--- |
| **Replay Attacks** | Attacker intercepts a valid signed request and replays it later. | **$\pm 5$-Min Sliding Temporal Window** + Atomic Nonce tracking with **MongoDB TTL auto-purge**. |
| **In-Transit Tampering** | Attacker alters payment amounts (`$500` &rarr; `$5000`) or recipient IDs. | **AWS SigV4 Canonical Hash**: Altering 1 bit changes the SHA-256 digest, breaking the signature. |
| **Timing Attacks** | Measuring string equality comparison latency to deduce secret keys byte-by-byte. | **Constant-Time Verification**: Uses `hmac.compare_digest` to ensure uniform execution time. |
| **Key Compromise** | Secret key is exposed or leaked. | **Zero-Downtime Key Rotation**: Old key enters a 24-hr `ROTATING` grace period while new key is activated; 1-click instant revocation. |
| **Database Leaks** | Attacker gains read access to the database. | **AES-256-GCM Envelope Encryption**: Symmetric keys are stored encrypted at rest with random 96-bit IVs. |
| **Man-In-The-Middle** | Eavesdropping on transport. | **Mandatory TLS/HTTPS Channel** encryption. |

---

## 📂 Project Structure

```text
HMAC/
├── backend/
│   ├── app/
│   │   ├── core/
│   │   │   ├── crypto.py             # RFC 2104 HMAC, SHA-256, CSPRNG, constant-time compare
│   │   │   ├── canonical.py          # AWS SigV4 canonical request engine
│   │   │   ├── envelope.py           # AES-256-GCM master key envelope encryption
│   │   │   └── errors.py             # Custom security exceptions with HTTP status codes
│   │   ├── database/
│   │   │   ├── connection.py         # Motor async MongoDB connection & TTL index manager
│   │   │   ├── models.py             # Pydantic schemas (Clients, Keys, Nonces, Audit Logs)
│   │   │   └── repositories/         # ClientRepo, KeyRepo (rotation), NonceRepo, AuditRepo
│   │   ├── middleware/
│   │   │   └── hmac_auth.py          # Central ASGI HMAC authentication pipeline
│   │   ├── api/v1/
│   │   │   └── protected_rest.py     # Protected payment, profile, and webhook endpoints
│   │   ├── graphql/
│   │   │   └── schema.py             # Protected Strawberry GraphQL queries & mutations
│   │   ├── config.py                 # Pydantic BaseSettings & environment config
│   │   └── main.py                   # FastAPI entrypoint & admin key management routes
│   └── requirements.txt
│
├── sdks/
│   ├── python/                       # Python Client SDK (httpx / requests plugin)
│   │   └── aegis_client/
│   └── typescript/                   # TypeScript Client SDK (Axios / Fetch plugin)
│       └── src/
│
├── frontend/                         # Developer Dashboard & Interactive HMAC Sandbox (React + Vite)
│   ├── src/
│   │   ├── components/
│   │   │   ├── Navbar.tsx            # Brand & live gateway status indicator
│   │   │   ├── KeyManager.tsx        # Client registration, key rotation, and revocation
│   │   │   ├── HmacPlayground.tsx    # Live visual canonicalizer & attack simulator
│   │   │   └── AuditLogStream.tsx    # Real-time forensic telemetry stream
│   │   └── utils/browserCrypto.ts    # Web Crypto API client-side signer
│   └── index.html
│
├── tests/                            # 47 Automated Test Cases
│   ├── test_rfc4231.py               # Official IETF RFC 4231 test vectors 1-7
│   ├── test_canonicalization.py      # AWS SigV4 query sorting & header normalization
│   ├── test_envelope.py              # AES-256-GCM encryption & tamper detection
│   ├── test_database.py              # MongoDB CRUD, key rotation grace period, replay nonces
│   ├── test_middleware.py            # Gateway clock skew, replay defense, and verification
│   ├── test_business_endpoints.py    # Protected REST & Strawberry GraphQL integrity
│   └── test_python_sdk.py            # Python SDK client-side request signing
│
├── scripts/
│   ├── seed.py                       # Prepopulates demo clients, keys, and audit logs
│   └── benchmark.py                  # Performance benchmark (Throughput & p99 latency)
│
└── README.md
```

---

## 🚀 Quickstart Guide

### 1. Prerequisites
* **Python 3.12+**
* **Node.js 18+** & npm
* **MongoDB** (running locally on port 27017 or MongoDB Atlas)

---

### 2. Setup the Backend & Virtual Environment

```bash
# Clone the repository
git clone https://github.com/AchalRaj0709/aegis-hmac.git
cd aegis-hmac

# Create & activate Python virtual environment
python -m venv venv
.\venv\Scripts\activate   # On Windows
# source venv/bin/activate # On macOS/Linux

# Install backend dependencies
pip install -r backend/requirements.txt
```

---

### 3. Seed Demo Data & Run Tests

```bash
# Seed demo clients and sample historical audit logs
python scripts/seed.py

# Run all 47 automated security and cryptographic tests
pytest -v
```

---

### 4. Launch the Applications

#### Terminal 1: Start FastAPI Backend Gateway
```bash
python -m uvicorn app.main:app --app-dir backend --reload --port 8000
```
* **API Documentation (Swagger UI)**: [http://localhost:8000/docs](http://localhost:8000/docs)
* **GraphQL Explorer**: [http://localhost:8000/graphql](http://localhost:8000/graphql)

#### Terminal 2: Start React + TypeScript Dashboard
```bash
cd frontend
npm install
npm run dev
```
* **Developer Dashboard & Sandbox**: [http://localhost:5173](http://localhost:5173)

---

## 💻 Client SDK Usage

### Python SDK (`sdks/python/`)

```python
import asyncio
from aegis_client import AegisClient

async def main():
    # Initialize client with credentials
    client = AegisClient(
        base_url="http://localhost:8000",
        client_id="client_fintech_prod",
        secret_key="your_256_bit_secret_key_here",
    )

    # 1. Tamper-Proof REST Payment Transfer
    transfer = await client.post(
        "/api/v1/payments/transfer",
        json={"recipient_id": "vendor_99", "amount": 250.00, "currency": "USD"}
    )
    print("Transfer Status:", transfer.json())

    # 2. Authenticated Strawberry GraphQL Mutation
    gql = await client.graphql(
        query="""
            mutation {
                executeTransfer(fromAccount: "acc_1", toAccount: "acc_2", amount: 150.0) {
                    success
                    transactionId
                }
            }
        """
    )
    print("GraphQL Result:", gql.json())

asyncio.run(main())
```

---

### TypeScript SDK (`sdks/typescript/`)

```typescript
import { createHmacFetch } from "@aegis/client-ts";

const hmacFetch = createHmacFetch({
  baseUrl: "http://localhost:8000",
  clientId: "client_fintech_prod",
  secretKey: "your_256_bit_secret_key_here",
});

// Outgoing requests are automatically signed with Canonical String & HMAC
const response = await hmacFetch("/api/v1/payments/transfer", {
  method: "POST",
  body: JSON.stringify({ recipient_id: "vendor_99", amount: 250.0 }),
});

const data = await response.json();
console.log("Verified:", data);
```

---

## ⚡ Performance Benchmarking

To measure signature verification throughput and latency percentiles under concurrent load:

```bash
python scripts/benchmark.py
```

### Benchmark Results:
* **Throughput**: Sustained **>100 req/sec** under concurrent load.
* **Internal Verification Overhead**: **<0.5ms** cryptographic calculation time.
* **Success Rate**: **100.0%** signatures verified without failure.

---

## 🧪 Automated Testing Breakdown

The test suite covers 47 test cases across 7 dedicated modules:
* `test_rfc4231.py`: Official IETF RFC 4231 test vectors 1 through 7 for HMAC-SHA256 correctness.
* `test_canonicalization.py`: Query parameter sorting, header case insensitivity, whitespace trimming, and payload hashing.
* `test_envelope.py`: AES-256-GCM envelope encryption, 96-bit random IV verification, and authentication tag tamper failure.
* `test_database.py`: MongoDB CRUD, zero-downtime dual-key rotation, and atomic nonce replay prevention.
* `test_middleware.py`: Gateway clock skew rejection ($\pm 300\text{s}$ window), duplicate nonce blocking, and signature verification.
* `test_business_endpoints.py`: REST financial transfers, secure profiles, webhook ingress, and GraphQL queries/mutations.
* `test_python_sdk.py`: `AegisHttpxAuth` automatic request signing against live FastAPI endpoints.

---

## 📄 License

MIT License. Designed and built by [AchalRaj0709](https://github.com/AchalRaj0709).
